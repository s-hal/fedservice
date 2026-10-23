"""Received statement validation through real signed Resolve chains."""

import json

from cryptojwt.jws.jws import JWS
from cryptojwt.jws.jws import factory
import pytest

from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.federation_jwt.registry import SUBORDINATE_STATEMENT
from tests.test_55_entity_statement_cache import ANCHOR
from tests.test_55_entity_statement_cache import INTERMEDIATE
from tests.test_55_entity_statement_cache import LEAF
from tests.test_55_entity_statement_cache import OTHER
from tests.test_55_entity_statement_cache import clock
from tests.test_55_entity_statement_cache import ec_url
from tests.test_55_entity_statement_cache import federation
from tests.test_55_entity_statement_cache import ss_url
from tests.test_57_resolve_cache_refresh import resolve
from tests.test_57_resolve_cache_refresh import success


@pytest.fixture
def intermediate_chain(federation):
    """Use one anchor, an intermediate and a leaf without a Fetch endpoint."""
    fed = federation
    fed.ec(LEAF, fed.now + 7200, hints=[INTERMEDIATE], path=None)
    fed.ec(INTERMEDIATE, fed.now + 7200, hints=[ANCHOR])
    fed.ss(INTERMEDIATE, LEAF, fed.now + 5400)
    fed.ss(ANCHOR, INTERMEDIATE, fed.now + 5400)
    assert set(fed.resolver.trust_anchors) == {ANCHOR}
    return fed


def set_source_endpoint(fed, value):
    """Sign received source_endpoint evidence independently of producer checks."""
    url = ss_url(INTERMEDIATE, LEAF)
    payload = factory(fed.documents[url]).jwt.payload()
    payload["source_endpoint"] = value
    token = JWS(json.dumps(payload), alg="ES256").sign_compact(
        fed.signing.get_signing_key("EC", issuer_id=INTERMEDIATE),
        protected={"typ": SUBORDINATE_STATEMENT.typ})
    fed.documents[url] = token
    return token


def chain_tokens(fed, intermediate=INTERMEDIATE):
    """Return the original compact tokens in Resolve response order."""
    return [fed.documents[ec_url(LEAF)], fed.documents[ss_url(intermediate, LEAF)],
            fed.documents[ss_url(ANCHOR, intermediate)], fed.documents[ec_url(ANCHOR)]]


def set_chain_header(fed, owner, name, value):
    """Sign an EC with received header evidence without a discovery check."""
    payload = factory(fed.documents[ec_url(owner)]).jwt.payload()
    token = JWS(json.dumps(payload), alg="ES256").sign_compact(
        fed.signing.get_signing_key("EC", issuer_id=owner),
        protected={"typ": ENTITY_CONFIGURATION.typ, name: value})
    fed.documents[ec_url(owner)] = token
    return token


@pytest.mark.parametrize("value", ["not a URL", "", "/fetch", "https://", None, False, 42, [], {},
    "https://intermediate.example.org/fetch?q=\ud800", "https://intermediate.example.org/\udfff"])
def test_resolve_rejects_source_endpoint_on_initial_and_cached_request(intermediate_chain, value):
    fed = intermediate_chain
    set_source_endpoint(fed, value)
    for _ in range(2):
        result = resolve(fed)
        assert result["error"] == "invalid_trust_chain"
        assert result["response_code"] == 400
        assert "response_args" not in result
        assert "metadata" not in result
        assert len(fed.http.calls) == 5


@pytest.mark.parametrize("value", [None, "https://intermediate.example.org:8443/fetch?version=1",
    "https://intermediate.example.org/\U0001d11e?version=1"])
def test_resolve_source_endpoint_absent_or_valid_preserves_success(intermediate_chain, value):
    fed = intermediate_chain
    if value is not None:
        set_source_endpoint(fed, value)
    for _ in range(2):
        claims = success(fed, resolve(fed), chain_tokens(fed))
        assert claims["metadata"] == verify_federation_jwt(
            ENTITY_CONFIGURATION, fed.documents[ec_url(LEAF)], fed.signing).claims()["metadata"]
        assert len(fed.http.calls) == 5
    assert all(call.request.url != value for call in fed.http.calls)


def test_resolve_invalid_source_endpoint_leaves_independent_candidate_to_same_anchor(intermediate_chain):
    fed = intermediate_chain
    bad_token = set_source_endpoint(fed, "not a URL")
    fed.ec(LEAF, fed.now + 7200, hints=[INTERMEDIATE, OTHER], path=None)
    fed.ec(OTHER, fed.now + 7200, hints=[ANCHOR])
    fed.ss(OTHER, LEAF, fed.now + 5400)
    fed.ss(ANCHOR, OTHER, fed.now + 5400)
    for _ in range(2):
        claims = success(fed, resolve(fed), chain_tokens(fed, OTHER))
        assert bad_token not in claims["trust_chain"]
        assert len(fed.http.calls) == 8


@pytest.mark.parametrize("name", ["trust_chain", "peer_trust_chain"])
@pytest.mark.parametrize("owner", [LEAF, INTERMEDIATE])
def test_resolve_rejects_discovered_chain_header_on_repeated_request(intermediate_chain, name, owner):
    fed = intermediate_chain
    token = set_chain_header(fed, owner, name, chain_tokens(fed))
    # The EC is genuinely signed, but its local discovery use is prohibited.
    assert verify_federation_jwt(ENTITY_CONFIGURATION, token, fed.signing).raw_token() == token
    for attempt in range(2):
        result = resolve(fed)
        assert result["error"] == "invalid_trust_chain"
        assert result["response_code"] == 400
        assert "response_args" not in result
        assert owner not in fed.collector.config_cache
        assert len(fed.http.calls) == attempt + (1 if owner == LEAF else 2)


@pytest.mark.parametrize("name", ["trust_chain", "peer_trust_chain"])
def test_resolve_chain_header_rejection_leaves_independent_candidate(intermediate_chain, name):
    fed = intermediate_chain
    set_chain_header(fed, INTERMEDIATE, name, chain_tokens(fed))
    fed.ec(LEAF, fed.now + 7200, hints=[INTERMEDIATE, OTHER], path=None)
    fed.ec(OTHER, fed.now + 7200, hints=[ANCHOR])
    fed.ss(OTHER, LEAF, fed.now + 5400)
    fed.ss(ANCHOR, OTHER, fed.now + 5400)
    for attempt in range(2):
        success(fed, resolve(fed), chain_tokens(fed, OTHER))
        assert INTERMEDIATE not in fed.collector.config_cache
        assert len(fed.http.calls) == 6 + attempt
