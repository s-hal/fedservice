"""Registration Policy enforcement through real signed Resolve candidates."""

from copy import deepcopy
import json

from cryptojwt.jws.jws import factory
import pytest

from fedservice.entity.server.response import do_response
from fedservice.federation_jwt.jose import sign_federation_jwt
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
from tests.test_57_resolve_statement_validation import chain_tokens
from tests.test_57_resolve_statement_validation import intermediate_chain


APPROVED = "urn:example:registration-policy:approved"
DIFFERENT = "urn:example:registration-policy:different"


def update_statement(fed, owner, subject, **fields):
    """Sign isolated fixture changes while retaining the original time bounds."""
    profile = ENTITY_CONFIGURATION if owner == subject else SUBORDINATE_STATEMENT
    url = ec_url(owner) if owner == subject else ss_url(owner, subject)
    payload = factory(fed.documents[url]).jwt.payload()
    payload.update(deepcopy(fields))
    token = sign_federation_jwt(profile, payload, fed.signing, owner, "ES256", iat=payload["iat"])
    fed.documents[url] = token
    return token


def assert_rejected(fed, result):
    """Check the existing Resolve error, not an unsigned success-shaped result."""
    assert result["error"] == "invalid_trust_chain"
    assert result["response_code"] == 400
    assert "response_args" not in result
    assert "response_msg" not in result
    assert "metadata" not in result
    envelope = do_response(fed.resolver.get_endpoint("resolve"), **result)
    assert envelope["response_code"] == 400
    assert json.loads(envelope["response"])["error"] == "invalid_trust_chain"
    assert ("Content-type", "application/json") in envelope["http_headers"]


@pytest.mark.parametrize("policies,constrained,accepted", [
    ([APPROVED], True, True), ([DIFFERENT], True, False), (None, True, False),
    ([], True, False), (None, False, True),
])
def test_resolve_registration_policy_initial_and_cached(intermediate_chain, policies, constrained, accepted):
    fed = intermediate_chain
    if constrained:
        update_statement(fed, ANCHOR, INTERMEDIATE,
                         constraints={"registration_policy": [{"policy": [APPROVED]}]})
    if policies is not None:
        update_statement(fed, INTERMEDIATE, LEAF, registration_policy=policies)
    documents = dict(fed.documents)
    for _ in range(2):
        result = resolve(fed)
        if accepted:
            claims = success(fed, result, chain_tokens(fed))
            assert claims["metadata"] == verify_federation_jwt(
                ENTITY_CONFIGURATION, documents[ec_url(LEAF)], fed.signing).claims()["metadata"]
        else:
            assert_rejected(fed, result)
        assert len(fed.http.calls) == 5
        assert fed.documents == documents
    assert set(fed.resolver.trust_anchors) == {ANCHOR}


@pytest.mark.parametrize("policy,accepted", [
    ("https://[v1.a]/policy", True),
    ("https://[V1.a]/policy", True),
    ("https://[v1.a%20b]/policy", False),
    ("https://[V1.a%2Fb]/policy", False),
])
def test_resolve_registration_policy_ipvfuture(intermediate_chain, policy, accepted):
    fed = intermediate_chain
    update_statement(fed, ANCHOR, INTERMEDIATE,
                     constraints={"registration_policy": [{"policy": [policy]}]})
    update_statement(fed, INTERMEDIATE, LEAF, registration_policy=[policy])
    documents = dict(fed.documents)
    for _ in range(2):
        result = resolve(fed)
        if accepted:
            success(fed, result, chain_tokens(fed))
            assert len(fed.http.calls) == 5
        else:
            assert_rejected(fed, result)
        assert fed.documents == documents
        assert all(call.request.url in documents for call in fed.http.calls)
    assert set(fed.resolver.trust_anchors) == {ANCHOR}


@pytest.mark.parametrize("order", [[INTERMEDIATE, OTHER], [OTHER, INTERMEDIATE]])
def test_resolve_registration_policy_independent_candidate_orders(intermediate_chain, order):
    fed = intermediate_chain
    fed.ec(LEAF, fed.now + 7200, hints=order, path=None)
    fed.ec(OTHER, fed.now + 7200, hints=[ANCHOR])
    fed.ss(OTHER, LEAF, fed.now + 5400)
    fed.ss(ANCHOR, OTHER, fed.now + 5400)
    for intermediate, policy in ((INTERMEDIATE, DIFFERENT), (OTHER, APPROVED)):
        update_statement(fed, ANCHOR, intermediate,
                         constraints={"registration_policy": [{"policy": [APPROVED]}]})
        update_statement(fed, intermediate, LEAF, registration_policy=[policy])
    documents = dict(fed.documents)
    for _ in range(2):
        claims = success(fed, resolve(fed), chain_tokens(fed, OTHER))
        assert documents[ss_url(INTERMEDIATE, LEAF)] not in claims["trust_chain"]
        assert documents[ss_url(ANCHOR, INTERMEDIATE)] not in claims["trust_chain"]
        assert len(fed.http.calls) == 8
        assert fed.documents == documents
    assert set(fed.resolver.trust_anchors) == {ANCHOR}


@pytest.mark.parametrize("policies,accepted", [([], False), ([APPROVED], True)])
def test_resolve_registration_policy_classifies_before_metadata_filtering(intermediate_chain, policies, accepted):
    fed = intermediate_chain
    metadata = {"federation_entity": {"organization_name": "original"}, "custom": {}}
    update_statement(fed, LEAF, LEAF, metadata=metadata)
    update_statement(fed, ANCHOR, INTERMEDIATE, constraints={"registration_policy": [
        {"policy": [APPROVED], "entity_types": ["custom"]}]})
    update_statement(fed, INTERMEDIATE, LEAF, registration_policy=policies,
                     constraints={"allowed_entity_types": []},
                     metadata={"federation_entity": {"organization_name": "direct"}},
                     metadata_policy={"federation_entity": {"organization_name": {"value": "policy"}}})
    for _ in range(2):
        result = fed.resolver.get_endpoint("resolve").process_request({
            "sub": LEAF, "trust_anchor": [ANCHOR], "entity_type": ["federation_entity"]},
            with_ta_ec=True)
        if accepted:
            claims = success(fed, result, chain_tokens(fed), name="policy")
            assert set(claims["metadata"]) == {"federation_entity"}
        else:
            assert_rejected(fed, result)
        assert len(fed.http.calls) == 5
