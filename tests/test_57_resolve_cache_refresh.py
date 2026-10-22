"""Signed Resolve recovery through the shared collector, without Trust Marks."""

import pytest
from requests.exceptions import ConnectionError
from requests.exceptions import Timeout

from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.federation_jwt.registry import RESOLVE_RESPONSE
from fedservice.federation_jwt.registry import SUBORDINATE_STATEMENT
from tests.test_55_entity_statement_cache import ANCHOR
from tests.test_55_entity_statement_cache import INTERMEDIATE
from tests.test_55_entity_statement_cache import LEAF
from tests.test_55_entity_statement_cache import OTHER
from tests.test_55_entity_statement_cache import clock
from tests.test_55_entity_statement_cache import ec_url
from tests.test_55_entity_statement_cache import federation
from tests.test_55_entity_statement_cache import ss_url
from tests.test_55_entity_statement_subject_binding import corrupt_signature


def resolve(fed, anchors=None):
    return fed.resolver.get_endpoint("resolve").process_request(
        {"sub": LEAF, "trust_anchor": anchors or [ANCHOR]}, with_ta_ec=True)


def success(fed, result, tokens, name="original"):
    verified = verify_federation_jwt(RESOLVE_RESPONSE, result["response_args"], fed.resolver.keyjar)
    claims = verified.claims()
    assert list(claims["trust_chain"]) == tokens
    assert claims["metadata"]["federation_entity"]["organization_name"] == name
    assert claims["exp"] == min(
        verify_federation_jwt(ENTITY_CONFIGURATION if index in (0, len(tokens) - 1)
                              else SUBORDINATE_STATEMENT,
                              token, fed.signing).claims()["exp"]
        for index, token in enumerate(tokens))
    assert "trust_marks" not in claims
    assert fed.resolver.get_service("trust_mark_status") is None
    assert all(call.request.method == "GET" for call in fed.http.calls)
    return claims


def expected_tokens(fed):
    return [fed.documents[ec_url(LEAF)], fed.documents[ss_url(ANCHOR, LEAF)],
            fed.documents[ec_url(ANCHOR)]]


@pytest.mark.parametrize("fraction", [0, 0.5])
@pytest.mark.parametrize("offset", [-0.125, 0, 0.125])
def test_resolve_immediately_recovers_from_cached_ec_expiry(federation, fraction, offset):
    fed = federation
    expiry = fed.now + 1200 + fraction
    fed.ec(LEAF, expiry)
    success(fed, resolve(fed), expected_tokens(fed))
    success(fed, resolve(fed), expected_tokens(fed))
    assert len(fed.http.calls) == 3
    fed.clock[0] = expiry + offset
    fed.ec(LEAF, expiry + 3600, name="renewed")
    success(fed, resolve(fed), expected_tokens(fed), "renewed")
    assert len(fed.http.calls) == 4
    assert fed.http.calls[-1].request.url == ec_url(LEAF)


@pytest.mark.parametrize("dependency", ["leaf", "anchor", "subordinate"])
def test_new_short_lived_material_is_used_once_and_never_past_deadline(federation, dependency):
    fed = federation
    expiry = fed.now + 100.5
    if dependency == "subordinate":
        fed.ss(ANCHOR, LEAF, expiry)
    else:
        fed.ec(LEAF if dependency == "leaf" else ANCHOR, expiry)
    success(fed, resolve(fed), expected_tokens(fed))
    assert len(fed.http.calls) == 3
    fed.clock[0] = expiry - 0.125
    success(fed, resolve(fed), expected_tokens(fed))
    assert len(fed.http.calls) == 4
    fed.clock[0] = expiry
    result = resolve(fed)
    assert result["error"] == "invalid_trust_chain" and result["response_code"] == 400
    assert "response_args" not in result


def test_early_refresh_failure_does_not_fall_back_to_usable_cache(federation):
    fed = federation
    success(fed, resolve(fed), expected_tokens(fed))
    fed.clock[0] = fed.now + 600.5
    fed.documents[ec_url(LEAF)] = Timeout("early refresh unavailable")
    result = resolve(fed)
    assert result["error"] == "server_error" and result["response_code"] == 504
    assert "response_args" not in result
    assert fed.collector.config_cache[LEAF] is None
    fed.ec(LEAF, fed.now + 7200, name="recovered")
    success(fed, resolve(fed), expected_tokens(fed), "recovered")


@pytest.mark.parametrize("failure,code,status", [
    ("missing", "not_found", 404), ("timeout", "server_error", 504),
    ("connection", "server_error", 502), ("upstream", "server_error", 502),
    ("media", "server_error", 502), ("signature", "invalid_trust_chain", 400),
    ("subject", "invalid_trust_chain", 400), ("expired", "invalid_trust_chain", 400),
])
def test_failed_leaf_refresh_preserves_error_mapping_and_can_recover(federation, failure, code, status):
    fed = federation
    expiry = fed.now + 1200.5
    success(fed, resolve(fed), expected_tokens(fed))
    fed.clock[0] = expiry + 0.125
    if failure == "signature":
        replacement = corrupt_signature(fed.ec(LEAF, expiry + 3600))
    elif failure == "subject":
        replacement = fed.ec(OTHER, expiry + 3600)
    elif failure == "expired":
        replacement = fed.ec(LEAF, expiry)
        # Keep ordinary verification leeway: only the operation deadline rejects.
        assert verify_federation_jwt(ENTITY_CONFIGURATION, replacement, fed.signing).claims()["exp"] == expiry
    else:
        replacement = {"missing": (404, {}, "missing"), "timeout": Timeout("slow"),
                       "connection": ConnectionError("unavailable"),
                       "upstream": (503, {}, "unavailable"),
                       "media": (200, {"Content-Type": "text/html"}, "invalid")}[failure]
    fed.documents[ec_url(LEAF)] = replacement
    result = resolve(fed)
    assert result["error"] == code and result["response_code"] == status
    assert "response_args" not in result
    assert fed.collector.config_cache.get(LEAF) is None
    fed.ec(LEAF, expiry + 3600, name="recovered")
    success(fed, resolve(fed), expected_tokens(fed), "recovered")


@pytest.mark.parametrize("dependency", ["anchor", "subordinate", "intermediate"])
def test_shared_dependencies_refresh_independently(federation, dependency):
    fed = federation
    expiry = fed.now + 1200.5
    fed.ec(LEAF, fed.now + 7200)
    if dependency == "anchor":
        fed.ec(ANCHOR, expiry)
    elif dependency == "subordinate":
        fed.ss(ANCHOR, LEAF, expiry)
    else:
        fed.ec(LEAF, fed.now + 7200, hints=[INTERMEDIATE])
        fed.ec(INTERMEDIATE, expiry, hints=[ANCHOR])
        fed.ss(INTERMEDIATE, LEAF, fed.now + 5400)
        fed.ss(ANCHOR, INTERMEDIATE, fed.now + 5400)
    result = resolve(fed)
    assert "response_args" in result
    old_count = len(fed.http.calls)
    fed.clock[0] = expiry
    if dependency == "anchor":
        fed.ec(ANCHOR, fed.now + 7200, path="/new-fetch")
    elif dependency == "subordinate":
        fed.ss(ANCHOR, LEAF, fed.now + 6000)
    else:
        fed.ec(INTERMEDIATE, fed.now + 7200, hints=[ANCHOR], path="/new-fetch")
    tokens = expected_tokens(fed) if dependency != "intermediate" else [
        fed.documents[ec_url(LEAF)], fed.documents[ss_url(INTERMEDIATE, LEAF)],
        fed.documents[ss_url(ANCHOR, INTERMEDIATE)], fed.documents[ec_url(ANCHOR)]]
    success(fed, resolve(fed), tokens)
    assert len(fed.http.calls) == old_count + 1
    if dependency != "subordinate":
        owner = ANCHOR if dependency == "anchor" else INTERMEDIATE
        assert fed.collector.get_federation_fetch_endpoint(owner) == owner + "/new-fetch"
        fed.clock[0] = fed.now + 5400
        fed.ss(owner, LEAF, fed.now + 9000, path="/new-fetch")
        if dependency == "intermediate":
            fed.ss(ANCHOR, INTERMEDIATE, fed.now + 9000)
        assert "response_args" in resolve(fed)
        assert any(call.request.url == ss_url(owner, LEAF, "/new-fetch") for call in fed.http.calls)


def test_failed_superior_refresh_leaves_independent_candidate(federation):
    fed = federation
    expiry = fed.now + 1200.5
    fed.resolver.add_trust_anchor(OTHER, fed.public[OTHER])
    fed.ec(LEAF, fed.now + 7200, hints=[ANCHOR, OTHER])
    fed.ec(ANCHOR, expiry)
    fed.ec(OTHER, fed.now + 7200)
    fed.ss(OTHER, LEAF, fed.now + 5400)
    assert "response_args" in resolve(fed, [ANCHOR, OTHER])
    fed.clock[0] = expiry
    fed.documents[ec_url(ANCHOR)] = Timeout("unavailable branch")
    success(fed, resolve(fed, [ANCHOR, OTHER]), [
        fed.documents[ec_url(LEAF)], fed.documents[ss_url(OTHER, LEAF)], fed.documents[ec_url(OTHER)]])


@pytest.mark.parametrize("dependency", ["leaf", "subordinate"])
def test_expiry_during_chain_assembly_is_controlled(federation, monkeypatch, dependency):
    fed = federation
    expiry = fed.now + 1200.5
    if dependency == "subordinate":
        fed.ec(LEAF, fed.now + 7200)
        fed.ss(ANCHOR, LEAF, expiry)
    original = fed.collector.get_chain

    def assemble(*args, **kwargs):
        fed.clock[0] = expiry
        return original(*args, **kwargs)

    monkeypatch.setattr(fed.collector, "get_chain", assemble)
    result = resolve(fed)
    assert result["error"] == "invalid_trust_chain" and result["response_code"] == 400
    assert "response_args" not in result


@pytest.mark.parametrize("owner", [LEAF, ANCHOR])
def test_retrieval_programming_errors_are_not_protocol_failures(federation, owner):
    fed = federation
    fed.documents[ec_url(owner)] = RuntimeError("programming error")
    with pytest.raises(RuntimeError, match="programming error"):
        resolve(fed)
