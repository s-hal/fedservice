"""Signed Resolve recovery through the shared collector, without Trust Marks."""

import json

from cryptojwt.jws.jws import JWS
from cryptojwt.jws.jws import factory
import pytest
from requests.exceptions import ConnectionError
from requests.exceptions import ConnectTimeout
from requests.exceptions import ReadTimeout
from requests.exceptions import InvalidURL
from requests.exceptions import ProxyError
from requests.exceptions import SSLError
from requests.exceptions import Timeout

from fedservice.entity.function import verify_trust_chains
from fedservice.entity.function import apply_policies
from fedservice.entity.function.trust_chain_collector import cache_key
from fedservice.entity.function.trust_chain_collector import time_key
from fedservice.federation_jwt.errors import FederationJwtKeyResolutionError
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.jose import sign_federation_jwt
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


def warm_refresh(fed, dependency, fraction=0.5):
    """Warm a signed chain with just the selected dependency due for refresh."""
    expiry = fed.now + 1200 + fraction
    fed.ec(LEAF, fed.now + 7200)
    if dependency == "subordinate":
        url = ss_url(ANCHOR, LEAF)
        fed.ss(ANCHOR, LEAF, expiry)
    else:
        owner = {"leaf": LEAF, "anchor": ANCHOR, "intermediate": INTERMEDIATE,
                 "upper_statement": INTERMEDIATE}[dependency]
        url = ec_url(owner)
        if dependency in ("intermediate", "upper_statement"):
            fed.ec(LEAF, fed.now + 7200, hints=[INTERMEDIATE])
            fed.ec(INTERMEDIATE, expiry if dependency == "intermediate" else fed.now + 7200,
                   hints=[ANCHOR])
            fed.ss(INTERMEDIATE, LEAF, fed.now + 5400)
            fed.ss(ANCHOR, INTERMEDIATE, expiry if dependency == "upper_statement" else fed.now + 5400)
            if dependency == "upper_statement":
                url = ss_url(ANCHOR, INTERMEDIATE)
        else:
            fed.ec(owner, expiry)
    tokens = expected_tokens(fed) if dependency not in ("intermediate", "upper_statement") else [
        fed.documents[ec_url(LEAF)], fed.documents[ss_url(INTERMEDIATE, LEAF)],
        fed.documents[ss_url(ANCHOR, INTERMEDIATE)], fed.documents[ec_url(ANCHOR)]]
    success(fed, resolve(fed), tokens)
    assert len(fed.http.calls) == (5 if dependency in ("intermediate", "upper_statement") else 3)
    fed.clock[0] = expiry - fed.collector.allowed_delta
    return expiry, url, tokens


@pytest.mark.parametrize("dependency", ["leaf", "intermediate", "anchor", "subordinate", "upper_statement"])
@pytest.mark.parametrize("failure", [
    Timeout("slow"), ConnectTimeout("connect slow"), ReadTimeout("read slow"),
    ConnectionError("offline"), (500, {}, "down"), (502, {}, "down"),
    (503, {}, "down"), (504, {}, "down"),
])
def test_early_refresh_failure_retains_usable_cache_and_retries(federation, dependency, failure):
    fed = federation
    expiry, url, tokens = warm_refresh(fed, dependency)
    count = len(fed.http.calls)
    fed.documents[url] = failure
    for attempt in (1, 2):
        claims = success(fed, resolve(fed), tokens)
        assert len(verify_trust_chains(
            fed.resolver, [list(reversed(claims["trust_chain"][:-1]))])) == 1
        assert claims["exp"] == min(factory(token).jwt.payload()["exp"] for token in tokens)
        assert len(fed.http.calls) == count + attempt
        assert fed.http.calls[-1].request.url == url
    if dependency in ("subordinate", "upper_statement"):
        subject = LEAF if dependency == "subordinate" else INTERMEDIATE
        fresh = fed.ss(ANCHOR, subject, fed.now + 7200)
        tokens[1 if dependency == "subordinate" else 2] = fresh
    else:
        owner = {"leaf": LEAF, "anchor": ANCHOR, "intermediate": INTERMEDIATE}[dependency]
        fresh = fed.ec(owner, fed.now + 7200, name="recovered",
                       hints=[ANCHOR] if dependency == "intermediate" else None)
        if dependency != "intermediate":
            tokens[0 if dependency == "leaf" else -1] = fresh
    success(fed, resolve(fed), tokens, "recovered" if dependency == "leaf" else "original")
    assert len(fed.http.calls) == count + 3
    if dependency in ("subordinate", "upper_statement"):
        assert fed.collector.entity_statement_cache[cache_key(ANCHOR, subject)] == fresh
    else:
        assert fed.collector.config_cache[owner]["_jws"] == fresh


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


def test_retrieval_programming_errors_are_not_protocol_failures(federation):
    fed = federation
    fed.documents[ec_url(LEAF)] = RuntimeError("programming error")
    with pytest.raises(RuntimeError, match="programming error"):
        resolve(fed)


@pytest.mark.parametrize("malformed", ["string", "missing", "null", "boolean", "infinite", "nan", "jwks"])
def test_malformed_first_authority_does_not_block_independent_chain(federation, malformed):
    fed = federation
    fed.resolver.add_trust_anchor(OTHER, fed.public[OTHER])
    fed.ec(LEAF, fed.now + 7200, hints=[ANCHOR, OTHER])
    fed.ec(OTHER, fed.now + 7200)
    fed.ss(OTHER, LEAF, fed.now + 5400)
    url = ec_url(ANCHOR) if malformed == "jwks" else ss_url(ANCHOR, LEAF)
    profile = ENTITY_CONFIGURATION if malformed == "jwks" else SUBORDINATE_STATEMENT
    payload = factory(fed.documents[url]).jwt.payload()
    if malformed == "jwks":
        del payload["jwks"]
    elif malformed == "missing":
        del payload["exp"]
    else:
        payload["exp"] = {"string": str(payload["exp"]), "null": None,
                          "boolean": True, "infinite": float("inf"), "nan": float("nan")}[malformed]
    # Deliberately malformed signed peer data cannot use the validating producer.
    fed.documents[url] = JWS(json.dumps(payload), alg="ES256").sign_compact(
        fed.signing.get_signing_key("EC", issuer_id=ANCHOR), protected={"typ": profile.typ})
    success(fed, resolve(fed, [ANCHOR, OTHER]), [
        fed.documents[ec_url(LEAF)], fed.documents[ss_url(OTHER, LEAF)], fed.documents[ec_url(OTHER)]])
    assert cache_key(ANCHOR, LEAF) not in fed.collector.entity_statement_cache
    assert time_key(ANCHOR, LEAF) not in fed.collector.entity_statement_cache
    assert fed.collector.entity_statement_cache[cache_key(OTHER, LEAF)] == fed.documents[ss_url(OTHER, LEAF)]
    assert any(call.request.url == url for call in fed.http.calls)


@pytest.mark.parametrize("corrected", [False, True])
def test_resolve_retries_missing_fetch_endpoint_once_per_operation(federation, corrected):
    fed = federation
    fed.ec(ANCHOR, fed.now + 7200, path=None)
    result = resolve(fed)
    assert result["error"] == "invalid_trust_chain" and result["response_code"] == 400
    assert "response_args" not in result
    assert len(fed.http.calls) == 2
    if corrected:
        fed.ec(ANCHOR, fed.now + 7200, path="/corrected-fetch")
        subordinate = fed.ss(ANCHOR, LEAF, fed.now + 5400, path="/corrected-fetch")
        success(fed, resolve(fed), [
            fed.documents[ec_url(LEAF)], subordinate, fed.documents[ec_url(ANCHOR)]])
        assert len(fed.http.calls) == 4
    else:
        # Even short-lived missing-endpoint replacements are fetched only once.
        fed.ec(ANCHOR, fed.now + 100.5, path=None)
        for expected_count in (3, 4):
            result = resolve(fed)
            assert result["error"] == "invalid_trust_chain" and result["response_code"] == 400
            assert "response_args" not in result
            assert len(fed.http.calls) == expected_count
        assert all(call.request.url != ss_url(ANCHOR, LEAF) for call in fed.http.calls)


def test_cached_subordinate_needs_no_fetch_endpoint_after_authority_refresh(federation):
    fed = federation
    expiry = fed.now + 1200.5
    fed.ec(LEAF, fed.now + 7200)
    fed.ec(ANCHOR, expiry)
    success(fed, resolve(fed), expected_tokens(fed))
    assert len(fed.http.calls) == 3
    fed.clock[0] = expiry - fed.collector.allowed_delta
    fed.ec(ANCHOR, fed.now + 7200, path=None)
    success(fed, resolve(fed), expected_tokens(fed))
    assert len(fed.http.calls) == 4
    assert fed.http.calls[-1].request.url == ec_url(ANCHOR)
    success(fed, resolve(fed), expected_tokens(fed))
    assert len(fed.http.calls) == 4


@pytest.mark.parametrize("dependency", ["leaf", "anchor", "subordinate"])
@pytest.mark.parametrize("fraction", [0, 0.5])
@pytest.mark.parametrize("offset", [-0.125, 0, 0.125])
def test_outage_fallback_rechecks_deadline_after_http(federation, dependency, fraction, offset):
    fed = federation
    expiry, url, tokens = warm_refresh(fed, dependency, fraction)
    count = len(fed.http.calls)

    def timeout_after_time_passes(request):
        fed.clock[0] = expiry + offset
        raise Timeout("time spent in retrieval")

    fed.documents[url] = timeout_after_time_passes
    result = resolve(fed)
    if offset < 0:
        success(fed, result, tokens)
    else:
        assert result["error"] == ("server_error" if dependency == "leaf" else "invalid_trust_chain")
        assert result["response_code"] == (504 if dependency == "leaf" else 400)
        assert "response_args" not in result
    assert len(fed.http.calls) == count + 1


def test_fallback_cannot_outlive_another_chain_dependency(federation):
    fed = federation
    fed.ec(ANCHOR, fed.now + 700.5)
    expiry, url, _ = warm_refresh(fed, "subordinate")
    count = len(fed.http.calls)

    def timeout_after_anchor_expires(request):
        fed.clock[0] = fed.now + 700.5
        assert fed.clock[0] < expiry
        raise Timeout("anchor expired during SS retrieval")

    fed.documents[url] = timeout_after_anchor_expires
    result = resolve(fed)
    assert result["error"] == "invalid_trust_chain" and result["response_code"] == 400
    assert "response_args" not in result
    assert len(fed.http.calls) == count + 2  # Due anchor refresh, then SS timeout.


@pytest.mark.parametrize("dependency", ["leaf", "subordinate"])
@pytest.mark.parametrize("failure", [
    (404, {}, "missing"), (400, {}, "invalid"), (401, {}, "auth"), (403, {}, "forbidden"),
    (410, {}, "gone"), (408, {}, "timeout"), (429, {}, "limited"),
    (501, {}, "unsupported"), (505, {}, "unsupported"),
    (200, {}, "missing media"), (200, {"Content-Type": "text/html"}, "wrong media"),
    SSLError("invalid certificate"), ProxyError("bad proxy"),
    InvalidURL("bad URL"), RuntimeError("programming failure"),
])
def test_warm_nontransient_failures_never_fall_back(federation, dependency, failure):
    fed = federation
    _, url, tokens = warm_refresh(fed, dependency)
    original = fed.documents[url]
    fed.documents[url] = failure
    count = len(fed.http.calls)
    if dependency == "leaf" and isinstance(failure, (InvalidURL, RuntimeError)):
        with pytest.raises(type(failure)):
            resolve(fed)
    else:
        result = resolve(fed)
        assert "response_args" not in result
        assert result["response_code"] >= 400
    assert len(fed.http.calls) == count + 1
    if dependency == "leaf":
        assert fed.collector.config_cache[LEAF] is None
    else:
        assert fed.collector.entity_statement_cache[cache_key(ANCHOR, LEAF)] is None
        assert fed.collector.entity_statement_cache[time_key(ANCHOR, LEAF)] is None
    # A later outage cannot undo the permanent failure's invalidation.
    fed.documents[url] = Timeout("still unavailable")
    assert "response_args" not in resolve(fed)
    fed.documents[url] = original
    success(fed, resolve(fed), tokens)


@pytest.mark.parametrize("dependency", ["leaf", "upper_statement"])
@pytest.mark.parametrize("failure", ["malformed", "subject", "issuer", "signature", "claims", "constraints"])
def test_invalid_replacement_then_outage_never_revives_old_evidence(federation, dependency, failure):
    fed = federation
    _, url, tokens = warm_refresh(fed, dependency)
    original = fed.documents[url]
    if failure == "malformed":
        replacement = "not a JWT"
    elif failure == "signature":
        replacement = corrupt_signature(original)
    else:
        payload = factory(original).jwt.payload()
        # A future-expiring rejected replacement must not suppress later retrieval.
        payload["exp"] = fed.now + 7200
        if failure == "subject":
            payload["sub"] = OTHER
        elif failure == "issuer":
            payload["iss"] = OTHER
        elif failure == "claims":
            payload["exp"] = "invalid"
        elif dependency == "upper_statement":
            payload["constraints"] = {"max_path_length": 0}
        else:
            # EC constraints are disallowed, regardless of the valid signature.
            payload["constraints"] = {"max_path_length": 0}
        issuer = LEAF if dependency == "leaf" else ANCHOR
        profile = ENTITY_CONFIGURATION if dependency == "leaf" else SUBORDINATE_STATEMENT
        replacement = JWS(json.dumps(payload), alg="ES256").sign_compact(
            fed.signing.get_signing_key("EC", issuer_id=issuer), protected={"typ": profile.typ})
    fed.documents[url] = replacement
    if dependency == "leaf" and failure == "malformed":
        with pytest.raises(ValueError):
            resolve(fed)
    else:
        result = resolve(fed)
        assert "response_args" not in result
    if dependency == "leaf":
        assert fed.collector.config_cache[LEAF] is None
    else:
        assert fed.collector.entity_statement_cache[cache_key(ANCHOR, INTERMEDIATE)] is None
    fed.documents[url] = Timeout("outage after rejection")
    assert "response_args" not in resolve(fed)
    fed.documents[url] = original
    success(fed, resolve(fed), tokens)


@pytest.mark.parametrize("failure,code,status", [
    ((404, {}, "missing"), "not_found", 404), (Timeout("slow"), "server_error", 504),
    (ConnectTimeout("slow"), "server_error", 504), (ConnectionError("offline"), "server_error", 502),
    ((500, {}, "down"), "server_error", 502), ((502, {}, "down"), "server_error", 502),
    ((503, {}, "down"), "server_error", 502), ((504, {}, "down"), "server_error", 502),
])
def test_cold_outages_keep_existing_error_mapping(federation, failure, code, status):
    fed = federation
    fed.documents[ec_url(LEAF)] = failure
    result = resolve(fed)
    assert result["error"] == code and result["response_code"] == status
    assert "response_args" not in result
    assert len(fed.http.calls) == 1


@pytest.mark.parametrize("failure", [Timeout("slow"), (503, {}, "down")])
def test_missing_fetch_endpoint_is_not_repaired_by_outage_fallback(federation, failure):
    fed = federation
    fed.ec(ANCHOR, fed.now + 7200, path=None)
    assert "response_args" not in resolve(fed)
    fed.documents[ec_url(ANCHOR)] = failure
    assert "response_args" not in resolve(fed)
    assert len(fed.http.calls) == 3
    assert all(call.request.url != ss_url(ANCHOR, LEAF) for call in fed.http.calls)


@pytest.mark.parametrize("retained", [True, False])
def test_no_missing_endpoint_refresh_when_cached_ss_is_usable(federation, retained):
    fed = federation
    _, url, tokens = warm_refresh(fed, "anchor")
    if retained:
        fed.documents[url] = Timeout("early EC refresh unavailable")
    else:
        tokens[-1] = fed.ec(ANCHOR, fed.now + 7200, path=None)
    count = len(fed.http.calls)
    success(fed, resolve(fed), tokens)
    assert len(fed.http.calls) == count + 1


def test_verification_timeout_is_not_a_transport_outage(federation, monkeypatch):
    fed = federation
    _, url, _ = warm_refresh(fed, "leaf")
    fed.ec(LEAF, fed.now + 7200)

    def verification_failure(*args, **kwargs):
        raise Timeout("verification application failure")

    monkeypatch.setattr("fedservice.entity.function.trust_chain_collector.verify_self_signed_signature",
                        verification_failure)
    result = resolve(fed)
    assert "response_args" not in result
    assert fed.collector.config_cache[LEAF] is None


@pytest.mark.parametrize("terminal", ["success", "timeout", "404", "quota"])
def test_tenant_location_terminal_outcome_controls_retention(federation, terminal):
    fed = federation
    tenant = LEAF + "/tenant"
    fed.signing.add_keys(tenant, fed.signing.get_signing_key("EC", issuer_id=LEAF))
    fed.public[tenant] = fed.public[LEAF]
    token = fed.ec(tenant, fed.now + 1200.5, hints=[ANCHOR])
    statement = fed.ss(ANCHOR, tenant, fed.now + 5400)
    primary = ec_url(LEAF)
    fed.documents[primary] = token
    endpoint = fed.resolver.get_endpoint("resolve")
    args = {"sub": tenant, "trust_anchor": [ANCHOR]}
    tokens = [token, statement, fed.documents[ec_url(ANCHOR)]]
    success(fed, endpoint.process_request(args, with_ta_ec=True), tokens)
    count = len(fed.http.calls)
    fed.clock[0] = fed.now + 600.5
    fed.documents[primary] = (404, {}, "not at primary location")
    if terminal == "timeout":
        fed.documents[ec_url(tenant)] = Timeout("tenant unavailable")
    elif terminal == "404":
        fed.documents[ec_url(tenant)] = (404, {}, "tenant missing")
    elif terminal == "quota":
        fed.collector.max_requests = 1
    result = endpoint.process_request(args, with_ta_ec=True)
    if terminal in ("success", "timeout"):
        success(fed, result, tokens)
    else:
        assert "response_args" not in result
        assert fed.collector.config_cache[tenant] is None
    urls = [call.request.url for call in fed.http.calls[count:]]
    assert urls == ([primary] if terminal == "quota" else [primary, ec_url(tenant)])


def test_policy_rejected_replacement_is_not_later_outage_evidence(federation):
    fed = federation
    _, url, tokens = warm_refresh(fed, "subordinate")
    payload = factory(tokens[1]).jwt.payload()
    payload['exp'] = fed.now + 7200
    payload['metadata_policy'] = {'federation_entity': {
        'organization_name': {'one_of': ['not the original name']}}}
    fed.documents[url] = sign_federation_jwt(
        SUBORDINATE_STATEMENT, payload, fed.signing, ANCHOR, 'ES256', iat=payload['iat'])
    assert resolve(fed)['error'] == 'invalid_metadata'
    assert fed.collector.entity_statement_cache[cache_key(ANCHOR, LEAF)] is None
    fed.documents[url] = Timeout('outage after policy rejection')
    assert 'response_args' not in resolve(fed)
    fed.documents[url] = tokens[1]
    success(fed, resolve(fed), tokens)


@pytest.mark.parametrize("missing", ["raw_ec", "ss_token", "ss_expiry", "mismatched_pair"])
def test_incomplete_cache_evidence_cannot_support_fallback(federation, missing):
    fed = federation
    _, url, _ = warm_refresh(fed, "leaf" if missing == "raw_ec" else "subordinate")
    if missing == "raw_ec":
        del fed.collector.config_cache[LEAF]['_jws']
    elif missing == "ss_token":
        del fed.collector.entity_statement_cache[cache_key(ANCHOR, LEAF)]
    elif missing == "ss_expiry":
        del fed.collector.entity_statement_cache[time_key(ANCHOR, LEAF)]
    else:
        fed.collector.entity_statement_cache[time_key(ANCHOR, LEAF)] += 100
    fed.documents[url] = Timeout('no complete retained evidence')
    assert 'response_args' not in resolve(fed)


def test_negative_delta_does_not_start_early_refresh(federation):
    fed = federation
    expiry, url, tokens = warm_refresh(fed, "subordinate")
    fed.collector.allowed_delta = -600
    fed.documents[url] = Timeout('not needed before expiry')
    count = len(fed.http.calls)
    fed.clock[0] = expiry - 0.125
    success(fed, resolve(fed), tokens)
    assert len(fed.http.calls) == count
    fed.clock[0] = expiry
    assert 'response_args' not in resolve(fed)
    assert len(fed.http.calls) == count + 1


def test_permanent_warm_failure_does_not_block_independent_candidate(federation):
    fed = federation
    fed.resolver.add_trust_anchor(OTHER, fed.public[OTHER])
    fed.ec(LEAF, fed.now + 7200, hints=[ANCHOR, OTHER])
    fed.ec(ANCHOR, fed.now + 1200.5)
    fed.ec(OTHER, fed.now + 7200)
    fed.ss(OTHER, LEAF, fed.now + 5400)
    success(fed, resolve(fed, [ANCHOR, OTHER]), expected_tokens(fed))
    count = len(fed.http.calls)
    fed.clock[0] = fed.now + 600.5
    fed.documents[ec_url(ANCHOR)] = (403, {}, 'not an outage')
    success(fed, resolve(fed, [ANCHOR, OTHER]), [
        fed.documents[ec_url(LEAF)], fed.documents[ss_url(OTHER, LEAF)], fed.documents[ec_url(OTHER)]])
    assert len(fed.http.calls) == count + 1


@pytest.mark.parametrize("dependency", ["leaf", "anchor"])
def test_bootstrap_valid_replacement_still_needs_established_keys(federation, dependency):
    fed = federation
    _, url, tokens = warm_refresh(fed, dependency)
    original = fed.documents[url]
    payload = factory(original).jwt.payload()
    payload['jwks'] = fed.public[OTHER]
    payload['exp'] = fed.now + 7200
    fed.documents[url] = JWS(json.dumps(payload), alg='ES256').sign_compact(
        fed.signing.get_signing_key('EC', issuer_id=OTHER),
        protected={'typ': ENTITY_CONFIGURATION.typ})
    # This preserves the established key-resolution exception, not trust in a
    # self-signature made with replacement embedded keys.
    with pytest.raises(FederationJwtKeyResolutionError):
        resolve(fed)
    owner = LEAF if dependency == 'leaf' else ANCHOR
    assert fed.collector.config_cache[owner] is None
    fed.documents[url] = Timeout('outage after trust failure')
    assert 'response_args' not in resolve(fed)
    fed.documents[url] = original
    success(fed, resolve(fed), tokens)


@pytest.mark.parametrize("replacement", ["constraints", "expiry"])
def test_ss_outage_preserves_newer_interleaved_pair_and_selected_tokens(federation, replacement):
    fed = federation
    expiry, url, tokens = warm_refresh(fed, "upper_statement")
    count = len(fed.http.calls)
    payload = factory(tokens[2]).jwt.payload()
    if replacement == "constraints":
        payload['constraints'] = {'max_path_length': 0}
    else:
        payload['exp'] = fed.clock[0] + 50
    new_token = sign_federation_jwt(
        SUBORDINATE_STATEMENT, payload, fed.signing, ANCHOR, 'ES256', iat=payload['iat'])

    def interleave(request):
        fed.documents[url] = new_token
        inner = fed.resolver.get_endpoint('resolve').process_request(
            {'sub': INTERMEDIATE, 'trust_anchor': [ANCHOR]}, with_ta_ec=True)
        success(fed, inner, [fed.documents[ec_url(INTERMEDIATE)], new_token, tokens[-1]])
        raise Timeout('outer SS refresh unavailable')

    fed.documents[url] = interleave
    claims = success(fed, resolve(fed), tokens)
    assert claims['exp'] == expiry
    verified = verify_trust_chains(fed.resolver, [list(reversed(claims['trust_chain'][:-1]))])
    assert len(verified) == 1
    assert apply_policies(fed.resolver, verified)[0].metadata == claims['metadata']
    assert fed.collector.entity_statement_cache[cache_key(ANCHOR, INTERMEDIATE)] == new_token
    assert fed.collector.entity_statement_cache[time_key(ANCHOR, INTERMEDIATE)] == payload['exp']
    assert [call.request.url for call in fed.http.calls[count:]] == [url, url]
    subsequent = resolve(fed)
    if replacement == 'constraints':
        assert subsequent['error'] == 'invalid_trust_chain' and subsequent['response_code'] == 400
        assert 'response_args' not in subsequent
    else:
        newer_tokens = tokens[:]
        newer_tokens[2] = new_token
        assert success(fed, subsequent, newer_tokens)['exp'] == payload['exp']
