"""Explicit online Trust Mark checking and opt-in Resolve policy."""

from copy import deepcopy
import json
from types import SimpleNamespace
from urllib.parse import parse_qs
from urllib.parse import urlencode

from cryptojwt.jws.jws import factory
from cryptojwt.jwt import utc_time_sans_frac
import pytest
from requests.exceptions import Timeout
import responses

from fedservice.defaults import federation_endpoints
from fedservice.entity.function import get_verified_trust_chains
from fedservice.federation_jwt.jose import sign_federation_jwt
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.federation_jwt.registry import RESOLVE_RESPONSE
from fedservice.federation_jwt.registry import TRUST_MARK
from fedservice.federation_jwt.registry import TRUST_MARK_DELEGATION
from fedservice.federation_jwt.registry import TRUST_MARK_STATUS_RESPONSE
from fedservice.trust_mark_entity.server.trust_mark_status import create_trust_mark_status_response
from fedservice.utils import make_federation_entity
from tests.test_55_entity_statement_subject_binding import corrupt_signature


ANCHOR = "https://anchor.example.org"
ISSUER = "https://issuer.example.org"
SUBJECT = "https://subject.example.org"
OTHER = "https://other-anchor.example.org"
OWNER = "https://mark-owner.example.org"
RESOLVER = "https://resolver.example.org"
MARK = "https://marks.example.org/first"
OMITTED = object()


def entity(entity_id, **kwargs):
    return make_federation_entity(
        entity_id, signing_alg="ES256",
        key_config={"key_defs": [{"type": "EC", "crv": "P-256", "use": ["sig"]}]}, **kwargs)


def resolver(anchor_keys, mode=OMITTED, with_service=True):
    endpoints = deepcopy(federation_endpoints("entity_configuration", "resolve"))
    if mode is not OMITTED:
        endpoints["resolve"]["kwargs"]["trust_mark_status_check"] = mode
    services = ["entity_configuration", "entity_statement"]
    if with_service:
        services.append("trust_mark_status")
    return entity(RESOLVER, endpoints=endpoints, services=services,
                  trust_anchors={ANCHOR: anchor_keys})


@pytest.fixture
def clock(monkeypatch):
    current = [utc_time_sans_frac()]
    for module in ("cryptojwt.jwt", "fedservice.federation_jwt.jose",
                   "fedservice.utils"):
        monkeypatch.setattr(module + ".utc_time_sans_frac", lambda: int(current[0]))
    for module in ("fedservice.entity.function.trust_mark_verifier",
                   "fedservice.entity.server.resolve", "fedservice.entity_statement.create",
                   "fedservice.entity_statement.cache"):
        monkeypatch.setattr(module + ".time", lambda: current[0])
    monkeypatch.setattr("fedservice.entity.function.trust_chain_collector.time",
                        SimpleNamespace(time=lambda: current[0]))
    return current


@pytest.fixture
def federation(clock):
    anchor = entity(ANCHOR, endpoints=["entity_configuration", "fetch", "trust_mark_status"],
                    trust_mark_issuers={MARK: [ISSUER, ANCHOR]})
    issuer = entity(ISSUER, endpoints=["entity_configuration", "trust_mark_status"],
                    authority_hints=[ANCHOR])
    subject = entity(SUBJECT, endpoints=["entity_configuration"], authority_hints=[ANCHOR])
    for item in (issuer, subject):
        anchor.server.subordinate[item.entity_id] = {"jwks": item.keyjar.export_jwks()}
    return SimpleNamespace(anchor=anchor, issuer=issuer, subject=subject,
                           resolver=resolver(anchor.keyjar.export_jwks()), clock=clock)


def mark(fed, expiry=OMITTED, issuer=None, mark_type=MARK, **extra):
    issuer = issuer or fed.issuer
    claims = dict(sub=SUBJECT, trust_mark_type=mark_type, **extra)
    if expiry is not OMITTED:
        claims["exp"] = expiry
    return sign_federation_jwt(TRUST_MARK, claims, issuer.keyjar, issuer.entity_id, "ES256",
                              iat=fed.clock[0] - 10)


def status(fed, token, value="active", issuer=None):
    issuer = issuer or fed.issuer
    return create_trust_mark_status_response(
        issuer.keyjar, issuer.entity_id, token, value, signing_alg="ES256")


def register(http, fed, issuer_exp=None, untrusted_ec=False):
    for item in (fed.anchor, fed.issuer, fed.subject):
        endpoint = item.get_endpoint("entity_configuration")
        token = endpoint.process_request({})["response"]
        if item is fed.issuer and (issuer_exp is not None or untrusted_ec):
            claims = factory(token).jwt.payload()
            if issuer_exp is not None:
                claims["exp"] = issuer_exp
            keys = entity(ISSUER, endpoints=["entity_configuration"]).keyjar if untrusted_ec else item.keyjar
            if untrusted_ec:
                claims["jwks"] = keys.export_jwks()
            token = sign_federation_jwt(ENTITY_CONFIGURATION, claims, keys, item.entity_id,
                                       "ES256", iat=claims["iat"])
        http.add("GET", endpoint.full_path, body=token, content_type=ENTITY_CONFIGURATION.content_type)
    endpoint = fed.anchor.get_endpoint("fetch")
    for item in (fed.issuer, fed.subject):
        token = endpoint.process_request({"sub": item.entity_id})["response_msg"]
        http.add("GET", endpoint.full_path + "?" + urlencode({"sub": item.entity_id}),
                 body=token, content_type=ENTITY_CONFIGURATION.content_type)


def posts(http):
    return [call.request for call in http.calls if call.request.method == "POST"]


def verify(fed, token, **kwargs):
    return fed.resolver.function.trust_mark_verifier(
        token, trust_anchor=ANCHOR, entity_id=SUBJECT, outer_trust_mark_type=MARK, **kwargs)


@pytest.mark.parametrize("mode", [OMITTED, False, True])
@pytest.mark.parametrize("expiry", [OMITTED, 300, 300.5])
@pytest.mark.parametrize("anchor_issuer", [False, True])
def test_function_mode_and_exact_post(federation, mode, expiry, anchor_issuer):
    fed = federation
    issuer = fed.anchor if anchor_issuer else fed.issuer
    token = mark(fed, OMITTED if expiry is OMITTED else fed.clock[0] + expiry, issuer)
    with responses.RequestsMock(assert_all_requests_are_fired=False) as http:
        register(http, fed)
        http.add("POST", issuer.get_endpoint("trust_mark_status").full_path,
                 body=status(fed, token, issuer=issuer), content_type=TRUST_MARK_STATUS_RESPONSE.content_type)
        result = verify(fed, token, **({} if mode is OMITTED else {"check_status": mode}))
        assert result["sub"] == SUBJECT
        assert result["iss"] == issuer.entity_id
        assert len(posts(http)) == int(mode is True)
        if mode is True:
            assert parse_qs(posts(http)[0].body) == {"trust_mark": [token]}
            assert posts(http)[0].url == issuer.get_endpoint("trust_mark_status").full_path


@pytest.mark.parametrize("mode", [OMITTED, False, True])
@pytest.mark.parametrize("anchor_issuer", [False, True])
def test_convenience_method_delegates_once(federation, mode, anchor_issuer):
    fed = federation
    issuer = fed.anchor if anchor_issuer else fed.issuer
    token = mark(fed, issuer=issuer)
    with responses.RequestsMock(assert_all_requests_are_fired=False) as http:
        register(http, fed)
        http.add("POST", issuer.get_endpoint("trust_mark_status").full_path,
                 body=status(fed, token, issuer=issuer), content_type=TRUST_MARK_STATUS_RESPONSE.content_type)
        result = fed.resolver.verify_trust_mark(
            token, **({} if mode is OMITTED else {"check_with_issuer": mode}))
        assert result["sub"] == SUBJECT
        assert len(posts(http)) == int(mode is not False)


@pytest.mark.parametrize("failure", ["bad_mark", "unknown_type", "unauthorized_issuer", "subject", "untrusted_ec", "unconfigured_anchor", "policy_endpoint", "missing_endpoint", "missing_service"])
def test_local_prerequisites_prevent_online_acceptance(federation, failure):
    fed = federation
    token = mark(fed)
    if failure == "bad_mark":
        token = corrupt_signature(token)
    elif failure == "unknown_type":
        fed.anchor.context.trust_mark_issuers = {}
    elif failure == "unauthorized_issuer":
        fed.anchor.context.trust_mark_issuers[MARK] = [OTHER]
    elif failure == "subject":
        token = sign_federation_jwt(TRUST_MARK, {"sub": OTHER, "trust_mark_type": MARK},
                                    fed.issuer.keyjar, ISSUER, "ES256")
    elif failure == "unconfigured_anchor":
        fed.resolver.trust_anchors = {}
        fed.resolver.keyjar.import_jwks(fed.issuer.keyjar.export_jwks(), ISSUER)
    elif failure in ("policy_endpoint", "missing_endpoint"):
        endpoint = fed.issuer.server.endpoint.pop("trust_mark_status")
        if failure == "policy_endpoint":
            fed.anchor.server.subordinate[ISSUER]["metadata_policy"] = {"federation_entity": {
                "federation_trust_mark_status_endpoint": {"value": endpoint.full_path}}}
    elif failure == "missing_service":
        fed.resolver = resolver(fed.anchor.keyjar.export_jwks(), with_service=False)
    with responses.RequestsMock(assert_all_requests_are_fired=False) as http:
        register(http, fed, untrusted_ec=failure == "untrusted_ec")
        assert verify(fed, token, check_status=True) is None
        assert not posts(http)
        if failure == "bad_mark":
            assert fed.resolver.verify_trust_mark(token) is None
            assert not posts(http)
    assert fed.resolver.verify_trust_mark("not-a-jwt") is None


def test_chain_under_another_anchor_cannot_authorize_check(federation):
    fed = federation
    other = entity(OTHER, endpoints=["entity_configuration", "fetch"])
    other.server.subordinate[ISSUER] = {"jwks": fed.issuer.keyjar.export_jwks()}
    fed.issuer.context.authority_hints = [OTHER]
    fed.resolver.add_trust_anchor(OTHER, other.keyjar.export_jwks())
    token = mark(fed)
    with responses.RequestsMock(assert_all_requests_are_fired=False) as http:
        register(http, fed)
        http.add("GET", other.get_endpoint("entity_configuration").full_path,
                 body=other.get_endpoint("entity_configuration").process_request({})["response"],
                 content_type=ENTITY_CONFIGURATION.content_type)
        http.add("GET", other.get_endpoint("fetch").full_path + "?" + urlencode({"sub": ISSUER}),
                 body=other.get_endpoint("fetch").process_request({"sub": ISSUER})["response_msg"],
                 content_type=ENTITY_CONFIGURATION.content_type)
        assert verify(fed, token, check_status=True) is None
        assert not posts(http)


@pytest.mark.parametrize("valid", [False, True])
def test_delegation_is_checked_before_status(federation, valid):
    fed = federation
    owner = entity(OWNER, endpoints=["entity_configuration"])
    fed.anchor.context.trust_mark_owners = {MARK: {"sub": OWNER, "jwks": owner.keyjar.export_jwks()}}
    delegation = sign_federation_jwt(
        TRUST_MARK_DELEGATION, {"sub": ISSUER if valid else OTHER, "trust_mark_type": MARK},
        owner.keyjar, OWNER, "ES256")
    token = mark(fed, delegation=delegation)
    with responses.RequestsMock(assert_all_requests_are_fired=False) as http:
        register(http, fed)
        http.add("POST", fed.issuer.get_endpoint("trust_mark_status").full_path,
                 body=status(fed, token), content_type=TRUST_MARK_STATUS_RESPONSE.content_type)
        result = verify(fed, token, check_status=True)
        assert (result is not None) is valid
        assert len(posts(http)) == int(valid)


@pytest.mark.parametrize("failure", ["expired", "revoked", "invalid", "issuer", "mark", "signature", "malformed", "media", "http", "timeout", "expires_in_flight"])
def test_online_failure_never_falls_back_to_local_acceptance(federation, failure):
    fed = federation
    deadline = fed.clock[0] + 300.5
    token = mark(fed, deadline)
    body = status(fed, token, failure if failure in ("expired", "revoked", "invalid") else "active")
    if failure == "issuer":
        body = status(fed, token, issuer=fed.anchor)
    elif failure == "mark":
        body = status(fed, mark(fed, deadline, tag="another"))
    elif failure == "signature":
        body = corrupt_signature(body)
    elif failure == "malformed":
        body = "not-a-jwt"

    def receive(request):
        assert parse_qs(request.body) == {"trust_mark": [token]}
        if failure == "timeout":
            raise Timeout("status timeout")
        if failure == "expires_in_flight":
            fed.clock[0] = deadline
        return (500 if failure == "http" else 200,
                {"Content-Type": "application/json" if failure == "media" else TRUST_MARK_STATUS_RESPONSE.content_type}, body)

    with responses.RequestsMock(assert_all_requests_are_fired=False) as http:
        register(http, fed)
        http.add_callback("POST", fed.issuer.get_endpoint("trust_mark_status").full_path, callback=receive)
        assert verify(fed, token, check_status=True) is None
        assert len(posts(http)) == 1


def test_active_status_is_not_cached_and_programming_errors_propagate(federation):
    fed = federation
    token = mark(fed)
    endpoint = fed.issuer.get_endpoint("trust_mark_status").full_path
    with responses.RequestsMock(assert_all_requests_are_fired=False) as http:
        register(http, fed)
        http.add("POST", endpoint, body=status(fed, token), content_type=TRUST_MARK_STATUS_RESPONSE.content_type)
        http.add("POST", endpoint, body=status(fed, token, "revoked"), content_type=TRUST_MARK_STATUS_RESPONSE.content_type)
        http.add("POST", endpoint, body=Timeout("outage"))
        assert verify(fed, token, check_status=True)
        assert verify(fed, token, check_status=True) is None
        assert verify(fed, token, check_status=True) is None
        assert len(posts(http)) == 3

        def bug(request):
            raise RuntimeError("programming error")

        http.add_callback("POST", endpoint, callback=bug)
        with pytest.raises(RuntimeError, match="programming error"):
            verify(fed, token, check_status=True)


def test_expired_discovery_is_refetched_not_replaced_by_stored_chain(federation):
    fed = federation
    expiry = fed.clock[0] + 800
    token = mark(fed)
    endpoint = fed.issuer.get_endpoint("trust_mark_status").full_path
    with responses.RequestsMock(assert_all_requests_are_fired=False) as http:
        register(http, fed, issuer_exp=expiry)
        chains = get_verified_trust_chains(fed.resolver, ISSUER)
        fed.resolver.store_trust_chains(ISSUER, chains)
        http.add("POST", endpoint, body=status(fed, token), content_type=TRUST_MARK_STATUS_RESPONSE.content_type)
        assert verify(fed, token, check_status=True)
        fed.clock[0] = expiry + 0.125
        assert verify(fed, token, check_status=True) is None
        assert len(posts(http)) == 1
    with responses.RequestsMock(assert_all_requests_are_fired=False) as http:
        register(http, fed, issuer_exp=fed.clock[0] + 3600)
        http.add("POST", endpoint, body=status(fed, token), content_type=TRUST_MARK_STATUS_RESPONSE.content_type)
        assert verify(fed, token, check_status=True)
        assert any(call.request.url == fed.issuer.get_endpoint("entity_configuration").full_path for call in http.calls)
        assert len(posts(http)) == 1
    assert chains[0].exp == expiry


@pytest.mark.parametrize("invalid", [None, "true", "false", 0, 1, [], {}])
def test_invalid_resolver_setting_rejected_at_construction(federation, invalid):
    with pytest.raises(ValueError, match="trust_mark_status_check"):
        resolver(federation.anchor.keyjar.export_jwks(), invalid)


def test_resolver_configuration_is_local_and_requires_service(federation):
    keys = federation.anchor.keyjar.export_jwks()
    before = deepcopy(federation_endpoints("resolve"))
    default = resolver(keys)
    local = resolver(keys, False, with_service=False)
    online = resolver(keys, True)
    assert not default.get_endpoint("resolve").trust_mark_status_check
    assert not local.get_endpoint("resolve").trust_mark_status_check
    assert online.get_endpoint("resolve").trust_mark_status_check
    with pytest.raises(ValueError, match="trust_mark_status client service"):
        resolver(keys, True, with_service=False)
    assert federation_endpoints("resolve") == before
    token = online.get_endpoint("entity_configuration").process_request({})["response"]
    verified = verify_federation_jwt(ENTITY_CONFIGURATION, token, online.keyjar)
    assert "trust_mark_status_check" not in json.dumps(dict(verified.message().to_dict()))


@pytest.mark.parametrize("online", [False, True])
@pytest.mark.parametrize("last_status", ["revoked", "timeout"])
def test_resolve_filters_independent_marks_and_bounds_only_included_expiry(federation, online, last_status):
    fed = federation
    fed.resolver = resolver(fed.anchor.keyjar.export_jwks(), online)
    expirations = [fed.clock[0] + 300.5, OMITTED, fed.clock[0] + 100.25]
    entries = []
    for index, expiry in enumerate(expirations):
        mark_type = MARK + "/{}".format(index)
        fed.anchor.context.trust_mark_issuers[mark_type] = [ISSUER]
        entries.append({"trust_mark_type": mark_type, "trust_mark": mark(fed, expiry, mark_type=mark_type)})
    fed.subject.context.trust_marks = entries

    def receive(request):
        token = parse_qs(request.body)["trust_mark"][0]
        index = [entry["trust_mark"] for entry in entries].index(token)
        if index == 2 and last_status == "timeout":
            raise Timeout("status unavailable")
        value = "revoked" if index == 2 else "active"
        return 200, {"Content-Type": TRUST_MARK_STATUS_RESPONSE.content_type}, status(fed, token, value)

    with responses.RequestsMock(assert_all_requests_are_fired=False) as http:
        register(http, fed)
        http.add_callback("POST", fed.issuer.get_endpoint("trust_mark_status").full_path, callback=receive)
        result = fed.resolver.get_endpoint("resolve").process_request({"sub": SUBJECT, "trust_anchor": [ANCHOR]})
        verified = verify_federation_jwt(RESOLVE_RESPONSE, result["response_args"], fed.resolver.keyjar)
        assert len(posts(http)) == (3 if online else 0)
    expected = entries[:2] if online else entries
    assert [dict(entry) for entry in verified.claims()["trust_marks"]] == expected
    assert verified.claims()["exp"] == verified.message()["exp"] == expirations[0 if online else 2]
    assert verified.claims()["sub"] == SUBJECT
    assert "federation_entity" in verified.claims()["metadata"]
    assert "trust_mark_status_check" not in verified.claims()


def test_resolve_without_successful_marks_still_returns_metadata(federation):
    fed = federation
    fed.resolver = resolver(fed.anchor.keyjar.export_jwks(), True)
    token = mark(fed, fed.clock[0] + 300.5)
    fed.subject.context.trust_marks = [{"trust_mark_type": MARK, "trust_mark": token}]
    with responses.RequestsMock(assert_all_requests_are_fired=False) as http:
        register(http, fed)
        http.add("POST", fed.issuer.get_endpoint("trust_mark_status").full_path,
                 body=status(fed, token, "revoked"), content_type=TRUST_MARK_STATUS_RESPONSE.content_type)
        result = fed.resolver.get_endpoint("resolve").process_request({"sub": SUBJECT, "trust_anchor": [ANCHOR]})
        verified = verify_federation_jwt(RESOLVE_RESPONSE, result["response_args"], fed.resolver.keyjar)
        assert "trust_marks" not in verified.claims()
        assert verified.claims()["exp"] > fed.clock[0] + 300.5
        assert verified.claims()["metadata"]
        assert len(posts(http)) == 1
