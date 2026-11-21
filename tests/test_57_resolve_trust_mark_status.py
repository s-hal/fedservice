"""Explicit online Trust Mark checking and opt-in Resolve policy."""

from copy import deepcopy
from contextvars import Context
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


def resolve_claims(fed, subject=SUBJECT, **kwargs):
    """Verify the real Resolve response and its usable deadline."""
    result = fed.resolver.get_endpoint('resolve').process_request(
        {'sub': subject, 'trust_anchor': [ANCHOR]}, **kwargs)
    verified = verify_federation_jwt(RESOLVE_RESPONSE, result['response_args'], fed.resolver.keyjar)
    assert verified.claims()['exp'] > fed.clock[0]
    return verified.claims()


def replace_ec(http, fed, owner, expiry, **changes):
    """Publish a fresh, genuinely signed EC with the selected changes."""
    endpoint = owner.get_endpoint('entity_configuration')
    claims = factory(endpoint.process_request({})['response']).jwt.payload()
    claims.update(exp=expiry, **changes)
    token = sign_federation_jwt(ENTITY_CONFIGURATION, claims, owner.keyjar, owner.entity_id,
                                'ES256', iat=fed.clock[0])
    http.replace('GET', endpoint.full_path, body=token, content_type=ENTITY_CONFIGURATION.content_type)
    return token


@pytest.mark.parametrize('online,outcome', [(False, 'active'), (True, 'active'),
                                           (True, 'revoked'), (True, 'timeout')])
def test_separate_issuer_retains_resolve_anchor(federation, online, outcome):
    fed = federation
    fed.resolver = resolver(fed.anchor.keyjar.export_jwks(), online)
    collector = fed.resolver.function.trust_chain_collector
    collector.refresh_fraction = 0.5
    start = fed.clock[0]
    token = mark(fed, start + 800.5)
    fed.subject.context.trust_marks = [{'trust_mark_type': MARK, 'trust_mark': token}]
    anchor_url = fed.anchor.get_endpoint('entity_configuration').full_path
    status_url = fed.issuer.get_endpoint('trust_mark_status').full_path
    with responses.RequestsMock(assert_all_requests_are_fired=False) as http:
        register(http, fed)
        anchor = replace_ec(http, fed, fed.anchor, start + 900)
        http.add('POST', status_url, body=status(fed, token),
                 content_type=TRUST_MARK_STATUS_RESPONSE.content_type)
        assert resolve_claims(fed, with_ta_ec=True)['trust_marks'][0]['trust_mark'] == token
        http.replace('GET', anchor_url, status=404)
        body = Timeout('status unavailable') if outcome == 'timeout' else status(fed, token, outcome)
        http.replace('POST', status_url, body=body, content_type=TRUST_MARK_STATUS_RESPONSE.content_type)
        for offset in (450, 451):
            fed.clock[0] = start + offset
            count = len(http.calls)
            claims = resolve_claims(fed, with_ta_ec=True)
            assert claims['trust_chain'][-1] == anchor
            assert collector.config_cache[ANCHOR]['_jws'] == anchor
            assert collector._resolve_anchor.get() is None
            if outcome == 'active':
                assert claims['trust_marks'][0]['trust_mark'] == token
                assert claims['exp'] == start + 800.5
            else:
                assert 'trust_marks' not in claims and claims['metadata']
                assert claims['exp'] == start + 900
            requests = [call.request for call in http.calls[count:]]
            assert [req.url for req in requests if req.method == 'GET'] == [anchor_url]
            checks = [req for req in requests if req.method == 'POST']
            assert len(checks) == int(online)
            if online:
                assert checks[0].url == status_url
                assert parse_qs(checks[0].body) == {'trust_mark': [token]}
        fed.clock[0] = start + 900
        result = fed.resolver.get_endpoint('resolve').process_request(
            {'sub': SUBJECT, 'trust_anchor': [ANCHOR]})
        assert result['error'] == 'invalid_trust_chain' and 'response_args' not in result


@pytest.mark.parametrize('online', [False, True])
@pytest.mark.parametrize('refresh', [None, 404, 503])
def test_resolve_mark_uses_selected_anchor_without_extra_get(federation, online, refresh):
    fed = federation
    fed.resolver = resolver(fed.anchor.keyjar.export_jwks(), online)
    fed.resolver.function.trust_chain_collector.refresh_fraction = 0.5
    start = fed.clock[0]
    expiry = start + 800.5
    token = mark(fed, expiry, fed.anchor)
    fed.subject.context.trust_marks = [{'trust_mark_type': MARK, 'trust_mark': token}]
    anchor_url = fed.anchor.get_endpoint('entity_configuration').full_path
    with responses.RequestsMock(assert_all_requests_are_fired=False) as http:
        register(http, fed)
        anchor = replace_ec(http, fed, fed.anchor, start + 900)
        http.add('POST', fed.anchor.get_endpoint('trust_mark_status').full_path,
                 body=status(fed, token, issuer=fed.anchor), content_type=TRUST_MARK_STATUS_RESPONSE.content_type)
        first = resolve_claims(fed, with_ta_ec=True)
        assert first['trust_marks'][0]['trust_mark'] == token
        count = len(http.calls)
        fed.clock[0] = start + (450 if refresh else 1)
        http.replace('GET', anchor_url, status=refresh or 503)
        second = resolve_claims(fed, with_ta_ec=True)
        assert second['trust_marks'][0]['trust_mark'] == token
        assert second['exp'] == expiry
        assert second['trust_chain'][-1] == anchor
        requests = [call.request for call in http.calls[count:]]
        assert [req.url for req in requests if req.method == 'GET'] == ([anchor_url] if refresh else [])
        checks = [req for req in requests if req.method == 'POST']
        assert len(checks) == int(online)
        if online:
            assert parse_qs(checks[0].body) == {'trust_mark': [token]}


@pytest.mark.parametrize('online', [False, True])
@pytest.mark.parametrize('change', ['authorization', 'remove', 'replace'])
def test_accepted_ec_changes_take_effect_for_resolve_marks(federation, online, change):
    fed = federation
    fed.resolver = resolver(fed.anchor.keyjar.export_jwks(), online)
    fed.resolver.function.trust_chain_collector.refresh_fraction = 0.5
    start = fed.clock[0]
    token = mark(fed, start + 800.5, fed.anchor)
    entry = {'trust_mark_type': MARK, 'trust_mark': token}
    fed.subject.context.trust_marks = [entry]

    def active(request):
        queried = parse_qs(request.body)['trust_mark'][0]
        return 200, {'Content-Type': TRUST_MARK_STATUS_RESPONSE.content_type}, status(
            fed, queried, issuer=fed.anchor)

    with responses.RequestsMock(assert_all_requests_are_fired=False) as http:
        register(http, fed)
        replace_ec(http, fed, fed.anchor, start + 900)
        replace_ec(http, fed, fed.subject, start + 900)
        http.add_callback('POST', fed.anchor.get_endpoint('trust_mark_status').full_path, callback=active)
        assert resolve_claims(fed)['trust_marks'][0]['trust_mark'] == token
        fed.clock[0] = start + 450
        if change == 'authorization':
            updated = replace_ec(http, fed, fed.anchor, start + 700.5, trust_mark_issuers={MARK: [OTHER]})
        else:
            if change == 'remove':
                fed.subject.context.trust_marks = []
            else:
                token = mark(fed, start + 700.25, fed.anchor, tag='replacement')
                fed.subject.context.trust_marks = [{'trust_mark_type': MARK, 'trust_mark': token}]
            updated = replace_ec(http, fed, fed.subject, start + 1350)
        count = len(posts(http))
        claims = resolve_claims(fed, with_ta_ec=True)
        assert claims['trust_chain'][-1 if change == 'authorization' else 0] == updated
        if change == 'replace':
            assert [dict(item) for item in claims['trust_marks']] == fed.subject.context.trust_marks
            assert claims['exp'] == start + 700.25
            assert len(posts(http)) == count + int(online)
            if online:
                assert parse_qs(posts(http)[-1].body) == {'trust_mark': [token]}
        else:
            assert 'trust_marks' not in claims and claims['metadata']
            assert claims['exp'] == start + (700.5 if change == 'authorization' else 900)
            assert len(posts(http)) == count
        if change == 'authorization':
            # A later failed refresh cannot revive the older authorization.
            fed.clock[0] = start + 600
            http.replace('GET', fed.anchor.get_endpoint('entity_configuration').full_path, status=503)
            retained = resolve_claims(fed, with_ta_ec=True)
            assert retained['trust_chain'][-1] == updated
            assert 'trust_marks' not in retained and retained['exp'] == start + 700.5
            assert len(posts(http)) == count


@pytest.mark.parametrize('failure', ['revoked', 'timeout', 'unbound'])
def test_retained_anchor_never_reuses_previous_active_status(federation, failure):
    fed = federation
    fed.resolver = resolver(fed.anchor.keyjar.export_jwks(), True)
    fed.resolver.function.trust_chain_collector.refresh_fraction = 0.5
    start = fed.clock[0]
    token = mark(fed, start + 800.5, fed.anchor)
    fed.subject.context.trust_marks = [{'trust_mark_type': MARK, 'trust_mark': token}]
    endpoint = fed.anchor.get_endpoint('trust_mark_status').full_path
    with responses.RequestsMock(assert_all_requests_are_fired=False) as http:
        register(http, fed)
        replace_ec(http, fed, fed.anchor, start + 900)
        http.add('POST', endpoint, body=status(fed, token, issuer=fed.anchor),
                 content_type=TRUST_MARK_STATUS_RESPONSE.content_type)
        assert resolve_claims(fed)['trust_marks'][0]['trust_mark'] == token
        fed.clock[0] = start + 450
        http.replace('GET', fed.anchor.get_endpoint('entity_configuration').full_path, status=404)
        body = (Timeout('required status unavailable') if failure == 'timeout' else status(
            fed, mark(fed, issuer=fed.anchor, tag='unbound') if failure == 'unbound' else token,
            'active' if failure == 'unbound' else 'revoked', issuer=fed.anchor))
        http.replace('POST', endpoint, body=body, content_type=TRUST_MARK_STATUS_RESPONSE.content_type)
        claims = resolve_claims(fed)
        assert 'trust_marks' not in claims and claims['metadata']
        assert claims['exp'] == start + 900
        assert len(posts(http)) == 2
        assert all(parse_qs(req.body) == {'trust_mark': [token]} for req in posts(http))


@pytest.mark.parametrize('online', [False, True])
def test_anchor_subject_without_mark_expiry_uses_selected_ec(federation, online):
    fed = federation
    fed.resolver = resolver(fed.anchor.keyjar.export_jwks(), online)
    fed.resolver.function.trust_chain_collector.refresh_fraction = 0.5
    expiry = fed.clock[0] + 900.5
    token = sign_federation_jwt(TRUST_MARK, {'sub': ANCHOR, 'trust_mark_type': MARK},
                                fed.anchor.keyjar, ANCHOR, 'ES256', iat=fed.clock[0])
    fed.anchor.context.trust_marks = [{'trust_mark_type': MARK, 'trust_mark': token}]
    with responses.RequestsMock(assert_all_requests_are_fired=False) as http:
        register(http, fed)
        anchor = replace_ec(http, fed, fed.anchor, expiry)
        http.add('POST', fed.anchor.get_endpoint('trust_mark_status').full_path,
                 body=status(fed, token, issuer=fed.anchor), content_type=TRUST_MARK_STATUS_RESPONSE.content_type)
        for _ in range(2):
            claims = resolve_claims(fed, subject=ANCHOR)
            assert list(claims['trust_chain']) == [anchor]
            assert claims['trust_marks'][0]['trust_mark'] == token
            assert claims['exp'] == expiry
            fed.clock[0] += 1
        assert len([call for call in http.calls if call.request.method == 'GET']) == 1
        assert len(posts(http)) == 2 * int(online)


@pytest.mark.parametrize('expired', ['anchor', 'mark'])
def test_resolve_rechecks_selected_evidence_deadline_after_status(federation, expired):
    fed = federation
    fed.resolver = resolver(fed.anchor.keyjar.export_jwks(), True)
    start = fed.clock[0]
    deadline = start + 300.5
    token = mark(fed, deadline if expired == 'mark' else start + 1800, fed.anchor)
    fed.subject.context.trust_marks = [{'trust_mark_type': MARK, 'trust_mark': token}]

    def active(request):
        fed.clock[0] = deadline
        return 200, {'Content-Type': TRUST_MARK_STATUS_RESPONSE.content_type}, status(
            fed, token, issuer=fed.anchor)

    with responses.RequestsMock(assert_all_requests_are_fired=False) as http:
        register(http, fed)
        replace_ec(http, fed, fed.anchor, deadline if expired == 'anchor' else start + 900)
        http.add_callback('POST', fed.anchor.get_endpoint('trust_mark_status').full_path, callback=active)
        result = fed.resolver.get_endpoint('resolve').process_request({'sub': SUBJECT, 'trust_anchor': [ANCHOR]})
        if expired == 'anchor':
            assert result['error'] == 'invalid_trust_chain' and 'response_args' not in result
        else:
            claims = verify_federation_jwt(RESOLVE_RESPONSE, result['response_args'], fed.resolver.keyjar).claims()
            assert 'trust_marks' not in claims and claims['metadata']
            assert claims['exp'] == start + 900
        assert len(posts(http)) == 1


@pytest.mark.parametrize('evidence', ['claims', 'different_anchor', 'untrusted', 'signature', 'expired', 'unconfigured'])
def test_resolve_anchor_context_requires_configured_authentic_evidence(federation, evidence):
    fed = federation
    token = mark(fed, issuer=fed.anchor)
    anchor = fed.anchor.get_endpoint('entity_configuration').process_request({})['response']
    if evidence == 'claims':
        anchor = factory(anchor).jwt.payload()
    elif evidence == 'different_anchor':
        other = entity(OTHER, endpoints=['entity_configuration'], trust_mark_issuers={MARK: [ANCHOR]})
        fed.resolver.add_trust_anchor(OTHER, other.keyjar.export_jwks())
        anchor = other.get_endpoint('entity_configuration').process_request({})['response']
    elif evidence == 'untrusted':
        other = entity(ANCHOR, endpoints=['entity_configuration'], trust_mark_issuers={MARK: [ANCHOR]})
        anchor = other.get_endpoint('entity_configuration').process_request({})['response']
    elif evidence == 'signature':
        anchor = corrupt_signature(anchor)
    elif evidence == 'expired':
        fed.clock[0] = factory(anchor).jwt.payload()['exp']
    else:
        fed.resolver.trust_anchors = {}
    verifier = fed.resolver.function.trust_mark_verifier
    with responses.RequestsMock(assert_all_requests_are_fired=False) as http:
        with verifier.using_resolve_anchor(ANCHOR, anchor):
            assert verify(fed, token) is None
        assert not http.calls
    assert verifier._resolve_anchor.get() is None


def test_resolve_anchor_context_is_local_nested_and_cleared(federation):
    fed = federation
    token = mark(fed, issuer=fed.anchor)
    anchor = fed.anchor.get_endpoint('entity_configuration').process_request({})['response']
    verifier = fed.resolver.function.trust_mark_verifier
    with responses.RequestsMock(assert_all_requests_are_fired=False) as http:
        http.add('GET', fed.anchor.get_endpoint('entity_configuration').full_path, status=503)
        with verifier.using_resolve_anchor(ANCHOR, anchor):
            assert verify(fed, token)
            assert Context().run(verify, fed, token) is None
            with pytest.raises(RuntimeError):
                with verifier.using_resolve_anchor(OTHER, anchor):
                    assert verify(fed, token) is None
                    raise RuntimeError('nested call failed')
            assert verify(fed, token)
        assert verify(fed, token) is None
        assert len(http.calls) == 2 and not posts(http)
    assert verifier._resolve_anchor.get() is None


def test_resolve_custom_verifier_retains_existing_keyword_contract(federation):
    fed = federation
    token = mark(fed, fed.clock[0] + 300.5, fed.anchor)
    fed.subject.context.trust_marks = [{'trust_mark_type': MARK, 'trust_mark': token}]
    calls = []

    def custom(*, trust_mark, trust_anchor, check_status, entity_id, outer_trust_mark_type):
        calls.append((trust_mark, trust_anchor, check_status, entity_id, outer_trust_mark_type))
        return verify_federation_jwt(TRUST_MARK, trust_mark, fed.resolver.keyjar).claims()

    fed.resolver.function.trust_mark_verifier = custom
    with responses.RequestsMock(assert_all_requests_are_fired=False) as http:
        register(http, fed)
        assert resolve_claims(fed)['trust_marks'][0]['trust_mark'] == token
        assert calls == [(token, ANCHOR, False, SUBJECT, MARK)]
        assert not posts(http)


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
    fed.subject.context.trust_marks = [{'trust_mark_type': MARK, 'trust_mark': token}]
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
        assert 'trust_marks' not in resolve_claims(fed)
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
    fed.subject.context.trust_marks = [{'trust_mark_type': MARK, 'trust_mark': token}]
    fed.resolver.get_endpoint('resolve').trust_mark_status_check = True
    with responses.RequestsMock(assert_all_requests_are_fired=False) as http:
        register(http, fed)
        http.add("POST", fed.issuer.get_endpoint("trust_mark_status").full_path,
                 body=status(fed, token), content_type=TRUST_MARK_STATUS_RESPONSE.content_type)
        result = verify(fed, token, check_status=True)
        assert (result is not None) is valid
        assert len(posts(http)) == int(valid)
        claims = resolve_claims(fed)
        assert ('trust_marks' in claims) is valid
        assert len(posts(http)) == 2 * int(valid)


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
