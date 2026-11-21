"""Signed Resolve recovery through the shared collector, without Trust Marks."""

import json
from threading import Event
from types import SimpleNamespace

from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.jws.jws import JWS
from cryptojwt.jws.jws import factory
from idpyoidc.exception import MissingPage
import pytest
from requests.exceptions import ConnectionError
from requests.exceptions import ChunkedEncodingError
from requests.exceptions import ConnectTimeout
from requests.exceptions import ReadTimeout
from requests.exceptions import InvalidURL
from requests.exceptions import ProxyError
from requests.exceptions import SSLError
from requests.exceptions import Timeout

from fedservice.entity import FederationEntity
from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import tree2chains
from fedservice.entity.function import verify_trust_chain
from fedservice.entity.function import verify_trust_chains
from fedservice.entity.function import apply_policies
from fedservice.entity.function.trust_chain_collector import TrustChainCollector
from fedservice.entity.function.trust_chain_collector import cache_key
from fedservice.entity.function.trust_chain_collector import time_key
from fedservice.entity.function.verifier import TrustChainVerifier
from fedservice.federation_jwt.errors import FederationJwtKeyResolutionError
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.jose import sign_federation_jwt
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.federation_jwt.registry import RESOLVE_RESPONSE
from fedservice.federation_jwt.registry import SUBORDINATE_STATEMENT
from fedservice.utils import build_entity_config
from tests.test_55_entity_statement_cache import ANCHOR
from tests.test_55_entity_statement_cache import INTERMEDIATE
from tests.test_55_entity_statement_cache import LEAF
from tests.test_55_entity_statement_cache import OTHER
from tests.test_55_entity_statement_cache import clock
from tests.test_55_entity_statement_cache import ec_url
from tests.test_55_entity_statement_cache import federation
from tests.test_55_entity_statement_cache import fraction_documents
from tests.test_55_entity_statement_cache import finish_worker
from tests.test_55_entity_statement_cache import start_worker
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


class ConfiguredResolveCollector(TrustChainCollector):
    """Configured extension retaining the collector's established signature."""

    def __init__(self, *args, behavior='delegate', **kwargs):
        super().__init__(*args, **kwargs)
        self.behavior, self.calls = behavior, []
        self.error = TypeError('configured collector body failed')

    def __call__(self, entity_id, max_superiors=None, seen=None, stop_at=''):
        self.calls.append((entity_id, max_superiors, seen, stop_at))
        if self.behavior == 'type_error':
            raise self.error
        if self.behavior == 'reject':
            return None
        return super().__call__(entity_id, max_superiors, seen, stop_at)


class ConfiguredResolveVerifier(TrustChainVerifier):
    """Configured extension retaining the verifier's established signature."""

    def __init__(self, *args, behavior='delegate', **kwargs):
        super().__init__(*args, **kwargs)
        self.behavior, self.calls = behavior, []
        self.error = TypeError('configured verifier body failed')

    def verify_with_outcomes(self, chain):
        self.calls.append(tuple(chain))
        if self.behavior == 'type_error':
            raise self.error
        if self.behavior == 'reject':
            return [], []
        if self.behavior == 'constraint':
            return [], [tuple(chain)]
        return super().verify_with_outcomes(chain)


class ConfiguredResolveCallableVerifier:
    """Callable-only extension using the real chain verifier internally."""

    def __init__(self, upstream_get, behavior='delegate', **kwargs):
        self.verifier = TrustChainVerifier(upstream_get, **kwargs)
        self.behavior, self.calls = behavior, []
        self.error = TypeError('configured callable verifier body failed')

    def __call__(self, chain):
        self.calls.append(tuple(chain))
        if self.behavior == 'type_error':
            raise self.error
        if self.behavior == 'reject':
            return []
        return self.verifier(chain)


def configured_resolve_component(fed, name, component_cls, behavior):
    """Construct an independent resolver with one importable function override."""
    config = build_entity_config(
        'https://configured-resolver.example.org', signing_alg='ES256',
        key_config={'key_defs': [{'type': 'EC', 'crv': 'P-256', 'use': ['sig']}]},
        endpoints=['entity_configuration', 'resolve'],
        services=['entity_configuration', 'entity_statement'])
    functions = config['function']['kwargs']['functions']
    functions['trust_chain_collector']['kwargs']['trust_anchors'] = {ANCHOR: fed.public[ANCHOR]}
    functions[name]['class'] = __name__ + '.' + component_cls.__name__
    functions[name]['kwargs']['behavior'] = behavior
    fed.resolver = FederationEntity(**config)
    fed.collector = fed.resolver.function.trust_chain_collector
    component = getattr(fed.resolver.function, name)
    assert type(component) is component_cls
    return component


@pytest.mark.parametrize('name,component_cls', [
    ('trust_chain_collector', ConfiguredResolveCollector),
    ('verifier', ConfiguredResolveVerifier),
    ('verifier', ConfiguredResolveCallableVerifier)])
@pytest.mark.parametrize('behavior', ['delegate', 'type_error', 'reject'])
def test_configured_resolve_component_contract(federation, name, component_cls, behavior):
    fed = federation
    component = configured_resolve_component(fed, name, component_cls, behavior)
    if behavior == 'type_error':
        with pytest.raises(TypeError) as raised:
            resolve(fed)
        assert raised.value is component.error
    elif behavior == 'reject':
        result = resolve(fed)
        assert result['error'] == 'invalid_trust_chain'
        assert result['response_code'] == 400
        assert 'response_args' not in result
    else:
        claims = success(fed, resolve(fed), expected_tokens(fed))
        expected_metadata = verify_federation_jwt(
            ENTITY_CONFIGURATION, fed.documents[ec_url(LEAF)], fed.signing).claims()['metadata']
        assert claims['metadata'] == expected_metadata
    assert len(component.calls) == 1
    if name == 'trust_chain_collector':
        assert component.calls[0] == (LEAF, None, None, ANCHOR)
    else:
        assert component.calls[0] == tuple(reversed(expected_tokens(fed)[:-1]))


def test_configured_resolve_component_constraint_outcome(federation, monkeypatch):
    fed = federation
    component = configured_resolve_component(fed, 'verifier', ConfiguredResolveVerifier, 'constraint')
    outcomes = []
    finish = fed.collector.finish_statement_verification

    def record_outcomes(chains, accepted, constraint_rejections):
        outcomes.append((accepted, constraint_rejections))
        return finish(chains, accepted, constraint_rejections=constraint_rejections)

    monkeypatch.setattr(fed.collector, 'finish_statement_verification', record_outcomes)
    result = resolve(fed)
    assert result['error'] == 'invalid_trust_chain'
    assert result['response_code'] == 400
    assert 'response_args' not in result
    expected_chain = tuple(reversed(expected_tokens(fed)[:-1]))
    assert component.calls == [expected_chain]
    assert outcomes == [([], [expected_chain])]


@pytest.mark.parametrize('dependency', ['leaf', 'subordinate'])
@pytest.mark.parametrize('deferred', [False, True])
@pytest.mark.parametrize('warmed', [False, True])
def test_interrupted_response_body_retention(federation, monkeypatch, dependency, deferred, warmed):
    fed = federation
    fed.collector.refresh_fraction = 0.5
    fed.ec(LEAF, fed.now + (900 if dependency == 'leaf' else 7200), issued_at=fed.now)
    fed.ss(ANCHOR, LEAF, fed.now + (900 if dependency == 'subordinate' else 7200), issued_at=fed.now)
    tokens = expected_tokens(fed)
    url = ec_url(LEAF) if dependency == 'leaf' else ss_url(ANCHOR, LEAF)
    if warmed:
        success(fed, resolve(fed), tokens)
    original_upstream = fed.collector.upstream_get
    original_httpc = original_upstream('attribute', 'httpc')
    if deferred:
        class InterruptedBody:
            def __init__(self, response):
                self.status_code, self.headers = response.status_code, response.headers

            @property
            def text(self):
                raise ChunkedEncodingError('body interrupted during consumption')

        def httpc(method, target, **kwargs):
            response = original_httpc(method, target, **kwargs)
            return InterruptedBody(response) if target == url else response

        def upstream_get(what, *args, **kwargs):
            if what == 'attribute' and args == ('httpc',):
                return httpc
            return original_upstream(what, *args, **kwargs)

        monkeypatch.setattr(fed.collector, 'upstream_get', upstream_get)
    else:
        fed.documents[url] = ChunkedEncodingError('body interrupted before HTTP returned')
    for offset in (450, 900):
        fed.clock[0] = fed.now + offset
        count = len(fed.http.calls)
        result = resolve(fed)
        assert [call.request.url for call in fed.http.calls[count:]].count(url) == 1
        if warmed and offset == 450:
            assert success(fed, result, tokens)['exp'] == fed.now + 900
        else:
            assert result['error'] == ('server_error' if dependency == 'leaf' else 'invalid_trust_chain')
            assert result['response_code'] == (502 if dependency == 'leaf' else 400)
            assert 'response_args' not in result
    monkeypatch.setattr(fed.collector, 'upstream_get', original_upstream)
    if dependency == 'leaf':
        tokens[0] = fed.ec(LEAF, fed.now + 1350, issued_at=fed.clock[0])
    else:
        tokens[1] = fed.ss(ANCHOR, LEAF, fed.now + 1350, issued_at=fed.clock[0])
    assert success(fed, resolve(fed), tokens)['exp'] == fed.now + 1350


@pytest.mark.parametrize('dependency', ['leaf', 'subordinate'])
def test_interrupted_response_body_class_outside_transport_is_not_fallback(federation, monkeypatch, dependency):
    fed = federation
    _, url, tokens = warm_refresh(fed, dependency)

    def local_failure(*args, **kwargs):
        raise ChunkedEncodingError('local processing failure, not an HTTP body')

    if dependency == 'leaf':
        monkeypatch.setattr('fedservice.entity.function.trust_chain_collector.verify_self_signed_signature',
                            local_failure)
        with pytest.raises(ChunkedEncodingError):
            resolve(fed)
        assert fed.collector.config_cache[LEAF]['_jws'] == tokens[0]
    else:
        monkeypatch.setattr(fed.collector, 'get_entity_statement', local_failure)
        assert 'response_args' not in resolve(fed)
        assert fed.collector._statement_pair(LEAF, ANCHOR)[0] == tokens[1]


@pytest.mark.parametrize('dependency', ['leaf', 'subordinate'])
def test_interrupted_response_body_standalone_contract(federation, dependency):
    fed = federation
    _, url, _ = warm_refresh(fed, dependency)
    fed.documents[url] = ChunkedEncodingError('standalone interrupted retrieval')
    with pytest.raises(ChunkedEncodingError):
        if dependency == 'leaf':
            fed.collector._get_cached_entity_configuration(LEAF)
        else:
            fed.collector._get_entity_statement(LEAF, ANCHOR, fetch_endpoint=ANCHOR + '/fetch')
    if dependency == 'leaf':
        assert fed.collector.config_cache[LEAF] is None
    else:
        assert fed.collector._statement_pair(LEAF, ANCHOR) == (None, None)


@pytest.mark.parametrize('refresh_fraction', [None, 0.5])
@pytest.mark.parametrize('fraction', [0, 0.5])
@pytest.mark.parametrize('warmed', [False, True])
def test_pending_ss_expiry_retains_validated_predecessor(federation, refresh_fraction, fraction, warmed):
    fed = federation
    fed.collector.refresh_fraction = refresh_fraction
    fed.collector.allowed_delta = 450
    fed.ec(LEAF, fed.now + 7200, hints=[INTERMEDIATE])
    fed.ec(INTERMEDIATE, fed.now + 7200, hints=[ANCHOR])
    expiry = fed.now + 900 + fraction
    original = fed.ss(INTERMEDIATE, LEAF, expiry, issued_at=fed.now)
    upper = fed.ss(ANCHOR, INTERMEDIATE, fed.now + 450, issued_at=fed.now)
    tokens = [fed.documents[ec_url(LEAF)], original, upper, fed.documents[ec_url(ANCHOR)]]
    if warmed:
        success(fed, resolve(fed), tokens)
    fed.clock[0] = fed.now + 450 + fraction
    candidate = corrupt_signature(fed.ss(INTERMEDIATE, LEAF, fed.now + 600 + fraction,
                                        issued_at=fed.clock[0]))
    fed.documents[ss_url(INTERMEDIATE, LEAF)] = candidate
    fed.documents[ss_url(ANCHOR, INTERMEDIATE)] = (404, {}, 'upper removed')
    assert resolve(fed)['error'] == 'invalid_trust_chain'
    assert fed.collector._statement_pair(LEAF, INTERMEDIATE)[0] == candidate
    fed.clock[0] = fed.now + 600 + fraction
    tokens[2] = fed.ss(ANCHOR, INTERMEDIATE, fed.now + 7200, issued_at=fed.clock[0])
    fed.documents[ss_url(INTERMEDIATE, LEAF)] = (404, {}, 'lower removed')
    count = len(fed.http.calls)
    result = resolve(fed)
    assert [call.request.url for call in fed.http.calls[count:]].count(ss_url(INTERMEDIATE, LEAF)) == 1
    if warmed:
        assert success(fed, result, tokens)['exp'] == expiry
        assert fed.collector._statement_pair(LEAF, INTERMEDIATE) == (original, expiry)
        fed.clock[0] = expiry - 0.125
        assert success(fed, resolve(fed), tokens)['exp'] == expiry
    else:
        assert result['error'] == 'invalid_trust_chain'
    fed.clock[0] = expiry
    result = resolve(fed)
    assert result['error'] == 'invalid_trust_chain' and result['response_code'] == 400


@pytest.mark.parametrize("owner", [LEAF, INTERMEDIATE, ANCHOR])
@pytest.mark.parametrize("failure", ["404", "503", "signature", "valid"])
def test_resolve_retains_each_ec_role(federation, owner, failure):
    fed = federation
    fed.collector.refresh_fraction = 0.5
    fed.ec(LEAF, fed.now + 7200, hints=[INTERMEDIATE])
    fed.ec(INTERMEDIATE, fed.now + 7200, hints=[ANCHOR])
    lower = fed.ss(INTERMEDIATE, LEAF, fed.now + 7200)
    upper = fed.ss(ANCHOR, INTERMEDIATE, fed.now + 7200)
    hints = {LEAF: [INTERMEDIATE], INTERMEDIATE: [ANCHOR], ANCHOR: None}
    original = fed.ec(owner, fed.now + 900, hints=hints[owner], issued_at=fed.now)
    tokens = [fed.documents[ec_url(LEAF)], lower, upper, fed.documents[ec_url(ANCHOR)]]
    success(fed, resolve(fed), tokens)
    count = len(fed.http.calls)
    fed.clock[0] = fed.now + 449
    success(fed, resolve(fed), tokens)
    assert len(fed.http.calls) == count
    fed.clock[0] = fed.now + 450
    if failure == "valid":
        selected = fed.ec(owner, fed.now + 1350, hints=hints[owner], issued_at=fed.clock[0])
        if owner == LEAF:
            tokens[0] = selected
        elif owner == ANCHOR:
            tokens[-1] = selected
    else:
        selected = original
        fed.documents[ec_url(owner)] = (corrupt_signature(original) if failure == "signature"
                                        else (int(failure), {}, "unavailable"))
    success(fed, resolve(fed), tokens)
    assert [call.request.url for call in fed.http.calls[count:]] == [ec_url(owner)]
    cached = fed.collector.config_cache[owner]
    assert cached["_jws"] == selected
    assert cached["exp"] == fed.now + (1350 if failure == "valid" else 900)
    assert fed.collector._statement_pair(LEAF, INTERMEDIATE) == (lower, fed.now + 7200)


def test_failed_intermediate_discovery_keeps_unrefreshed_ss(federation):
    fed = federation
    fed.collector.refresh_fraction = 0.5
    fed.ec(LEAF, fed.now + 7200, hints=[INTERMEDIATE])
    old = fed.ec(INTERMEDIATE, fed.now + 900, hints=[ANCHOR], issued_at=fed.now)
    lower = fed.ss(INTERMEDIATE, LEAF, fed.now + 7200)
    upper = fed.ss(ANCHOR, INTERMEDIATE, fed.now + 7200)
    tokens = [fed.documents[ec_url(LEAF)], lower, upper, fed.documents[ec_url(ANCHOR)]]
    success(fed, resolve(fed), tokens)
    fed.documents[ec_url(INTERMEDIATE)] = (404, {}, "removed")
    for offset in (450, 900):
        fed.clock[0] = fed.now + offset
        count = len(fed.http.calls)
        result = resolve(fed)
        assert fed.collector._statement_pair(LEAF, INTERMEDIATE) == (lower, fed.now + 7200)
        assert [call.request.url for call in fed.http.calls[count:]] == [ec_url(INTERMEDIATE)]
        if offset == 450:
            success(fed, result, tokens)
            assert fed.collector.config_cache[INTERMEDIATE]["_jws"] == old
        else:
            assert result["error"] == "invalid_trust_chain"
    fed.ec(INTERMEDIATE, fed.now + 7200, hints=[ANCHOR])
    count = len(fed.http.calls)
    success(fed, resolve(fed), tokens)
    assert [call.request.url for call in fed.http.calls[count:]] == [ec_url(INTERMEDIATE)]


@pytest.mark.parametrize("offset", [-0.125, 0, 0.125])
def test_path_ec_failed_refresh_crosses_original_fractional_deadline(federation, offset):
    fed = federation
    fed.collector.refresh_fraction = 0.5
    tenant = LEAF + '/tenant'
    fed.public[tenant] = fed.public[LEAF]
    fed.signing.add_keys(tenant, fed.signing.get_signing_key('EC', issuer_id=LEAF))
    expiry = fed.now + 900.5
    original = fed.ec(tenant, expiry, hints=[ANCHOR], issued_at=fed.now)
    statement = fed.ss(ANCHOR, tenant, fed.now + 7200)
    root = fed.documents[ec_url(LEAF)]
    endpoint = fed.resolver.get_endpoint('resolve')
    args = {'sub': tenant, 'trust_anchor': [ANCHOR]}
    tokens = [original, statement, fed.documents[ec_url(ANCHOR)]]
    success(fed, endpoint.process_request(args, with_ta_ec=True), tokens)
    fed.clock[0] = fed.now + 450.25

    def gone(request):
        fed.clock[0] = expiry + offset
        return 404, {}, 'removed'

    fed.documents[ec_url(tenant)] = gone
    count = len(fed.http.calls)
    result = endpoint.process_request(args, with_ta_ec=True)
    if offset < 0:
        assert success(fed, result, tokens)['exp'] == expiry
    else:
        assert result['error'] == 'not_found' and result['response_code'] == 404
        assert fed.collector.config_cache[tenant] is None
    assert [call.request.url for call in fed.http.calls[count:]] == [ec_url(tenant)]
    assert ec_url(LEAF) not in [call.request.url for call in fed.http.calls]
    assert fed.documents[ec_url(LEAF)] == root
    tokens[0] = fed.ec(tenant, fed.now + 7200, hints=[ANCHOR], issued_at=fed.clock[0])
    success(fed, endpoint.process_request(args, with_ta_ec=True), tokens)


@pytest.mark.parametrize('owner', [LEAF, ANCHOR])
def test_shorter_accepted_ec_never_revives_predecessor(federation, owner):
    fed = federation
    fed.collector.refresh_fraction = 0.5
    fed.ec(LEAF, fed.now + 7200)
    original = fed.ec(owner, fed.now + 900, issued_at=fed.now)
    success(fed, resolve(fed), expected_tokens(fed))
    fed.clock[0] = fed.now + 450
    expiry = fed.now + 600.5
    new = fed.ec(owner, expiry, issued_at=fed.clock[0])
    tokens = expected_tokens(fed)
    assert success(fed, resolve(fed), tokens)['exp'] == expiry
    fed.documents[ec_url(owner)] = (404, {}, 'removed')
    fed.clock[0] = expiry - 0.125
    assert success(fed, resolve(fed), tokens)['exp'] == expiry
    assert fed.collector.config_cache[owner]['_jws'] == new != original
    fed.clock[0] = expiry
    assert 'response_args' not in resolve(fed)
    assert fed.collector.config_cache[owner] is None


def test_expired_unaccepted_ec_does_not_hide_valid_predecessor(federation):
    fed = federation
    fed.collector.refresh_fraction = 0.5
    original = fed.ec(LEAF, fed.now + 900, issued_at=fed.now)
    tokens = expected_tokens(fed)
    success(fed, resolve(fed), tokens)
    fed.clock[0] = fed.now + 450
    candidate = fed.ec(LEAF, fed.now + 600.5, issued_at=fed.clock[0])
    collect_trust_chains(fed.resolver, LEAF, for_resolve=True)
    assert fed.collector.config_cache[LEAF]['_jws'] == candidate
    fed.clock[0] = fed.now + 600.5
    fed.documents[ec_url(LEAF)] = (404, {}, 'removed before acceptance')
    count = len(fed.http.calls)
    success(fed, resolve(fed), tokens)
    assert len(fed.http.calls) == count + 1
    assert fed.collector.config_cache[LEAF]['_jws'] == original


@pytest.mark.parametrize('warmed', [False, True])
@pytest.mark.parametrize('retain_keys', [False, True])
def test_anchor_subject_retention_requires_current_configured_keys(federation, warmed, retain_keys):
    fed = federation
    fed.collector.refresh_fraction = 0.5
    original = fed.ec(ANCHOR, fed.now + 900, issued_at=fed.now)
    endpoint = fed.resolver.get_endpoint('resolve')
    args = {'sub': ANCHOR, 'trust_anchor': [ANCHOR]}
    if warmed:
        success(fed, endpoint.process_request(args), [original])
    fed.clock[0] = fed.now + 450
    payload = factory(original).jwt.payload()
    payload['jwks'] = fed.public[OTHER]
    candidate = JWS(json.dumps(payload), alg='ES256').sign_compact(
        fed.signing.get_signing_key('EC', issuer_id=OTHER),
        protected={'typ': ENTITY_CONFIGURATION.typ})
    fed.documents[ec_url(ANCHOR)] = candidate
    if not retain_keys:
        del fed.resolver.keyjar[ANCHOR]
    count = len(fed.http.calls)
    result = endpoint.process_request(args)
    assert len(fed.http.calls) == count + 1
    if warmed and retain_keys:
        success(fed, result, [original])
        assert fed.collector.config_cache[ANCHOR]['_jws'] == original
    else:
        assert result['error'] == 'invalid_trust_chain'
        assert 'response_args' not in result
    with pytest.raises(FederationJwtKeyResolutionError):
        verify_federation_jwt(ENTITY_CONFIGURATION, candidate, fed.resolver.keyjar)


def test_accepted_intermediate_ec_changes_fetch_route(federation):
    fed = federation
    fed.collector.refresh_fraction = 0.5
    fed.ec(LEAF, fed.now + 7200, hints=[INTERMEDIATE])
    fed.ec(INTERMEDIATE, fed.now + 900, hints=[ANCHOR], issued_at=fed.now)
    fed.ss(INTERMEDIATE, LEAF, fed.now + 900, issued_at=fed.now)
    upper = fed.ss(ANCHOR, INTERMEDIATE, fed.now + 7200)
    success(fed, resolve(fed), [fed.documents[ec_url(LEAF)], fed.documents[ss_url(INTERMEDIATE, LEAF)],
                              upper, fed.documents[ec_url(ANCHOR)]])
    fed.clock[0] = fed.now + 450
    new = fed.ec(INTERMEDIATE, fed.now + 1350, hints=[ANCHOR], path='/new', issued_at=fed.clock[0])
    lower = fed.ss(INTERMEDIATE, LEAF, fed.now + 1350, path='/new', issued_at=fed.clock[0])
    count = len(fed.http.calls)
    tokens = [fed.documents[ec_url(LEAF)], lower, upper, fed.documents[ec_url(ANCHOR)]]
    success(fed, resolve(fed), tokens)
    assert [call.request.url for call in fed.http.calls[count:]] == [
        ec_url(INTERMEDIATE), ss_url(INTERMEDIATE, LEAF, '/new')]
    assert fed.collector.config_cache[INTERMEDIATE]['_jws'] == new
    fed.documents[ec_url(INTERMEDIATE)] = (404, {}, 'removed')
    fed.clock[0] = fed.now + 900
    count = len(fed.http.calls)
    success(fed, resolve(fed), tokens)
    assert [call.request.url for call in fed.http.calls[count:]] == [
        ec_url(INTERMEDIATE), ss_url(INTERMEDIATE, LEAF, '/new')]


@pytest.mark.parametrize('accept', [False, True])
@pytest.mark.parametrize('reply', ['404', 'valid'])
def test_delayed_ec_refresh_preserves_independent_publication(federation, accept, reply):
    fed = federation
    fed.collector.refresh_fraction = 0.5
    fed.ec(LEAF, fed.now + 900, issued_at=fed.now)
    tokens = expected_tokens(fed)
    success(fed, resolve(fed), tokens)
    fed.clock[0] = fed.now + 450
    newer = fed.ec(LEAF, fed.now + 1800, issued_at=fed.clock[0])
    outer = fed.ec(LEAF, fed.now + 1350, issued_at=fed.clock[0])
    accepted = []

    def delayed(request):
        fed.documents[ec_url(LEAF)] = newer
        if accept:
            success(fed, resolve(fed), [newer] + tokens[1:])
        else:
            fed.collector._get_cached_entity_configuration(LEAF, for_resolve=True)
        accepted.append(fed.collector.config_cache[LEAF])
        if reply == '404':
            return 404, {}, 'removed'
        return 200, {'Content-Type': ENTITY_CONFIGURATION.content_type}, outer

    fed.documents[ec_url(LEAF)] = delayed
    count = len(fed.http.calls)
    result = resolve(fed)
    success(fed, result, ([outer] + tokens[1:]) if reply == 'valid' else tokens)
    assert len(fed.http.calls) == count + 2
    assert fed.collector.config_cache[LEAF] is accepted[0]
    assert accepted[0]['_jws'] == newer


def test_delayed_ec_failure_cannot_remove_identical_independent_acceptance(federation, monkeypatch):
    fed = federation
    fed.collector.refresh_fraction = 0.5
    fed.ec(LEAF, fed.now + 900, issued_at=fed.now)
    success(fed, resolve(fed), expected_tokens(fed))
    fed.clock[0] = fed.now + 450
    new = fed.ec(LEAF, fed.now + 1800, issued_at=fed.clock[0])
    verifier = fed.resolver.function.verifier
    verify = verifier.verify_with_outcomes
    accepted = []

    def delayed(chain, **kwargs):
        monkeypatch.setattr(verifier, 'verify_with_outcomes', verify)
        success(fed, resolve(fed), expected_tokens(fed))
        accepted.append(fed.collector.config_cache[LEAF])
        raise RuntimeError('local verification error after independent acceptance')

    monkeypatch.setattr(verifier, 'verify_with_outcomes', delayed)
    with pytest.raises(RuntimeError):
        resolve(fed)
    assert fed.collector.config_cache[LEAF] is accepted[0]
    assert accepted[0]['_jws'] == new
    assert LEAF not in fed.collector._pending_configurations


@pytest.mark.parametrize("failure", ["missing", "signature", "unavailable", "expired", "header", "key"])
def test_resolve_retains_validated_ss_after_failed_refresh(federation, failure):
    fed = federation
    fed.collector.refresh_fraction = 0.5
    fed.ec(LEAF, fed.now + 7200, issued_at=fed.now)
    original = fed.ss(ANCHOR, LEAF, fed.now + 900, issued_at=fed.now)
    tokens = expected_tokens(fed)
    success(fed, resolve(fed), tokens)
    count = len(fed.http.calls)
    fed.clock[0] = fed.now + 449
    assert success(fed, resolve(fed), tokens)["exp"] == fed.now + 900
    assert len(fed.http.calls) == count
    fed.clock[0] = fed.now + 450
    url = ss_url(ANCHOR, LEAF)
    if failure in ("missing", "unavailable"):
        reply = (404 if failure == "missing" else 503, {}, "unavailable")
    elif failure == "signature":
        reply = corrupt_signature(original)
    else:
        payload = factory(original).jwt.payload()
        if failure == "expired":
            payload["exp"] = fed.clock[0]
        signer = OTHER if failure == "key" else ANCHOR
        reply = JWS(json.dumps(payload), alg="ES256").sign_compact(
            fed.signing.get_signing_key("EC", issuer_id=signer),
            protected={"typ": "wrong+jwt" if failure == "header" else SUBORDINATE_STATEMENT.typ})
    fed.documents[url] = reply
    for attempt in (1, 2):
        assert success(fed, resolve(fed), tokens)["exp"] == fed.now + 900
        assert len(fed.http.calls) == count + attempt
        assert fed.collector._statement_pair(LEAF, ANCHOR) == (original, fed.now + 900)
    replacement = fed.ss(ANCHOR, LEAF, fed.now + 1350, issued_at=fed.now + 450)
    tokens[1] = replacement
    assert success(fed, resolve(fed), tokens)["exp"] == fed.now + 1350
    assert len(fed.http.calls) == count + 3
    assert fed.collector._statement_pair(LEAF, ANCHOR) == (replacement, fed.now + 1350)


@pytest.mark.parametrize("fraction", [0, 0.5])
def test_shorter_accepted_ss_never_revives_predecessor(federation, fraction):
    fed = federation
    fed.collector.refresh_fraction = 0.5
    fed.ec(LEAF, fed.now + 7200, issued_at=fed.now)
    old = fed.ss(ANCHOR, LEAF, fed.now + 900, issued_at=fed.now)
    success(fed, resolve(fed), expected_tokens(fed))
    fed.clock[0] = fed.now + 450
    expiry = fed.now + 600 + fraction
    new = fed.ss(ANCHOR, LEAF, expiry, issued_at=fed.now + 450)
    tokens = expected_tokens(fed)
    assert success(fed, resolve(fed), tokens)["exp"] == expiry
    assert old != new and fed.collector._statement_pair(LEAF, ANCHOR) == (new, expiry)
    fed.documents[ss_url(ANCHOR, LEAF)] = (404, {}, "removed")
    fed.clock[0] = expiry - 0.125
    count = len(fed.http.calls)
    assert success(fed, resolve(fed), tokens)["exp"] == expiry
    assert len(fed.http.calls) == count + 1
    fed.clock[0] = expiry
    result = resolve(fed)
    assert result["error"] == "invalid_trust_chain" and result["response_code"] == 400
    assert fed.clock[0] < fed.now + 900
    assert fed.collector._statement_pair(LEAF, ANCHOR) == (None, None)
    assert len(fed.http.calls) == count + 2


@pytest.mark.parametrize("during_http", [False, True])
@pytest.mark.parametrize("offset", [-0.125, 0, 0.125])
def test_failed_ss_refresh_obeys_fractional_original_deadline(federation, during_http, offset):
    fed = federation
    fed.collector.refresh_fraction = 0.5
    fed.ec(LEAF, fed.now + 7200)
    expiry = fed.now + 900.5
    fed.ss(ANCHOR, LEAF, expiry, issued_at=fed.now)
    tokens = expected_tokens(fed)
    success(fed, resolve(fed), tokens)
    fed.clock[0] = fed.now + 450.25 if during_http else expiry + offset

    def gone(request):
        if during_http:
            fed.clock[0] = expiry + offset
        return 404, {}, "removed"

    fed.documents[ss_url(ANCHOR, LEAF)] = gone
    count = len(fed.http.calls)
    result = resolve(fed)
    assert len(fed.http.calls) == count + 1
    if offset < 0:
        assert success(fed, result, tokens)["exp"] == expiry
    else:
        assert result["error"] == "invalid_trust_chain" and result["response_code"] == 400
        assert fed.collector._statement_pair(LEAF, ANCHOR) == (None, None)


def test_resolve_ss_retention_starts_at_legacy_delta_boundary(federation):
    fed = federation
    fed.collector.allowed_delta = 300
    fed.ec(LEAF, fed.now + 7200)
    fed.ss(ANCHOR, LEAF, fed.now + 900, issued_at=fed.now)
    tokens = expected_tokens(fed)
    success(fed, resolve(fed), tokens)
    count = len(fed.http.calls)
    fed.documents[ss_url(ANCHOR, LEAF)] = (410, {}, "gone")
    fed.clock[0] = fed.now + 599.875
    success(fed, resolve(fed), tokens)
    assert len(fed.http.calls) == count
    fed.clock[0] = fed.now + 600
    assert success(fed, resolve(fed), tokens)["exp"] == fed.now + 900
    assert len(fed.http.calls) == count + 1


@pytest.mark.parametrize("warmed", [False, True])
def test_removed_intermediate_ss_serves_new_leaf_only_until_original_expiry(federation, warmed):
    fed = federation
    fed.collector.refresh_fraction = 0.5
    fed.ec(LEAF, fed.now + 7200, hints=[INTERMEDIATE])
    fed.ec(OTHER, fed.now + 7200, hints=[INTERMEDIATE])
    fed.ec(INTERMEDIATE, fed.now + 7200, hints=[ANCHOR])
    fed.ss(INTERMEDIATE, LEAF, fed.now + 7200)
    child = fed.ss(INTERMEDIATE, OTHER, fed.now + 7200)
    shared = fed.ss(ANCHOR, INTERMEDIATE, fed.now + 900, issued_at=fed.now)
    if warmed:
        success(fed, resolve(fed), [
            fed.documents[ec_url(LEAF)], fed.documents[ss_url(INTERMEDIATE, LEAF)],
            shared, fed.documents[ec_url(ANCHOR)]])
    fed.documents[ss_url(ANCHOR, INTERMEDIATE)] = (404, {}, "removed")
    endpoint = fed.resolver.get_endpoint("resolve")
    for offset in (450, 900):
        fed.clock[0] = fed.now + offset
        count = len(fed.http.calls)
        result = endpoint.process_request({"sub": OTHER, "trust_anchor": [ANCHOR]}, with_ta_ec=True)
        assert [call.request.url for call in fed.http.calls[count:]].count(ss_url(ANCHOR, INTERMEDIATE)) == 1
        if warmed and offset == 450:
            claims = success(fed, result, [fed.documents[ec_url(OTHER)], child, shared,
                                         fed.documents[ec_url(ANCHOR)]])
            assert claims["sub"] == OTHER and claims["exp"] == fed.now + 900
            assert fed.collector._statement_pair(INTERMEDIATE, ANCHOR) == (shared, fed.now + 900)
        else:
            assert result["error"] == "invalid_trust_chain" and result["response_code"] == 400
            assert "response_args" not in result


def test_concurrent_direct_ss_fetch_keeps_404_behavior_during_resolve(federation):
    fed = federation
    fed.collector.refresh_fraction = 0.5
    fed.ec(LEAF, fed.now + 7200)
    fed.ec(OTHER, fed.now + 7200, hints=[ANCHOR])
    fed.ss(ANCHOR, LEAF, fed.now + 900, issued_at=fed.now)
    fed.ss(ANCHOR, OTHER, fed.now + 900, issued_at=fed.now)
    tokens = expected_tokens(fed)
    success(fed, resolve(fed), tokens)
    success(fed, fed.resolver.get_endpoint("resolve").process_request(
        {"sub": OTHER, "trust_anchor": [ANCHOR]}, with_ta_ec=True),
        [fed.documents[ec_url(OTHER)], fed.documents[ss_url(ANCHOR, OTHER)], tokens[-1]])
    fed.clock[0] = fed.now + 450
    paused, release = Event(), Event()

    def gone(request):
        paused.set()
        assert release.wait(timeout=10)
        return 404, {}, "removed"

    fed.documents[ss_url(ANCHOR, LEAF)] = gone
    fed.documents[ss_url(ANCHOR, OTHER)] = (404, {}, "removed")
    worker = start_worker(lambda: resolve(fed))
    try:
        assert paused.wait(timeout=10)
        with pytest.raises(MissingPage):
            fed.collector._get_entity_statement(OTHER, ANCHOR, fetch_endpoint=ANCHOR + "/fetch")
    finally:
        release.set()
        result = finish_worker(worker)
    assert success(fed, result, tokens)["exp"] == fed.now + 900
    assert fed.collector._request_budget.get() is None
    assert fed.collector._statement_pair(OTHER, ANCHOR) == (None, None)


def test_unverified_cold_collection_is_not_last_validated_ss(federation):
    fed = federation
    fed.collector.refresh_fraction = 0.5
    fed.ec(LEAF, fed.now + 7200)
    fed.ss(ANCHOR, LEAF, fed.now + 900, issued_at=fed.now)
    chains, _ = collect_trust_chains(fed.resolver, LEAF)
    assert chains and fed.collector._pending_statements[(ANCHOR, LEAF)][2] == (None, None)
    fed.clock[0] = fed.now + 450
    fed.documents[ss_url(ANCHOR, LEAF)] = (404, {}, "removed")
    result = resolve(fed)
    assert result["error"] == "invalid_trust_chain" and result["response_code"] == 400
    assert "response_args" not in result


@pytest.mark.parametrize("valid", [False, True])
def test_legacy_ss_pair_requires_real_verification_before_retention(federation, valid):
    fed = federation
    fed.collector.refresh_fraction = 0.5
    fed.ec(LEAF, fed.now + 7200)
    original = fed.ss(ANCHOR, LEAF, fed.now + 900, issued_at=fed.now)
    tokens = expected_tokens(fed)
    success(fed, resolve(fed), tokens)
    fed.collector._statement_revisions.clear()
    fed.collector._pending_statements.clear()
    if not valid:
        fed.collector.entity_statement_cache[cache_key(ANCHOR, LEAF)] = corrupt_signature(original)
    fed.clock[0] = fed.now + 450
    fed.documents[ss_url(ANCHOR, LEAF)] = (404, {}, "removed")
    result = resolve(fed)
    if valid:
        assert success(fed, result, tokens)["exp"] == fed.now + 900
    else:
        assert result["error"] == "invalid_trust_chain" and result["response_code"] == 400


def test_local_verifier_error_keeps_prior_ss_without_leaking_resolve_mode(federation, monkeypatch):
    fed = federation
    _, url, tokens = warm_refresh(fed, "subordinate")
    fed.ss(ANCHOR, LEAF, fed.now + 7200)

    def unavailable(*args, **kwargs):
        raise Timeout("local verification error")

    with monkeypatch.context() as patch:
        patch.setattr(fed.resolver.function.verifier, "verify_with_outcomes", unavailable)
        with pytest.raises(Timeout, match="local verification error"):
            resolve(fed)
    assert fed.collector._statement_pair(LEAF, ANCHOR) == (
        tokens[1], factory(tokens[1]).jwt.payload()["exp"])
    fed.documents[url] = (404, {}, "removed")
    with pytest.raises(MissingPage):
        fed.collector._get_entity_statement(LEAF, ANCHOR, fetch_endpoint=ANCHOR + "/fetch")


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
    if fed.collector.refresh_fraction is None:
        fed.clock[0] = expiry - fed.collector.allowed_delta
    else:
        issued_at = factory(fed.documents[url]).jwt.payload()["iat"]
        fed.clock[0] = issued_at + fed.collector.refresh_fraction * (expiry - issued_at)
    return expiry, url, tokens


@pytest.mark.parametrize("dependency", ["leaf", "intermediate", "anchor", "subordinate", "upper_statement"])
@pytest.mark.parametrize("failure", [
    Timeout("slow"), ConnectTimeout("connect slow"), ReadTimeout("read slow"),
    ConnectionError("offline"), (500, {}, "down"), (502, {}, "down"),
    (503, {}, "down"), (504, {}, "down"),
])
@pytest.mark.parametrize("refresh_fraction", [None, 0.5, 0.75])
def test_early_refresh_failure_retains_usable_cache_and_retries(
        federation, dependency, failure, refresh_fraction):
    fed = federation
    fed.collector.refresh_fraction = refresh_fraction
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
@pytest.mark.parametrize("refresh_fraction", [None, 0.5])
def test_outage_fallback_rechecks_deadline_after_http(
        federation, dependency, fraction, offset, refresh_fraction):
    fed = federation
    fed.collector.refresh_fraction = refresh_fraction
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
@pytest.mark.parametrize("refresh_fraction", [None, 0.75])
def test_warm_refresh_failures_follow_resolve_scope(
        federation, dependency, failure, refresh_fraction):
    fed = federation
    fed.collector.refresh_fraction = refresh_fraction
    _, url, tokens = warm_refresh(fed, dependency)
    original = fed.documents[url]
    fed.documents[url] = failure
    count = len(fed.http.calls)
    peer_failure = not isinstance(failure, (InvalidURL, RuntimeError))
    if dependency == "leaf" and isinstance(failure, (InvalidURL, RuntimeError)):
        with pytest.raises(type(failure)):
            resolve(fed)
    else:
        result = resolve(fed)
        if peer_failure:
            success(fed, result, tokens)
        else:
            assert "response_args" not in result
            assert result["response_code"] >= 400
    assert len(fed.http.calls) == count + 1
    if dependency == "leaf":
        assert fed.collector.config_cache[LEAF]['_jws'] == original
    else:
        assert fed.collector._statement_pair(LEAF, ANCHOR) == (
            original, factory(original).jwt.payload()["exp"])
    # Local failures do not become success, nor do they erase accepted evidence.
    fed.documents[url] = Timeout("still unavailable")
    success(fed, resolve(fed), tokens)
    fed.documents[url] = original
    success(fed, resolve(fed), tokens)


@pytest.mark.parametrize("dependency", ["leaf", "upper_statement"])
@pytest.mark.parametrize("failure", ["malformed", "subject", "issuer", "signature", "claims", "constraints"])
@pytest.mark.parametrize("refresh_fraction", [None, 0.75])
def test_invalid_replacement_retention_does_not_bypass_valid_constraints(
        federation, dependency, failure, refresh_fraction):
    fed = federation
    fed.collector.refresh_fraction = refresh_fraction
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
    retained = dependency == "leaf" or failure != "constraints"
    result = resolve(fed)
    if retained:
        success(fed, result, tokens)
    else:
        assert "response_args" not in result
    if dependency == "leaf":
        assert fed.collector.config_cache[LEAF]['_jws'] == original
    else:
        assert fed.collector.entity_statement_cache[cache_key(ANCHOR, INTERMEDIATE)] == (
            original if retained else None)
    fed.documents[url] = Timeout("outage after rejection")
    if retained:
        success(fed, resolve(fed), tokens)
    else:
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
    original = fed.collector.config_cache[LEAF]
    fed.ec(LEAF, fed.now + 7200)

    def verification_failure(*args, **kwargs):
        raise Timeout("verification application failure")

    monkeypatch.setattr("fedservice.entity.function.trust_chain_collector.verify_self_signed_signature",
                        verification_failure)
    result = resolve(fed)
    assert "response_args" not in result
    assert fed.collector.config_cache[LEAF] is original


@pytest.mark.parametrize("terminal", ["success", "timeout", "404", "one_request_budget"])
def test_path_entity_refresh_outcome_controls_retention(federation, terminal):
    fed = federation
    tenant = LEAF + "/tenant"
    fed.signing.add_keys(tenant, fed.signing.get_signing_key("EC", issuer_id=LEAF))
    fed.public[tenant] = fed.public[LEAF]
    token = fed.ec(tenant, fed.now + 1200.5, hints=[ANCHOR])
    statement = fed.ss(ANCHOR, tenant, fed.now + 5400)
    endpoint = fed.resolver.get_endpoint("resolve")
    args = {"sub": tenant, "trust_anchor": [ANCHOR]}
    tokens = [token, statement, fed.documents[ec_url(ANCHOR)]]
    success(fed, endpoint.process_request(args, with_ta_ec=True), tokens)
    count = len(fed.http.calls)
    fed.clock[0] = fed.now + 600.5
    if terminal == "timeout":
        fed.documents[ec_url(tenant)] = Timeout("tenant unavailable")
    elif terminal == "404":
        fed.documents[ec_url(tenant)] = (404, {}, "tenant missing")
    elif terminal == "one_request_budget":
        fed.collector.max_requests = 1
    else:
        tokens[0] = fed.ec(tenant, fed.now + 7200, hints=[ANCHOR])
    result = endpoint.process_request(args, with_ta_ec=True)
    success(fed, result, tokens)
    assert fed.collector.config_cache[tenant]["_jws"] == tokens[0]
    urls = [call.request.url for call in fed.http.calls[count:]]
    assert urls == [ec_url(tenant)]
    assert ec_url(LEAF) not in [call.request.url for call in fed.http.calls]


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


def policy_subjects(fed, refresh_fraction, fraction=0.5):
    """Publish two leaves sharing an ancestor policy that only one satisfies."""
    fed.collector.refresh_fraction = refresh_fraction
    fed.ec(ANCHOR, fed.now + 7200)
    fed.ec(INTERMEDIATE, fed.now + 7200, hints=[ANCHOR])
    fed.ec(LEAF, fed.now + 7200, name="allowed", hints=[INTERMEDIATE])
    fed.ec(OTHER, fed.now + 1600.5, name="disallowed", hints=[INTERMEDIATE])
    fed.ss(INTERMEDIATE, LEAF, fed.now + 5400)
    fed.ss(INTERMEDIATE, OTHER, fed.now + 5400)
    expiry = fed.now + 1200 + fraction
    original = fed.ss(ANCHOR, INTERMEDIATE, expiry)
    payload = factory(original).jwt.payload()
    payload["metadata_policy"] = {"federation_entity": {
        "organization_name": {"one_of": ["allowed"]}}}
    shared = sign_federation_jwt(
        SUBORDINATE_STATEMENT, payload, fed.signing, ANCHOR, "ES256", iat=payload["iat"])
    fed.documents[ss_url(ANCHOR, INTERMEDIATE)] = shared
    return [fed.documents[ec_url(LEAF)], fed.documents[ss_url(INTERMEDIATE, LEAF)],
            shared, fed.documents[ec_url(ANCHOR)]]


def reject_policy_subject(fed):
    """Require candidate-local policy rejection through the public Resolve endpoint."""
    result = fed.resolver.get_endpoint("resolve").process_request(
        {"sub": OTHER, "trust_anchor": [ANCHOR]}, with_ta_ec=True)
    assert result["error"] == "invalid_metadata" and result["response_code"] == 400
    assert "response_args" not in result and "response_msg" not in result


def refresh_time(fed, token):
    """Derive the active refresh boundary from the exact signed claims."""
    claims = factory(token).jwt.payload()
    fraction = fed.collector.refresh_fraction
    return (claims["exp"] - fed.collector.allowed_delta if fraction is None else
            claims["iat"] + fraction * (claims["exp"] - claims["iat"]))


def restoration_subjects(fed, refresh_fraction, changed_first=False, sibling_expiry=None,
                         other_name="disallowed"):
    """Warm A's shared policy, then give rejected B a constraint-limited sibling."""
    tokens = policy_subjects(fed, refresh_fraction)
    success(fed, resolve(fed), tokens, "allowed")
    branches = ["https://long-branch.example.org"]
    if sibling_expiry is not None:
        branches.append("https://last-branch.example.org")
    for branch in branches:
        key = new_ec_key(crv="P-256", use="sig")
        fed.signing.import_jwks({"keys": [key.serialize(private=True)]}, branch)
        fed.public[branch] = {"keys": [key.serialize(private=False)]}
        fed.ec(branch, fed.now + 7200, hints=[INTERMEDIATE])
        fed.ss(branch, OTHER, fed.now + 5400)
        fed.ss(INTERMEDIATE, branch, fed.now + 5400)
    fed.ec(OTHER, fed.now + 7200, name=other_name, hints=[INTERMEDIATE] + branches)
    fed.clock[0] = refresh_time(fed, tokens[2])
    payload = factory(tokens[2]).jwt.payload()
    expiry = payload["exp"]
    assert fed.clock[0] < expiry and fed.collector.too_old(payload)
    first = tokens[2]
    if changed_first:
        payload["publication"] = "changed first reply"
        first = sign_federation_jwt(
            SUBORDINATE_STATEMENT, payload, fed.signing, ANCHOR, "ES256", iat=payload["iat"])
        assert first != tokens[2]
    replies = [first]
    sibling_tokens = None
    if sibling_expiry is not None:
        sibling = factory(tokens[2]).jwt.payload()
        sibling.update(publication="policy-accepted sibling", exp=sibling_expiry)
        sibling["metadata_policy"]["federation_entity"]["organization_name"]["one_of"] = [other_name]
        assert fed.clock[0] < sibling_expiry and fed.collector.too_old(sibling)
        replies.append(sign_federation_jwt(
            SUBORDINATE_STATEMENT, sibling, fed.signing, ANCHOR, "ES256", iat=sibling["iat"]))
        sibling_tokens = [fed.documents[ec_url(OTHER)], fed.documents[ss_url(branches[0], OTHER)],
                          fed.documents[ss_url(INTERMEDIATE, branches[0])], replies[-1], tokens[-1]]
    payload.update(publication="constraint-limited sibling", exp=fed.now + 7200,
                   constraints={"max_path_length": 1})
    last = sign_federation_jwt(
        SUBORDINATE_STATEMENT, payload, fed.signing, ANCHOR, "ES256", iat=payload["iat"])
    replies.append(last)
    scenario = SimpleNamespace(tokens=tokens, first=first, last=last, expiry=expiry,
                               sibling_tokens=sibling_tokens,
                               url=ss_url(ANCHOR, INTERMEDIATE), visits=[])

    def refresh(request):
        scenario.visits.append(request.url)
        assert len(scenario.visits) <= len(replies), "unexpected repair retrieval"
        return 200, {"Content-Type": SUBORDINATE_STATEMENT.content_type}, replies[len(scenario.visits) - 1]

    fed.documents[scenario.url] = refresh
    return scenario


@pytest.mark.parametrize("refresh_fraction", [None, 0.5])
@pytest.mark.parametrize("changed_first", [False, True], ids=["unchanged", "replacement"])
def test_unchanged_restoration_survives_other_leaf_policy_failure(federation, monkeypatch,
                                                                refresh_fraction, changed_first):
    fed = federation
    scenario = restoration_subjects(fed, refresh_fraction, changed_first)
    finish = fed.collector.finish_policy_validation
    verified = fed.collector.finish_statement_verification
    processed = []

    def observe_verification(chains, accepted, constraint_rejections=()):
        assert len(chains) == 2 and len(accepted) == 1
        assert len(constraint_rejections) == 1 and scenario.last in constraint_rejections[0]
        verified(chains, accepted, constraint_rejections)

    def observe_policy(chains, accepted):
        assert len(chains) == 1 and not accepted
        assert chains[0].err["metadata_policy"]["error"] == "invalid_metadata"
        state = fed.collector._statement_snapshot(INTERMEDIATE, ANCHOR)
        assert state[:2] == (scenario.first, scenario.expiry)
        assert chains[0]._statement_restorations[(ANCHOR, INTERMEDIATE)] == state
        assert ((ANCHOR, INTERMEDIATE) in chains[0]._statement_replacements) is changed_first
        finish(chains, accepted)
        assert not hasattr(chains[0], "_statement_restorations")
        assert not hasattr(chains[0], "_statement_replacements")
        processed.extend(chains)

    start = len(fed.http.calls)
    with monkeypatch.context() as patch:
        patch.setattr(fed.collector, "finish_statement_verification", observe_verification)
        patch.setattr(fed.collector, "finish_policy_validation", observe_policy)
        reject_policy_subject(fed)
    assert len(processed) == 1
    assert scenario.visits == [scenario.url] * 2
    assert [call.request.url for call in fed.http.calls[start:]].count(scenario.url) == 2
    assert fed.collector._statement_pair(INTERMEDIATE, ANCHOR) == (
        (None, None) if changed_first else (scenario.tokens[2], scenario.expiry))
    assert (ANCHOR, INTERMEDIATE) not in fed.collector._pending_statements
    fed.documents[scenario.url] = Timeout("shared Fetch unavailable after B's rejection")
    start = len(fed.http.calls)
    result = resolve(fed)
    assert [call.request.url for call in fed.http.calls[start:]] == [scenario.url]
    expected = scenario.tokens[:]
    if changed_first:
        assert result["error"] == "invalid_trust_chain" and result["response_code"] == 400
        assert "response_args" not in result and "response_msg" not in result
        assert fed.collector._statement_pair(INTERMEDIATE, ANCHOR) == (None, None)
        fed.documents[scenario.url] = scenario.first
        expected[2] = scenario.first
        start = len(fed.http.calls)
        result = resolve(fed)
        assert [call.request.url for call in fed.http.calls[start:]] == [scenario.url]
    claims = success(fed, result, expected, "allowed")
    assert type(claims["iat"]) is int and claims["exp"] == scenario.expiry
    assert fed.collector._statement_pair(INTERMEDIATE, ANCHOR) == (expected[2], scenario.expiry)
    returned = verify_trust_chains(fed.resolver, [list(reversed(claims["trust_chain"][:-1]))])
    assert len(returned) == 1
    assert apply_policies(fed.resolver, returned)[0].metadata == claims["metadata"]


@pytest.mark.parametrize("refresh_fraction", [None, 0.5])
@pytest.mark.parametrize("lifetime", [1200.5, 1100.25])
@pytest.mark.parametrize("other_name", ["disallowed", "allowed"])
def test_original_restoration_can_promote_policy_accepted_sibling(federation, monkeypatch,
                                                                 refresh_fraction, lifetime, other_name):
    fed = federation
    scenario = restoration_subjects(fed, refresh_fraction, sibling_expiry=fed.now + lifetime,
                                    other_name=other_name)
    finish = fed.collector.finish_policy_validation
    verified = fed.collector.finish_statement_verification
    processed = []

    def observe_verification(chains, accepted, constraint_rejections=()):
        assert len(chains) == 3 and len(accepted) == 2
        assert len(constraint_rejections) == 1 and scenario.last in constraint_rejections[0]
        verified(chains, accepted, constraint_rejections)

    def observe_policy(chains, accepted):
        assert len(chains) == 2
        assert accepted == (chains[1:] if other_name == "disallowed" else chains)
        if other_name == "disallowed":
            assert chains[0].err["metadata_policy"]["error"] == "invalid_metadata"
        state = fed.collector._statement_snapshot(INTERMEDIATE, ANCHOR)
        assert state[:2] == (scenario.tokens[2], scenario.expiry)
        assert (ANCHOR, INTERMEDIATE) not in chains[0]._statement_replacements
        for chain in chains:
            assert chain._statement_restorations[(ANCHOR, INTERMEDIATE)] == state
            assert not getattr(chain.chain, "_statement_context", {})
            assert "_statement_" not in json.dumps(chain.dump())
        finish(chains, accepted)
        assert all(not hasattr(chain, attr) for chain in chains
                   for attr in ("_statement_restorations", "_statement_replacements"))
        processed.extend(chains)

    start = len(fed.http.calls)
    with monkeypatch.context() as patch:
        patch.setattr(fed.collector, "finish_statement_verification", observe_verification)
        patch.setattr(fed.collector, "finish_policy_validation", observe_policy)
        result = fed.resolver.get_endpoint("resolve").process_request(
            {"sub": OTHER, "trust_anchor": [ANCHOR]}, with_ta_ec=True)
    assert len(processed) == 2 and scenario.visits == [scenario.url] * 3
    assert [call.request.url for call in fed.http.calls[start:]].count(scenario.url) == 3
    expected = (scenario.sibling_tokens if other_name == "disallowed" else
                [fed.documents[ec_url(OTHER)], fed.documents[ss_url(INTERMEDIATE, OTHER)],
                 scenario.tokens[2], scenario.tokens[-1]])
    assert scenario.sibling_tokens[-2] != scenario.tokens[2]
    claims = success(fed, result, expected, other_name)
    assert type(claims["iat"]) is int
    assert claims["exp"] == (fed.now + lifetime if other_name == "disallowed" else scenario.expiry)
    assert fed.collector._statement_pair(INTERMEDIATE, ANCHOR) == (expected[-2], claims["exp"])
    assert "_statement_" not in json.dumps(factory(result["response_args"]).jwt.payload())
    returned = verify_trust_chains(fed.resolver, [list(reversed(claims["trust_chain"][:-1]))])
    assert len(returned) == 1
    assert apply_policies(fed.resolver, returned)[0].metadata == claims["metadata"]


@pytest.mark.parametrize("refresh_fraction", [None, 0.5])
@pytest.mark.parametrize("offset", [-0.125, 0, 0.125])
@pytest.mark.parametrize("advance_at", ["before-refresh", "during-refresh", "policy-finalization"])
def test_unchanged_restoration_fallback_obeys_precise_expiry(federation, monkeypatch,
                                                           refresh_fraction, offset, advance_at):
    fed = federation
    scenario = restoration_subjects(fed, refresh_fraction)
    finish = fed.collector.finish_policy_validation

    def advance_policy(chains, accepted):
        assert len(chains) == 1 and not accepted
        assert fed.collector._statement_pair(INTERMEDIATE, ANCHOR) == (scenario.first, scenario.expiry)
        fed.clock[0] = scenario.expiry + offset
        finish(chains, accepted)

    with monkeypatch.context() as patch:
        if advance_at == "policy-finalization":
            patch.setattr(fed.collector, "finish_policy_validation", advance_policy)
        reject_policy_subject(fed)
    assert scenario.visits == [scenario.url] * 2
    assert fed.collector._statement_pair(INTERMEDIATE, ANCHOR) == (
        (None, None) if advance_at == "policy-finalization" and offset >= 0 else
        (scenario.first, scenario.expiry))
    if advance_at == "before-refresh":
        fed.clock[0] = scenario.expiry + offset

    def timeout(request):
        if advance_at == "during-refresh":
            fed.clock[0] = scenario.expiry + offset
        raise Timeout("shared original expires during outage")

    fed.documents[scenario.url] = timeout
    start = len(fed.http.calls)
    result = resolve(fed)
    assert [call.request.url for call in fed.http.calls[start:]] == [scenario.url]
    if offset < 0:
        assert success(fed, result, scenario.tokens, "allowed")["exp"] == scenario.expiry
        assert fed.collector._statement_pair(INTERMEDIATE, ANCHOR) == (scenario.first, scenario.expiry)
    else:
        assert result["error"] == "invalid_trust_chain" and result["response_code"] == 400
        assert "response_args" not in result and "response_msg" not in result
        assert fed.collector._statement_pair(INTERMEDIATE, ANCHOR) == (None, None)
        assert (ANCHOR, INTERMEDIATE) not in fed.collector._pending_statements


@pytest.mark.parametrize("refresh_fraction", [None, 0.5])
@pytest.mark.parametrize("intervention", ["publication", "accepted-identical"])
def test_unchanged_restoration_preserves_independent_revision(federation, monkeypatch,
                                                            refresh_fraction, intervention):
    fed = federation
    scenario = restoration_subjects(fed, refresh_fraction)
    paused, release = Event(), Event()
    finish = fed.collector.finish_policy_validation
    processed, independent_accepted = [], []

    def pause_rejection(chains, accepted):
        if chains and chains[0].verified_chain[-1]["sub"] == OTHER:
            assert len(chains) == 1 and not accepted
            assert chains[0]._statement_restorations[(ANCHOR, INTERMEDIATE)] == (
                fed.collector._statement_snapshot(INTERMEDIATE, ANCHOR))
            paused.set()
            assert release.wait(timeout=10), "B's policy finalization gate was not released"
            finish(chains, accepted)
            processed.extend(chains)
        else:
            before = fed.collector._statement_snapshot(INTERMEDIATE, ANCHOR)
            finish(chains, accepted)
            after = fed.collector._statement_snapshot(INTERMEDIATE, ANCHOR)
            assert before[:2] == after[:2] and before[2] != after[2]
            independent_accepted.extend(accepted)

    with monkeypatch.context() as patch:
        patch.setattr(fed.collector, "finish_policy_validation", pause_rejection)
        outer = start_worker(lambda: reject_policy_subject(fed))
        independent = None
        try:
            assert paused.wait(timeout=10), "B did not reach policy finalization"
            assert scenario.visits == [scenario.url] * 2
            old = fed.collector._statement_snapshot(INTERMEDIATE, ANCHOR)
            assert old[:2] == (scenario.first, scenario.expiry)
            expected = scenario.tokens[:]
            if intervention == "publication":
                payload = factory(scenario.first).jwt.payload()
                payload.update(publication="independent publication", exp=fed.now + 7200)
                expected[2] = sign_federation_jwt(
                    SUBORDINATE_STATEMENT, payload, fed.signing, ANCHOR, "ES256", iat=payload["iat"])
            fed.documents[scenario.url] = expected[2]
            start = len(fed.http.calls)
            if intervention == "accepted-identical":
                independent = start_worker(lambda: resolve(fed))
                success(fed, finish_worker(independent), expected, "allowed")
                assert len(independent_accepted) == 1
            else:
                independent = start_worker(lambda: collect_trust_chains(fed.resolver, LEAF))
                independent_chains, ec = finish_worker(independent)
            assert [call.request.url for call in fed.http.calls[start:]] == [scenario.url]
            current = fed.collector._statement_snapshot(INTERMEDIATE, ANCHOR)
            assert current[0] == expected[2] and current[2] != old[2]
            pending = fed.collector._pending_statements.get((ANCHOR, INTERMEDIATE))
            assert (pending is not None) is (intervention == "publication")
            assert outer[0].is_alive()
        finally:
            release.set()
            try:
                finish_worker(outer)
            finally:
                if independent is not None:
                    finish_worker(independent)
    assert len(processed) == 1
    assert fed.collector._statement_snapshot(INTERMEDIATE, ANCHOR) == current
    assert fed.collector._pending_statements.get((ANCHOR, INTERMEDIATE)) is pending
    assert not hasattr(processed[0], "_statement_restorations")
    assert not hasattr(processed[0], "_statement_replacements")
    if intervention == "publication":
        verified = verify_trust_chains(fed.resolver, independent_chains, ec)
        assert len(verified) == 1 and apply_policies(fed.resolver, verified) == verified
    success(fed, resolve(fed), expected, "allowed")


def concurrent_policy_refresh(fed, monkeypatch, refresh_fraction, second_succeeds=True, lifetime=7200,
                              expect_refresh=False):
    """Finish an independent operation while B is paused before its real policy check."""
    tokens = policy_subjects(fed, refresh_fraction)
    success(fed, resolve(fed), tokens, "allowed")
    fed.clock[0] = refresh_time(fed, tokens[2])
    payload = factory(tokens[2]).jwt.payload()
    payload.update(publication="concurrent replacement", exp=fed.now + lifetime)
    tokens[2] = sign_federation_jwt(
        SUBORDINATE_STATEMENT, payload, fed.signing, ANCHOR, "ES256", iat=payload["iat"])
    url = ss_url(ANCHOR, INTERMEDIATE)
    fed.documents[url] = tokens[2]
    paused, release = Event(), Event()
    policy = fed.resolver.function.policy
    apply = policy.apply_policy

    def pause_rejected_subject(metadata, rules, **kwargs):
        if metadata.get("organization_name") == "disallowed" and not paused.is_set():
            paused.set()
            assert release.wait(timeout=10), "policy gate was not released"
        return apply(metadata, rules, **kwargs)

    monkeypatch.setattr(policy, "apply_policy", pause_rejected_subject)
    rejected_worker = start_worker(lambda: fed.resolver.get_endpoint("resolve").process_request(
        {"sub": OTHER, "trust_anchor": [ANCHOR]}, with_ta_ec=True))
    accepted_worker = None
    try:
        assert paused.wait(timeout=10), "B did not reach policy evaluation"
        count = len(fed.http.calls)
        accepted_worker = start_worker(lambda: fed.resolver.get_endpoint("resolve").process_request(
            {"sub": LEAF if second_succeeds else OTHER, "trust_anchor": [ANCHOR]}, with_ta_ec=True))
        result = finish_worker(accepted_worker)
        if second_succeeds:
            claims = success(fed, result, tokens, "allowed")
            assert type(claims["iat"]) is int
            assert "_statement_" not in json.dumps(factory(result["response_args"]).jwt.payload())
        else:
            assert result["error"] == "invalid_metadata" and result["response_code"] == 400
            assert "response_args" not in result
        assert len(fed.http.calls) == count + int(expect_refresh)
        assert rejected_worker[0].is_alive()
    finally:
        release.set()
        try:
            rejected_result = finish_worker(rejected_worker)
        finally:
            if accepted_worker is not None:
                finish_worker(accepted_worker)
    assert rejected_result["error"] == "invalid_metadata" and rejected_result["response_code"] == 400
    assert "response_args" not in rejected_result and "response_msg" not in rejected_result
    assert fed.collector._statement_pair(INTERMEDIATE, ANCHOR) == (
        (tokens[2], payload["exp"]) if second_succeeds else (None, None))
    return tokens


@pytest.mark.parametrize("refresh_fraction", [None, 0.5])
@pytest.mark.parametrize("second_succeeds", [True, False])
def test_concurrent_policy_rejection_preserves_accepted_shared_statement(federation, monkeypatch,
                                                                       refresh_fraction, second_succeeds):
    fed = federation
    tokens = concurrent_policy_refresh(fed, monkeypatch, refresh_fraction, second_succeeds)
    url = ss_url(ANCHOR, INTERMEDIATE)
    fed.documents[url] = Timeout("shared Fetch unavailable after B's rejection")
    count = len(fed.http.calls)
    result = resolve(fed)
    if second_succeeds:
        claims = success(fed, result, tokens, "allowed")
        assert len(fed.http.calls) == count
    else:
        assert result["error"] == "invalid_trust_chain" and result["response_code"] == 400
        assert "response_args" not in result
        assert fed.collector._statement_pair(INTERMEDIATE, ANCHOR) == (None, None)
        fed.documents[url] = tokens[2]
        claims = success(fed, resolve(fed), tokens, "allowed")
    returned = verify_trust_chains(fed.resolver, [list(reversed(claims["trust_chain"][:-1]))])
    assert len(returned) == 1
    assert apply_policies(fed.resolver, returned)[0].metadata == claims["metadata"]


@pytest.mark.parametrize("refresh_fraction", [None, 0.5])
def test_identical_concurrent_refresh_does_not_protect_rejected_replacement(federation, monkeypatch,
                                                                          refresh_fraction):
    concurrent_policy_refresh(federation, monkeypatch, refresh_fraction, second_succeeds=False,
                              lifetime=1200.5, expect_refresh=True)


@pytest.mark.parametrize("refresh_fraction", [None, 0.5])
@pytest.mark.parametrize("offset", [-0.125, 0, 0.125])
@pytest.mark.parametrize("during_http", [False, True])
def test_concurrently_protected_statement_still_expires(federation, monkeypatch, refresh_fraction,
                                                      offset, during_http):
    fed = federation
    tokens = concurrent_policy_refresh(fed, monkeypatch, refresh_fraction, lifetime=2400.5)
    expiry = factory(tokens[2]).jwt.payload()["exp"]
    fed.clock[0] = refresh_time(fed, tokens[2]) if during_http else expiry + offset

    def timeout(request):
        if during_http:
            fed.clock[0] = expiry + offset
        raise Timeout("remaining validity consumed during refresh")

    url = ss_url(ANCHOR, INTERMEDIATE)
    fed.documents[url] = timeout
    count = len(fed.http.calls)
    result = resolve(fed)
    assert [call.request.url for call in fed.http.calls[count:]] == [url]
    if offset < 0:
        assert success(fed, result, tokens, "allowed")["exp"] == expiry
    else:
        assert result["error"] == "invalid_trust_chain" and result["response_code"] == 400
        assert "response_args" not in result
        assert fed.collector._statement_pair(INTERMEDIATE, ANCHOR) == (None, None)


@pytest.mark.parametrize("refresh_fraction", [None, 0.5])
@pytest.mark.parametrize("pause_at", ["verification", "policy"])
def test_old_candidate_cannot_claim_recreated_entry(federation, monkeypatch, refresh_fraction, pause_at):
    fed = federation
    tokens = policy_subjects(fed, refresh_fraction)
    success(fed, resolve(fed), tokens, "allowed")
    fed.clock[0] = refresh_time(fed, tokens[2])
    payload = factory(tokens[2]).jwt.payload()
    payload.update(publication="recreated replacement", exp=fed.now + 7200)
    tokens[2] = sign_federation_jwt(
        SUBORDINATE_STATEMENT, payload, fed.signing, ANCHOR, "ES256", iat=payload["iat"])
    fed.documents[ss_url(ANCHOR, INTERMEDIATE)] = tokens[2]
    paused, release = Event(), Event()
    if pause_at == "verification":
        verifier = fed.resolver.function.verifier
        verify = verifier.verify_with_outcomes

        def wait_for_verification(chain, **kwargs):
            if factory(chain[-1]).jwt.payload()["sub"] == OTHER:
                paused.set()
                assert release.wait(timeout=10)
            return verify(chain, **kwargs)

        monkeypatch.setattr(verifier, "verify_with_outcomes", wait_for_verification)
    else:
        policy = fed.resolver.function.policy
        apply = policy.apply_policy

        def wait_for_policy(metadata, rules, **kwargs):
            if metadata.get("organization_name") == "disallowed":
                paused.set()
                assert release.wait(timeout=10)
            return apply(metadata, rules, **kwargs)

        monkeypatch.setattr(policy, "apply_policy", wait_for_policy)
    worker = start_worker(lambda: fed.resolver.get_endpoint("resolve").process_request(
        {"sub": OTHER, "trust_anchor": [ANCHOR]}, with_ta_ec=True))
    try:
        assert paused.wait(timeout=10)
        old = fed.collector._statement_snapshot(INTERMEDIATE, ANCHOR)
        fed.collector._discard_statement(INTERMEDIATE, ANCHOR, old)
        assert (ANCHOR, INTERMEDIATE) not in fed.collector._statement_revisions
        chains, ec = collect_trust_chains(fed.resolver, LEAF)
        recreated = fed.collector._statement_snapshot(INTERMEDIATE, ANCHOR)
        assert recreated[:2] == old[:2] and recreated[2] != old[2]
        pending = fed.collector._pending_statements[(ANCHOR, INTERMEDIATE)]
    finally:
        release.set()
        result = finish_worker(worker)
    assert result["error"] == "invalid_metadata" and result["response_code"] == 400
    assert "response_args" not in result
    assert fed.collector._statement_snapshot(INTERMEDIATE, ANCHOR) == recreated
    assert fed.collector._pending_statements[(ANCHOR, INTERMEDIATE)] is pending
    accepted = verify_trust_chains(fed.resolver, chains, ec)
    assert len(accepted) == 1
    assert apply_policies(fed.resolver, accepted) == accepted
    assert not hasattr(accepted[0], "_statement_replacements")
    assert not getattr(accepted[0].chain, "_statement_context", {})
    assert "_statement_replacements" not in accepted[0].dump()
    success(fed, resolve(fed), tokens, "allowed")


@pytest.mark.parametrize("refresh_fraction", [None, 0.5])
def test_policy_rejection_preserves_unchanged_shared_statement(federation, refresh_fraction):
    fed = federation
    tokens = policy_subjects(fed, refresh_fraction)
    success(fed, resolve(fed), tokens, "allowed")
    url = ss_url(ANCHOR, INTERMEDIATE)
    count = len(fed.http.calls)
    reject_policy_subject(fed)
    assert url not in [call.request.url for call in fed.http.calls[count:]]
    fed.documents[url] = Timeout("shared ancestor temporarily unavailable")
    count = len(fed.http.calls)
    result = resolve(fed)
    assert "response_args" in result, result
    claims = success(fed, result, tokens, "allowed")
    assert len(fed.http.calls) == count
    assert type(claims["iat"]) is int
    assert claims["exp"] == fed.now + 1200.5
    assert fed.collector._statement_pair(INTERMEDIATE, ANCHOR) == (tokens[2], claims["exp"])
    returned = verify_trust_chains(fed.resolver, [list(reversed(claims["trust_chain"][:-1]))])
    assert len(returned) == 1
    assert apply_policies(fed.resolver, returned)[0].metadata == claims["metadata"]
    assert not hasattr(returned[0], "_statement_replacements")

    fed.clock[0] = refresh_time(fed, tokens[2])
    for failure in (Timeout("early refresh outage"), (503, {}, "temporarily unavailable")):
        fed.documents[url] = failure
        count = len(fed.http.calls)
        success(fed, resolve(fed), tokens, "allowed")
        assert [call.request.url for call in fed.http.calls[count:]] == [url]
        assert fed.collector._statement_pair(INTERMEDIATE, ANCHOR) == (tokens[2], claims["exp"])

    # B recovers only when its own EC reaches the configured refresh threshold.
    fed.clock[0] = refresh_time(fed, fed.documents[ec_url(OTHER)])
    corrected = fed.ec(OTHER, fed.now + 7200, name="allowed", hints=[INTERMEDIATE])
    count = len(fed.http.calls)
    recovered = fed.resolver.get_endpoint("resolve").process_request(
        {"sub": OTHER, "trust_anchor": [ANCHOR]}, with_ta_ec=True)
    other_tokens = [corrected, fed.documents[ss_url(INTERMEDIATE, OTHER)], *tokens[2:]]
    other_claims = success(fed, recovered, other_tokens, "allowed")
    assert other_claims["sub"] == OTHER
    assert other_claims["metadata"]["federation_entity"]["federation_fetch_endpoint"] == OTHER + "/fetch"
    assert [call.request.url for call in fed.http.calls[count:]] == [
        ec_url(OTHER), ss_url(INTERMEDIATE, OTHER), url]


@pytest.mark.parametrize("refresh_fraction", [None, 0.5])
def test_policy_rejection_preserves_identically_refreshed_shared_statement(federation, refresh_fraction):
    fed = federation
    tokens = policy_subjects(fed, refresh_fraction)
    success(fed, resolve(fed), tokens, "allowed")
    fed.clock[0] = refresh_time(fed, tokens[2])
    count = len(fed.http.calls)
    reject_policy_subject(fed)
    url = ss_url(ANCHOR, INTERMEDIATE)
    assert [call.request.url for call in fed.http.calls[count:]].count(url) == 1
    assert fed.collector._statement_pair(INTERMEDIATE, ANCHOR) == (tokens[2], fed.now + 1200.5)
    fed.documents[url] = Timeout("unchanged refreshed statement remains usable")
    count = len(fed.http.calls)
    success(fed, resolve(fed), tokens, "allowed")
    assert [call.request.url for call in fed.http.calls[count:]] == [url]


def test_incomplete_collection_preserves_statements_for_later_verification(federation):
    fed = federation
    tokens = policy_subjects(fed, None)
    tree, ec = fed.collector(LEAF, max_superiors=1)
    assert not verify_trust_chains(fed.resolver, tree2chains(tree), ec)
    lower = (tokens[1], factory(tokens[1]).jwt.payload()["exp"])
    assert fed.collector._statement_pair(LEAF, INTERMEDIATE) == lower
    assert fed.collector._pending_statements[(INTERMEDIATE, LEAF)][:2] == lower
    count = len(fed.http.calls)
    success(fed, resolve(fed), tokens, "allowed")
    assert [call.request.url for call in fed.http.calls[count:]] == [
        ec_url(ANCHOR), ss_url(ANCHOR, INTERMEDIATE)]
    assert not fed.collector._pending_statements


@pytest.mark.parametrize("refresh_fraction", [None, 0.5])
@pytest.mark.parametrize("fraction", [0, 0.5])
@pytest.mark.parametrize("offset", [-0.125, 0, 0.125])
@pytest.mark.parametrize("during_http", [False, True])
def test_policy_retained_shared_statement_obeys_deadline(
        federation, refresh_fraction, fraction, offset, during_http):
    fed = federation
    tokens = policy_subjects(fed, refresh_fraction, fraction)
    success(fed, resolve(fed), tokens, "allowed")
    reject_policy_subject(fed)
    expiry = factory(tokens[2]).jwt.payload()["exp"]
    fed.clock[0] = refresh_time(fed, tokens[2]) if during_http else expiry + offset

    def outage(request):
        if during_http:
            fed.clock[0] = expiry + offset
        raise Timeout("shared statement deadline during outage")

    url = ss_url(ANCHOR, INTERMEDIATE)
    fed.documents[url] = outage
    count = len(fed.http.calls)
    result = resolve(fed)
    assert [call.request.url for call in fed.http.calls[count:]] == [url]
    if offset < 0:
        assert success(fed, result, tokens, "allowed")["exp"] == expiry
    else:
        assert result["error"] == "invalid_trust_chain" and result["response_code"] == 400
        assert "response_args" not in result
        assert fed.collector._statement_pair(INTERMEDIATE, ANCHOR) == (None, None)


@pytest.mark.parametrize("refresh_fraction", [None, 0.5])
@pytest.mark.parametrize("change", ["policy", "expiry"])
def test_policy_rejection_preserves_newer_interleaved_statement(
        federation, monkeypatch, refresh_fraction, change):
    fed = federation
    tokens = policy_subjects(fed, refresh_fraction)
    success(fed, resolve(fed), tokens, "allowed")
    fed.clock[0] = refresh_time(fed, tokens[2])
    payload = factory(tokens[2]).jwt.payload()
    payload["publication"] = "outer replacement"
    replacement = sign_federation_jwt(
        SUBORDINATE_STATEMENT, payload, fed.signing, ANCHOR, "ES256", iat=payload["iat"])
    payload["publication"] = "independent replacement"
    payload["metadata_policy"]["federation_entity"]["organization_name"]["one_of"] = (
        ["original", "disallowed"] if change == "policy" else ["original", "allowed", "disallowed"])
    payload["exp"] = fed.now + (2400.5 if change == "policy" else 1000.5)
    newer = sign_federation_jwt(
        SUBORDINATE_STATEMENT, payload, fed.signing, ANCHOR, "ES256", iat=payload["iat"])
    url = ss_url(ANCHOR, INTERMEDIATE)
    fed.documents[url] = replacement
    policy = fed.resolver.function.policy
    apply = policy.apply_policy
    interleaved = []

    def interleave(metadata, rules, **kwargs):
        if metadata.get("organization_name") == "disallowed" and not interleaved:
            interleaved.append(True)
            fed.documents[url] = newer
            inner = fed.resolver.get_endpoint("resolve").process_request(
                {"sub": INTERMEDIATE, "trust_anchor": [ANCHOR]}, with_ta_ec=True)
            success(fed, inner, [fed.documents[ec_url(INTERMEDIATE)], newer, tokens[-1]])
        return apply(metadata, rules, **kwargs)

    monkeypatch.setattr(policy, "apply_policy", interleave)
    reject_policy_subject(fed)
    assert interleaved == [True]
    assert fed.collector._statement_pair(INTERMEDIATE, ANCHOR) == (newer, payload["exp"])
    other = fed.resolver.get_endpoint("resolve").process_request(
        {"sub": OTHER, "trust_anchor": [ANCHOR]}, with_ta_ec=True)
    other_tokens = [fed.documents[ec_url(OTHER)], fed.documents[ss_url(INTERMEDIATE, OTHER)],
                    newer, tokens[-1]]
    claims = success(fed, other, other_tokens, "disallowed")
    returned = verify_trust_chains(fed.resolver, [list(reversed(claims["trust_chain"][:-1]))])
    assert len(returned) == 1
    assert apply_policies(fed.resolver, returned)[0].metadata == claims["metadata"]
    if change == "policy":
        assert resolve(fed)["error"] == "invalid_metadata"
    else:
        assert claims["exp"] == payload["exp"]
        fed.clock[0] = payload["exp"]
        fed.documents[url] = Timeout("newer evidence has expired")
        assert resolve(fed)["error"] == "invalid_trust_chain"


@pytest.mark.parametrize("singular,restored_original", [(False, False), (True, False), (False, True)])
def test_deferred_policy_validation_retains_only_candidate_replacement_context(federation, singular,
                                                                             restored_original):
    fed = federation
    if restored_original:
        scenario = restoration_subjects(fed, None)
        tokens = scenario.tokens
        replacement = tokens[2]
        payload = factory(replacement).jwt.payload()
    else:
        tokens = policy_subjects(fed, None)
        success(fed, resolve(fed), tokens, "allowed")
        fed.clock[0] = refresh_time(fed, tokens[2])
        payload = factory(tokens[2]).jwt.payload()
        payload.update(exp=fed.now + 7200, publication="replacement")
        replacement = sign_federation_jwt(
            SUBORDINATE_STATEMENT, payload, fed.signing, ANCHOR, "ES256", iat=payload["iat"])
        fed.documents[ss_url(ANCHOR, INTERMEDIATE)] = replacement
    url = ss_url(ANCHOR, INTERMEDIATE)
    chains, ec = collect_trust_chains(fed.resolver, OTHER)
    candidates = (verify_trust_chain(fed.resolver, chains[0] + [ec]) if singular else
                  verify_trust_chains(fed.resolver, chains, ec))
    assert len(candidates) == 1
    assert not fed.collector._pending_statements
    if restored_original:
        assert scenario.visits == [url] * 2
        assert (ANCHOR, INTERMEDIATE) not in candidates[0]._statement_replacements
        assert candidates[0]._statement_restorations[(ANCHOR, INTERMEDIATE)] == (
            fed.collector._statement_snapshot(INTERMEDIATE, ANCHOR))
    else:
        assert candidates[0]._statement_replacements[(ANCHOR, INTERMEDIATE)][:2] == (replacement, payload["exp"])
    assert "_statement_replacements" not in candidates[0].dump()
    serialized = candidates[0].dump()
    assert type(serialized["chain"]) is list
    assert serialized["chain"] == list(candidates[0].chain)
    assert "_statement_" not in json.dumps(serialized)
    assert not getattr(candidates[0].chain, "_statement_context", {})
    assert fed.collector._statement_pair(INTERMEDIATE, ANCHOR) == (replacement, payload["exp"])
    # A separate Fetch remains pending while this candidate's policy is finalized.
    fed.collector._get_entity_statement(LEAF, ANCHOR, fetch_endpoint=ANCHOR + "/fetch")
    unrelated = fed.collector._statement_snapshot(LEAF, ANCHOR)
    pending = fed.collector._pending_statements[(ANCHOR, LEAF)]
    assert apply_policies(fed.resolver, candidates) == []
    assert candidates[0].err["metadata_policy"]["error"] == "invalid_metadata"
    assert not hasattr(candidates[0], "_statement_replacements")
    assert not hasattr(candidates[0], "_statement_restorations")
    assert fed.collector._statement_snapshot(LEAF, ANCHOR) == unrelated
    assert fed.collector._pending_statements[(ANCHOR, LEAF)] is pending
    assert fed.collector._statement_pair(INTERMEDIATE, ANCHOR) == (
        (replacement, payload["exp"]) if restored_original else (None, None))
    fed.documents[url] = Timeout("outage after deferred policy rejection")
    if restored_original:
        count = len(fed.http.calls)
        success(fed, resolve(fed), tokens, "allowed")
        assert [call.request.url for call in fed.http.calls[count:]] == [url]
    else:
        assert resolve(fed)["error"] == "invalid_trust_chain"
    fed.documents[url] = tokens[2]
    success(fed, resolve(fed), tokens, "allowed")


@pytest.mark.parametrize("missing", ["raw_ec", "ss_token", "ss_expiry", "mismatched_pair"])
@pytest.mark.parametrize("refresh_fraction", [None, 0.5])
def test_incomplete_cache_evidence_cannot_support_fallback(federation, missing, refresh_fraction):
    fed = federation
    fed.collector.refresh_fraction = refresh_fraction
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


@pytest.mark.parametrize("refresh_fraction", [None, 0.5])
def test_permanent_warm_failure_does_not_block_independent_candidate(federation, refresh_fraction):
    fed = federation
    fed.collector.refresh_fraction = refresh_fraction
    fed.resolver.add_trust_anchor(OTHER, fed.public[OTHER])
    fed.ec(LEAF, fed.now + 7200, hints=[ANCHOR, OTHER])
    fed.ec(ANCHOR, fed.now + 1200.5)
    fed.ec(OTHER, fed.now + 7200)
    fed.ss(OTHER, LEAF, fed.now + 5400)
    success(fed, resolve(fed, [ANCHOR, OTHER]), expected_tokens(fed))
    tokens = expected_tokens(fed)
    count = len(fed.http.calls)
    fed.clock[0] = fed.now + 600.5
    fed.documents[ec_url(ANCHOR)] = (403, {}, 'not an outage')
    success(fed, resolve(fed, [ANCHOR, OTHER]), tokens)
    assert len(fed.http.calls) == count + 1
    # The independent candidate still works once the retained anchor is unusable.
    fed.clock[0] = fed.now + 1200.5
    success(fed, resolve(fed, [ANCHOR, OTHER]), [
        fed.documents[ec_url(LEAF)], fed.documents[ss_url(OTHER, LEAF)], fed.documents[ec_url(OTHER)]])


@pytest.mark.parametrize("dependency", ["leaf", "anchor"])
@pytest.mark.parametrize("refresh_fraction", [None, 0.5])
def test_bootstrap_valid_replacement_still_needs_established_keys(federation, dependency, refresh_fraction):
    fed = federation
    fed.collector.refresh_fraction = refresh_fraction
    _, url, tokens = warm_refresh(fed, dependency)
    original = fed.documents[url]
    payload = factory(original).jwt.payload()
    payload['jwks'] = fed.public[OTHER]
    payload['exp'] = fed.now + 7200
    fed.documents[url] = JWS(json.dumps(payload), alg='ES256').sign_compact(
        fed.signing.get_signing_key('EC', issuer_id=OTHER),
        protected={'typ': ENTITY_CONFIGURATION.typ})
    count = len(fed.http.calls)
    success(fed, resolve(fed), tokens)
    assert len(fed.http.calls) == count + 1
    owner = LEAF if dependency == 'leaf' else ANCHOR
    assert fed.collector.config_cache[owner]['_jws'] == original
    # Direct verification still raises; embedded keys never establish trust.
    with pytest.raises(FederationJwtKeyResolutionError):
        verify_federation_jwt(ENTITY_CONFIGURATION, fed.documents[url], fed.resolver.keyjar)
    fed.documents[url] = Timeout('outage after trust failure')
    success(fed, resolve(fed), tokens)
    fed.documents[url] = original
    success(fed, resolve(fed), tokens)


@pytest.mark.parametrize('certified', [False, True])
@pytest.mark.parametrize('refresh_fraction', [None, 0.5])
@pytest.mark.parametrize('shared_hint', [False, True])
@pytest.mark.parametrize('limit', [None, 'requests', 'depth'])
def test_subject_ec_changed_hints(federation, certified, refresh_fraction, shared_hint, limit):
    fed = federation
    fed.collector.refresh_fraction = refresh_fraction
    fed.collector.allowed_delta = 450
    original = fed.ec(LEAF, fed.now + 900, name='accepted', issued_at=fed.now,
                      hints=[INTERMEDIATE, ANCHOR] if shared_hint else [ANCHOR])
    tokens = expected_tokens(fed)
    success(fed, resolve(fed), tokens, name='accepted')
    fed.clock[0] = fed.now + 450
    payload = factory(original).jwt.payload()
    payload.update(authority_hints=[INTERMEDIATE], iat=fed.clock[0], exp=fed.now + 1350)
    payload['metadata']['federation_entity']['organization_name'] = 'replacement'
    if not certified:
        payload['jwks'] = fed.public[OTHER]
    candidate = JWS(json.dumps(payload), alg='ES256').sign_compact(
        fed.signing.get_signing_key('EC', issuer_id=LEAF if certified else OTHER),
        protected={'typ': ENTITY_CONFIGURATION.typ})
    fed.documents[ec_url(LEAF)] = candidate
    fed.documents[ec_url(INTERMEDIATE)] = (404, {}, 'new route unavailable')
    if limit == 'requests':
        fed.collector.max_requests = 1
    elif limit == 'depth':
        fed.collector.max_superiors = 0
    count = len(fed.http.calls)
    result = resolve(fed)
    if limit is not None:
        assert [call.request.url for call in fed.http.calls[count:]] == [ec_url(LEAF)]
        assert result['error'] == 'invalid_trust_chain' and 'response_args' not in result
        assert fed.collector.config_cache[LEAF]['_jws'] == candidate
        return
    assert [call.request.url for call in fed.http.calls[count:]] == [ec_url(LEAF), ec_url(INTERMEDIATE)]
    if not certified:
        assert success(fed, result, tokens, name='accepted')['exp'] == fed.now + 900
        assert fed.collector.config_cache[LEAF]['_jws'] == original
        fed.documents[ec_url(LEAF)] = (404, {}, 'subject unavailable')
        success(fed, resolve(fed), tokens, name='accepted')
        fed.clock[0] = fed.now + 900
        assert 'response_args' not in resolve(fed)
    else:
        assert result['error'] == 'invalid_trust_chain' and 'response_args' not in result
        assert fed.collector.config_cache[LEAF]['_jws'] == candidate
        fed.ec(INTERMEDIATE, fed.now + 7200, hints=[ANCHOR])
        lower = fed.ss(INTERMEDIATE, LEAF, fed.now + 7200)
        upper = fed.ss(ANCHOR, INTERMEDIATE, fed.now + 7200)
        claims = success(fed, resolve(fed), [candidate, lower, upper, tokens[-1]], name='replacement')
        assert claims['exp'] == fed.now + 1350


@pytest.mark.parametrize('authorize', [False, True])
def test_subject_ec_survives_intermediate_discovery(federation, authorize):
    fed = federation
    fed.collector.refresh_fraction = 0.5
    old = fed.ec(INTERMEDIATE, fed.now + 900, hints=[ANCHOR], issued_at=fed.now,
                 name='subject-accepted')
    upper = fed.ss(ANCHOR, INTERMEDIATE, fed.now + 7200)
    endpoint = fed.resolver.get_endpoint('resolve')
    args = {'sub': INTERMEDIATE, 'trust_anchor': [ANCHOR]}
    tokens = [old, upper, fed.documents[ec_url(ANCHOR)]]
    success(fed, endpoint.process_request(args, with_ta_ec=True), tokens, name='subject-accepted')
    fed.clock[0] = fed.now + 450
    claims = factory(old).jwt.payload()
    claims.update(jwks=fed.public[OTHER], iat=fed.clock[0], exp=fed.now + 1350)
    claims['metadata']['federation_entity'].update(
        organization_name='discovery-update', federation_fetch_endpoint=INTERMEDIATE + '/new')
    new = JWS(json.dumps(claims), alg='ES256').sign_compact(
        fed.signing.get_signing_key('EC', issuer_id=OTHER), protected={'typ': ENTITY_CONFIGURATION.typ})
    fed.documents[ec_url(INTERMEDIATE)] = new
    fed.ec(LEAF, fed.now + 7200, hints=[INTERMEDIATE])
    lower = fed.ss(INTERMEDIATE, LEAF, fed.now + 7200, path='/new')
    count = len(fed.http.calls)
    success(fed, resolve(fed), [fed.documents[ec_url(LEAF)], lower, upper, tokens[-1]])
    assert ss_url(INTERMEDIATE, LEAF, '/new') in [call.request.url for call in fed.http.calls[count:]]
    assert fed.collector.config_cache[INTERMEDIATE]['_jws'] == new
    restored = endpoint.process_request(args, with_ta_ec=True)
    assert success(fed, restored, tokens, name='subject-accepted')['exp'] == fed.now + 900
    # Subject fallback must not withdraw the accepted discovery route.
    success(fed, resolve(fed), [fed.documents[ec_url(LEAF)], lower, upper, tokens[-1]])
    assert fed.collector.config_cache[INTERMEDIATE]['_jws'] == new
    if authorize:
        fed.public[INTERMEDIATE] = fed.public[OTHER]
        fed.signing.import_jwks(fed.public[OTHER], INTERMEDIATE)
        tokens[1] = fed.ss(ANCHOR, INTERMEDIATE, fed.now + 7200)
        fed.collector.refresh_fraction = None
        fed.collector.allowed_delta = 10000
        tokens[0] = new
        accepted = endpoint.process_request(args, with_ta_ec=True)
        assert success(fed, accepted, tokens, name='discovery-update')['exp'] == fed.now + 1350
        fed.documents[ec_url(INTERMEDIATE)] = (404, {}, 'outage after authorization')
    fed.clock[0] = fed.now + 900
    result = endpoint.process_request(args, with_ta_ec=True)
    if authorize:
        assert success(fed, result, tokens, name='discovery-update')['exp'] == fed.now + 1350
        claims.update(iat=fed.clock[0], exp=fed.now + 1000.5)
        shorter = JWS(json.dumps(claims), alg='ES256').sign_compact(
            fed.signing.get_signing_key('EC', issuer_id=OTHER), protected={'typ': ENTITY_CONFIGURATION.typ})
        fed.documents[ec_url(INTERMEDIATE)] = shorter
        tokens[0] = shorter
        assert success(fed, endpoint.process_request(args, with_ta_ec=True), tokens,
                       name='discovery-update')['exp'] == fed.now + 1000.5
        fed.documents[ec_url(INTERMEDIATE)] = (404, {}, 'shorter accepted EC removed')
        fed.clock[0] = fed.now + 1000.375
        success(fed, endpoint.process_request(args, with_ta_ec=True), tokens, name='discovery-update')
        fed.clock[0] = fed.now + 1000.5
        assert 'response_args' not in endpoint.process_request(args, with_ta_ec=True)
    else:
        assert result['error'] == 'invalid_trust_chain' and 'response_args' not in result


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


@pytest.mark.parametrize("dependency", ["leaf", "anchor", "subordinate"])
@pytest.mark.parametrize("lifetime", [1, 7 * 86400])
@pytest.mark.parametrize("fraction", [0.5, 0.75, 1])
def test_fraction_refresh_boundary_preserves_selected_resolve_artifacts(
        federation, dependency, lifetime, fraction):
    fed = federation
    issued_at, expiry, url = fraction_documents(fed, dependency, lifetime, fraction)
    original = expected_tokens(fed)
    success(fed, resolve(fed), original)
    assert len(fed.http.calls) == 3
    threshold = issued_at + fraction * lifetime
    fed.clock[0] = threshold - 0.125
    assert success(fed, resolve(fed), original)["exp"] == expiry
    assert len(fed.http.calls) == 3
    # Chain assembly must ignore the refresh threshold, not the hard deadline.
    assert fed.collector.get_chain([LEAF, ANCHOR], ANCHOR, with_ta_ec=True) == original
    fed.clock[0] = threshold
    if dependency == "subordinate":
        fresh = fed.ss(ANCHOR, LEAF, expiry + lifetime, issued_at=threshold)
        index = 1
    else:
        fresh = fed.ec(LEAF if dependency == "leaf" else ANCHOR,
                       expiry + lifetime, issued_at=threshold)
        index = 0 if dependency == "leaf" else -1
    selected = original[:]
    selected[index] = fresh
    assert success(fed, resolve(fed), selected)["exp"] == expiry + lifetime
    assert len(fed.http.calls) == 4
    assert fed.http.calls[-1].request.url == url


@pytest.mark.parametrize("dependency", ["leaf", "anchor", "subordinate"])
def test_fraction_due_replacement_and_same_jwt_do_not_reset_refresh(federation, dependency):
    fed = federation
    issued_at, expiry, url = fraction_documents(fed, dependency, 8, 0.5)
    success(fed, resolve(fed), expected_tokens(fed))
    fed.clock[0] = issued_at + 6
    if dependency == "subordinate":
        fresh = fed.ss(ANCHOR, LEAF, expiry + 0.5, issued_at=issued_at - 0.25)
    else:
        fresh = fed.ec(LEAF if dependency == "leaf" else ANCHOR,
                       expiry + 0.5, issued_at=issued_at - 0.25)
    tokens = expected_tokens(fed)
    for count in (4, 5, 6):
        # No internal retry loop, but later lookups can re-fetch this same JWT.
        assert success(fed, resolve(fed), tokens)["exp"] == expiry + 0.5
        assert len(fed.http.calls) == count
        assert fed.http.calls[-1].request.url == url
        assert fed.collector.too_old(factory(fresh).jwt.payload())
        assert fed.collector.get_chain([LEAF, ANCHOR], ANCHOR, with_ta_ec=True) == tokens
        fed.clock[0] += 0.125
    fed.clock[0] = expiry + 0.5
    result = resolve(fed)
    assert result["error"] == "invalid_trust_chain" and result["response_code"] == 400
    assert "response_args" not in result


@pytest.mark.parametrize("dependency", ["leaf", "anchor", "subordinate"])
@pytest.mark.parametrize("fraction", [0.5, 1])
@pytest.mark.parametrize("offset", [0, 0.125])
def test_fraction_outage_at_expiry_cannot_reuse_retained_statement(
        federation, dependency, fraction, offset):
    fed = federation
    _, expiry, url = fraction_documents(fed, dependency, 1, fraction)
    success(fed, resolve(fed), expected_tokens(fed))
    fed.documents[url] = Timeout("no replacement")
    fed.clock[0] = expiry + offset
    result = resolve(fed)
    assert result["error"] == ("server_error" if dependency == "leaf" else "invalid_trust_chain")
    assert result["response_code"] == (504 if dependency == "leaf" else 400)
    assert "response_args" not in result
    assert len(fed.http.calls) == 4


@pytest.mark.parametrize("dependency", ["leaf", "subordinate"])
@pytest.mark.parametrize("invalid", ["missing", "string", "boolean", "null", "nan", "infinite", "equal", "after"])
def test_fraction_invalid_cached_iat_never_establishes_reuse(federation, dependency, invalid):
    fed = federation
    _, _, url = fraction_documents(fed, dependency, 7200, 0.5)
    success(fed, resolve(fed), expected_tokens(fed))
    payload = factory(fed.documents[url]).jwt.payload()
    if invalid == "missing":
        del payload["iat"]
    else:
        payload["iat"] = {
            "string": str(payload["iat"]), "boolean": True, "null": None,
            "nan": float("nan"), "infinite": float("inf"),
            "equal": payload["exp"], "after": payload["exp"] + 1,
        }[invalid]
    owner = LEAF if dependency == "leaf" else ANCHOR
    profile = ENTITY_CONFIGURATION if dependency == "leaf" else SUBORDINATE_STATEMENT
    malformed = JWS(json.dumps(payload), alg="ES256").sign_compact(
        fed.signing.get_signing_key("EC", issuer_id=owner), protected={"typ": profile.typ})
    if dependency == "leaf":
        fed.collector.config_cache[LEAF] = dict(payload, _jws=malformed)
    else:
        fed.collector.entity_statement_cache[cache_key(ANCHOR, LEAF)] = malformed
    result = resolve(fed)
    assert result["error"] == "invalid_trust_chain" and result["response_code"] == 400
    assert "response_args" not in result
    assert len(fed.http.calls) == 3
