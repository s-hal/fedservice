"""Collection quotas through real signed chains and mocked HTTP boundaries."""

from contextvars import copy_context
from copy import deepcopy
import json
from types import SimpleNamespace
from unittest.mock import Mock

from cryptojwt.jws.jws import factory
import pytest
from requests.exceptions import ConnectionError
from requests.exceptions import Timeout

from fedservice import defaults
from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import tree2chains
from fedservice.entity.function import verify_self_signed_signature
from fedservice.entity.function import verify_trust_chains
from fedservice.entity.function.trust_chain_collector import TrustChainCollector
from fedservice.entity.function.trust_chain_collector import cache_key
from fedservice.entity.function.trust_chain_collector import time_key
from fedservice.entity.server.response import do_response
from fedservice.federation_jwt.jose import sign_federation_jwt
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.federation_jwt.registry import SUBORDINATE_STATEMENT
from fedservice.utils import make_federation_entity
from tests.test_55_entity_statement_cache import ANCHOR, INTERMEDIATE, LEAF, OTHER
from tests.test_55_entity_statement_cache import clock, ec_url, federation, ss_url
from tests.test_57_resolve_cache_refresh import expected_tokens, resolve, success


def configure(fed, construction="builder", **limits):
    """Use the actual constructor or builder, retaining the signed HTTP fixture."""
    if construction == "direct":
        collector = TrustChainCollector(fed.resolver.unit_get, {ANCHOR: fed.public[ANCHOR]},
                                        **limits)
        fed.resolver.function.trust_chain_collector = collector
    else:
        config = {"function": {"trust_chain_collector": limits}}
        before = deepcopy(config)
        fed.resolver = make_federation_entity(
            "https://resolver.example.org", signing_alg="ES256",
            key_config={"key_defs": [{"type": "EC", "crv": "P-256", "use": ["sig"]}]},
            trust_anchors={ANCHOR: fed.public[ANCHOR]},
            endpoints=["entity_configuration", "resolve"],
            services=["entity_configuration", "entity_statement"], init_kwargs=config)
        assert config == before
        collector = fed.resolver.function.trust_chain_collector
    fed.collector = collector
    return collector


def one_intermediate(fed):
    """Publish a leaf to IE to TA chain with comfortably current statements."""
    fed.ec(LEAF, fed.clock[0] + 7200, hints=[INTERMEDIATE])
    fed.ec(INTERMEDIATE, fed.clock[0] + 7200, hints=[ANCHOR])
    fed.ec(ANCHOR, fed.clock[0] + 7200)
    fed.ss(INTERMEDIATE, LEAF, fed.clock[0] + 5400)
    fed.ss(ANCHOR, INTERMEDIATE, fed.clock[0] + 5400)


def intermediate_tokens(fed):
    """Return exact received tokens in Resolve response order."""
    return [fed.documents[ec_url(LEAF)], fed.documents[ss_url(INTERMEDIATE, LEAF)],
            fed.documents[ss_url(ANCHOR, INTERMEDIATE)], fed.documents[ec_url(ANCHOR)]]


def rejected(fed, result):
    """Require the existing JSON invalid-chain response, never a signed success."""
    assert result["error"] == "invalid_trust_chain"
    assert result["response_code"] == 400
    assert result["error_description"]
    assert "response_args" not in result and "response_msg" not in result
    envelope = do_response(fed.resolver.get_endpoint("resolve"), **result)
    assert envelope["response_code"] == 400
    assert ("Content-type", "application/json") in envelope["http_headers"]
    assert json.loads(envelope["response"])["error"] == "invalid_trust_chain"


def collect_entry(fed, entry, **kwargs):
    """Verify the candidates from each public collector entry point."""
    token = fed.documents[ec_url(LEAF)]
    if entry == "call":
        tree, token = fed.collector(LEAF, stop_at=ANCHOR, **kwargs)
    elif entry == "tree":
        tree = fed.collector.collect_tree(
            LEAF, verify_self_signed_signature(token), stop_at=ANCHOR, **kwargs)
    else:
        tree = {INTERMEDIATE: fed.collector.collect_branch(
            LEAF, INTERMEDIATE, stop_at=ANCHOR, **kwargs)}
    return verify_trust_chains(fed.resolver, tree2chains(tree), token)


@pytest.mark.parametrize("construction", ["direct", "builder"])
@pytest.mark.parametrize("supplied", [False, True])
def test_default_limits_preserve_both_collection_paths(federation, construction, supplied):
    fed = federation
    one_intermediate(fed)
    configure(fed, construction)
    token = fed.documents[ec_url(LEAF)] if supplied else ""
    chains, token = collect_trust_chains(fed.resolver, LEAF, token, stop_at=ANCHOR)
    assert len(verify_trust_chains(fed.resolver, chains, token)) == 1
    assert len(fed.http.calls) == (4 if supplied else 5)


@pytest.mark.parametrize("construction", ["direct", "builder"])
def test_central_defaults_reach_constructor(federation, construction):
    collector = configure(federation, construction)
    assert collector.max_superiors == defaults.DEFAULT_MAX_SUPERIORS
    assert collector.max_requests == defaults.DEFAULT_MAX_REQUESTS
    configured = defaults.FEDERATION_ENTITY_FUNCTIONS["trust_chain_collector"]["kwargs"]
    assert configured["max_superiors"] == collector.max_superiors
    assert configured["max_requests"] == collector.max_requests


@pytest.mark.parametrize("construction", ["direct", "builder"])
@pytest.mark.parametrize("setting", ["max_superiors", "max_requests"])
@pytest.mark.parametrize("value", [None, True, False, "2", 2.0, -1, {}, []])
def test_invalid_limits_fail_before_http(federation, construction, setting, value):
    with pytest.raises(ValueError, match=setting):
        configure(federation, construction, **{setting: value})
    assert not federation.http.calls


@pytest.mark.parametrize("construction", ["direct", "builder"])
def test_zero_requests_is_invalid(federation, construction):
    with pytest.raises(ValueError, match="max_requests"):
        configure(federation, construction, max_requests=0)
    assert not federation.http.calls


def test_builder_limits_are_entity_local_and_do_not_mutate_defaults(federation):
    fed = federation
    one_intermediate(fed)
    before = deepcopy(defaults.DEFAULT_FEDERATION_ENTITY_FUNCTIONS)
    configure(fed, max_superiors=1, max_requests=3)
    restricted = SimpleNamespace(resolver=fed.resolver)
    configure(fed, max_superiors=2, max_requests=5)
    success(fed, resolve(fed), intermediate_tokens(fed))
    rejected(restricted, resolve(restricted))
    assert len(fed.http.calls) == 8
    assert defaults.DEFAULT_FEDERATION_ENTITY_FUNCTIONS == before


@pytest.mark.parametrize("construction", ["direct", "builder"])
@pytest.mark.parametrize("supplied", [False, True])
@pytest.mark.parametrize("limit", [0, 1, 2])
def test_configured_depth_boundaries(federation, construction, supplied, limit):
    fed = federation
    one_intermediate(fed)
    configure(fed, construction, max_superiors=limit)
    token = fed.documents[ec_url(LEAF)] if supplied else ""
    chains, token = collect_trust_chains(fed.resolver, LEAF, token, stop_at=ANCHOR)
    assert bool(verify_trust_chains(fed.resolver, chains, token)) is (limit == 2)
    assert len(fed.http.calls) == 2 * limit + (0 if supplied else 1)


@pytest.mark.parametrize("entry", ["call", "tree", "branch"])
def test_per_call_depth_override_is_local(federation, entry):
    fed = federation
    one_intermediate(fed)
    configure(fed, max_superiors=1)
    assert not collect_entry(fed, entry, max_superiors=0)
    assert not collect_entry(fed, entry, max_superiors=1)
    assert not collect_entry(fed, entry, max_superiors=None)
    assert len(collect_entry(fed, entry, max_superiors=2)) == 1
    assert not collect_entry(fed, entry)
    assert fed.collector.max_superiors == 1
    assert len(fed.http.calls) == (5 if entry == "call" else 4)


@pytest.mark.parametrize("entry", ["call", "tree", "branch"])
@pytest.mark.parametrize("value", [False, -1, "2", 1.5])
def test_invalid_per_call_depth_precedes_http(federation, entry, value):
    one_intermediate(federation)
    with pytest.raises(ValueError, match="max_superiors"):
        collect_entry(federation, entry, max_superiors=value)
    assert not federation.http.calls


def test_zero_depth_still_resolves_configured_anchor(federation):
    fed = federation
    configure(fed, max_superiors=0, max_requests=1)
    result = fed.resolver.get_endpoint("resolve").process_request(
        {"sub": ANCHOR, "trust_anchor": [ANCHOR]}, with_ta_ec=True)
    success(fed, result, [fed.documents[ec_url(ANCHOR)]])
    assert len(fed.http.calls) == 1


@pytest.mark.parametrize("budget", [4, 5])
def test_cold_request_boundary_and_retry(federation, budget):
    fed = federation
    one_intermediate(fed)
    configure(fed, max_requests=budget)
    result = resolve(fed)
    if budget == 5:
        success(fed, result, intermediate_tokens(fed))
    else:
        rejected(fed, result)
    assert len(fed.http.calls) == budget
    success(fed, resolve(fed), intermediate_tokens(fed))
    assert len(fed.http.calls) == 5


def test_last_permitted_call_can_complete_from_warm_cache(federation):
    fed = federation
    one_intermediate(fed)
    fed.ec(LEAF, fed.now + 1200.5, hints=[INTERMEDIATE])
    configure(fed, max_requests=1)
    for count in range(1, 5):
        rejected(fed, resolve(fed))
        assert len(fed.http.calls) == count
    success(fed, resolve(fed), intermediate_tokens(fed))
    success(fed, resolve(fed), intermediate_tokens(fed))
    assert len(fed.http.calls) == 5
    fed.clock[0] += 600.5
    fed.ec(LEAF, fed.now + 7200, hints=[INTERMEDIATE])
    # The subject refresh uses the entire allowance; the remaining chain is cached.
    success(fed, resolve(fed), intermediate_tokens(fed))
    assert len(fed.http.calls) == 6
    assert fed.http.calls[-1].request.url == ec_url(LEAF)


@pytest.mark.parametrize("depth,budget,calls", [(1, 5, 3), (2, 2, 2)])
def test_peer_claims_and_resolve_parameters_do_not_override_limits(federation, depth, budget, calls):
    fed = federation
    one_intermediate(fed)
    configure(fed, max_superiors=depth, max_requests=budget)
    payload = factory(fed.documents[ec_url(LEAF)]).jwt.payload()
    payload.update(max_superiors=50, max_requests=500)
    fed.documents[ec_url(LEAF)] = sign_federation_jwt(
        ENTITY_CONFIGURATION, payload, fed.signing, LEAF, "ES256", iat=payload["iat"])
    result = fed.resolver.get_endpoint("resolve").process_request({
        "sub": LEAF, "trust_anchor": [ANCHOR], "max_superiors": 50, "max_requests": 500})
    rejected(fed, result)
    assert len(fed.http.calls) == calls


@pytest.mark.parametrize("entry", ["tree", "branch"])
@pytest.mark.parametrize("budget", [3, 4])
def test_direct_supplied_entries_charge_only_actual_requests(federation, entry, budget):
    fed = federation
    one_intermediate(fed)
    configure(fed, max_requests=budget)
    assert bool(collect_entry(fed, entry)) is (budget == 4)
    assert len(fed.http.calls) == budget
    assert len(collect_entry(fed, entry)) == 1
    assert len(fed.http.calls) == 4


@pytest.mark.parametrize("failure", [None, Timeout("slow peer"), ConnectionError("unreachable")])
@pytest.mark.parametrize("width", [16, 32])
def test_false_hints_share_budget_and_stop_traversal(federation, monkeypatch, failure, width):
    fed = federation
    hints = ["https://missing{}.example.org".format(i) for i in range(width)]
    fed.ec(LEAF, fed.now + 7200, hints=hints)
    if failure:
        fed.documents.update({ec_url(hint): failure for hint in hints})
    configure(fed, max_requests=5)
    document = Mock(wraps=fed.collector.get_document)
    monkeypatch.setattr(fed.collector, "get_document", document)
    rejected(fed, resolve(fed))
    assert len(fed.http.calls) == 5
    assert [call.request.url for call in fed.http.calls] == [ec_url(LEAF)] + [
        ec_url(hint) for hint in hints[:4]]
    # Five actual calls and one denied attempt, not an attempt for every hint.
    assert document.call_count == 6
    rejected(fed, resolve(fed))
    assert len(fed.http.calls) == 10


def test_default_request_limit_is_enabled(federation):
    fed = federation
    budget = defaults.DEFAULT_MAX_REQUESTS
    fed.ec(LEAF, fed.now + 7200, hints=[
        "https://missing{}.example.org".format(i) for i in range(budget + 3)])
    rejected(fed, resolve(fed))
    assert len(fed.http.calls) == budget


def test_deeper_siblings_share_one_request_allowance(federation, monkeypatch):
    fed = federation
    one_intermediate(fed)
    fed.ec(INTERMEDIATE, fed.now + 7200, hints=[OTHER, ANCHOR])
    fed.ec(OTHER, fed.now + 7200, hints=["https://missing.example.org", ANCHOR])
    fed.ss(OTHER, INTERMEDIATE, fed.now + 5400)
    configure(fed, max_requests=5)
    document = Mock(wraps=fed.collector.get_document)
    monkeypatch.setattr(fed.collector, "get_document", document)
    rejected(fed, resolve(fed))
    assert len(fed.http.calls) == 5
    assert document.call_count == 6
    assert ec_url(ANCHOR) not in [call.request.url for call in fed.http.calls]


@pytest.mark.parametrize("budget", [1, 2, 3])
def test_tenant_fallback_charges_each_http_call(federation, budget):
    fed = federation
    configure(fed, max_requests=budget)
    tenant = OTHER + "/tenant"
    fed.public[tenant] = fed.public[OTHER]
    fed.signing.add_keys(tenant, fed.signing.get_signing_key("EC", issuer_id=OTHER))
    token = fed.ec(tenant, fed.now + 7200, hints=[ANCHOR])
    if budget == 1:
        result = fed.resolver.get_endpoint("resolve").process_request(
            {"sub": tenant, "trust_anchor": [ANCHOR]})
        rejected(fed, result)
    else:
        tree, received = fed.collector(tenant)
        assert received == token
        assert not verify_trust_chains(fed.resolver, tree2chains(tree), received)
    assert [call.request.url for call in fed.http.calls] == [
        ec_url(OTHER), ec_url(tenant), ec_url(ANCHOR)][:budget]


@pytest.mark.parametrize("budget", [2, 3])
def test_fetch_endpoint_recovery_uses_collection_budget(federation, budget):
    fed = federation
    configure(fed, max_requests=budget)
    fed.ec(ANCHOR, fed.now + 7200, path=None)
    fed.collector(ANCHOR)
    fed.ec(ANCHOR, fed.now + 7200)
    result = resolve(fed)
    if budget == 3:
        success(fed, result, expected_tokens(fed))
    else:
        rejected(fed, result)
    assert len(fed.http.calls) == budget + 1


def test_successful_collections_get_fresh_refresh_allowances(federation):
    fed = federation
    one_intermediate(fed)
    configure(fed, max_requests=5)
    success(fed, resolve(fed), intermediate_tokens(fed))
    fed.clock[0] += 7200
    one_intermediate(fed)
    success(fed, resolve(fed), intermediate_tokens(fed))
    assert len(fed.http.calls) == 10


@pytest.mark.parametrize("bad", ["depth", "malformed"])
def test_bad_candidate_leaves_allowance_for_independent_chain(federation, bad):
    fed = federation
    one_intermediate(fed)
    fed.ec(LEAF, fed.now + 7200, hints=[INTERMEDIATE, ANCHOR])
    if bad == "malformed":
        fed.documents[ec_url(INTERMEDIATE)] = "not a JWT"
    configure(fed, max_superiors=1, max_requests=5)
    success(fed, resolve(fed), expected_tokens(fed))
    assert len(fed.http.calls) == (5 if bad == "depth" else 4)


def test_completed_nested_candidate_survives_later_exhaustion(federation):
    fed = federation
    one_intermediate(fed)
    fed.ec(LEAF, fed.now + 7200, hints=[INTERMEDIATE, OTHER])
    fed.ec(INTERMEDIATE, fed.now + 7200, hints=[ANCHOR, "https://missing.example.org"])
    configure(fed, max_requests=5)
    success(fed, resolve(fed), intermediate_tokens(fed))
    assert len(fed.http.calls) == 5


def test_cycles_terminate_without_a_verified_result(federation):
    fed = federation
    one_intermediate(fed)
    fed.ec(INTERMEDIATE, fed.now + 7200, hints=[LEAF])
    fed.ss(LEAF, INTERMEDIATE, fed.now + 5400)
    rejected(fed, resolve(fed))
    assert len(fed.http.calls) == 4


def test_shared_ancestor_is_not_a_sibling_cycle(federation):
    fed = federation
    one_intermediate(fed)
    fed.ec(LEAF, fed.now + 7200, hints=[INTERMEDIATE, OTHER])
    fed.ec(OTHER, fed.now + 7200, hints=[ANCHOR])
    fed.ss(OTHER, LEAF, fed.now + 5400)
    fed.ss(ANCHOR, OTHER, fed.now + 5400)
    configure(fed, max_superiors=2, max_requests=8)
    chains, token = collect_trust_chains(fed.resolver, LEAF, stop_at=ANCHOR)
    verified = verify_trust_chains(fed.resolver, chains, token)
    assert {tuple(chain.iss_path) for chain in verified} == {
        (LEAF, INTERMEDIATE, ANCHOR), (LEAF, OTHER, ANCHOR)}
    assert len(fed.http.calls) == 8


@pytest.mark.parametrize("copied_context", [False, True])
def test_interleaved_independent_collections_do_not_share_budget(federation, copied_context):
    fed = federation
    configure(fed, max_requests=3)
    fed.ec(OTHER, fed.now + 7200, hints=[ANCHOR])
    fed.ss(ANCHOR, OTHER, fed.now + 5400)
    anchor_token = fed.documents[ec_url(ANCHOR)]
    results = []

    def interleave(request):
        # Restore the document before the inner operation fetches the same TA.
        fed.documents[ec_url(ANCHOR)] = anchor_token
        endpoint = fed.resolver.get_endpoint("resolve")
        arguments = {"sub": OTHER, "trust_anchor": [ANCHOR]}
        if copied_context:
            result = copy_context().run(endpoint.process_request, arguments, with_ta_ec=True)
        else:
            result = endpoint.process_request(arguments, with_ta_ec=True)
        results.append(result)
        return 200, {"Content-Type": ENTITY_CONFIGURATION.content_type}, anchor_token

    fed.documents[ec_url(ANCHOR)] = interleave
    result = resolve(fed)
    success(fed, result, expected_tokens(fed))
    success(fed, results[0], [fed.documents[ec_url(OTHER)],
                             fed.documents[ss_url(ANCHOR, OTHER)], anchor_token])
    assert len(fed.http.calls) == 6


def test_initial_transport_failure_does_not_leak_operation_state(federation):
    fed = federation
    configure(fed, max_requests=3)
    token = fed.documents[ec_url(LEAF)]
    fed.documents[ec_url(LEAF)] = Timeout("unavailable")
    assert resolve(fed)["response_code"] == 504
    fed.documents[ec_url(LEAF)] = token
    success(fed, resolve(fed), expected_tokens(fed))
    assert len(fed.http.calls) == 4


def refresh_retention_paths(fed, case, budget, short=True):
    """Publish ordered branches that revisit dependencies of the first candidate."""
    one_intermediate(fed)
    configure(fed, max_requests=budget)
    if case == "anchor":
        fed.ec(LEAF, fed.now + 7200, hints=[ANCHOR, INTERMEDIATE])
        if short:
            fed.ec(ANCHOR, fed.now + 100)
        urls = [ec_url(LEAF), ec_url(ANCHOR), ss_url(ANCHOR, LEAF),
                ec_url(INTERMEDIATE), ss_url(INTERMEDIATE, LEAF)]
        if short:
            urls.append(ec_url(ANCHOR))
        urls.append(ss_url(ANCHOR, INTERMEDIATE))
        tokens = expected_tokens(fed)
    else:
        fed.ec(LEAF, fed.now + 7200, hints=[INTERMEDIATE, OTHER])
        fed.ec(OTHER, fed.now + 7200, hints=[INTERMEDIATE])
        fed.ss(OTHER, LEAF, fed.now + 5400)
        fed.ss(INTERMEDIATE, OTHER, fed.now + 5400)
        if short:
            fed.ss(ANCHOR, INTERMEDIATE, fed.now + 100)
            if case == "ordering":
                fed.ec(ANCHOR, fed.now + 100)
        urls = [ec_url(LEAF), ec_url(INTERMEDIATE), ss_url(INTERMEDIATE, LEAF),
                ec_url(ANCHOR), ss_url(ANCHOR, INTERMEDIATE), ec_url(OTHER),
                ss_url(OTHER, LEAF), ss_url(INTERMEDIATE, OTHER)]
        if short:
            if case == "ordering":
                urls.append(ec_url(ANCHOR))
            urls.append(ss_url(ANCHOR, INTERMEDIATE))
        tokens = intermediate_tokens(fed)
    return tokens, urls[:budget]


@pytest.mark.parametrize("case,budget,short", [
    ("anchor", 5, True), ("statement", 8, True), ("ordering", 9, True),
    ("anchor", 5, False), ("statement", 8, False), ("ordering", 9, False),
    ("anchor", 7, True), ("statement", 9, True), ("ordering", 10, True),
    ("ordering", 8, True),
])
def test_completed_candidate_retains_dependencies_when_refresh_is_denied(
        federation, case, budget, short):
    fed = federation
    tokens, urls = refresh_retention_paths(fed, case, budget, short)
    claims = success(fed, resolve(fed), tokens)
    assert claims["exp"] == fed.now + (100 if short else 5400)
    assert [call.request.url for call in fed.http.calls] == urls


@pytest.mark.parametrize("case,budget", [("anchor", 5), ("statement", 8), ("ordering", 9)])
def test_retained_candidate_cannot_outlive_its_dependencies(federation, case, budget):
    fed = federation
    _, urls = refresh_retention_paths(fed, case, budget)
    last_url = urls[-1]
    token = fed.documents[last_url]

    def expire_on_last_call(request):
        if len(fed.http.calls) == budget - 1:
            fed.clock[0] = fed.now + 100
        return 200, {"Content-Type": ENTITY_CONFIGURATION.content_type}, token

    fed.documents[last_url] = expire_on_last_call
    rejected(fed, resolve(fed))
    assert [call.request.url for call in fed.http.calls] == urls


@pytest.mark.parametrize("case,budget,failure", [
    ("anchor", 6, Timeout("refresh timed out")),
    ("anchor", 6, "not a JWT"),
    ("statement", 9, (503, {}, "refresh unavailable")),
    ("statement", 9, "not a JWT"),
    ("ordering", 9, Timeout("refresh timed out")),
])
def test_actual_refresh_failure_does_not_retain_old_candidate(federation, case, budget, failure):
    fed = federation
    _, urls = refresh_retention_paths(fed, case, budget)
    refresh_url = urls[-1]
    token = fed.documents[refresh_url]
    visits = []

    def fail_refresh(request):
        visits.append(request.url)
        if len(visits) == 1:
            return 200, {"Content-Type": ENTITY_CONFIGURATION.content_type}, token
        if isinstance(failure, Exception):
            raise failure
        if isinstance(failure, tuple):
            return failure
        return 200, {"Content-Type": ENTITY_CONFIGURATION.content_type}, failure

    fed.documents[refresh_url] = fail_refresh
    rejected(fed, resolve(fed))
    assert len(visits) == 2
    assert [call.request.url for call in fed.http.calls] == urls


def test_quota_interruption_preserves_newer_interleaved_statement(federation):
    fed = federation
    tokens, urls = refresh_retention_paths(fed, "ordering", 9)
    anchor_token = fed.documents[ec_url(ANCHOR)]
    old_statement = fed.documents[ss_url(ANCHOR, INTERMEDIATE)]
    visits = []
    refreshed = []

    def interleave_refresh(request):
        visits.append(request.url)
        if len(visits) == 2:
            fed.documents[ec_url(ANCHOR)] = anchor_token
            payload = factory(old_statement).jwt.payload()
            payload["publication"] = "newer"
            new_statement = sign_federation_jwt(
                SUBORDINATE_STATEMENT, payload, fed.signing, ANCHOR, "ES256", iat=payload["iat"])
            fed.documents[ss_url(ANCHOR, INTERMEDIATE)] = new_statement
            inner = fed.resolver.get_endpoint("resolve").process_request(
                {"sub": INTERMEDIATE, "trust_anchor": [ANCHOR]}, with_ta_ec=True)
            success(fed, inner, [fed.documents[ec_url(INTERMEDIATE)], new_statement, anchor_token])
            refreshed.append(new_statement)
        return 200, {"Content-Type": ENTITY_CONFIGURATION.content_type}, anchor_token

    fed.documents[ec_url(ANCHOR)] = interleave_refresh
    result = resolve(fed)
    assert len(refreshed) == 1 and refreshed[0] != old_statement
    tokens[2] = refreshed[0]
    success(fed, result, tokens)
    assert fed.collector.entity_statement_cache[cache_key(ANCHOR, INTERMEDIATE)] == refreshed[0]
    assert fed.collector.entity_statement_cache[time_key(ANCHOR, INTERMEDIATE)] == fed.now + 100
    # The outer operation uses nine calls; the independent inner refresh uses two.
    assert [call.request.url for call in fed.http.calls] == (
        urls[:-1] + [ec_url(ANCHOR), ss_url(ANCHOR, INTERMEDIATE)] + urls[-1:])


def test_failed_ec_refresh_then_denied_fallback_does_not_restore_statement(federation):
    fed = federation
    one_intermediate(fed)
    configure(fed, max_requests=9)
    tenant = INTERMEDIATE + "/tenant"
    fed.public[tenant] = fed.public[INTERMEDIATE]
    fed.signing.add_keys(tenant, fed.signing.get_signing_key("EC", issuer_id=INTERMEDIATE))
    fed.ec(LEAF, fed.now + 7200, hints=[tenant, OTHER])
    tenant_token = fed.ec(tenant, fed.now + 100, hints=[ANCHOR])
    fed.ec(OTHER, fed.now + 7200, hints=[LEAF])
    fed.ss(tenant, LEAF, fed.now + 100)
    fed.ss(ANCHOR, tenant, fed.now + 5400)
    fed.ss(OTHER, LEAF, fed.now + 5400)
    fed.ss(LEAF, OTHER, fed.now + 5400)
    visits = []

    def primary_location(request):
        visits.append(request.url)
        if len(visits) == 1:
            return 200, {"Content-Type": ENTITY_CONFIGURATION.content_type}, tenant_token
        return 404, {}, "refresh location unavailable"

    fed.documents[ec_url(INTERMEDIATE)] = primary_location
    rejected(fed, resolve(fed))
    assert [call.request.url for call in fed.http.calls] == [
        ec_url(LEAF), ec_url(INTERMEDIATE), ss_url(tenant, LEAF),
        ec_url(ANCHOR), ss_url(ANCHOR, tenant), ec_url(OTHER),
        ss_url(OTHER, LEAF), ss_url(LEAF, OTHER), ec_url(INTERMEDIATE)]
    assert fed.collector.config_cache[tenant] is None
    assert fed.collector.entity_statement_cache[cache_key(tenant, LEAF)] is None
    assert fed.collector.entity_statement_cache[time_key(tenant, LEAF)] is None
