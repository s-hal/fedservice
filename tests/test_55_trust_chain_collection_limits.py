"""Collection quotas through real signed chains and mocked HTTP boundaries."""

from contextvars import copy_context
from copy import deepcopy
import json
from threading import Event
from types import SimpleNamespace
from unittest.mock import Mock

from cryptojwt.jwk.ec import new_ec_key
from cryptojwt.jws.jws import JWS
from cryptojwt.jws.jws import factory
import pytest
from requests.exceptions import ConnectionError
from requests.exceptions import Timeout

from fedservice import defaults
from fedservice.entity.function import apply_policies
from fedservice.entity.function import collect_trust_chains
from fedservice.entity.function import tree2chains
from fedservice.entity.function import verify_self_signed_signature
from fedservice.entity.function import verify_trust_chains
from fedservice.entity.function.trust_chain_collector import TrustChainCollector
from fedservice.entity.function.trust_chain_collector import cache_key
from fedservice.entity.function.trust_chain_collector import time_key
from fedservice.entity.server.response import do_response
from fedservice.federation_jwt.jose import sign_federation_jwt
from fedservice.federation_jwt.jose import verify_federation_jwt
from fedservice.federation_jwt.registry import ENTITY_CONFIGURATION
from fedservice.federation_jwt.registry import RESOLVE_RESPONSE
from fedservice.federation_jwt.registry import SUBORDINATE_STATEMENT
from fedservice.utils import make_federation_entity
from tests.test_55_entity_statement_cache import ANCHOR, INTERMEDIATE, LEAF, OTHER
from tests.test_55_entity_statement_cache import clock, ec_url, federation, ss_url
from tests.test_55_entity_statement_cache import finish_worker, start_worker
from tests.test_55_entity_statement_subject_binding import corrupt_signature
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


def sibling_refresh_paths(fed, refresh_fraction, changed_first=False):
    """Warm two paths sharing an SS, then return a fresh path-limiting replacement."""
    tokens, _ = refresh_retention_paths(fed, "statement", 100, short=False)
    fed.collector.refresh_fraction = refresh_fraction
    tokens[2] = fed.ss(ANCHOR, INTERMEDIATE, fed.now + 1200.5)
    success(fed, resolve(fed), tokens)
    payload = factory(tokens[2]).jwt.payload()
    expiry = payload["exp"]
    fed.clock[0] = (expiry - fed.collector.allowed_delta if refresh_fraction is None else
                    payload["iat"] + refresh_fraction * (expiry - payload["iat"]))
    if changed_first:
        original = tokens[2]
        payload["publication"] = "first refreshed SS"
        tokens[2] = sign_federation_jwt(
            SUBORDINATE_STATEMENT, payload, fed.signing, ANCHOR, "ES256", iat=payload["iat"])
        assert tokens[2] != original
        assert fed.collector._statement_pair(INTERMEDIATE, ANCHOR) == (original, expiry)
    assert fed.clock[0] < expiry and fed.collector.too_old(payload)
    payload.update(exp=fed.now + 7200, constraints={"max_path_length": 1})
    replacement = sign_federation_jwt(
        SUBORDINATE_STATEMENT, payload, fed.signing, ANCHOR, "ES256", iat=payload["iat"])
    return tokens, replacement, expiry


def policy_sibling_refresh_paths(fed, refresh_fraction, second_reply="original",
                                rejected_paths=(True, False), intermediate_name="original",
                                finish_at=None):
    """Warm three paths, then publish policy- and constraint-distinct shared SSs."""
    tokens, _ = refresh_retention_paths(fed, "statement", 100, short=False)
    third = "https://third.example.org"
    key = new_ec_key(crv="P-256", use="sig")
    fed.signing.import_jwks({"keys": [key.serialize(private=True)]}, third)
    fed.public[third] = {"keys": [key.serialize(private=False)]}
    tokens[0] = fed.ec(LEAF, fed.now + 7200, hints=[INTERMEDIATE, OTHER, third])
    fed.ec(INTERMEDIATE, fed.now + 7200, name=intermediate_name, hints=[ANCHOR])
    fed.ec(third, fed.now + 7200, hints=[INTERMEDIATE])
    fed.ss(third, LEAF, fed.now + 5400)
    fed.ss(INTERMEDIATE, third, fed.now + 5400)
    fed.collector.refresh_fraction = refresh_fraction
    original = tokens[2] = fed.ss(ANCHOR, INTERMEDIATE, fed.now + 1200.5)
    success(fed, resolve(fed), tokens)
    payload = factory(original).jwt.payload()
    fed.clock[0] = (payload["exp"] - fed.collector.allowed_delta if refresh_fraction is None else
                    payload["iat"] + refresh_fraction * (payload["exp"] - payload["iat"]))
    assert fed.clock[0] < payload["exp"] and fed.collector.too_old(payload)
    replies = []
    for index in range(3):
        changed = deepcopy(payload)
        if index == 0 or index == 2 or second_reply != "original":
            changed["publication"] = "shared visit {}".format(index + 1)
        if index < 2 and rejected_paths[index]:
            changed["metadata_policy"] = {"federation_entity": {
                "organization_name": {"one_of": ["not the original name"]}}}
        if index == 1 and second_reply == "earlier":
            changed["exp"] = fed.now + 1100.25
            assert fed.clock[0] < changed["exp"] and fed.collector.too_old(changed)
        if index == 2:
            changed.update(exp=fed.now + 7200, constraints={"max_path_length": 1})
        replies.append(original if changed == payload else sign_federation_jwt(
            SUBORDINATE_STATEMENT, changed, fed.signing, ANCHOR, "ES256", iat=changed["iat"]))
    tokens[2] = replies[0]
    scenario = SimpleNamespace(
        first=tokens, second=[tokens[0], fed.documents[ss_url(OTHER, LEAF)],
                              fed.documents[ss_url(INTERMEDIATE, OTHER)], replies[1], tokens[-1]],
        last=replies[2], original=original, visits=[], start=len(fed.http.calls),
        url=ss_url(ANCHOR, INTERMEDIATE))

    def refresh(request):
        scenario.visits.append(request.url)
        assert len(scenario.visits) <= 3, "unexpected repair retrieval"
        if len(scenario.visits) == 3 and finish_at is not None:
            fed.clock[0] = finish_at
        return 200, {"Content-Type": SUBORDINATE_STATEMENT.content_type}, replies[len(scenario.visits) - 1]

    fed.documents[scenario.url] = refresh
    return scenario


@pytest.mark.parametrize("refresh_fraction", [None, 0.5])
@pytest.mark.parametrize("second_reply", ["original", "changed"])
@pytest.mark.parametrize("reject_first", [True, False])
def test_policy_accepted_sibling_reconciles_tentative_restoration(federation, monkeypatch,
                                                                refresh_fraction, second_reply, reject_first):
    fed = federation
    scenario = policy_sibling_refresh_paths(fed, refresh_fraction, second_reply,
                                           rejected_paths=(reject_first, False))
    assert scenario.first[-2] != scenario.original
    assert (scenario.second[-2] == scenario.original) is (second_reply == "original")
    finish = fed.collector.finish_policy_validation
    verified = fed.collector.finish_statement_verification
    processed = []

    def observe_verification(chains, accepted, constraint_rejections=()):
        assert len(chains) == 3 and len(accepted) == 2
        assert len(constraint_rejections) == 1
        assert scenario.last in constraint_rejections[0]
        verified(chains, accepted, constraint_rejections)

    def observe(chains, accepted):
        assert len(chains) == 2
        assert accepted == (chains[1:] if reject_first else chains)
        if reject_first:
            assert chains[0].err["metadata_policy"]["error"] == "invalid_metadata"
        assert chains[1].iss_path == [LEAF, OTHER, INTERMEDIATE, ANCHOR]
        assert fed.collector._statement_pair(INTERMEDIATE, ANCHOR) == (
            scenario.first[2], fed.now + 1200.5)
        for chain in chains:
            assert not getattr(chain.chain, "_statement_context", {})
            assert "_statement_" not in json.dumps(chain.dump())
        finish(chains, accepted)
        assert all(not hasattr(chain, attr) for chain in chains
                   for attr in ("_statement_restorations", "_statement_replacements"))
        processed.extend(chains)

    with monkeypatch.context() as patch:
        patch.setattr(fed.collector, "finish_statement_verification", observe_verification)
        patch.setattr(fed.collector, "finish_policy_validation", observe)
        result = resolve(fed)
    assert len(processed) == 2
    assert scenario.visits == [scenario.url] * 3
    assert [call.request.url for call in fed.http.calls[scenario.start:]] == scenario.visits
    assert "response_args" in result, result
    selected = scenario.second if reject_first else scenario.first
    claims = success(fed, result, selected)
    assert type(claims["iat"]) is int
    assert claims["exp"] == fed.now + 1200.5
    assert "_statement_" not in json.dumps(factory(result["response_args"]).jwt.payload())
    assert fed.collector._statement_pair(INTERMEDIATE, ANCHOR) == (selected[-2], claims["exp"])
    returned = verify_trust_chains(fed.resolver, [list(reversed(claims["trust_chain"][:-1]))])
    assert len(returned) == 1
    assert apply_policies(fed.resolver, returned)[0].metadata == claims["metadata"]


@pytest.mark.parametrize("refresh_fraction", [None, 0.5])
@pytest.mark.parametrize("offset", [None, -0.125, 0, 0.125])
def test_policy_sibling_reconciliation_obeys_selected_expiry(federation, refresh_fraction, offset):
    fed = federation
    expiry = fed.now + 1100.25
    scenario = policy_sibling_refresh_paths(
        fed, refresh_fraction, "earlier", finish_at=None if offset is None else expiry + offset)
    result = resolve(fed)
    assert scenario.visits == [scenario.url] * 3
    assert [call.request.url for call in fed.http.calls[scenario.start:]] == scenario.visits
    if offset is None or offset < 0:
        claims = success(fed, result, scenario.second)
        assert type(claims["iat"]) is int and claims["exp"] == expiry
        assert fed.collector._statement_pair(INTERMEDIATE, ANCHOR) == (scenario.second[-2], expiry)
    else:
        assert result["response_code"] == 400
        assert result["error"] in ("invalid_metadata", "invalid_trust_chain")
        assert "response_args" not in result and "response_msg" not in result
        assert fed.collector._statement_pair(INTERMEDIATE, ANCHOR) == (None, None)


@pytest.mark.parametrize("refresh_fraction", [None, 0.5])
def test_policy_sibling_rejection_requires_valid_publication_to_recover(federation, monkeypatch,
                                                                      refresh_fraction):
    fed = federation
    scenario = policy_sibling_refresh_paths(fed, refresh_fraction, "changed", rejected_paths=(True, True))
    finish = fed.collector.finish_policy_validation
    processed = []

    def observe(chains, accepted):
        assert len(chains) == 2 and not accepted
        assert all(chain.err["metadata_policy"]["error"] == "invalid_metadata" for chain in chains)
        finish(chains, accepted)
        processed.extend(chains)

    with monkeypatch.context() as patch:
        patch.setattr(fed.collector, "finish_policy_validation", observe)
        result = resolve(fed)
    assert len(processed) == 2 and scenario.visits == [scenario.url] * 3
    assert result["error"] == "invalid_metadata" and result["response_code"] == 400
    assert "response_args" not in result and "response_msg" not in result
    assert fed.collector._statement_pair(INTERMEDIATE, ANCHOR) == (None, None)
    assert (ANCHOR, INTERMEDIATE) not in fed.collector._pending_statements
    fed.documents[scenario.url] = Timeout("outage after all policy candidates rejected")
    rejected(fed, resolve(fed))
    assert fed.collector._statement_pair(INTERMEDIATE, ANCHOR) == (None, None)
    fed.documents[scenario.url] = scenario.last
    recovered = scenario.first[:]
    recovered[-2] = scenario.last
    claims = success(fed, resolve(fed), recovered)
    returned = verify_trust_chains(fed.resolver, [list(reversed(claims["trust_chain"][:-1]))])
    assert len(returned) == 1
    assert apply_policies(fed.resolver, returned)[0].metadata == claims["metadata"]


@pytest.mark.parametrize("refresh_fraction", [None, 0.5])
@pytest.mark.parametrize("second_reply", ["original", "changed"])
def test_deferred_policy_reconciles_only_owned_tentative_restoration(federation, refresh_fraction,
                                                                  second_reply):
    fed = federation
    scenario = policy_sibling_refresh_paths(fed, refresh_fraction, second_reply)
    chains, ec = collect_trust_chains(fed.resolver, LEAF)
    candidates = verify_trust_chains(fed.resolver, chains, ec)
    assert len(candidates) == 2
    state = fed.collector._statement_snapshot(INTERMEDIATE, ANCHOR)
    assert state[:2] == (scenario.first[-2], fed.now + 1200.5)
    for candidate in candidates:
        assert candidate._statement_restorations[(ANCHOR, INTERMEDIATE)] == state
        assert "_statement_" not in json.dumps(candidate.dump())
        assert not getattr(candidate.chain, "_statement_context", {})
    assert not fed.collector._pending_statements
    assert apply_policies(fed.resolver, candidates) == candidates[1:]
    assert fed.collector._statement_pair(INTERMEDIATE, ANCHOR) == (scenario.second[-2], state[1])
    assert all(not hasattr(candidate, attr) for candidate in candidates
               for attr in ("_statement_restorations", "_statement_replacements"))
    assert [call.request.url for call in fed.http.calls[scenario.start:]] == [scenario.url] * 3


@pytest.mark.parametrize("refresh_fraction", [None, 0.5])
@pytest.mark.parametrize("intervention", ["publication", "accepted-identical", "recreated", "deleted"])
def test_policy_sibling_reconciliation_preserves_independent_revision(federation, monkeypatch,
                                                                    refresh_fraction, intervention):
    fed = federation
    scenario = policy_sibling_refresh_paths(fed, refresh_fraction, "changed",
                                           intermediate_name="not the original name")
    paused, release = Event(), Event()
    finish = fed.collector.finish_policy_validation
    independent_policy = []
    processed = []

    def pause_outer(chains, accepted):
        if chains and chains[0].verified_chain[-1]["sub"] == LEAF:
            assert len(chains) == 2 and accepted == chains[1:]
            assert chains[0]._statement_restorations[(ANCHOR, INTERMEDIATE)] == (
                fed.collector._statement_snapshot(INTERMEDIATE, ANCHOR))
            paused.set()
            assert release.wait(timeout=10), "outer finalization gate was not released"
            finish(chains, accepted)
            processed.extend(chains)
        else:
            before = fed.collector._statement_snapshot(INTERMEDIATE, ANCHOR)
            finish(chains, accepted)
            after = fed.collector._statement_snapshot(INTERMEDIATE, ANCHOR)
            assert before[:2] == after[:2] and before[2] != after[2]
            independent_policy.extend(accepted)

    with monkeypatch.context() as patch:
        patch.setattr(fed.collector, "finish_policy_validation", pause_outer)
        outer = start_worker(lambda: resolve(fed))
        independent = None
        try:
            assert paused.wait(timeout=10), "outer request did not reach policy finalization"
            assert scenario.visits == [scenario.url] * 3
            old = fed.collector._statement_snapshot(INTERMEDIATE, ANCHOR)
            if intervention in ("recreated", "deleted"):
                fed.collector._discard_statement(INTERMEDIATE, ANCHOR, old)
            if intervention != "deleted":
                token = scenario.last if intervention == "publication" else scenario.first[-2]
                fed.documents[scenario.url] = token
                if intervention == "accepted-identical":
                    independent = start_worker(lambda: fed.resolver.get_endpoint("resolve").process_request(
                        {"sub": INTERMEDIATE, "trust_anchor": [ANCHOR]}, with_ta_ec=True))
                    success(fed, finish_worker(independent),
                            [fed.documents[ec_url(INTERMEDIATE)], token, scenario.first[-1]],
                            "not the original name")
                    assert len(independent_policy) == 1
                else:
                    independent = start_worker(lambda: collect_trust_chains(fed.resolver, INTERMEDIATE))
                    independent_chains, independent_ec = finish_worker(independent)
                current = fed.collector._statement_snapshot(INTERMEDIATE, ANCHOR)
                assert current[0] == token and current[2] != old[2]
            else:
                current = fed.collector._statement_snapshot(INTERMEDIATE, ANCHOR)
            pending = fed.collector._pending_statements.get((ANCHOR, INTERMEDIATE))
            if intervention in ("publication", "recreated"):
                assert pending is not None
            assert outer[0].is_alive()
        finally:
            release.set()
            try:
                result = finish_worker(outer)
            finally:
                if independent is not None:
                    finish_worker(independent)
    assert fed.collector._statement_snapshot(INTERMEDIATE, ANCHOR) == current
    assert fed.collector._pending_statements.get((ANCHOR, INTERMEDIATE)) is pending
    assert all(not hasattr(chain, attr) for chain in processed
               for attr in ("_statement_restorations", "_statement_replacements"))
    if intervention == "deleted":
        rejected(fed, result)
        assert current[:2] == (None, None)
    else:
        success(fed, result, scenario.second)
        if intervention != "accepted-identical":
            verified = verify_trust_chains(fed.resolver, independent_chains, independent_ec)
            assert len(verified) == 1
            assert apply_policies(fed.resolver, verified) == verified


@pytest.mark.parametrize("refresh_fraction", [None, 0.5])
@pytest.mark.parametrize("changed_first", [False, True], ids=["original-first", "changed-first"])
def test_rejected_sibling_refresh_preserves_accepted_candidate(federation, refresh_fraction, changed_first):
    fed = federation
    tokens, replacement, expiry = sibling_refresh_paths(fed, refresh_fraction, changed_first)
    url = ss_url(ANCHOR, INTERMEDIATE)
    start = len(fed.http.calls)
    visits = []

    def refresh(request):
        visits.append(request.url)
        return 200, {"Content-Type": SUBORDINATE_STATEMENT.content_type}, (
            tokens[2] if len(visits) == 1 else replacement)

    fed.documents[url] = refresh
    result = resolve(fed)
    assert visits == [url, url]
    assert [call.request.url for call in fed.http.calls[start:]] == visits
    assert "response_args" in result, result
    claims = success(fed, result, tokens)
    assert type(claims["iat"]) is int
    assert claims["exp"] == expiry
    returned = verify_trust_chains(fed.resolver, [list(reversed(claims["trust_chain"][:-1]))])
    assert len(returned) == 1
    assert apply_policies(fed.resolver, returned)[0].metadata == claims["metadata"]
    assert fed.collector._statement_pair(INTERMEDIATE, ANCHOR) == (tokens[2], expiry)
    # The real verifier accepts S2 on the short path, but not the longer sibling.
    verifier = fed.resolver.function.verifier
    assert len(verifier([replacement, tokens[1], tokens[0]])) == 1
    assert not verifier([replacement, fed.documents[ss_url(INTERMEDIATE, OTHER)],
                         fed.documents[ss_url(OTHER, LEAF)], tokens[0]])
    fed.documents[url] = replacement
    refreshed = tokens[:]
    refreshed[2] = replacement
    success(fed, resolve(fed), refreshed)
    assert len(fed.http.calls) == start + 3


@pytest.mark.parametrize("refresh_fraction", [None, 0.5])
@pytest.mark.parametrize("policy_rejected", [False, True])
def test_restored_sibling_statement_completes_policy_validation(federation, monkeypatch,
                                                              refresh_fraction, policy_rejected):
    fed = federation
    tokens, replacement, expiry = sibling_refresh_paths(fed, refresh_fraction, changed_first=True)
    if policy_rejected:
        payload = factory(tokens[2]).jwt.payload()
        payload["metadata_policy"] = {"federation_entity": {
            "organization_name": {"one_of": ["not the original name"]}}}
        tokens[2] = sign_federation_jwt(
            SUBORDINATE_STATEMENT, payload, fed.signing, ANCHOR, "ES256", iat=payload["iat"])
    url = ss_url(ANCHOR, INTERMEDIATE)
    visits = []

    def refresh(request):
        visits.append(request.url)
        return 200, {"Content-Type": SUBORDINATE_STATEMENT.content_type}, (
            tokens[2] if len(visits) == 1 else replacement)

    fed.documents[url] = refresh
    finish = fed.collector.finish_policy_validation
    processed = []

    def check_policy_handoff(chains, accepted):
        assert len(chains) == 1
        assert accepted == ([] if policy_rejected else chains)
        assert fed.collector._statement_pair(INTERMEDIATE, ANCHOR) == (tokens[2], expiry)
        assert chains[0]._statement_replacements[(ANCHOR, INTERMEDIATE)][:2] == (tokens[2], expiry)
        assert "_statement_replacements" not in chains[0].dump()
        finish(chains, accepted)
        assert not hasattr(chains[0], "_statement_replacements")
        processed.extend(chains)

    start = len(fed.http.calls)
    with monkeypatch.context() as patch:
        patch.setattr(fed.collector, "finish_policy_validation", check_policy_handoff)
        result = resolve(fed)
    assert len(processed) == 1
    assert visits == [url, url]
    assert [call.request.url for call in fed.http.calls[start:]] == visits
    if not policy_rejected:
        success(fed, result, tokens)
        return
    assert result["error"] == "invalid_metadata" and result["response_code"] == 400
    assert "response_args" not in result and "response_msg" not in result
    assert fed.collector._statement_pair(INTERMEDIATE, ANCHOR) == (None, None)
    assert (ANCHOR, INTERMEDIATE) not in fed.collector._pending_statements
    fed.documents[url] = Timeout("outage after restored replacement failed policy")
    rejected(fed, resolve(fed))
    assert fed.collector._statement_pair(INTERMEDIATE, ANCHOR) == (None, None)
    fed.documents[url] = replacement
    tokens[2] = replacement
    claims = success(fed, resolve(fed), tokens)
    returned = verify_trust_chains(fed.resolver, [list(reversed(claims["trust_chain"][:-1]))])
    assert len(returned) == 1
    assert apply_policies(fed.resolver, returned)[0].metadata == claims["metadata"]


@pytest.mark.parametrize("refresh_fraction", [None, 0.5])
@pytest.mark.parametrize("offset", [-0.125, 0, 0.125])
@pytest.mark.parametrize("changed_first", [False, True], ids=["original-first", "changed-first"])
def test_rejected_sibling_refresh_obeys_precise_deadline(federation, refresh_fraction, offset,
                                                      changed_first):
    fed = federation
    tokens, replacement, expiry = sibling_refresh_paths(fed, refresh_fraction, changed_first)
    url = ss_url(ANCHOR, INTERMEDIATE)
    visits = []

    def refresh(request):
        visits.append(request.url)
        if len(visits) == 2:
            fed.clock[0] = expiry + offset
        return 200, {"Content-Type": SUBORDINATE_STATEMENT.content_type}, (
            tokens[2] if len(visits) == 1 else replacement)

    fed.documents[url] = refresh
    result = resolve(fed)
    assert visits == [url, url]
    if offset < 0:
        assert success(fed, result, tokens)["exp"] == expiry
        assert fed.collector._statement_pair(INTERMEDIATE, ANCHOR) == (tokens[2], expiry)
    else:
        rejected(fed, result)
        assert fed.collector._statement_pair(INTERMEDIATE, ANCHOR) == (None, None)


@pytest.mark.parametrize("refresh_fraction", [None, 0.5])
@pytest.mark.parametrize("failure", ["signature", "claims", "binding", "malformed", "missing"])
@pytest.mark.parametrize("changed_first", [False, True], ids=["original-first", "changed-first"])
def test_invalid_sibling_refresh_does_not_restore_accepted_pair(federation, refresh_fraction, failure,
                                                             changed_first):
    fed = federation
    tokens, replacement, _ = sibling_refresh_paths(fed, refresh_fraction, changed_first)
    payload = factory(replacement).jwt.payload()
    if failure == "signature":
        replacement = corrupt_signature(replacement)
    elif failure in ("claims", "binding"):
        if failure == "claims":
            payload["constraints"]["max_path_length"] = "1"
        elif failure == "binding":
            payload["sub"] = OTHER
        # Bypass producer validation only to construct genuinely invalid peer input.
        replacement = JWS(json.dumps(payload), alg="ES256").sign_compact(
            fed.signing.get_signing_key("EC", issuer_id=ANCHOR),
            protected={"typ": SUBORDINATE_STATEMENT.typ})
    elif failure == "malformed":
        replacement = "not a JWT"
    url = ss_url(ANCHOR, INTERMEDIATE)
    visits = []

    def refresh(request):
        visits.append(request.url)
        if len(visits) == 2 and failure == "missing":
            return 404, {}, "missing"
        return 200, {"Content-Type": SUBORDINATE_STATEMENT.content_type}, (
            tokens[2] if len(visits) == 1 else replacement)

    fed.documents[url] = refresh
    rejected(fed, resolve(fed))
    assert visits == [url, url]
    assert fed.collector._statement_pair(INTERMEDIATE, ANCHOR) == (None, None)


@pytest.mark.parametrize("refresh_fraction", [None, 0.5])
@pytest.mark.parametrize("publication", ["newer", "constraints", "expiry"])
@pytest.mark.parametrize("changed_first", [False, True], ids=["original-first", "changed-first"])
def test_rejected_sibling_refresh_preserves_newer_pair(federation, refresh_fraction, publication,
                                                    changed_first):
    fed = federation
    tokens, replacement, _ = sibling_refresh_paths(fed, refresh_fraction, changed_first)
    payload = factory(replacement).jwt.payload()
    payload["publication"] = "newer"
    if publication == "constraints":
        payload["constraints"]["max_path_length"] = 0
    elif publication == "expiry":
        payload["exp"] = fed.now + 1000.5
    newer = sign_federation_jwt(
        SUBORDINATE_STATEMENT, payload, fed.signing, ANCHOR, "ES256", iat=payload["iat"])
    url = ss_url(ANCHOR, INTERMEDIATE)
    visits = []

    def refresh(request):
        visits.append(request.url)
        if len(visits) == 2:
            fed.documents[url] = newer
            inner = fed.resolver.get_endpoint("resolve").process_request(
                {"sub": INTERMEDIATE, "trust_anchor": [ANCHOR]}, with_ta_ec=True)
            success(fed, inner, [fed.documents[ec_url(INTERMEDIATE)], newer, tokens[-1]])
        return 200, {"Content-Type": SUBORDINATE_STATEMENT.content_type}, (
            tokens[2] if len(visits) == 1 else replacement)

    fed.documents[url] = refresh
    result = resolve(fed)
    assert visits == [url, url]
    assert fed.collector._statement_pair(INTERMEDIATE, ANCHOR) == (newer, payload["exp"])
    claims = success(fed, result, tokens)
    returned = verify_trust_chains(fed.resolver, [list(reversed(claims["trust_chain"][:-1]))])
    assert len(returned) == 1
    assert apply_policies(fed.resolver, returned)[0].metadata == claims["metadata"]
    subsequent = resolve(fed)
    if publication == "constraints":
        rejected(fed, subsequent)
    else:
        refreshed = tokens[:]
        refreshed[2] = newer
        success(fed, subsequent, refreshed)


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


@pytest.mark.parametrize("case,budget,failure,retained", [
    ("anchor", 6, Timeout("refresh timed out"), True),
    ("anchor", 6, "not a JWT", False),
    ("statement", 9, (503, {}, "refresh unavailable"), True),
    ("statement", 9, "not a JWT", False),
    ("ordering", 9, Timeout("refresh timed out"), True),
])
def test_actual_refresh_failure_retains_only_transient_candidates(federation, case, budget, failure, retained):
    fed = federation
    tokens, urls = refresh_retention_paths(fed, case, budget)
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
    result = resolve(fed)
    if retained:
        success(fed, result, tokens)
    else:
        rejected(fed, result)
    assert len(visits) == 2
    assert [call.request.url for call in fed.http.calls] == urls


@pytest.mark.parametrize("replacement", ["publication", "constraints", "expiry"])
@pytest.mark.parametrize("refresh_failure", [None, Timeout("outer refresh timed out"),
                                            (503, {}, "outer refresh unavailable"),
                                            (200, {"Content-Type": ENTITY_CONFIGURATION.content_type},
                                             "not a JWT")])
def test_quota_interruption_preserves_newer_interleaved_statement(federation, replacement, refresh_failure):
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
            if replacement == "constraints":
                payload["constraints"] = {"max_path_length": 0}
            elif replacement == "expiry":
                payload["exp"] = fed.now + 50
            else:
                payload["publication"] = "newer"
            new_statement = sign_federation_jwt(
                SUBORDINATE_STATEMENT, payload, fed.signing, ANCHOR, "ES256", iat=payload["iat"])
            fed.documents[ss_url(ANCHOR, INTERMEDIATE)] = new_statement
            inner = fed.resolver.get_endpoint("resolve").process_request(
                {"sub": INTERMEDIATE, "trust_anchor": [ANCHOR]}, with_ta_ec=True)
            success(fed, inner, [fed.documents[ec_url(INTERMEDIATE)], new_statement, anchor_token])
            refreshed.append(new_statement)
            if isinstance(refresh_failure, Exception):
                raise refresh_failure
            if refresh_failure is not None:
                return refresh_failure
        return 200, {"Content-Type": ENTITY_CONFIGURATION.content_type}, anchor_token

    fed.documents[ec_url(ANCHOR)] = interleave_refresh
    result = resolve(fed)
    assert len(refreshed) == 1 and refreshed[0] != old_statement
    new_expiry = fed.now + (50 if replacement == "expiry" else 100)
    assert fed.collector.entity_statement_cache[cache_key(ANCHOR, INTERMEDIATE)] == refreshed[0]
    assert fed.collector.entity_statement_cache[time_key(ANCHOR, INTERMEDIATE)] == new_expiry
    # The outer operation uses nine calls; the independent inner refresh uses two.
    assert [call.request.url for call in fed.http.calls] == (
        urls[:-1] + [ec_url(ANCHOR), ss_url(ANCHOR, INTERMEDIATE)] + urls[-1:])

    claims = verify_federation_jwt(
        RESOLVE_RESPONSE, result["response_args"], fed.resolver.keyjar).claims()
    # Validate the exact returned chain from the configured anchor, not just
    # the enclosing response signature or the statements individually.
    returned_chains = verify_trust_chains(
        fed.resolver, [list(reversed(claims["trust_chain"][:-1]))])
    assert len(returned_chains) == 1
    validated = returned_chains[0]
    assert validated.anchor == ANCHOR
    assert claims["exp"] <= validated.exp
    assert apply_policies(fed.resolver, returned_chains) == returned_chains
    assert claims["metadata"] == validated.metadata
    success(fed, result, tokens)
    assert claims["exp"] == fed.now + 100

    subsequent = resolve(fed)
    if replacement == "constraints":
        rejected(fed, subsequent)
    else:
        newer_tokens = tokens[:]
        newer_tokens[2] = refreshed[0]
        assert success(fed, subsequent, newer_tokens)["exp"] == new_expiry


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
