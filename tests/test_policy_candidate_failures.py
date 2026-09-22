"""Policy rejection through builder-created, cryptographically verified chains."""

from copy import deepcopy

import pytest

from fedservice.entity.function import apply_policies
from fedservice.entity_statement.statement import TrustChain
from tests import create_trust_chain_messages
from tests.build_federation import build_federation
from tests.test_41_federation_entity import FEDERATION_CONFIG_2
from tests.test_41_federation_entity import INTERMEDIATE_ID
from tests.test_41_federation_entity import LEAF_ID
from tests.test_41_federation_entity import TA1_ID


@pytest.fixture
def federation():
    return build_federation(deepcopy(FEDERATION_CONFIG_2))


def verified_candidate(federation, failure=None):
    """Issue and verify an independent candidate using real federation endpoints."""
    ta = federation[TA1_ID]
    intermediate = federation[INTERMEDIATE_ID]
    leaf = federation[LEAF_ID]["federation_entity"]
    if failure == "merge":
        superior_rule = {"value": "RS256"}
        child_rule = {"value": "ES256"}
    else:
        superior_rule = {"one_of": ["disallowed-secret-value"] if failure else ["RS256"]}
        child_rule = {"one_of": list(superior_rule["one_of"])}
    # Explicit JSON publication records keep builder-only entity_types out of
    # subject-specific Fetch payloads.
    for issuer, subject in ((ta, INTERMEDIATE_ID), (intermediate, LEAF_ID)):
        issuer.server.subordinate[subject].pop("entity_types", None)
    ta.server.policy[INTERMEDIATE_ID] = {
        "metadata_policy": {
            "openid_relying_party": {"id_token_signed_response_alg": superior_rule}
        }
    }
    intermediate.server.policy[LEAF_ID] = {
        "metadata_policy": {
            "openid_relying_party": {"id_token_signed_response_alg": child_rule}
        }
    }
    messages = create_trust_chain_messages(federation[LEAF_ID], intermediate, ta)
    candidates = leaf.function.verifier([
        messages[ta.get_endpoint("fetch").full_path],
        messages[intermediate.get_endpoint("fetch").full_path],
        messages[leaf.get_endpoint("entity_configuration").full_path],
    ])
    assert len(candidates) == 1
    return candidates[0]


@pytest.mark.parametrize("failure", ["application", "merge"])
@pytest.mark.parametrize("reverse", [False, True])
def test_rejection_keeps_valid_alternatives(federation, failure, reverse, caplog):
    invalid = verified_candidate(federation, failure)
    valid = verified_candidate(federation)
    invalid.metadata["partial"] = {"secret": "not-for-logs"}
    invalid.combined_policy["partial"] = {"secret": "not-for-logs"}
    invalid.err["unrelated"] = {"error": "retained"}
    candidates = [invalid, valid]
    if reverse:
        candidates.reverse()

    assert apply_policies(federation[LEAF_ID], candidates) == [valid]
    assert valid.metadata["openid_relying_party"]["id_token_signed_response_alg"] == "RS256"
    assert invalid.metadata == {}
    assert invalid.combined_policy == {}
    assert invalid.err == {
        "unrelated": {"error": "retained"},
        "metadata_policy": {
            "error": "invalid_metadata", "stage": "metadata_policy",
            "subject": LEAF_ID, "trust_anchor": TA1_ID,
        },
    }
    assert "invalid_metadata" in caplog.text
    assert LEAF_ID in caplog.text
    assert "not-for-logs" not in caplog.text
    assert "disallowed-secret-value" not in caplog.text


def test_all_rejected_and_empty(federation):
    rejected = [verified_candidate(federation, "application"),
                verified_candidate(federation, "merge")]
    assert apply_policies(federation[LEAF_ID], rejected) == []
    assert all(candidate.err["metadata_policy"]["error"] == "invalid_metadata"
               for candidate in rejected)
    assert all(candidate.metadata == candidate.combined_policy == {}
               for candidate in rejected)
    assert apply_policies(federation[LEAF_ID], []) == []


def test_success_order_and_retry_clear_only_owned_error(federation):
    candidate = verified_candidate(federation, "application")
    candidate.err["unrelated"] = "retained"
    assert apply_policies(federation[LEAF_ID], [candidate]) == []
    corrected = verified_candidate(federation)
    candidate.verified_chain = deepcopy(corrected.verified_chain)
    other = verified_candidate(federation)
    assert apply_policies(federation[LEAF_ID], [candidate, other]) == [candidate, other]
    assert candidate.err == {"unrelated": "retained"}


@pytest.mark.parametrize("exception", [TypeError, AttributeError])
def test_unexpected_failure_propagates(federation, monkeypatch, exception):
    candidate = verified_candidate(federation)
    candidate.err["metadata_policy"] = {"error": "stale"}
    policy = federation[LEAF_ID]["federation_entity"].function.policy

    def unexpected(*args, **kwargs):
        raise exception("unexpected internal failure")

    monkeypatch.setattr(policy, "apply_policy", unexpected)
    with pytest.raises(exception, match="unexpected internal failure"):
        apply_policies(federation[LEAF_ID], [candidate])
    assert "metadata_policy" not in candidate.err


@pytest.fixture
def critical_federation():
    ids = [TA1_ID, INTERMEDIATE_ID, "https://lower.example.org", LEAF_ID]
    config = {}
    for index, entity_id in enumerate(ids):
        config[entity_id] = {
            "entity_type": "trust_anchor" if index == 0 else "federation_entity",
            "trust_anchors": [TA1_ID],
            "kwargs": {"endpoints": ["entity_configuration", "fetch"],
                       "preference": {"organization_name": "Subject name"}},
        }
        if index < len(ids) - 1:
            config[entity_id]["subordinates"] = [ids[index + 1]]
        if index:
            config[entity_id]["kwargs"]["authority_hints"] = [ids[index - 1]]
    entities = build_federation(config)
    for index, entity_id in enumerate(ids[:-1]):
        entities[entity_id].server.policy[ids[index + 1]] = {
            "metadata_policy": {"federation_entity": {
                "organization_name": {"value": "Policy name", "regexp": "private-expression"},
            }},
        }
    return [entities[entity_id] for entity_id in ids]


def issue_critical_candidate(entities):
    """Issue a four-statement chain and use the actual chain verifier."""
    leaf = entities[-1]
    messages = create_trust_chain_messages(leaf, *reversed(entities[:-1]))
    return leaf.function.verifier([
        messages[issuer.get_endpoint("fetch").full_path] for issuer in entities[:-1]
    ] + [messages[leaf.get_endpoint("entity_configuration").full_path]])


@pytest.mark.parametrize("position", [0, 1, 2])
@pytest.mark.parametrize("critical", [[], ["value"], ["regexp"]])
def test_signed_critical_declaration_at_each_position(critical_federation, position, critical):
    entities = critical_federation
    policy = entities[position].server.policy[entities[position + 1].entity_id]
    policy["metadata_policy_crit"] = critical
    # Its declaration must matter even without policy for the subject's type.
    policy["metadata_policy"] = {"oauth_client": {"client_name": {"regexp": "private-expression"}}}
    assert not issue_critical_candidate(entities)
    del policy["metadata_policy_crit"]
    candidates = issue_critical_candidate(entities)
    assert len(candidates) == 1
    assert apply_policies(entities[-1], candidates) == candidates
    assert candidates[0].metadata == {"federation_entity": {
        "organization_name": "Policy name", "federation_fetch_endpoint": LEAF_ID + "/fetch",
    }}


@pytest.mark.parametrize("position", [0, 1, 2])
@pytest.mark.parametrize("reverse", [False, True])
def test_pre_resolution_critical_check_is_candidate_local(
        critical_federation, position, reverse, monkeypatch, caplog):
    entities = critical_federation
    valid = issue_critical_candidate(entities)[0]
    # Independent payload fixture at the policy boundary also covers previously
    # cached records: criticality must be checked before any filtering or merge.
    statements = deepcopy(valid.verified_chain)
    statements[position]["metadata_policy_crit"] = ["regexp"]
    statements[position]["metadata_policy"] = {}
    statements[0]["constraints"] = {"allowed_entity_types": []}
    invalid = TrustChain(anchor=TA1_ID, verified_chain=statements)
    before = deepcopy([invalid.verified_chain, valid.verified_chain])
    ordered = [valid, invalid] if reverse else [invalid, valid]
    for _ in range(2):
        assert apply_policies(entities[-1], ordered) == [valid]
        assert invalid.metadata == invalid.combined_policy == {}
        assert invalid.err["metadata_policy"]["error"] == "invalid_metadata"
        assert valid.metadata == {"federation_entity": {
            "organization_name": "Policy name", "federation_fetch_endpoint": LEAF_ID + "/fetch",
        }}
        assert [invalid.verified_chain, valid.verified_chain] == before
    assert "private-expression" not in caplog.text
    policy = entities[-1].function.policy
    monkeypatch.setattr(policy, "gather_policies", lambda *args: pytest.fail("must reject before merge"))
    assert apply_policies(entities[-1], [invalid]) == []
