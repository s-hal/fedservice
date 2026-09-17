"""Policy rejection through builder-created, cryptographically verified chains."""

from copy import deepcopy

import pytest

from fedservice.entity.function import apply_policies
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
