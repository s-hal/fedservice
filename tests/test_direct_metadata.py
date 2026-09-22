"""Complete-result fixtures for direct metadata composition and isolation."""

from copy import deepcopy

import pytest

from fedservice.entity.function import apply_policies
from fedservice.entity.function.policy import TrustChainPolicy
from fedservice.entity_statement.statement import TrustChain
from fedservice.message import Policy
from fedservice.message import MetadataPolicy
from tests.build_federation import build_federation
from tests.test_41_federation_entity import FEDERATION_CONFIG_2
from tests.test_41_federation_entity import LEAF_ID


SUBJECT = "https://subject.example.org"
INTERMEDIATE = "https://intermediate.example.org"
ANCHOR = "https://ta.example.org"
SUBJECT_METADATA = {
    "organization_name": "Subject name",
    "homepage_uri": "https://subject.example.org/",
    "contacts": ["ops@subject.example.org"],
}
EXPECTED_OVERLAY = {
    "organization_name": "Verified subject name",
    "homepage_uri": "https://subject.example.org/",
    "contacts": ["ops@subject.example.org"],
}


@pytest.fixture(scope="module")
def consumer():
    return build_federation(deepcopy(FEDERATION_CONFIG_2))[LEAF_ID]


def candidate(direct=None, policy=None, ancestor=True, subject=SUBJECT):
    """Build independent verified-payload fixtures at the policy boundary."""
    statements = []
    issuer = ANCHOR
    if ancestor:
        statements.append({
            "iss": ANCHOR, "sub": INTERMEDIATE,
            "metadata": {"federation_entity": {
                "organization_name": "Ancestor describes IE",
            }},
        })
        issuer = INTERMEDIATE
    statements.append({"iss": issuer, "sub": subject})
    if direct is not None:
        statements[-1]["metadata"] = {"federation_entity": deepcopy(direct)}
    if policy is not None:
        statements[-1]["metadata_policy"] = {"federation_entity": deepcopy(policy)}
    statements.append({
        "iss": subject, "sub": subject,
        "metadata": {"federation_entity": deepcopy(SUBJECT_METADATA)},
    })
    return TrustChain(anchor=ANCHOR, verified_chain=statements)


@pytest.mark.parametrize("ancestor", [False, True])
@pytest.mark.parametrize("direct,policy,expected", [
    (None, None, SUBJECT_METADATA),
    ({"organization_name": "Verified subject name"}, None, EXPECTED_OVERLAY),
    (None, {"organization_name": {"value": "Verified subject name"}}, EXPECTED_OVERLAY),
    ({"organization_name": "Verified subject name"},
     {"organization_name": {"one_of": ["Verified subject name"]}}, EXPECTED_OVERLAY),
    ({"organization_name": "Direct name"},
     {"organization_name": {"value": "Verified subject name"}}, EXPECTED_OVERLAY),
    ({"organization_name": "Verified subject name"},
     {"organization_name": {"default": "Fallback"}, "logo_uri": {"default": "https://logo.example.org/"}},
     dict(EXPECTED_OVERLAY, logo_uri="https://logo.example.org/")),
])
def test_complete_composition(consumer, ancestor, direct, policy, expected):
    chain = candidate(direct, policy, ancestor)
    before = deepcopy(chain.verified_chain)
    assert apply_policies(consumer, [chain]) == [chain]
    assert chain.metadata == {"federation_entity": expected}
    assert chain.verified_chain == before
    assert apply_policies(consumer, [chain]) == [chain]
    assert chain.metadata == {"federation_entity": expected}
    assert chain.verified_chain == before


@pytest.mark.parametrize("raw, expected", [
    ({"organization_name": {"value": "Verified subject name"}}, EXPECTED_OVERLAY),
    ({"organization_name": {"default": "Fallback"},
      "logo_uri": {"default": "https://subject.example.org/logo"}},
     dict(SUBJECT_METADATA, logo_uri="https://subject.example.org/logo")),
    ({"organization_name": {"value": None}}, {
        "homepage_uri": SUBJECT_METADATA["homepage_uri"],
        "contacts": SUBJECT_METADATA["contacts"],
    }),
])
def test_schema_values_reach_existing_policy_resolution(consumer, raw, expected):
    parsed = {claim: Policy(**rule).to_dict() for claim, rule in raw.items()}
    nested = MetadataPolicy(federation_entity=parsed)
    nested.verify()
    schema_chain = candidate(policy=nested.to_dict()["federation_entity"])
    raw_chain = candidate(policy=raw)
    before = deepcopy([schema_chain.verified_chain, raw_chain.verified_chain])
    for _ in range(2):
        assert apply_policies(consumer, [schema_chain, raw_chain]) == [schema_chain, raw_chain]
        assert schema_chain.metadata == raw_chain.metadata == {"federation_entity": expected}
        assert [schema_chain.verified_chain, raw_chain.verified_chain] == before


def test_resolving_intermediate_uses_its_own_superior(consumer):
    chain = candidate()
    chain.verified_chain = [
        chain.verified_chain[0],
        {"iss": INTERMEDIATE, "sub": INTERMEDIATE,
         "metadata": {"federation_entity": deepcopy(SUBJECT_METADATA)}},
    ]
    assert apply_policies(consumer, [chain]) == [chain]
    assert chain.metadata == {"federation_entity": {
        "organization_name": "Ancestor describes IE",
        "homepage_uri": "https://subject.example.org/",
        "contacts": ["ops@subject.example.org"],
    }}


def test_entity_type_membership_including_declared_empty(consumer):
    chain = candidate({"organization_name": "Verified subject name"})
    chain.verified_chain[-1]["metadata"]["openid_provider"] = {}
    chain.verified_chain[-2]["metadata"].update({
        "openid_provider": {"issuer": SUBJECT},
        "oauth_client": {"client_name": "Undeclared"},
    })
    before = deepcopy(chain.verified_chain)
    apply_policies(consumer, [chain])
    assert chain.metadata == {
        "federation_entity": EXPECTED_OVERLAY,
        "openid_provider": {"issuer": SUBJECT},
    }
    assert set(chain.combined_policy) == {"federation_entity", "openid_provider"}
    assert chain.verified_chain == before


@pytest.mark.parametrize("upper, lower, expected_types", [
    (None, None, {"federation_entity", "openid_provider", "oauth_client"}),
    ([], None, {"federation_entity"}),
    (None, ["openid_provider"], {"federation_entity", "openid_provider"}),
    (["openid_provider"], ["openid_provider", "oauth_client"],
     {"federation_entity", "openid_provider"}),
    (["openid_provider"], ["oauth_client"], {"federation_entity"}),
])
def test_allowed_types_between_direct_metadata_and_policy(consumer, upper, lower, expected_types):
    chain = candidate({"organization_name": "Verified subject name"})
    chain.verified_chain[-1]["metadata"].update({"openid_provider": {}, "oauth_client": {}})
    chain.verified_chain[-2]["metadata"].update({
        "openid_provider": {"issuer": SUBJECT},
        "oauth_client": {"client_name": "Direct client"},
        "openid_relying_party": {"client_name": "Undeclared"},
    })
    chain.verified_chain[-2]["metadata_policy"] = {
        "openid_provider": {"issuer": {"one_of": [SUBJECT]}},
        "oauth_client": {"client_name": {"value": "Policy client"}},
        "openid_relying_party": {"client_name": {"value": "Must not create"}},
    }
    for statement, allowed in zip(chain.verified_chain[:-1], (upper, lower)):
        if allowed is not None:
            statement["constraints"] = {"allowed_entity_types": allowed}
    before = deepcopy(chain.verified_chain)
    all_expected = {"federation_entity": EXPECTED_OVERLAY,
                    "openid_provider": {"issuer": SUBJECT},
                    "oauth_client": {"client_name": "Policy client"}}
    for _ in range(2):
        assert apply_policies(consumer, [chain]) == [chain]
        assert chain.metadata == {typ: all_expected[typ] for typ in expected_types}
        assert set(chain.combined_policy) == expected_types
        assert chain.verified_chain == before
    TrustChainPolicy(None)(chain, entity_type="oauth_client")
    assert chain.metadata == ({"oauth_client": all_expected["oauth_client"]}
                              if "oauth_client" in expected_types else {})


def test_filtered_type_policy_is_not_evaluated(consumer):
    chain = candidate()
    chain.verified_chain[-1]["metadata"]["oauth_client"] = {}
    for index, statement in enumerate(chain.verified_chain[:-1]):
        statement["metadata_policy"] = {"oauth_client": {"client_name": {"value": str(index)}}}
    chain.verified_chain[0]["constraints"] = {"allowed_entity_types": []}
    assert apply_policies(consumer, [chain]) == [chain]
    assert chain.metadata == {"federation_entity": SUBJECT_METADATA}


def test_overlay_rejection_preserves_inputs_and_clears_results(consumer):
    chain = candidate(
        {"organization_name": "Forbidden"},
        {"organization_name": {"one_of": ["Verified subject name"]}},
    )
    before = deepcopy(chain.verified_chain)
    assert apply_policies(consumer, [chain]) == []
    assert chain.metadata == chain.combined_policy == {}
    assert chain.verified_chain == before
    assert chain.err["metadata_policy"]["error"] == "invalid_metadata"


@pytest.mark.parametrize("reverse", [False, True])
def test_shared_nested_inputs_alternatives_and_returned_mutation(consumer, reverse):
    shared = deepcopy(SUBJECT_METADATA)
    shared["extension"] = {"nested": ["original"]}
    shared_policy = {"contacts": {"value": ["policy@example.org"]}}
    first = candidate({"organization_name": "First"}, shared_policy)
    second = candidate({"organization_name": "Second"}, shared_policy,
                       subject="https://other.example.org")
    for chain in (first, second):
        chain.verified_chain[-1]["metadata"]["federation_entity"] = shared
        chain.verified_chain[-2]["metadata_policy"]["federation_entity"] = shared_policy
    before = deepcopy([first.verified_chain, second.verified_chain])
    ordered = [second, first] if reverse else [first, second]
    assert apply_policies(consumer, ordered) == ordered
    for chain, name in ((first, "First"), (second, "Second")):
        assert chain.metadata == {"federation_entity": {
            "organization_name": name,
            "homepage_uri": "https://subject.example.org/",
            "contacts": ["policy@example.org"],
            "extension": {"nested": ["original"]},
        }}
    first.metadata["federation_entity"]["contacts"].append("changed")
    first.metadata["federation_entity"]["extension"]["nested"].append("changed")
    assert second.metadata["federation_entity"]["contacts"] == ["policy@example.org"]
    assert first.combined_policy["federation_entity"]["metadata_policy"] == shared_policy
    assert [first.verified_chain, second.verified_chain] == before
    first.combined_policy["federation_entity"]["metadata_policy"]["contacts"]["value"].append("changed")
    assert shared_policy == {"contacts": {"value": ["policy@example.org"]}}
    assert apply_policies(consumer, ordered) == ordered
    assert first.metadata["federation_entity"]["extension"] == {"nested": ["original"]}


@pytest.mark.parametrize("superior,child,accepted", [(True, False, False), (False, True, True)])
def test_policy_merges_superior_first(consumer, superior, child, accepted):
    chain = candidate(policy={"organization_name": {"essential": child}})
    chain.verified_chain[0]["metadata_policy"] = {
        "federation_entity": {"organization_name": {"essential": superior}},
    }
    before = deepcopy(chain.verified_chain)
    assert apply_policies(consumer, [chain]) == ([chain] if accepted else [])
    assert chain.metadata == ({"federation_entity": SUBJECT_METADATA} if accepted else {})
    assert chain.verified_chain == before


def test_direct_nested_results_do_not_alias_combined_policy(consumer):
    chain = candidate({"extension": {"nested": ["direct"]}})
    before = deepcopy(chain.verified_chain)
    apply_policies(consumer, [chain])
    chain.metadata["federation_entity"]["extension"]["nested"].append("changed")
    assert chain.combined_policy["federation_entity"]["metadata"] == {
        "extension": {"nested": ["direct"]},
    }
    assert chain.verified_chain == before
    chain.combined_policy["federation_entity"]["metadata"]["extension"]["nested"].append("policy")
    assert chain.verified_chain == before


def test_retry_drops_stale_and_undeclared_types(consumer):
    chain = candidate()
    chain.metadata["undeclared"] = {"stale": True}
    chain.combined_policy["undeclared"] = {"stale": True}
    apply_policies(consumer, [chain])
    assert chain.metadata == {"federation_entity": SUBJECT_METADATA}
    assert set(chain.combined_policy) == {"federation_entity"}
    TrustChainPolicy(None)(chain, entity_type="undeclared")
    assert chain.metadata == chain.combined_policy == {}


@pytest.mark.parametrize("protocol,expected", [
    (None, {"contacts": []}), ("oidc", {}), ("oauth2", {}),
])
def test_protocol_behavior_and_direct_input_isolation(protocol, expected):
    metadata = {"contacts": ["subject@example.org"]}
    policy = {"metadata": {"contacts": []}, "metadata_policy": {}}
    before = deepcopy((metadata, policy))
    result = TrustChainPolicy(None).apply_policy(metadata, policy, protocol=protocol)
    assert result == expected
    assert (metadata, policy) == before
