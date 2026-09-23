"""Independent OpenID Federation 1.1 standard-operator expectations."""

from copy import deepcopy

import pytest

from fedservice.entity.function import PolicyError
from fedservice.entity.function.policy import TrustChainPolicy
from fedservice.entity.function.policy import combine_claim_policy
from fedservice.entity.function.policy_operator import Add


@pytest.mark.parametrize("metadata, values, expected", [
    ({"items": ["a", "b"]}, ["b", "c"], {"items": ["a", "b", "c"]}),
    ({}, ["b", "c"], {"items": ["b", "c"]}),
    ({"items": []}, ["b", "b", "c"], {"items": ["b", "c"]}),
    ({"items": ["a"], "other": "unchanged"}, [], {"items": ["a"], "other": "unchanged"}),
    ({}, [], {"items": []}),
])
def test_add_flat_independent_idempotent(metadata, values, expected):
    policy = {"metadata_policy": {"items": {"add": values}}}
    before = deepcopy((metadata, policy))
    processor = TrustChainPolicy(None)
    result = processor.apply_policy(metadata, policy, protocol=None)
    assert result == expected
    assert processor.apply_policy(result, policy, protocol=None) == expected
    assert (metadata, policy) == before
    result["items"].append("changed")
    assert (metadata, policy) == before


@pytest.mark.parametrize("metadata", ["a", 1, None, False, {}, [1], [["a"]]])
def test_add_rejects_unsupported_metadata(metadata):
    with pytest.raises(PolicyError):
        TrustChainPolicy(None).apply_policy({"items": metadata}, {"metadata_policy": {
            "items": {"add": ["b"]},
        }})


def test_add_absent_does_not_alias_operator_input():
    values = ["a", "b"]
    metadata = {}
    Add()("items", metadata, {"items": {"add": values}})
    metadata["items"].append("c")
    assert values == ["a", "b"]


def test_value_precedes_add():
    metadata = {"items": ["old"]}
    policy = {"metadata_policy": {"items": {"value": ["a", "b"], "add": ["b", "c"]}}}
    before = deepcopy((metadata, policy))
    assert TrustChainPolicy(None).apply_policy(metadata, policy) == {"items": ["a", "b", "c"]}
    assert (metadata, policy) == before


@pytest.mark.parametrize("upper,lower,expected", [
    (["web", "native"], ["web", "native"], {"web", "native"}),
    (["web"], ["web", "native"], {"web"}),
    (["web", "native"], ["web"], {"web"}),
    (["web", "native"], ["web", "mobile"], {"web"}),
])
def test_one_of_intersection(upper, lower, expected):
    superior, child = {"one_of": upper}, {"one_of": lower}
    before = deepcopy((superior, child))
    result = combine_claim_policy(superior, child)
    assert {key: set(value) for key, value in result.items()} == {"one_of": expected}
    assert (superior, child) == before


@pytest.mark.parametrize("upper,lower", [(["web"], ["native"]), ([], ["web"]), (["web"], [])])
def test_one_of_empty_intersection_rejected(upper, lower):
    with pytest.raises(PolicyError):
        combine_claim_policy({"one_of": upper}, {"one_of": lower})


@pytest.mark.parametrize("metadata,rule,expected", [
    ({"kind": "web"}, {"one_of": ["web", "native"]}, {"kind": "web"}),
    ({}, {"one_of": ["web"]}, {}),
    ({}, {"one_of": ["web"], "default": "web", "essential": True}, {"kind": "web"}),
    ({"kind": "old"}, {"one_of": ["web"], "value": "web"}, {"kind": "web"}),
])
def test_one_of_application(metadata, rule, expected):
    before = deepcopy((metadata, rule))
    assert TrustChainPolicy(None).apply_policy(metadata, {"metadata_policy": {"kind": rule}}) == expected
    assert (metadata, rule) == before


@pytest.mark.parametrize("value", ["mobile", ["web"], [], 1, {}, None])
def test_one_of_rejects_disallowed_or_unsupported_metadata(value):
    with pytest.raises(PolicyError):
        TrustChainPolicy(None).apply_policy({"kind": value}, {"metadata_policy": {
            "kind": {"one_of": ["web"]},
        }})


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("value", ["web", "mobile"])
def test_one_of_value_compatibility(reverse, value):
    policies = [{"one_of": ["web", "native"]}, {"value": value}]
    if reverse:
        policies.reverse()
    if value == "mobile":
        with pytest.raises(PolicyError):
            combine_claim_policy(*policies)
    else:
        expected = {"value": "web"} if reverse else {"value": "web", "one_of": ["web", "native"]}
        assert combine_claim_policy(*policies) == expected


@pytest.mark.parametrize("operator", ["add", "subset_of", "superset_of"])
@pytest.mark.parametrize("reverse", [False, True])
def test_one_of_prohibited_combinations(operator, reverse):
    policies = [{"one_of": ["web"]}, {operator: ["web"]}]
    if reverse:
        policies.reverse()
    with pytest.raises(PolicyError):
        combine_claim_policy(*policies)


def test_one_of_default_merge():
    assert combine_claim_policy({"one_of": ["web"]}, {"default": "web"}) == {
        "one_of": ["web"], "default": "web",
    }


def test_one_of_value_must_satisfy_both_restrictions():
    with pytest.raises(PolicyError):
        combine_claim_policy({"one_of": ["web", "native"]},
                             {"value": "mobile", "one_of": ["web", "mobile"]})


@pytest.mark.parametrize("upper,lower,expected", [
    (["a"], ["b"], {"a", "b"}),
    (["a", "b"], ["b", "c"], {"a", "b", "c"}),
    (["a", "b"], ["a", "b"], {"a", "b"}),
    (["a", "b"], ["a"], {"a", "b"}),
    ([], ["a"], {"a"}),
    (["a"], [], {"a"}),
    ([], [], set()),
])
def test_superset_of_union(upper, lower, expected):
    superior, child = {"superset_of": upper}, {"superset_of": lower}
    before = deepcopy((superior, child))
    result = combine_claim_policy(superior, child)
    assert {key: set(value) for key, value in result.items()} == {"superset_of": expected}
    assert (superior, child) == before


@pytest.mark.parametrize("allowed", [["a", "b", "c"], ["a"]])
def test_superset_of_union_subset_compatibility(allowed):
    superior = {"subset_of": allowed, "superset_of": ["a"]}
    child = {"superset_of": ["b"]}
    if "b" not in allowed:
        with pytest.raises(PolicyError):
            combine_claim_policy(superior, child)
    else:
        result = combine_claim_policy(superior, child)
        assert {key: set(value) for key, value in result.items()} == {
            "subset_of": {"a", "b", "c"}, "superset_of": {"a", "b"},
        }


@pytest.mark.parametrize("metadata", [{}, {"items": ["a", "b"]}, {"items": ["b", "a", "c"]}])
def test_superset_of_application(metadata):
    policy = {"metadata_policy": {"items": {"superset_of": ["a", "b"]}}}
    before = deepcopy((metadata, policy))
    assert TrustChainPolicy(None).apply_policy(metadata, policy) == metadata
    assert (metadata, policy) == before


@pytest.mark.parametrize("value", [["a"], [], "ab", 1, None, {}, [1]])
def test_superset_of_rejects_missing_or_unsupported_metadata(value):
    with pytest.raises(PolicyError):
        TrustChainPolicy(None).apply_policy({"items": value}, {"metadata_policy": {
            "items": {"superset_of": ["a", "b"]},
        }})


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("value", [["a", "b"], ["a"]])
def test_superset_of_value_compatibility(reverse, value):
    policies = [{"superset_of": ["a", "b"]}, {"value": value}]
    if reverse:
        policies.reverse()
    if value == ["a"]:
        with pytest.raises(PolicyError):
            combine_claim_policy(*policies)
    else:
        expected = {"value": value} if reverse else {"value": value, "superset_of": ["a", "b"]}
        assert combine_claim_policy(*policies) == expected


@pytest.mark.parametrize("operator", ["add", "default"])
def test_superset_of_allowed_application_order(operator):
    rule = combine_claim_policy({"superset_of": ["a", "b"]}, {operator: ["a", "b"]})
    assert rule == {"superset_of": ["a", "b"], operator: ["a", "b"]}
    assert TrustChainPolicy(None).apply_policy({}, {"metadata_policy": {"items": rule}}) == {
        "items": ["a", "b"],
    }


@pytest.mark.parametrize("upper,lower,expected", [
    (False, False, False), (False, True, True), (True, False, True), (True, True, True),
])
@pytest.mark.parametrize("value_position", [None, "upper", "lower", "both"])
def test_essential_or(upper, lower, expected, value_position):
    superior, child = {"essential": upper}, {"essential": lower}
    result = {"essential": expected}
    if value_position in ("upper", "both"):
        superior["value"] = "x"
    if value_position in ("lower", "both"):
        child["value"] = "x"
    if value_position is not None:
        result["value"] = "x"
    before = deepcopy((superior, child))
    assert combine_claim_policy(superior, child) == result
    assert (superior, child) == before


@pytest.mark.parametrize("essential", [False, True])
@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("other", [{}, {"value": "x"}, {"default": "x"}, {"one_of": ["x"]},
                                    {"add": ["x"]}, {"subset_of": ["x"]}, {"superset_of": ["x"]}])
def test_essential_one_sided_is_copied(essential, reverse, other):
    policies = [{"essential": essential}, deepcopy(other)]
    if reverse:
        policies.reverse()
    before = deepcopy(policies)
    assert combine_claim_policy(*policies) == dict(other, essential=essential)
    assert policies == before


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("superior,child", [
    ({"value": None}, {"essential": True}),
    ({"value": None, "essential": False}, {"essential": True}),
    ({"value": None, "essential": True}, {}),
    ({"value": None, "essential": True}, {"essential": False}),
])
def test_essential_null_conflict_during_merge(superior, child, reverse):
    policies = [superior, child]
    if reverse:
        policies.reverse()
    with pytest.raises(PolicyError):
        combine_claim_policy(*policies)


@pytest.mark.parametrize("metadata,rule,expected", [
    ({}, {"essential": False}, {}),
    ({"item": "x"}, {"essential": True}, {"item": "x"}),
    ({"item": None}, {"essential": True}, {"item": None}),
    ({}, {"essential": True, "value": "x"}, {"item": "x"}),
    ({}, {"essential": True, "default": "x"}, {"item": "x"}),
    ({}, {"essential": True, "add": ["x"]}, {"item": ["x"]}),
    ({"item": "x"}, {"essential": False, "value": None}, {}),
])
def test_essential_application_after_other_operators(metadata, rule, expected):
    before = deepcopy((metadata, rule))
    processor = TrustChainPolicy(None)
    for _ in range(2):
        assert processor.apply_policy(metadata, {"metadata_policy": {"item": rule}}) == expected
    assert (metadata, rule) == before


@pytest.mark.parametrize("metadata,rule", [
    ({}, {"essential": True}),
    ({"item": "x"}, {"value": None, "essential": True}),
    ({"item": "x"}, {"value": None, "default": "x", "essential": True}),
])
def test_essential_application_failure(metadata, rule):
    with pytest.raises(PolicyError):
        TrustChainPolicy(None).apply_policy(metadata, {"metadata_policy": {"item": rule}})
