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
