"""Independent OpenID Federation 1.1 standard-operator expectations."""

from copy import deepcopy

import pytest

from fedservice.entity.function import PolicyError
from fedservice.entity.function.policy import TrustChainPolicy
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
