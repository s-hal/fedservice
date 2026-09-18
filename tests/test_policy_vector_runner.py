"""Regression coverage for the historical policy-vector diagnostic runner."""

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys

import pytest

from policy_test import pol_test as runner
from fedservice.entity.function import PolicyError


@pytest.mark.parametrize("actual,expected,equal", [
    ({"a": 1}, {"a": 1, "b": 2}, False),
    ({"a": 1, "b": 2}, {"a": 1}, False),
    ({"a": 1, "b": 3}, {"a": 1, "b": 2}, False),
    ({"a": {"b": 2}}, {"a": {"b": 2, "c": 3}}, False),
    ({"a": True}, {"a": 1}, False),
    ({"a": 1}, {"a": 1.0}, False),
    ({"a": "X"}, {"a": ["X"]}, False),
    ({"a": ["X"]}, {"a": "X"}, False),
    ({"a": ["X", "Y"]}, {"a": ["Y", "X"]}, False),
    ({"grant_types": ["X", "Y"]}, {"grant_types": ["Y", "X"]}, True),
    ({"grant_types": [["X"]]}, {"grant_types": [["X"]]}, False),
    ({"grant_types": [True]}, {"grant_types": [True]}, False),
    ({"grant_types": {"value": ["X", "Y"]}},
     {"grant_types": {"value": ["Y", "X"]}}, True),
    ({}, {}, True),
])
def test_complete_structure_comparison(actual, expected, equal):
    assert runner.compare_dict(actual, expected) is equal


@pytest.mark.parametrize("operator", sorted(runner.SET_OPERATORS))
def test_set_operators_require_flat_string_arrays(operator):
    assert runner.compare_dict({operator: ["a", "b"]}, {operator: ["b", "a"]})
    assert not runner.compare_dict({operator: [["a"]]}, {operator: ["a"]})
    assert not runner.compare_dict({operator: ["a"]}, {operator: [["a"]]})
    assert not runner.compare_dict({operator: [1]}, {operator: [1]})


def success_case():
    return {"n": 1, "TA": {}, "INT": {}, "metadata": {}, "merged": {}, "resolved": {}}


@pytest.mark.parametrize("expected_error,raised_stage,exception,passed", [
    ("merge", "merge", PolicyError, True),
    ("application", "application", PolicyError, True),
    ("application", "merge", PolicyError, False),
    (None, "merge", PolicyError, False),
    (None, "application", PolicyError, False),
    ("merge", "merge", TypeError, False),
    ("application", "application", TypeError, False),
    ("application", "application", ValueError, False),
    ("merge", None, None, False),
    ("application", None, None, False),
    (None, None, None, True),
])
def test_expected_errors_are_stage_specific(
        monkeypatch, expected_error, raised_stage, exception, passed):
    case = success_case()
    if expected_error:
        case.pop("resolved")
        case["error"] = "historical code, not exception prose"
        if expected_error == "merge":
            case.pop("merged")

    def merge(*args):
        if raised_stage == "merge":
            raise exception("production failure")
        return {"metadata_policy": {}}

    def apply(*args, **kwargs):
        assert kwargs["protocol"] is None
        if raised_stage == "application":
            raise exception("production failure")
        return {}

    monkeypatch.setattr(runner, "combine", merge)
    monkeypatch.setattr(runner.TrustChainPolicy, "apply_policy", apply)
    stage, error = runner.run_case(case)
    assert (error is None) is passed
    assert stage == ("merge" if raised_stage == "merge" or expected_error == "merge"
                     else "application")


@pytest.mark.parametrize("merged", [None, {}, {"metadata_policy": {"extra": {}}}])
def test_missing_or_wrong_merged_policy(monkeypatch, merged):
    monkeypatch.setattr(runner, "combine", lambda *args: merged)
    stage, error = runner.run_case(success_case())
    assert stage == "merge"
    assert error is not None


@pytest.mark.parametrize("resolved", [None, {"extra": 1}])
def test_empty_resolved_is_not_skipped(monkeypatch, resolved):
    monkeypatch.setattr(runner, "combine", lambda *args: {"metadata_policy": {}})
    monkeypatch.setattr(runner.TrustChainPolicy, "apply_policy",
                        lambda *args, **kwargs: resolved)
    assert runner.run_case(success_case())[1] is not None


@pytest.mark.parametrize("updates", [
    {"error": "failure"}, {"merged": None}, {"resolved": None},
    {"TA": []}, {"error": "", "resolved": None},
])
def test_invalid_record_shapes(updates):
    case = success_case()
    case.update(updates)
    assert runner.run_case(case)[0] == "input"


def test_mutation_cannot_change_expectations_or_source(monkeypatch):
    shared = {"grant_types": {"value": ["a"]}}
    case = success_case()
    case.update(TA=shared, INT=shared, merged=shared)
    metadata = {"grant_types": ["a"]}
    case.update(metadata=metadata, resolved=metadata)
    before = deepcopy(case)

    def merge(superior, subordinate):
        superior["metadata_policy"].clear()
        subordinate["metadata_policy"].clear()
        return {"metadata_policy": deepcopy(shared)}

    def apply(self, actual, policy, protocol):
        actual.clear()
        policy.clear()
        return deepcopy(metadata)

    monkeypatch.setattr(runner, "combine", merge)
    monkeypatch.setattr(runner.TrustChainPolicy, "apply_policy", apply)
    assert runner.run_case(case)[1] is None
    assert runner.run_case(case)[1] is None
    assert case == before


def run_cli(tmp_path, corpus):
    filename = tmp_path / "cases.json"
    filename.write_text(json.dumps(corpus), encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(Path(runner.__file__).resolve()), str(filename)],
        cwd=str(tmp_path), capture_output=True, text=True,
    )


def test_cli_all_pass(tmp_path):
    result = run_cli(tmp_path, [success_case()])
    assert result.returncode == 0
    assert "PASS case=1 stage=application" in result.stdout
    assert result.stdout.endswith("Totals: cases=1 passed=1 failed=0 input_errors=0\n")


@pytest.mark.parametrize("malformed_count", [1, 2])
def test_cli_accounts_for_failures_and_continues(tmp_path, malformed_count):
    wrong = success_case()
    wrong.update(n=2, resolved={"missing": "value"})
    malformed = [{"n": n} for n in range(3, 3 + malformed_count)]
    last = success_case()
    last["n"] = 3 + malformed_count
    result = run_cli(tmp_path, [success_case(), wrong] + malformed + [last])
    assert result.returncode == 1
    assert "FAIL case=2 stage=application" in result.stdout
    for case in malformed:
        assert "FAIL case={} stage=input".format(case["n"]) in result.stdout
    assert "PASS case={} stage=application".format(last["n"]) in result.stdout
    assert result.stdout.endswith(
        "Totals: cases={} passed=2 failed={} input_errors={}\n".format(
            3 + malformed_count, 1 + malformed_count, malformed_count,
        )
    )


@pytest.mark.parametrize("corpus,totals", [
    ({}, "cases=0 passed=0 failed=0 input_errors=1"),
    ([], "cases=0 passed=0 failed=0 input_errors=1"),
    ([None], "cases=1 passed=0 failed=1 input_errors=1"),
])
def test_cli_rejects_malformed_corpus(tmp_path, corpus, totals):
    result = run_cli(tmp_path, corpus)
    assert result.returncode == 1
    assert result.stdout.endswith("Totals: {}\n".format(totals))


def test_cli_unreadable_and_invalid_json(tmp_path):
    filename = tmp_path / "missing.json"
    command = [sys.executable, str(Path(runner.__file__).resolve()), str(filename)]
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == 1
    assert result.stdout.endswith("Totals: cases=0 passed=0 failed=0 input_errors=1\n")
    filename.write_text("{", encoding="utf-8")
    result = subprocess.run(command, capture_output=True, text=True)
    assert result.returncode == 1
    assert result.stdout.endswith("Totals: cases=0 passed=0 failed=0 input_errors=1\n")


def test_import_does_not_execute_corpus(tmp_path):
    script = (
        "import importlib.util; "
        "spec = importlib.util.spec_from_file_location('runner', {!r}); "
        "module = importlib.util.module_from_spec(spec); "
        "spec.loader.exec_module(module)"
    ).format(str(Path(runner.__file__).resolve()))
    result = subprocess.run([sys.executable, "-c", script], cwd=str(tmp_path),
                            capture_output=True, text=True)
    assert result.returncode == 0
    assert result.stdout == ""
    assert result.stderr == ""
