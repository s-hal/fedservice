#!/usr/bin/env python
"""Run bundled historical policy vectors as independent diagnostics."""

import argparse
from copy import deepcopy
import json
from pathlib import Path

from fedservice.entity.function import PolicyError
from fedservice.entity.function.policy import combine
from fedservice.entity.function.policy import TrustChainPolicy


SET_OPERATORS = {"add", "one_of", "subset_of", "superset_of"}
DEFAULT_CORPUS = Path(__file__).with_name(
    "metadata-policy-test-vectors-2025-02-13.json"
)


def compare_dict(actual, expected, path=()):
    """Compare JSON structures, using membership only for known string sets."""
    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return actual.keys() == expected.keys() and all(
            compare_dict(actual[key], value, path + (key,))
            for key, value in expected.items()
        )
    if isinstance(expected, list):
        is_set = path and (
            path[-1] in SET_OPERATORS or "grant_types" in path
        )
        if is_set:
            if not all(type(value) is str for value in actual + expected):
                return False
            return set(actual) == set(expected)
        return len(actual) == len(expected) and all(
            compare_dict(left, right, path + (index,))
            for index, (left, right) in enumerate(zip(actual, expected))
        )
    return actual == expected


def _expected_stage(case):
    if not isinstance(case, dict) or "n" not in case:
        raise ValueError("record must be an object with a case ID")
    for key in ("TA", "INT", "metadata"):
        if not isinstance(case.get(key), dict):
            raise ValueError("{} must be an object".format(key))
    if "error" in case:
        if not isinstance(case["error"], str) or not case["error"]:
            raise ValueError("error must be a non-empty string")
        if "resolved" in case:
            raise ValueError("error and resolved are contradictory")
        if "merged" not in case:
            return "merge"
        if not isinstance(case["merged"], dict):
            raise ValueError("merged must be an object")
        return "application"
    if not all(isinstance(case.get(key), dict) for key in ("merged", "resolved")):
        raise ValueError("success requires merged and resolved objects")
    return None


def run_case(case):
    """Return a case's outcome stage and diagnostic, with isolated inputs."""
    try:
        expected_error = _expected_stage(case)
    except ValueError as err:
        return "input", str(err)

    try:
        merged = combine(
            {"metadata_policy": deepcopy(case["TA"])},
            {"metadata_policy": deepcopy(case["INT"])},
        )
    except PolicyError as err:
        if expected_error == "merge":
            return "merge", None
        return "merge", "unexpected PolicyError: {}".format(err)
    except Exception as err:
        return "merge", "{}: {}".format(type(err).__name__, err)

    if expected_error == "merge":
        return "merge", "expected PolicyError was not raised"
    if not isinstance(merged, dict) or "metadata_policy" not in merged:
        return "merge", "missing metadata_policy output"
    if not compare_dict(merged["metadata_policy"], case["merged"]):
        return "merge", "metadata_policy differs from merged expectation"

    try:
        resolved = TrustChainPolicy(None).apply_policy(
            deepcopy(case["metadata"]), deepcopy(merged), protocol=None
        )
    except PolicyError as err:
        if expected_error == "application":
            return "application", None
        return "application", "unexpected PolicyError: {}".format(err)
    except Exception as err:
        return "application", "{}: {}".format(type(err).__name__, err)

    if expected_error == "application":
        return "application", "expected PolicyError was not raised"
    if not compare_dict(resolved, case["resolved"]):
        return "application", "output differs from resolved expectation"
    return "application", None


def main(argv=None):
    """Print every case outcome and return a failing status for any failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("filename", nargs="?", type=Path, default=DEFAULT_CORPUS)
    args = parser.parse_args(argv)
    try:
        with args.filename.open(encoding="utf-8") as corpus:
            cases = json.load(corpus)
        if not isinstance(cases, list) or not cases:
            raise ValueError("corpus must be a non-empty array of records")
    except (OSError, ValueError) as err:
        print("FAIL corpus input: {}: {}".format(type(err).__name__, err))
        print("Totals: cases=0 passed=0 failed=0 input_errors=1")
        return 1

    passed = 0
    input_errors = 0
    for index, case in enumerate(cases):
        stage, error = run_case(case)
        case_id = case.get("n", "index-{}".format(index)) if isinstance(case, dict) else index
        if error is None:
            passed += 1
        elif stage == "input":
            input_errors += 1
        print("{} case={} stage={}: {}".format(
            "FAIL" if error is not None else "PASS", case_id, stage,
            error if error is not None else "expectation satisfied",
        ))
    failed = len(cases) - passed
    print("Totals: cases={} passed={} failed={} input_errors={}".format(
        len(cases), passed, failed, input_errors
    ))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
