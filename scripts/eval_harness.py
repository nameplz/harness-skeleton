#!/usr/bin/env python3
"""Run deterministic regression cases for Harness risk routing."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
import sys
from typing import Any

try:
    from .harness_common import HarnessError
    from .harness_risk import classify_risk
except ImportError:  # Direct script invocation from the repository root.
    from harness_common import HarnessError
    from harness_risk import classify_risk

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FIXTURE = ROOT / "evals/risk-cases.json"
MAX_FIXTURE_BYTES = 1024 * 1024
MAX_CASES = 100
EXPECTED_FIELDS = {"level", "code_review", "security_review"}
CASE_FIELDS = EXPECTED_FIELDS | {"name", "paths", "diff", "expected", "required_hints", "forbidden_hints"}
RISK_LEVELS = {"T0", "T1", "T2", "T3"}


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate fixture field")
        result[key] = value
    return result


def _load_cases(path: Path) -> list[dict[str, Any]]:
    try:
        if path.is_symlink():
            raise ValueError("fixture must not be a symlink")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as fixture:
            info = os.fstat(fixture.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("fixture must be a regular file")
            if info.st_size > MAX_FIXTURE_BYTES:
                raise ValueError("fixture exceeds size limit")
            raw = fixture.read(MAX_FIXTURE_BYTES + 1)
        if len(raw) > MAX_FIXTURE_BYTES:
            raise ValueError("fixture exceeds size limit")
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("could not read fixture") from exc
    if not isinstance(payload, dict) or set(payload) != {"cases"}:
        raise ValueError("top level must contain only cases")
    cases = payload["cases"]
    if not isinstance(cases, list) or not cases or len(cases) > MAX_CASES:
        raise ValueError("cases must be a non-empty list with at most 100 entries")
    for index, case in enumerate(cases):
        if not isinstance(case, dict) or set(case) - CASE_FIELDS:
            raise ValueError(f"case {index} has invalid fields")
        if not {"name", "paths", "diff", "expected"} <= set(case):
            raise ValueError(f"case {index} is missing required fields")
        if (
            not isinstance(case["name"], str)
            or not case["name"].strip()
            or len(case["name"]) > 160
            or _has_control_characters(case["name"])
        ):
            raise ValueError(f"case {index} has invalid name")
        if not isinstance(case["paths"], list) or any(not isinstance(path, str) for path in case["paths"]):
            raise ValueError(f"case {index} paths must be a string list")
        if not isinstance(case["diff"], str) or len(case["diff"].encode("utf-8")) > MAX_FIXTURE_BYTES:
            raise ValueError(f"case {index} diff must be bounded text")
        expected = case["expected"]
        if not isinstance(expected, dict) or set(expected) != EXPECTED_FIELDS:
            raise ValueError(f"case {index} expected must define risk level and review routes")
        if not isinstance(expected["level"], str) or expected["level"] not in RISK_LEVELS or any(
            type(expected[field]) is not bool for field in EXPECTED_FIELDS - {"level"}
        ):
            raise ValueError(f"case {index} expected values are invalid")
        for field in ("required_hints", "forbidden_hints"):
            values = case.get(field, [])
            if not isinstance(values, list) or any(
                not isinstance(value, str) or not value or _has_control_characters(value) for value in values
            ):
                raise ValueError(f"case {index} {field} must be a non-empty string list")
    return cases


def _has_control_characters(value: str) -> bool:
    return any(ord(char) < 32 or ord(char) == 127 for char in value)


def evaluate_cases(cases: list[dict[str, Any]]) -> list[str]:
    mismatches: list[str] = []
    for case in cases:
        assessment = classify_risk(case["paths"], case["diff"])
        actual = assessment.to_dict()
        for field, expected in case["expected"].items():
            if actual[field] != expected:
                mismatches.append(
                    f"{case['name']}: expected {field}={expected!r}, got {actual[field]!r}"
                )
        for hint in case.get("required_hints", []):
            if not any(hint in value for value in assessment.hints):
                mismatches.append(f"{case['name']}: missing hint {hint!r}")
        for hint in case.get("forbidden_hints", []):
            if any(hint in value for value in assessment.hints):
                mismatches.append(f"{case['name']}: unexpected hint {hint!r}")
    return mismatches


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    args = parser.parse_args(argv)
    try:
        cases = _load_cases(args.fixture)
        mismatches = evaluate_cases(cases)
    except (HarnessError, ValueError) as exc:
        print(f"invalid risk eval fixture: {exc}", file=sys.stderr)
        return 2
    if mismatches:
        print("risk eval failed:")
        for mismatch in mismatches:
            print(f"- {mismatch}")
        return 1
    print(f"risk eval: {len(cases)} cases passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
