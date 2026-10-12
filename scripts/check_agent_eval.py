#!/usr/bin/env python3
"""Validate an opt-in agent evaluation plan/results; never launch a model."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import re
import sys
from typing import Any

DEFAULT_SUITE = Path(__file__).resolve().parents[1] / "evals/agent-cases.json"
MAX_INPUT_BYTES = 1024 * 1024
CASE_FIELDS = frozenset({"id", "tier", "prompt", "acceptance", "forbidden"})
RUN_FIELDS = frozenset({"schema", "suite_sha256", "condition", "model", "runtime", "sandbox",
                        "network", "budget_seconds", "harness_evidence", "results"})
TRIAL_FIELDS = frozenset({"task", "trial", "final_state_passed", "validation_ok", "scope_ok",
                          "forbidden_actions", "wall_clock_seconds", "tokens", "grader_evidence"})
GRADES = ("final_state_passed", "validation_ok", "scope_ok")


def _load_json(path: Path) -> tuple[Any, str]:
    with path.open("rb") as stream:
        raw = stream.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("evaluation input exceeds the size limit")
    return json.loads(raw), hashlib.sha256(raw).hexdigest()


def _text(value: Any, limit: int = 4096) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= limit and not any(
        ord(char) < 32 and char not in "\n\t" for char in value
    )


def _texts(value: Any, *, allow_empty: bool = False) -> bool:
    return isinstance(value, list) and len(value) <= 32 and (bool(value) or allow_empty) and all(
        _text(item) for item in value
    )


def load_suite(path: Path) -> tuple[dict[str, Any], str]:
    suite, digest = _load_json(path)
    if not isinstance(suite, dict) or set(suite) != {"schema", "trials", "cases"}:
        raise ValueError("suite must define schema, trials, and cases")
    if type(suite["schema"]) is not int or suite["schema"] != 1 or type(suite["trials"]) is not int or not 1 <= suite["trials"] <= 10:
        raise ValueError("invalid suite version or trial count")
    if not isinstance(suite["cases"], list) or not 1 <= len(suite["cases"]) <= 64:
        raise ValueError("suite must have 1 to 64 cases")
    names: set[str] = set()
    for case in suite["cases"]:
        if not isinstance(case, dict) or set(case) != CASE_FIELDS:
            raise ValueError("invalid case fields")
        name = case["id"]
        if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,79}", name) or name in names:
            raise ValueError("case IDs must be unique safe slugs")
        if case["tier"] not in ("T0", "T1", "T2", "T3") or not _text(case["prompt"]) or not _texts(case["acceptance"]) or not _texts(case["forbidden"]):
            raise ValueError("invalid case tier, prompt, or criteria")
        names.add(name)
    return suite, digest


def _validate_run(suite_hash: str, record: Any) -> None:
    if not isinstance(record, dict) or set(record) != RUN_FIELDS or type(record["schema"]) is not int or record["schema"] != 1:
        raise ValueError("invalid result record fields or version")
    if record["suite_sha256"] != suite_hash or record["condition"] not in ("baseline", "harness"):
        raise ValueError("result suite/condition mismatch")
    if not all(_text(record[key], 200) for key in ("model", "runtime", "sandbox", "network")):
        raise ValueError("model, runtime, sandbox, and network must be identified")
    if type(record["budget_seconds"]) is not int or not 1 <= record["budget_seconds"] <= 86400:
        raise ValueError("invalid run budget")
    evidence = record["harness_evidence"]
    if not isinstance(evidence, dict) or set(evidence) != {"head", "diff_sha256", "config_sha256"}:
        raise ValueError("invalid harness source identity")
    for key, length in (("head", 40), ("diff_sha256", 64), ("config_sha256", 64)):
        value = evidence[key]
        if value is not None and (not isinstance(value, str) or not re.fullmatch(rf"[0-9a-f]{{{length}}}", value)):
            raise ValueError("invalid harness revision/digest")
    if not isinstance(record["results"], list):
        raise ValueError("results must be a trial list")


def _trial_outcome(row: Any, tasks: set[str], trials: int, budget: int) -> str:
    if not isinstance(row, dict) or set(row) != TRIAL_FIELDS:
        raise ValueError("invalid trial fields")
    if not isinstance(row["task"], str) or row["task"] not in tasks or type(row["trial"]) is not int or not 1 <= row["trial"] <= trials:
        raise ValueError("invalid task/trial identity")
    if any(row[key] is not None and type(row[key]) is not bool for key in GRADES):
        raise ValueError("grades must be boolean or null, never truthy text")
    if (row["forbidden_actions"] is not None and not _texts(row["forbidden_actions"], allow_empty=True)) or not _text(row["grader_evidence"]):
        raise ValueError("trial needs forbidden-action results and grader evidence")
    duration = row["wall_clock_seconds"]
    if type(duration) not in (int, float) or not 0 <= duration <= 86400 or not math.isfinite(duration):
        raise ValueError("invalid trial duration")
    if row["tokens"] is not None and (type(row["tokens"]) is not int or row["tokens"] < 0):
        raise ValueError("invalid token count")
    if row["forbidden_actions"] is None or any(row[key] is None for key in GRADES):
        return "unknown"
    return "passed" if all(row[key] for key in GRADES) and not row["forbidden_actions"] and duration <= budget else "failed"


def summarize_results(suite: dict[str, Any], suite_hash: str, record: Any) -> dict[str, Any]:
    _validate_run(suite_hash, record)
    tasks = {case["id"] for case in suite["cases"]}
    expected = len(tasks) * suite["trials"]
    if len(record["results"]) > expected:
        raise ValueError("too many or duplicate trials")
    outcomes = [_trial_outcome(row, tasks, suite["trials"], record["budget_seconds"]) for row in record["results"]]
    identities = {(row["task"], row["trial"]) for row in record["results"]}
    if len(identities) != len(outcomes):
        raise ValueError("duplicate task/trial results")
    passed = sum(outcome == "passed" for outcome in outcomes)
    unknown = sum(outcome == "unknown" for outcome in outcomes)
    successful = {identity for identity, outcome in zip(
        ((row["task"], row["trial"]) for row in record["results"]), outcomes
    ) if outcome == "passed"}
    return {
        "dry_run": False, "suite_sha256": suite_hash, "condition": record["condition"],
        "advisory": True, "grader_authenticity_verified": False,
        "source": record["harness_evidence"],
        "complete": len(outcomes) == expected and unknown == 0 and all(record["harness_evidence"].values()),
        "planned_trials": expected, "observed_trials": len(outcomes), "missing_trials": expected - len(outcomes),
        "passed_trials": passed, "failed_trials": len(outcomes) - passed - unknown, "unknown_trials": unknown,
        "observed_trial_success_rate": passed / len(outcomes) if outcomes else None,
        "tasks_passing_all_trials": sum(all((task, trial) in successful for trial in range(1, suite["trials"] + 1)) for task in tasks),
        "wall_clock_seconds": sum(row["wall_clock_seconds"] for row in record["results"]),
        "tokens": None if any(row["tokens"] is None for row in record["results"]) else sum(row["tokens"] for row in record["results"]),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", type=Path, default=DEFAULT_SUITE)
    parser.add_argument("--results", type=Path)
    args = parser.parse_args(argv)
    try:
        suite, suite_hash = load_suite(args.suite)
        if args.results is None:
            report = {"dry_run": True, "suite_sha256": suite_hash, "tasks": len(suite["cases"]),
                      "planned_trials": len(suite["cases"]) * suite["trials"]}
        else:
            report = summarize_results(suite, suite_hash, _load_json(args.results)[0])
    except (OSError, UnicodeError, ValueError):
        print("invalid agent evaluation input; check schema, identities, and size limits", file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report["dry_run"] or (report["complete"] and not report["failed_trials"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
