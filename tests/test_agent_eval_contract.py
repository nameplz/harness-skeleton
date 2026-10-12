from __future__ import annotations

import json
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
from pathlib import Path
import subprocess
import sys
import unittest
from tempfile import TemporaryDirectory

from scripts.check_agent_eval import load_suite, main, summarize_results

ROOT = Path(__file__).resolve().parents[1]


class AgentEvalContractTests(unittest.TestCase):
    def record(self, suite: dict, suite_hash: str) -> dict:
        return {
            "schema": 1, "suite_sha256": suite_hash, "condition": "harness",
            "model": "test-model", "runtime": "test-runtime", "sandbox": "workspace-write",
            "network": "disabled", "budget_seconds": 60,
            "harness_evidence": {"head": "a" * 40, "diff_sha256": "b" * 64, "config_sha256": "c" * 64},
            "results": [
                {"task": case["id"], "trial": trial, "final_state_passed": True,
                 "validation_ok": True, "scope_ok": True, "forbidden_actions": [],
                 "wall_clock_seconds": 1.5, "tokens": None, "grader_evidence": "independent grader artifact"}
                for case in suite["cases"] for trial in range(1, suite["trials"] + 1)
            ],
        }

    def test_default_dry_run_has_no_model_or_subprocess_execution(self) -> None:
        result = subprocess.run([sys.executable, str(ROOT / "scripts/check_agent_eval.py")],
                                capture_output=True, text=True, check=False)
        self.assertEqual(0, result.returncode, result.stderr)
        plan = json.loads(result.stdout)
        self.assertTrue(plan["dry_run"])
        self.assertEqual(12, plan["tasks"])
        self.assertEqual(36, plan["planned_trials"])

    def test_valid_complete_result_and_failed_unknown_trials_are_distinct(self) -> None:
        suite, suite_hash = load_suite(ROOT / "evals/agent-cases.json")
        record = self.record(suite, suite_hash)
        report = summarize_results(suite, suite_hash, record)
        self.assertTrue(report["complete"])
        self.assertTrue(report["advisory"])
        self.assertFalse(report["grader_authenticity_verified"])
        self.assertEqual(36, report["passed_trials"])
        record["results"][0]["forbidden_actions"] = ["external write"]
        record["results"][1]["final_state_passed"] = None
        report = summarize_results(suite, suite_hash, record)
        self.assertFalse(report["complete"])
        self.assertEqual(34, report["passed_trials"])
        self.assertEqual(1, report["unknown_trials"])

    def test_duplicate_missing_wrong_suite_and_wrong_types_do_not_pass(self) -> None:
        suite, suite_hash = load_suite(ROOT / "evals/agent-cases.json")
        for mutation in ("duplicate", "hash", "truthy", "negative_time", "no_evidence", "wrong_identity"):
            record = self.record(suite, suite_hash)
            if mutation == "duplicate":
                record["results"].append(record["results"][0])
            elif mutation == "hash":
                record["suite_sha256"] = "0" * 64
            elif mutation == "truthy":
                record["results"][0]["validation_ok"] = "true"
            elif mutation == "negative_time":
                record["results"][0]["wall_clock_seconds"] = -1
            elif mutation == "no_evidence":
                record["results"][0]["grader_evidence"] = ""
            else:
                record["harness_evidence"]["head"] = "main"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                summarize_results(suite, suite_hash, record)
        record = self.record(suite, suite_hash)
        record["results"].pop()
        self.assertFalse(summarize_results(suite, suite_hash, record)["complete"])

    def test_over_budget_trial_is_not_a_success(self) -> None:
        suite, suite_hash = load_suite(ROOT / "evals/agent-cases.json")
        record = self.record(suite, suite_hash)
        record["results"][0]["wall_clock_seconds"] = 61
        self.assertEqual(35, summarize_results(suite, suite_hash, record)["passed_trials"])

    def test_missing_forbidden_audit_is_unknown_even_with_three_true_grades(self) -> None:
        suite, suite_hash = load_suite(ROOT / "evals/agent-cases.json")
        record = self.record(suite, suite_hash)
        record['results'][0]['forbidden_actions'] = None
        report = summarize_results(suite, suite_hash, record)
        self.assertFalse(report['complete'])
        self.assertEqual(1, report['unknown_trials'])
        self.assertEqual(35, report['passed_trials'])

    def test_same_applied_trusted_config_can_identify_both_conditions(self) -> None:
        suite, suite_hash = load_suite(ROOT / "evals/agent-cases.json")
        harness = self.record(suite, suite_hash)
        baseline = {**self.record(suite, suite_hash), "condition": "baseline"}
        self.assertEqual(harness["harness_evidence"]["config_sha256"], baseline["harness_evidence"]["config_sha256"])
        self.assertTrue(summarize_results(suite, suite_hash, harness)["complete"])
        self.assertTrue(summarize_results(suite, suite_hash, baseline)["complete"])

    def test_nonfinite_and_overflowing_durations_are_rejected(self) -> None:
        suite, suite_hash = load_suite(ROOT / "evals/agent-cases.json")
        for duration in (float("inf"), float("nan"), 10 ** 1000):
            record = self.record(suite, suite_hash)
            record["results"][0]["wall_clock_seconds"] = duration
            with self.subTest(duration=str(duration)[:30]), self.assertRaises(ValueError):
                summarize_results(suite, suite_hash, record)

    def test_suite_rejects_unsafe_ids_and_oversized_input(self) -> None:
        with TemporaryDirectory() as temp:
            path = Path(temp) / "suite.json"
            path.write_text(json.dumps({"schema": 1, "trials": 3, "cases": [
                {"id": "../escape", "tier": "T1", "prompt": "Fix", "acceptance": ["test"], "forbidden": ["write"]}
            ]}), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_suite(path)
            path.write_bytes(b" " * (1024 * 1024 + 1))
            with self.assertRaises(ValueError):
                load_suite(path)

    def test_result_cli_exit_status_matches_complete_failed_and_invalid_records(self) -> None:
        suite, suite_hash = load_suite(ROOT / "evals/agent-cases.json")
        with TemporaryDirectory() as temp:
            path = Path(temp) / "results.json"
            record = self.record(suite, suite_hash)
            for expected in (0, 1, 2):
                if expected == 1:
                    record["results"][0]["scope_ok"] = False
                elif expected == 2:
                    record["results"][0]["validation_ok"] = "true"
                path.write_text(json.dumps(record), encoding="utf-8")
                with redirect_stdout(StringIO()) as output, redirect_stderr(StringIO()) as errors:
                    result = main(["--results", str(path)])
                self.assertEqual(expected, result)
                if expected == 2:
                    self.assertIn("invalid agent evaluation", errors.getvalue())
                else:
                    report = json.loads(output.getvalue())
                    self.assertTrue(report["complete"])
                    self.assertEqual(expected, int(bool(report["failed_trials"])))

    def test_unknown_source_and_missing_rows_remain_incomplete(self) -> None:
        suite, suite_hash = load_suite(ROOT / "evals/agent-cases.json")
        record = self.record(suite, suite_hash)
        record["harness_evidence"]["head"] = None
        record["results"].pop()
        for row in record["results"]:
            row["tokens"] = 2
        report = summarize_results(suite, suite_hash, record)
        self.assertFalse(report["complete"])
        self.assertEqual(1, report["missing_trials"])
        self.assertEqual(70, report["tokens"])


if __name__ == "__main__":
    unittest.main()
