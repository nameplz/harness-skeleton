from __future__ import annotations

import json
from pathlib import Path
import sys
import unittest
from tempfile import TemporaryDirectory
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.command_runner import CommandResult  # noqa: E402
from scripts.verify_ci import (  # noqa: E402
    CI_CONTROL_FILES,
    VerificationError,
    _check_status,
    _match_required_checks,
    _require_tracked_ci_inputs,
    _valid_repository,
    verify_ci,
)
from tests.test_ci_security import setup_project, valid_workflow  # noqa: E402

HEAD = "a" * 40
EXPECTED_CI_CONTROL_FILES = (
    "scripts/command_runner.py", "scripts/harness.py", "scripts/harness_doctor.py",
    "scripts/harness_common.py", "scripts/harness_evidence.py", "scripts/harness_risk.py",
    "scripts/github_expression_scanner.py", "scripts/check_ci_security.py",
    "scripts/ci_action_policy.py", "scripts/verify_ci.py",
)


class VerifyCiTests(unittest.TestCase):
    def test_tracked_ci_control_file_set_includes_every_policy_module(self) -> None:
        self.assertEqual(EXPECTED_CI_CONTROL_FILES, CI_CONTROL_FILES)

    def project(self, root: Path) -> None:
        setup_project(root)
        (root / ".github/workflows/ci.yml").write_text(
            valid_workflow(name="Project CI", job_id="project_tests", job_name="Project tests"),
            encoding="utf-8",
        )
        for relative_path in CI_CONTROL_FILES:
            path = root / relative_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()

    def evidence(self, *, head: str = HEAD, dirty: bool = False, digest: str = "d" * 64) -> dict:
        return {"status": "ok", "head": head, "dirty": dirty, "diff_sha256": digest}

    def github(self, checks: list[dict], *, latest_head: str = HEAD, first_head: str = HEAD):
        pr_reads = 0

        def command(argv, **_kwargs):
            nonlocal pr_reads
            if argv[0] == "git" and argv[1:3] == ["ls-files", "-v"]:
                tracked = [".harness/config.toml", ".github/workflows/ci.yml", *CI_CONTROL_FILES]
                return CommandResult(0, "\0".join(f"H {path}" for path in tracked) + "\0")
            if argv[1:3] == ["repo", "view"]:
                return CommandResult(0, json.dumps({"nameWithOwner": "owner/project"}))
            if argv[1:3] == ["pr", "view"]:
                pr_reads += 1
                head = first_head if pr_reads == 1 else latest_head
                return CommandResult(0, json.dumps({
                    "number": 42, "state": "OPEN", "headRefOid": head,
                    "baseRefName": "main", "url": "https://github.com/owner/project/pull/42",
                }))
            if argv[1:3] == ["pr", "checks"]:
                code = 1 if any(item.get("bucket") == "fail" for item in checks) else 8 if any(
                    item.get("bucket") == "pending" for item in checks
                ) else 0
                return CommandResult(code, json.dumps(checks))
            raise AssertionError(argv)

        return command

    def check_row(self, *, state: str = "SUCCESS", bucket: str = "pass", name: str = "Project CI / Project tests",
                  workflow: str = "Project CI", event: str = "pull_request") -> dict:
        return {"name": name, "state": state, "bucket": bucket, "workflow": workflow,
                "event": event, "link": "https://github.com/check/1", "startedAt": "2026-10-23T00:00:00Z"}

    def test_all_required_full_profile_jobs_success_for_current_pr_revision(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.project(root)
            with patch("scripts.verify_ci.capture_workspace", side_effect=[self.evidence(), self.evidence()]), \
                 patch("scripts.verify_ci.run_bounded_command", side_effect=self.github([self.check_row()])) as gh:
                result = verify_ci(root, 42)
            self.assertTrue(result["ok"])
            self.assertEqual("success", result["status"])
            self.assertEqual(HEAD, result["head_sha"])
            self.assertEqual("project_tests", result["required_checks"][0]["job_id"])
            self.assertTrue(any(call.args[0][1:3] == ["pr", "checks"] for call in gh.call_args_list))

    def test_failed_pending_cancelled_skipped_missing_and_unrelated_checks_are_not_success(self) -> None:
        cases = (
            ([self.check_row(state="FAILURE", bucket="fail")], "failure"),
            ([self.check_row(state="IN_PROGRESS", bucket="pending")], "pending"),
            ([self.check_row(state="CANCELLED", bucket="cancel")], "cancelled"),
            ([self.check_row(state="SKIPPED", bucket="skipping")], "skipped"),
            ([self.check_row(state="STALE", bucket="")], "skipped"),
            ([], "missing"),
            ([self.check_row(name="Unrelated workflow / Project tests", workflow="Unrelated workflow")], "missing"),
            ([self.check_row(event="push")], "missing"),
        )
        for checks, status in cases:
            with self.subTest(status=status), TemporaryDirectory() as temp:
                root = Path(temp)
                self.project(root)
                with patch("scripts.verify_ci.capture_workspace", side_effect=[self.evidence(), self.evidence()]), \
                     patch("scripts.verify_ci.run_bounded_command", side_effect=self.github(checks)):
                    result = verify_ci(root, 42)
                self.assertFalse(result["ok"])
                self.assertEqual(status, result["status"])

    def test_job_display_names_containing_slashes_match_without_truncation(self) -> None:
        required = [{
            "workflow": "Project CI", "workflow_path": ".github/workflows/ci.yml",
            "job_id": "project_tests", "job_name": "Project / tests",
        }]
        checks = [self.check_row(name="Project CI / Project / tests")]
        result = _match_required_checks(required, checks)
        self.assertEqual("success", result[0]["status"])

    def test_undated_pending_run_cannot_be_hidden_by_an_older_success(self) -> None:
        expected = [{
            "workflow": "Project CI", "workflow_path": ".github/workflows/ci.yml",
            "job_id": "project_tests", "job_name": "Project tests",
        }]
        pending = self.check_row(state="IN_PROGRESS", bucket="pending")
        pending["startedAt"] = None
        result = _match_required_checks(expected, [self.check_row(), pending])
        self.assertEqual("pending", result[0]["status"])

    def test_check_matches_full_job_display_name_instead_of_an_id_alias(self) -> None:
        expected = [
            {"workflow": "Project CI", "workflow_path": ".github/workflows/ci.yml",
             "job_id": "foo", "job_name": "A"},
            {"workflow": "Project CI", "workflow_path": ".github/workflows/ci.yml",
             "job_id": "bar", "job_name": "foo"},
        ]
        checks = [self.check_row(name="Project CI / foo")]
        result = _match_required_checks(expected, checks)
        self.assertEqual(["missing", "success"], [item["status"] for item in result])

    def test_non_full_job_id_cannot_impersonate_the_full_job_display_name(self) -> None:
        required = [{
            "workflow": "Project CI", "workflow_path": ".github/workflows/ci.yml",
            "job_id": "full", "job_name": "Actual Full Tests",
        }]
        checks = [self.check_row(name="Project CI / full")]
        result = _match_required_checks(required, checks)
        self.assertEqual("missing", result[0]["status"])

    def test_contradictory_github_check_fields_cannot_report_success(self) -> None:
        for row, expected in (
            ({"bucket": "pass", "state": "STALE"}, "skipped"),
            ({"bucket": "pass", "state": "FAILURE"}, "failure"),
            ({"bucket": "pass", "state": "CANCELLED"}, "cancelled"),
            ({"bucket": "fail", "state": "SUCCESS"}, "failure"),
            ({"bucket": "pass", "state": "UNKNOWN"}, "blocked"),
            ({"bucket": "new-value", "state": "SUCCESS"}, "blocked"),
            ({"state": "SUCCESS"}, "blocked"),
        ):
            with self.subTest(row=row):
                self.assertEqual(expected, _check_status(row))

    def test_matrix_suffix_check_does_not_impersonate_an_exact_full_check(self) -> None:
        required = [{"workflow": "Project CI", "workflow_path": ".github/workflows/ci.yml",
                     "job_id": "project_tests", "job_name": "Project tests"}]
        checks = [self.check_row(name="Project CI / Project tests (ubuntu-24.04)")]
        result = _match_required_checks(required, checks)
        self.assertEqual("missing", result[0]["status"])

    def test_stale_or_changed_pr_revision_cannot_be_verified(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.project(root)
            old_head = "b" * 40
            with patch("scripts.verify_ci.capture_workspace", side_effect=[self.evidence(), self.evidence()]), \
                 patch("scripts.verify_ci.run_bounded_command", side_effect=self.github([self.check_row()], latest_head=old_head)):
                changed = verify_ci(root, 42)
            self.assertEqual("blocked", changed["status"])
            self.assertIn("head changed", changed["errors"][0])

        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.project(root)
            with patch("scripts.verify_ci.capture_workspace", return_value=self.evidence(head="c" * 40)), \
                 patch("scripts.verify_ci.run_bounded_command", side_effect=self.github([self.check_row()])):
                mismatch = verify_ci(root, 42)
            self.assertEqual("blocked", mismatch["status"])
            self.assertIn("does not match", mismatch["errors"][0])

    def test_local_changes_or_changes_during_remote_lookup_block_verification(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.project(root)
            with patch("scripts.verify_ci.capture_workspace", return_value=self.evidence(dirty=True)):
                dirty = verify_ci(root, 42)
            self.assertEqual("blocked", dirty["status"])

        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.project(root)
            before = self.evidence()
            after = self.evidence(digest="e" * 64)
            with patch("scripts.verify_ci.capture_workspace", side_effect=[before, after]), \
                 patch("scripts.verify_ci.run_bounded_command", side_effect=self.github([self.check_row()])):
                changed = verify_ci(root, 42)
            self.assertEqual("blocked", changed["status"])
            self.assertIn("changed during", changed["errors"][0])

    def test_ignored_ci_config_cannot_be_used_for_verification(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.project(root)
            with patch("scripts.verify_ci.capture_workspace", return_value=self.evidence()), \
                 patch("scripts.verify_ci.run_bounded_command",
                       return_value=CommandResult(0, "H .github/workflows/ci.yml\0")):
                result = verify_ci(root, 42)
        self.assertEqual("blocked", result["status"])
        self.assertIn("committed", result["errors"][0])

    def test_config_change_during_github_lookup_blocks_verification(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.project(root)
            config_path = root / ".harness/config.toml"
            command = self.github([self.check_row()])

            def mutate_config(argv, **kwargs):
                result = command(argv, **kwargs)
                if argv[1:3] == ["pr", "checks"]:
                    config_path.write_text(
                        config_path.read_text(encoding="utf-8").replace("python", "python3", 1),
                        encoding="utf-8",
                    )
                return result

            with patch("scripts.verify_ci.capture_workspace", side_effect=[self.evidence(), self.evidence()]), \
                 patch("scripts.verify_ci.run_bounded_command", side_effect=mutate_config):
                result = verify_ci(root, 42)
        self.assertEqual("blocked", result["status"])
        self.assertIn("configuration changed", result["errors"][0])

    def test_api_authentication_failure_timeout_and_actions_disabled_are_blocked(self) -> None:
        failures = (
            CommandResult(1, "HTTP 403 Forbidden"),
            CommandResult(124, "", timed_out=True),
            CommandResult(1, "Actions has been disabled for this repository"),
        )
        for failure in failures:
            with self.subTest(output=failure.output), TemporaryDirectory() as temp:
                root = Path(temp)
                self.project(root)
                with patch("scripts.verify_ci.capture_workspace", return_value=self.evidence()), \
                     patch("scripts.verify_ci.run_bounded_command", return_value=failure):
                    result = verify_ci(root, 42)
                self.assertFalse(result["ok"])
                self.assertEqual("blocked", result["status"])

    def test_invalid_pr_and_repository_inputs_are_blocked(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.project(root)
            self.assertEqual("blocked", verify_ci(root, 0)["status"])
            self.assertEqual("blocked", verify_ci(root, 42, repository="../other")["status"])
        for invalid in ("../other", "foo/../bar", "foo/./bar"):
            self.assertFalse(_valid_repository(invalid), invalid)
        for valid in ("owner/repo", "github.com/owner/repo"):
            self.assertTrue(_valid_repository(valid), valid)

    def test_import_failure_for_required_control_script_is_structured(self) -> None:
        with TemporaryDirectory() as temp:
            with patch("scripts.verify_ci._require_tracked_ci_inputs", side_effect=ImportError("missing helper")):
                report = verify_ci(Path(temp), 42)
        self.assertEqual("blocked", report["status"])
        self.assertIn("local CI control scripts", report["errors"][0])

    def test_tracked_input_index_flags_and_symlinks_block_verification(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.project(root)
            tracked = [".harness/config.toml", ".github/workflows/ci.yml", *CI_CONTROL_FILES]
            flagged = [f"H {path}" for path in tracked]
            flagged[0] = f"s {tracked[0]}"
            with patch("scripts.verify_ci.run_bounded_command",
                       return_value=CommandResult(0, "\0".join(flagged) + "\0")):
                with self.assertRaisesRegex(VerificationError, "index flags"):
                    _require_tracked_ci_inputs(root)

        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.project(root)
            config = root / ".harness/config.toml"
            target = root / ".harness/other.toml"
            config.replace(target)
            config.symlink_to(target)
            with patch("scripts.verify_ci.run_bounded_command",
                       return_value=CommandResult(0, "\0".join(f"H {path}" for path in
                           [".harness/config.toml", ".github/workflows/ci.yml", *CI_CONTROL_FILES]) + "\0")):
                with self.assertRaisesRegex(VerificationError, "regular files"):
                    _require_tracked_ci_inputs(root)


if __name__ == "__main__":
    unittest.main()
