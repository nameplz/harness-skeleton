from __future__ import annotations

import ast
from io import BytesIO
from pathlib import Path
import subprocess
import sys
import unittest
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scripts.check_ci_security import is_sensitive_path
from scripts.command_runner import CommandResult
from scripts.harness import HarnessError, doctor, run_checks
from scripts.harness_risk import classify_risk, inspect_git_risk
from tests import test_harness as baseline
from tests import test_harness_doctor as doctor_fixtures

ROOT = Path(__file__).resolve().parents[1]
CONTROL_PATHS = (
    "AGENTS.md", ".agents/skills/harness/SKILL.md", ".agents/skills/pr-workflow/SKILL.md",
    "scripts/github_expression_scanner.py", "scripts/command_runner.py",
    "packages/foo/AGENTS.md", ".agents/skills/other/SKILL.md",
)


class HarnessRegressionTests(unittest.TestCase):
    def git(self, root: Path, *arguments: str) -> str:
        result = subprocess.run(["git", *arguments], cwd=root, capture_output=True,
                                text=True, check=False)
        self.assertEqual(0, result.returncode, result.stderr)
        return result.stdout.strip()

    def config(self, root: Path) -> None:
        baseline.HarnessCheckTests.write_config(self, root, [["true"]], [["true"]])

    def test_control_files_are_protected_by_both_policy_layers(self) -> None:
        for path in CONTROL_PATHS:
            with self.subTest(path=path):
                self.assertTrue(is_sensitive_path(path))
                self.assertEqual("T3", classify_risk([path], "").level)
        self.assertEqual("T0", classify_risk(["docs/guide.md"], "+authorization").level)
        self.assertFalse(is_sensitive_path("docs/guide.md"))

    def test_trusted_validators_and_their_local_imports_are_protected(self) -> None:
        pending = ["harness.py", "check_ci_security.py", "check_pr_contract.py"]
        visited = set()
        while pending:
            name = pending.pop()
            if name in visited:
                continue
            visited.add(name)
            relative = "scripts/" + name
            self.assertTrue(is_sensitive_path(relative), relative)
            self.assertEqual("T3", classify_risk([relative], "").level, relative)
            for node in ast.walk(ast.parse((ROOT / relative).read_text(encoding="utf-8"))):
                if isinstance(node, ast.ImportFrom) and node.module:
                    dependency = node.module.rsplit(".", 1)[-1] + ".py"
                    if (ROOT / "scripts" / dependency).is_file():
                        pending.append(dependency)

    def test_untracked_reader_requests_only_limit_plus_one_bytes(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.git(root, "init", "-q")
            target = root.resolve() / "large.txt"
            target.write_bytes(b"x" * 17)
            requested = []
            original = Path.open

            class Reader(BytesIO):
                def read(self, size: int = -1) -> bytes:
                    requested.append(size)
                    return super().read(size)

            def opened(path, *args, **kwargs):
                if path == target and args == ("rb",):
                    return Reader(b"x" * 17)
                return original(path, *args, **kwargs)

            with patch("scripts.harness_risk.MAX_UNTRACKED_FILE_BYTES", 16), patch.object(Path, "open", opened):
                with self.assertRaisesRegex(HarnessError, "untracked file exceeds"):
                    inspect_git_risk(root, load_config_fn=lambda _: None)
            self.assertEqual([17], requested)

    def test_untracked_boundary_and_symlink_are_handled(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.git(root, "init", "-q")
            (root / "value.txt").write_bytes(b"x" * 16)
            (root / "link.txt").symlink_to("value.txt")
            with patch("scripts.harness_risk.MAX_UNTRACKED_FILE_BYTES", 16):
                result = inspect_git_risk(root, load_config_fn=lambda _: None)
            self.assertIn("value.txt", result.changed_paths)

    def test_doctor_requires_pr_workflow_and_executable_hook_shape(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.git(root, "init", "-q")
            self.config(root)
            doctor_fixtures._write_doctor_files(root)
            self.assertTrue(doctor(root)["ok"])
            (root / ".agents/skills/pr-workflow/SKILL.md").unlink()
            self.assertIn(".agents/skills/pr-workflow/SKILL.md", doctor(root)["errors"])
            path = root / ".codex/config.toml"
            good = path.read_text(encoding="utf-8")
            for replacement in ("echo", "false", "python3 -c"):
                with self.subTest(replacement=replacement):
                    path.write_text(good.replace("python3 ", replacement + " "), encoding="utf-8")
                    self.assertTrue(any("Harness hook" in item for item in doctor(root)["errors"]))
            path.write_text(good.replace('type = "command"', 'type = "prompt"'), encoding="utf-8")
            self.assertTrue(any("Harness hook" in item for item in doctor(root)["errors"]))
            path.write_text(good.replace('matcher = "^Bash$"', 'matcher = "^Other$"'), encoding="utf-8")
            self.assertTrue(any("Harness hook" in item for item in doctor(root)["errors"]))

    def test_check_metadata_distinguishes_limits_start_errors_and_aggregate_deadline(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.config(root)
            for result, reason in ((CommandResult(124, "", timed_out=True), "timeout"),
                                   (CommandResult(125, "", output_limited=True), "output_limit")):
                with self.subTest(reason=reason), patch("scripts.harness.run_bounded_command", return_value=result):
                    item = run_checks(root, "quick")["checks"][0]
                    self.assertEqual(reason, item["failure_reason"])
                    self.assertEqual(result.timed_out, item["timed_out"])
                    self.assertEqual(result.output_limited, item["output_limited"])
                    self.assertTrue(item["started"])
                    self.assertGreaterEqual(item["duration_ms"], 0)
            with patch("scripts.harness.run_bounded_command", side_effect=OSError("private detail")):
                item = run_checks(root, "quick")["checks"][0]
                self.assertEqual("start_failed", item["failure_reason"])
                self.assertFalse(item["started"])
            with patch("scripts.harness.CHECK_QUICK_TIMEOUT_SECONDS", 0):
                item = run_checks(root, "quick")["checks"][0]
                self.assertEqual("aggregate_timeout", item["failure_reason"])
                self.assertFalse(item["started"])
                self.assertIsNone(item["duration_ms"])

    def test_evidence_changes_when_dirty_content_changes_without_status_changes(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.config(root)
            self.git(root, "init", "-q")
            self.git(root, "add", ".")
            self.git(root, "-c", "user.name=Test", "-c", "user.email=test@example.test", "commit", "-qm", "base")
            head = self.git(root, "rev-parse", "HEAD")
            target = root / "new.bin"
            target.write_bytes(b"\xfffirst")
            first = run_checks(root, "quick")
            target.write_bytes(b"\xfesecond")
            second = run_checks(root, "quick")
            self.assertEqual(head, first["evidence"]["head"])
            self.assertTrue(first["evidence"]["dirty"])
            self.assertNotEqual(first["evidence"]["diff_sha256"], second["evidence"]["diff_sha256"])
            self.assertTrue(first["evidence_unchanged"])

    def test_unknown_git_identity_does_not_break_checks_and_trusted_config_is_hashed(self) -> None:
        with TemporaryDirectory() as temp, TemporaryDirectory() as trusted:
            root, config_root = Path(temp), Path(trusted)
            self.config(root)
            self.config(config_root)
            path = config_root / ".harness/config.toml"
            path.write_text(path.read_text(encoding="utf-8") + "\n# trusted config\n", encoding="utf-8")
            report = run_checks(root, "quick", config_root=config_root)
            import hashlib

            self.assertTrue(report["ok"])
            self.assertIsNone(report["evidence"]["head"])
            self.assertIsNone(report["evidence"]["dirty"])
            self.assertIsNone(report["evidence_unchanged"])
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), report["evidence"]["config_sha256"])

    def test_source_change_during_check_invalidates_evidence(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.git(root, "init", "-q")
            self.config(root)

            def changed(*args, **kwargs):
                (root / "new.txt").write_text("changed\n", encoding="utf-8")
                return CommandResult(0, "")

            with patch("scripts.harness.run_bounded_command", side_effect=changed):
                report = run_checks(root, "quick")
            self.assertFalse(report["evidence_unchanged"])
            self.assertFalse(report["ok"])

    def test_git_identity_appearing_during_check_invalidates_evidence(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.config(root)

            def initialized(*args, **kwargs):
                self.git(root, "init", "-q")
                return CommandResult(0, "")

            with patch("scripts.harness.run_bounded_command", side_effect=initialized):
                report = run_checks(root, "quick")
            self.assertFalse(report["ok"])
            self.assertFalse(report["evidence_unchanged"])


    def test_evidence_git_commands_share_a_five_second_budget(self) -> None:
        from scripts.harness_evidence import capture_workspace

        with patch("scripts.harness_evidence.time.monotonic", side_effect=[0, 6]), patch(
            "scripts.harness_evidence._git_output"
        ) as git:
            evidence = capture_workspace(ROOT)
        self.assertIsNone(evidence["diff_sha256"])
        git.assert_not_called()

    def test_known_git_evidence_error_prevents_validation(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.git(root, "init", "-q")
            self.config(root)
            (root / "oversized.bin").write_bytes(b"x" * 17)
            with patch("scripts.harness_risk.MAX_UNTRACKED_FILE_BYTES", 16), patch(
                "scripts.harness.run_bounded_command"
            ) as command:
                report = run_checks(root, "quick")
            self.assertFalse(report["ok"])
            self.assertEqual("error", report["evidence"]["status"])
            self.assertFalse(report["checks"][0]["started"])
            self.assertEqual("identity_error", report["checks"][0]["failure_reason"])
            command.assert_not_called()

    def test_gitignore_preserves_original_secret_and_build_exclusions(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.git(root, "init", "-q")
            (root / ".gitignore").write_bytes((ROOT / ".gitignore").read_bytes())
            for name in (".env", "node_modules/x", ".next/x", "out/x", "next-env.d.ts",
                         "tsconfig.tsbuildinfo", ".worktrees/x", ".harness-changed-files.txt", ".coverage"):
                with self.subTest(name=name):
                    self.assertEqual(name, self.git(root, "check-ignore", name))


if __name__ == "__main__":
    unittest.main()
