from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from io import StringIO
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scripts.harness import doctor, main


class HarnessDoctorTests(unittest.TestCase):
    def write_config(self, root: Path, quick: list[list[str]], full: list[list[str]]) -> Path:
        config = root / ".harness/config.toml"
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text(
            "schema = 2\n\n[checks]\n"
            f"quick = {json.dumps(quick)}\n"
            f"full = {json.dumps(full)}\n",
            encoding="utf-8",
        )
        return config

    def run_git(self, root: Path, *arguments: str) -> None:
        completed = subprocess.run(
            ["git", *arguments], cwd=root, capture_output=True, text=True,
            check=False, shell=False, env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1"},
        )
        self.assertEqual(0, completed.returncode, completed.stderr)

    def test_doctor_checks_required_files_config_and_git_state(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_config(root, [["true"]], [["true"]])
            _write_doctor_files(root)
            self.run_git(root, "init", "-q")
            self.run_git(root, "config", "user.name", "Harness Test")
            self.run_git(root, "config", "user.email", "harness@example.test")
            self.run_git(root, "add", ".")
            self.run_git(root, "-c", "user.name=Harness Test", "-c", "user.email=harness@example.test", "commit", "-qm", "baseline")
            (root / "notes.txt").write_text("dirty\n", encoding="utf-8")
            output = StringIO()

            with redirect_stdout(output):
                exit_code = main(["doctor", "--root", str(root)])

            report = json.loads(output.getvalue())
            self.assertEqual(0, exit_code)
            self.assertTrue(report["ok"])
            self.assertGreater(report["git"]["changed_paths"], 0)
            self.assertEqual(1, report["config"]["quick_checks"])

    def test_bootstrap_doctor_accepts_missing_ci_without_reporting_it_configured(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            _write_doctor_files(root)
            (root / ".harness/config.toml").unlink()
            (root / ".github/workflows/ci.yml").unlink()
            (root / ".github/workflows").rmdir()
            self.run_git(root, "init", "-q")

            bootstrap = doctor(root, bootstrap=True)
            regular = doctor(root)

            self.assertTrue(bootstrap["ok"], bootstrap["errors"])
            self.assertEqual("unconfigured", bootstrap["status"])
            self.assertFalse(regular["ok"])
            self.assertEqual("unconfigured", regular["status"])
            self.assertTrue(any("unconfigured" in error for error in regular["errors"]))

    def test_doctor_uses_trusted_config_root_for_ci_policy(self) -> None:
        with TemporaryDirectory() as temp, TemporaryDirectory() as trusted_temp:
            root, trusted = Path(temp), Path(trusted_temp)
            _write_doctor_files(root)
            self.write_config(trusted, [["python", "-m", "unittest"]], [["python", "-m", "unittest"]])
            (root / ".harness/config.toml").unlink()
            self.run_git(root, "init", "-q")

            report = doctor(root, config_root=trusted)

        self.assertTrue(report["ok"], report["errors"])
        self.assertEqual("configured", report["config"]["status"])
        self.assertEqual("configured", report["ci"]["status"])

    def test_doctor_returns_structured_error_when_extracted_module_is_missing(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            with patch.dict(sys.modules, {"scripts.harness_doctor": None, "harness_doctor": None}):
                report = doctor(root, bootstrap=True)
        self.assertFalse(report["ok"])
        self.assertEqual("invalid", report["status"])
        self.assertTrue(any("doctor module" in error for error in report["errors"]))

    def test_bootstrap_doctor_does_not_hide_invalid_existing_ci(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            _write_doctor_files(root)
            workflow = root / ".github/workflows/ci.yml"
            workflow.write_text(
                workflow.read_text(encoding="utf-8").replace("permissions: {}", "permissions: write-all", 1),
                encoding="utf-8",
            )
            report = doctor(root, bootstrap=True)
        self.assertFalse(report["ok"])
        self.assertEqual("invalid", report["ci"]["status"])
        self.assertTrue(any("permissions" in error for error in report["errors"]))

    def test_doctor_reports_malformed_workflow_directory_instead_of_unconfigured(self) -> None:
        for kind in ("file", "symlink"):
            with self.subTest(kind=kind), TemporaryDirectory() as temp, TemporaryDirectory() as outside:
                root = Path(temp)
                _write_doctor_files(root)
                workflow_dir = root / ".github/workflows"
                for workflow in workflow_dir.iterdir():
                    workflow.unlink()
                workflow_dir.rmdir()
                if kind == "file":
                    workflow_dir.write_text("not a directory", encoding="utf-8")
                else:
                    target = Path(outside) / "workflows"
                    target.mkdir()
                    workflow_dir.symlink_to(target, target_is_directory=True)
                report = doctor(root, bootstrap=True)
            self.assertFalse(report["ok"])
            self.assertEqual("invalid", report["ci"]["status"])
            self.assertTrue(any(".github/workflows" in error for error in report["errors"]))

    def test_doctor_reports_workflow_inspection_errors_without_crashing(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            _write_doctor_files(root)
            self.run_git(root, "init", "-q")
            with patch("scripts.check_ci_security.workflow_files", side_effect=PermissionError("denied")):
                report = doctor(root, bootstrap=True)
        self.assertFalse(report["ok"])
        self.assertEqual("invalid", report["ci"]["status"])
        self.assertTrue(any("could not be inspected" in error for error in report["errors"]))

    def test_doctor_reports_missing_required_file(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_config(root, [["true"]], [["true"]])
            _write_doctor_files(root)
            (root / "scripts/github_expression_scanner.py").unlink()
            self.run_git(root, "init", "-q")
            output = StringIO()

            with redirect_stdout(output):
                exit_code = main(["doctor", "--root", str(root)])

            report = json.loads(output.getvalue())
            self.assertEqual(1, exit_code)
            self.assertFalse(report["ok"])
            self.assertIn("scripts/github_expression_scanner.py", report["errors"])

    def test_doctor_rejects_missing_reviewer_role(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_config(root, [["true"]], [["true"]])
            _write_doctor_files(root)
            (root / ".codex/agents/reviewer.toml").unlink()

            report = doctor(root)

            self.assertFalse(report["ok"])
            self.assertTrue(any("reviewer" in error for error in report["errors"]))

    def test_doctor_rejects_missing_reviewer_role_declaration(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_config(root, [["true"]], [["true"]])
            _write_doctor_files(root)
            project = root / ".codex/config.toml"
            project.write_text(
                project.read_text(encoding="utf-8").replace(
                    '[agents.reviewer]\nconfig_file = "agents/reviewer.toml"\n', ""
                ),
                encoding="utf-8",
            )

            report = doctor(root)

            self.assertFalse(report["ok"])
            self.assertIn(".codex/config.toml (missing reviewer role)", report["errors"])

    def test_doctor_rejects_invalid_reviewer_toml(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_config(root, [["true"]], [["true"]])
            _write_doctor_files(root)
            (root / ".codex/agents/reviewer.toml").write_text("sandbox_mode = [", encoding="utf-8")

            report = doctor(root)

            self.assertFalse(report["ok"])
            self.assertTrue(any("reviewer" in error and "invalid" in error for error in report["errors"]))

    def test_doctor_rejects_reviewer_config_path_escape(self) -> None:
        for config_file in ("../reviewer.toml", "/tmp/reviewer.toml"):
            with self.subTest(config_file=config_file), TemporaryDirectory() as temp:
                root = Path(temp)
                self.write_config(root, [["true"]], [["true"]])
                _write_doctor_files(root)
                project = root / ".codex/config.toml"
                content = project.read_text(encoding="utf-8").replace(
                    'config_file = "agents/reviewer.toml"',
                    f'config_file = {json.dumps(config_file)}',
                )
                project.write_text(content, encoding="utf-8")

                report = doctor(root)

                self.assertFalse(report["ok"])
                self.assertTrue(any("reviewer" in error and "config_file" in error for error in report["errors"]))

    def test_doctor_rejects_reviewer_symlink_escape(self) -> None:
        with TemporaryDirectory() as temp, TemporaryDirectory() as outside:
            root = Path(temp)
            self.write_config(root, [["true"]], [["true"]])
            _write_doctor_files(root)
            external = Path(outside) / "reviewer.toml"
            external.write_text('sandbox_mode = "read-only"\ndeveloper_instructions = "review"\n', encoding="utf-8")
            reviewer = root / ".codex/agents/reviewer.toml"
            reviewer.unlink()
            reviewer.symlink_to(external)

            report = doctor(root)

            self.assertFalse(report["ok"])
            self.assertTrue(any("reviewer" in error for error in report["errors"]))

    def test_doctor_requires_read_only_and_nonempty_reviewer_instructions(self) -> None:
        cases = (
            ('sandbox_mode = "workspace-write"', "read-only"),
            ('developer_instructions = "   "', "developer_instructions"),
        )
        for replacement, expected in cases:
            with self.subTest(expected=expected), TemporaryDirectory() as temp:
                root = Path(temp)
                self.write_config(root, [["true"]], [["true"]])
                _write_doctor_files(root)
                reviewer = root / ".codex/agents/reviewer.toml"
                content = reviewer.read_text(encoding="utf-8")
                if expected == "read-only":
                    content = content.replace('sandbox_mode = "read-only"', replacement)
                else:
                    content = content.replace(
                        'developer_instructions = "read-only review"', replacement
                    )
                reviewer.write_text(content, encoding="utf-8")

                report = doctor(root)

                self.assertFalse(report["ok"])
                self.assertTrue(any(expected in error for error in report["errors"]))

    def test_doctor_accepts_roles_without_model_pinning(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_config(root, [["true"]], [["true"]])
            _write_doctor_files(root)
            self.run_git(root, "init", "-q")

            report = doctor(root)

            self.assertTrue(report["ok"], report["errors"])

    def test_doctor_preserves_docs_and_deployment_layout_checks(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_config(root, [["true"]], [["true"]])
            _write_doctor_files(root)
            (root / "AGENTS.md").write_text("See {missing_policy}.\n", encoding="utf-8")
            (root / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")
            ignored = root / "node_modules/pkg/Dockerfile"
            ignored.parent.mkdir(parents=True)
            ignored.write_text("FROM scratch\n", encoding="utf-8")
            self.run_git(root, "init", "-q")

            report = doctor(root)

            self.assertFalse(report["ok"])
            self.assertTrue(any("placeholder" in error for error in report["errors"]))
            self.assertTrue(any("Dockerfile" in error for error in report["errors"]))
            self.assertFalse(any("node_modules" in error for error in report["errors"]))



def _write_doctor_files(root: Path) -> None:
    required = (
        "AGENTS.md", "docs/ARCHITECTURE.md", "docs/ADR.md", "docs/CI_SETUP.md",
        ".agents/skills/harness/SKILL.md", ".agents/skills/pr-workflow/SKILL.md",
        ".agents/skills/ci-setup/SKILL.md", ".github/PULL_REQUEST_TEMPLATE.md",
        ".harness/task-template.md", ".codex/config.toml", ".codex/agents/reviewer.toml",
        ".codex/agents/security-reviewer.toml", ".codex/hooks/harness_hook.py",
        "scripts/command_runner.py", "scripts/harness.py", "scripts/harness_doctor.py",
        "scripts/harness_common.py", "scripts/harness_risk.py", "scripts/harness_evidence.py",
        "scripts/github_expression_scanner.py", "scripts/check_ci_security.py",
        "scripts/ci_action_policy.py", "scripts/verify_ci.py",
    )
    for relative in required:
        _write_doctor_fixture_file(root, relative)
    _write_doctor_fixture_config(root)
    _write_doctor_fixture_workflow(root)


def _write_doctor_fixture_file(root: Path, relative: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if relative == ".codex/config.toml":
        path.write_text(
            '[agents.reviewer]\nconfig_file = "agents/reviewer.toml"\n'
            '[agents.security_reviewer]\nconfig_file = "agents/security-reviewer.toml"\n'
            "[[hooks.PreToolUse]]\nmatcher = \"^Bash$\"\n"
            "[[hooks.PreToolUse.hooks]]\ntype = \"command\"\n"
            "command = 'python3 \"$(git rev-parse --show-toplevel)/.codex/hooks/harness_hook.py\"'\n"
            "[[hooks.PermissionRequest]]\nmatcher = \"^Bash$\"\n"
            "[[hooks.PermissionRequest.hooks]]\ntype = \"command\"\n"
            "command = 'python3 \"$(git rev-parse --show-toplevel)/.codex/hooks/harness_hook.py\"'\n"
            "[[hooks.Stop]]\n[[hooks.Stop.hooks]]\ntype = \"command\"\n"
            "command = 'python3 \"$(git rev-parse --show-toplevel)/.codex/hooks/harness_hook.py\"'\n",
            encoding="utf-8",
        )
    elif relative in {".codex/agents/reviewer.toml", ".codex/agents/security-reviewer.toml"}:
        role = "security reviewer" if "security" in relative else "read-only review"
        path.write_text(
            'sandbox_mode = "read-only"\n'
            f'developer_instructions = "{role}"\n', encoding="utf-8",
        )
    else:
        path.write_text("present\n", encoding="utf-8")


def _write_doctor_fixture_config(root: Path) -> None:
    config = root / ".harness/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(
        "schema = 2\n\n[checks]\n"
        'quick = [["python", "-m", "unittest"]]\n'
        'full = [["python", "scripts/harness.py", "check", "--full"]]\n',
        encoding="utf-8",
    )


def _write_doctor_fixture_workflow(root: Path) -> None:
    workflow = root / ".github/workflows/ci.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(
        "name: Project CI\non:\n  pull_request:\npermissions: {}\njobs:\n"
        "  validate:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 15\n"
        "    permissions: {}\n    steps:\n"
        "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n"
        "        with:\n          persist-credentials: false\n"
        "      - run: python -I scripts/harness.py check --full\n",
        encoding="utf-8",
    )
