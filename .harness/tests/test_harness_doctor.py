from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tomllib
import unittest
from contextlib import redirect_stdout
from io import StringIO
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scripts.harness import doctor, main
from scripts.harness_doctor import VALIDATION_SETUP, _has_model_setting, _claude_frontmatter

ROOT = Path(__file__).resolve().parents[2]


class HarnessDoctorTests(unittest.TestCase):
    def test_wp05_ac4_mv6_optional_adapter_combinations(self) -> None:
        for codex, claude in ((False, False), (True, False), (False, True), (True, True)):
            with self.subTest(codex=codex, claude=claude), TemporaryDirectory() as temp:
                root = Path(temp)
                _write_doctor_files(root)
                if not codex:
                    shutil.rmtree(root / ".codex")
                if claude:
                    shutil.copytree(ROOT / ".claude", root / ".claude")
                self.run_git(root, "init", "-q")
                report = doctor(root)
                self.assertTrue(report["ok"], report["errors"])
                self.assertEqual("configured", report["status"])
                self.assertEqual([], report["warnings"])

    def test_wp05_ac5_adapters_have_no_model_pinning_and_share_instructions(self) -> None:
        codex = tomllib.loads((ROOT / ".codex/config.toml").read_text())
        self.assertNotIn("PermissionRequest", codex["hooks"])
        self.assertFalse(_has_model_setting(codex))
        settings = json.loads((ROOT / ".claude/settings.json").read_text())
        self.assertFalse(_has_model_setting(settings))
        for role in ("reviewer", "security-reviewer"):
            data = tomllib.loads((ROOT / f".codex/agents/{role}.toml").read_text())
            self.assertFalse(_has_model_setting(data))
            metadata, instructions = _claude_frontmatter((ROOT / f".claude/agents/{role}.md").read_text())
            self.assertNotRegex(metadata, r"(?m)^model:")
            self.assertEqual(data["developer_instructions"].strip(), instructions.strip())

    def test_claude_doctor_rejects_missing_hooks_and_write_tools(self) -> None:
        for invalid in ("settings", "missing settings", "tools", "duplicate tools", "quoted tools", "instructions"):
            with self.subTest(invalid=invalid), TemporaryDirectory() as temp:
                root = Path(temp)
                _write_doctor_files(root)
                shutil.copytree(ROOT / ".claude", root / ".claude")
                settings = root / ".claude/settings.json"
                reviewer = root / ".claude/agents/reviewer.md"
                if invalid == "settings":
                    settings.write_text('{"hooks": {}}')
                elif invalid == "missing settings":
                    settings.unlink()
                elif invalid == "instructions":
                    metadata, _ = _claude_frontmatter(reviewer.read_text())
                    reviewer.write_text(f"---\n{metadata}\n---\n")
                else:
                    replacement = {"tools": "tools: Read, Bash", "duplicate tools": "tools: Read\ntools: Bash",
                                   "quoted tools": 'tools: Read\n"tools": Bash'}[invalid]
                    reviewer.write_text(reviewer.read_text().replace("tools: Read, Grep, Glob", replacement))
                self.run_git(root, "init", "-q")
                report = doctor(root)
                self.assertFalse(report["ok"])
                self.assertTrue(any(".claude/" in error for error in report["errors"]))

    def test_claude_doctor_rejects_adapter_symlink_escape(self) -> None:
        with TemporaryDirectory() as temp, TemporaryDirectory() as external:
            root = Path(temp)
            _write_doctor_files(root)
            shutil.copytree(ROOT / ".claude", Path(external) / ".claude")
            (root / ".claude").symlink_to(Path(external) / ".claude", target_is_directory=True)
            report = doctor(root, bootstrap=True)
            self.assertFalse(report["ok"])
            self.assertIn(".claude/settings.json (invalid)", report["errors"])

    def test_adapter_model_overrides_warn_without_changing_readiness(self) -> None:
        for adapter in ("codex", "claude settings", "claude reviewer"):
            with self.subTest(adapter=adapter), TemporaryDirectory() as temp:
                root = Path(temp)
                _write_doctor_files(root)
                shutil.copytree(ROOT / ".claude", root / ".claude")
                if adapter == "codex":
                    path = root / ".codex/agents/reviewer.toml"
                    key = "model" + "_reasoning_effort"
                    path.write_text(path.read_text() + f'{key} = "custom"\n')
                elif adapter == "claude settings":
                    path = root / ".claude/settings.json"
                    data = json.loads(path.read_text())
                    data["model"] = "custom"
                    path.write_text(json.dumps(data))
                else:
                    path = root / ".claude/agents/reviewer.md"
                    path.write_text(path.read_text().replace("---\n", "---\nmodel: custom\n", 1))
                self.run_git(root, "init", "-q")
                report = doctor(root)
                self.assertTrue(report["ok"], report["errors"])
                self.assertEqual("configured", report["status"])
                self.assertTrue(any("runtime defaults" in warning for warning in report["warnings"]))

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
        if arguments and arguments[0] == "init":
            hook = root / ".harness/githooks/pre-commit"
            hook.parent.mkdir(parents=True, exist_ok=True)
            hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            hook.chmod(0o755)
            self.run_git(root, "config", "core.hooksPath", ".harness/githooks")

    def test_doctor_requires_gate_but_bootstrap_only_warns(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            _write_doctor_files(root)
            self.run_git(root, "init", "-q")
            self.run_git(root, "config", "--unset", "core.hooksPath")
            regular = doctor(root)
            bootstrap = doctor(root, bootstrap=True)
            self.assertFalse(regular["ok"])
            self.assertEqual("unconfigured", regular["status"])
            self.assertTrue(any("install-gate" in error for error in regular["errors"]))
            self.assertTrue(bootstrap["ok"], bootstrap["errors"])
            self.assertTrue(any("install-gate" in warning for warning in bootstrap["warnings"]))

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
            self.assertEqual("configured", report["status"])
            self.assertGreater(report["git"]["changed_paths"], 0)
            self.assertEqual(1, report["config"]["quick_checks"])

    def test_bootstrap_doctor_accepts_missing_profiles_without_reporting_configured(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            _write_doctor_files(root)
            (root / ".harness/config.toml").unlink()
            self.run_git(root, "init", "-q")

            bootstrap = doctor(root, bootstrap=True)
            regular = doctor(root)

            self.assertTrue(bootstrap["ok"], bootstrap["errors"])
            self.assertEqual("unconfigured", bootstrap["status"])
            self.assertEqual(VALIDATION_SETUP, bootstrap["next_action"])
            self.assertFalse(regular["ok"])
            self.assertEqual("unconfigured", regular["status"])
            self.assertTrue(any("unconfigured" in error for error in regular["errors"]))

    def test_doctor_uses_trusted_config_root_without_workflows(self) -> None:
        with TemporaryDirectory() as temp, TemporaryDirectory() as trusted_temp:
            root, trusted = Path(temp), Path(trusted_temp)
            _write_doctor_files(root)
            self.write_config(trusted, [["python", "-m", "unittest"]], [["python", "-m", "unittest"]])
            (root / ".harness/config.toml").unlink()
            self.run_git(root, "init", "-q")

            self.assertFalse((root / ".github/workflows").exists())
            report = doctor(root, config_root=trusted)

        self.assertTrue(report["ok"], report["errors"])
        self.assertEqual("configured", report["config"]["status"])
        self.assertEqual("configured", report["status"])
        self.assertNotIn("ci", report)

    def test_doctor_returns_structured_error_when_extracted_module_is_missing(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            with patch.dict(sys.modules, {"scripts.harness_doctor": None, "harness_doctor": None}):
                report = doctor(root, bootstrap=True)
        self.assertFalse(report["ok"])
        self.assertEqual("invalid", report["status"])
        self.assertTrue(any("doctor module" in error for error in report["errors"]))

    def test_bootstrap_doctor_rejects_invalid_profiles(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            _write_doctor_files(root)
            (root / ".harness/config.toml").write_text("schema = [", encoding="utf-8")
            self.run_git(root, "init", "-q")
            report = doctor(root, bootstrap=True)
        self.assertFalse(report["ok"])
        self.assertEqual("invalid", report["config"]["status"])
        self.assertEqual("unconfigured", report["status"])

    def test_doctor_reports_unavailable_git_and_hook_executables(self) -> None:
        for unavailable, expected in (("git", "Git executable"), ("python3", "Harness hook")):
            with self.subTest(unavailable=unavailable), TemporaryDirectory() as temp:
                root = Path(temp)
                _write_doctor_files(root)
                self.run_git(root, "init", "-q")
                which = shutil.which
                with patch("scripts.harness_doctor.shutil.which",
                           side_effect=lambda name: None if name == unavailable else which(name)):
                    report = doctor(root)
                self.assertFalse(report["ok"])
                self.assertEqual("unconfigured", report["status"])
                self.assertTrue(any(expected in error for error in report["errors"]))

    def test_doctor_reports_empty_profiles_and_setup_guidance(self) -> None:
        for quick, full in (([], []), ([["true"]], []), ([], [["true"]])):
            with self.subTest(quick=quick, full=full), TemporaryDirectory() as temp:
                root = Path(temp)
                _write_doctor_files(root)
                self.write_config(root, quick, full)
                self.run_git(root, "init", "-q")
                report = doctor(root)
                self.assertFalse(report["ok"])
                self.assertEqual("unconfigured", report["status"])
                self.assertEqual(VALIDATION_SETUP, report["next_action"])
                self.assertIn(f"validation is unconfigured: {VALIDATION_SETUP}", report["errors"])

    def test_doctor_reports_missing_required_file(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_config(root, [["true"]], [["true"]])
            _write_doctor_files(root)
            (root / "scripts/harness_evidence.py").unlink()
            self.run_git(root, "init", "-q")
            output = StringIO()

            with redirect_stdout(output):
                exit_code = main(["doctor", "--root", str(root)])

            report = json.loads(output.getvalue())
            self.assertEqual(1, exit_code)
            self.assertFalse(report["ok"])
            self.assertIn("scripts/harness_evidence.py", report["errors"])

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

    def test_doctor_preserves_doc_checks_without_restricting_deployment_layout(self) -> None:
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
            self.assertFalse(any("Dockerfile" in error for error in report["errors"]))
            (root / "AGENTS.md").write_text("Project guide.\n", encoding="utf-8")
            self.assertTrue(doctor(root)["ok"])
            self.assertFalse(any("node_modules" in error for error in report["errors"]))



def _write_doctor_files(root: Path) -> None:
    required = (
        "AGENTS.md", "docs/ARCHITECTURE.md", "docs/ADR.md",
        ".agents/skills/harness/SKILL.md",
        ".harness/task-template.md", ".codex/config.toml", ".codex/agents/reviewer.toml",
        ".codex/agents/security-reviewer.toml", "scripts/hooks/agent_hook.py",
        "scripts/command_runner.py", "scripts/harness.py", "scripts/harness_doctor.py",
        "scripts/harness_common.py", "scripts/harness_risk.py", "scripts/harness_evidence.py",
        "scripts/harness_gate.py", ".harness/githooks/pre-commit",
    )
    for relative in required:
        _write_doctor_fixture_file(root, relative)
    _write_doctor_fixture_config(root)


def _write_doctor_fixture_file(root: Path, relative: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if relative == ".codex/config.toml":
        path.write_text(
            '[agents.reviewer]\nconfig_file = "agents/reviewer.toml"\n'
            '[agents.security_reviewer]\nconfig_file = "agents/security-reviewer.toml"\n'
            "[[hooks.PreToolUse]]\nmatcher = \"^Bash$\"\n"
            "[[hooks.PreToolUse.hooks]]\ntype = \"command\"\n"
            "command = 'python3 \"$(git rev-parse --show-toplevel)/scripts/hooks/agent_hook.py\"'\n"
            "[[hooks.Stop]]\n[[hooks.Stop.hooks]]\ntype = \"command\"\n"
            "command = 'python3 \"$(git rev-parse --show-toplevel)/scripts/hooks/agent_hook.py\"'\n",
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
