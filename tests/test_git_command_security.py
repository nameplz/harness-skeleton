from __future__ import annotations

from pathlib import Path
import sys
import unittest
import subprocess
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.harness import HarnessError, _validate_command_safety  # noqa: E402
from scripts.command_runner import run_bounded_command  # noqa: E402


class GitCommandSecurityTests(unittest.TestCase):
    def test_git_config_cannot_select_external_helpers(self) -> None:
        unsafe_settings = (
            "protocol.ext.allow=always",
            "remote.origin.uploadpack=./helper",
            "remote.origin.receivepack=./helper",
            "diff.helper.command=./helper",
            "diff.helper.textconv=./helper",
            "merge.helper.driver=./helper",
            "url.https://evil.example/.insteadof=origin",
            "remote.origin.vcs=./helper",
            "core.gitproxy=./helper",
            "gpg.program=./helper",
            "submodule.helper.update=./helper",
        )
        for setting in unsafe_settings:
            with self.subTest(setting=setting), self.assertRaises(HarnessError):
                _validate_command_safety(
                    ["git", "-c", setting, "status"],
                    Path("/workspace"),
                    "checks.full",
                    0,
                )

    def test_git_helper_execution_options_and_external_remote_syntax_are_rejected(self) -> None:
        commands = (
            ["git", "ls-remote", "ext::./helper"],
            ["git", "clone", "ext::./helper"],
            ["git", "clone", "--upload-pack=./helper", "repo"],
            ["git", "clone", "--receive-pack=./helper", "repo"],
            ["git", "clone", "-u", "./helper", "repo"],
            ["git", "--exec-path=./bin", "clone", "repo"],
            ["git", "diff", "--no-ext-diff", "--no-textconv", "--output=result.patch"],
        )
        for command in commands:
            with self.subTest(command=command), self.assertRaises(HarnessError):
                _validate_command_safety(command, Path("/workspace"), "checks.full", 0)

    def test_safe_display_configuration_remains_usable(self) -> None:
        command = ["git", "-c", "color.ui=false", "status"]

        _validate_command_safety(command, Path("/workspace"), "checks.full", 0)

    def test_bounded_git_command_disables_candidate_fsmonitor_helper(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            marker = root / "helper-ran"
            helper = root / "fsmonitor.sh"
            helper.write_text(f"#!/bin/sh\ntouch '{marker}'\n", encoding="utf-8")
            helper.chmod(0o755)
            for arguments in (
                ("init", "-q"),
                ("config", "core.fsmonitor", str(helper)),
            ):
                completed = subprocess.run(
                    ["git", *arguments],
                    cwd=root,
                    capture_output=True,
                    text=True,
                    check=False,
                    shell=False,
                )
                self.assertEqual(0, completed.returncode, completed.stderr)

            result = run_bounded_command(
                ["git", "status", "--short"],
                cwd=root,
                timeout_seconds=5,
                max_output_bytes=1024,
            )

            self.assertEqual(0, result.returncode, result.output)
            self.assertFalse(marker.exists())
