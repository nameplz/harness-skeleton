from __future__ import annotations

from pathlib import Path
import sys
import unittest
import subprocess
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.harness import HarnessError, _validate_command_safety  # noqa: E402
from scripts.command_runner import run_bounded_command  # noqa: E402


class GitCommandSecurityTests(unittest.TestCase):
    def test_wp01_ac3_mv6_only_read_only_git_subcommands_are_allowed(self) -> None:
        for subcommand in ("status", "diff", "log", "show", "ls-files", "rev-parse", "grep", "describe", "cat-file"):
            with self.subTest(subcommand=subcommand):
                _validate_command_safety(["git", "--no-pager", subcommand], ROOT, "checks.full", 0)

        commands = (
            ["git", "clean", "-fdx"], ["git", "checkout", "."],
            ["git", "commit", "-m", "x"], ["git", "push"],
            ["git", "reset", "--hard"], ["git", "ls-remote", "ext::helper"],
            ["git", "-C", ".", "clean", "-fdx"],
            ["git.exe", "--git-dir=.git", "push"],
            ["git", "custom-alias"], ["git"], ["git", "--version"],
        )
        for command in commands:
            with self.subTest(command=command), self.assertRaisesRegex(HarnessError, "read-only Git"):
                _validate_command_safety(command, ROOT, "checks.full", 0)

    def test_global_git_configuration_overrides_are_rejected(self) -> None:
        commands = (
            ["git", "-c", "alias.x=!sh -c 'touch /tmp/pwn'", "x"],
            ["git", "-c", "core.pager=sh -c id", "log"],
            ["git", "--config-env=core.pager=X", "log"],
            ["git", "-ccore.pager=cat", "log"],
            ["git", "--config", "core.pager=cat", "log"],
            ["git", "--config=core.pager=cat", "log"],
            ["git", "--config-env", "core.pager=X", "log"],
            ["git", "-C", ".", "-c", "color.ui=false", "status"],
            ["git.exe", "-c", "protocol.allow=always", "status"],
            ["git", "-c", "color.ui=false"],
        )
        for command in commands:
            with self.subTest(command=command), self.assertRaisesRegex(HarnessError, "safe Git configuration"):
                _validate_command_safety(command, ROOT, "checks.full", 0)

    def test_subcommand_options_and_paths_are_not_global_configuration(self) -> None:
        commands = (
            ["git", "diff", "--check"],
            ["git", "status"],
            ["git", "-C", ".", "--no-pager", "log"],
            ["git", "log", "-c"],
            ["git", "diff", "--", "--config=fixture.txt"],
        )
        for command in commands:
            with self.subTest(command=command):
                _validate_command_safety(command, ROOT, "checks.full", 0)

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
