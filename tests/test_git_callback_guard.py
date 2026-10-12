from pathlib import Path
import os
import shutil
import subprocess
import unittest
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scripts.command_runner import CommandResult, run_bounded_command
from scripts.harness import HarnessError, _validate_command_safety


class GitCallbackGuardTests(unittest.TestCase):
    def git(self, root: Path, *args: str) -> None:
        subprocess.run(["git", *args], cwd=root, check=True, capture_output=True)

    def test_callbacks_and_included_configuration_fail_before_git_inspection(self) -> None:
        for included in (False, True):
            with self.subTest(included=included), TemporaryDirectory() as temp:
                root = Path(temp)
                self.git(root, "init", "-q")
                (root / ".gitattributes").write_text("*.txt filter=evil\n")
                (root / "value.txt").write_text("first\n")
                self.git(root, "add", ".")
                self.git(root, "-c", "user.name=Test", "-c", "user.email=test@example.test", "commit", "-qm", "base")
                marker = root / "callback-executed"
                setting = f"touch '{marker}' && cat"
                if included:
                    config = root / "included.config"
                    self.git(root, "config", "--file", str(config), "filter.evil.clean", setting)
                    self.git(root, "config", "include.path", str(config))
                else:
                    self.git(root, "config", "filter.evil.clean", setting)
                (root / "value.txt").write_text("changed\n")
                for command in ("status", "diff"):
                    result = run_bounded_command(["git", "-C", str(root), command], cwd=root,
                                                 timeout_seconds=5, max_output_bytes=4096)
                    self.assertNotEqual(0, result.returncode)
                    self.assertFalse(marker.exists())
                    self.assertFalse(result.started)

    def test_no_callback_and_required_only_filter_allow_inspection(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.git(root, "init", "-q")
            self.git(root, "config", "filter.safe.required", "false")
            result = run_bounded_command(["git", "status", "--porcelain"], cwd=root,
                                         timeout_seconds=5, max_output_bytes=4096)
            self.assertEqual(0, result.returncode)

    def test_git_exe_uses_the_same_callback_preflight(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.git(root, "init", "-q")
            self.git(root, "config", "filter.evil.clean", "cat")
            executable = root / "git.exe"
            executable.symlink_to(shutil.which("git"))
            result = run_bounded_command([str(executable), "status"], cwd=root,
                                         timeout_seconds=5, max_output_bytes=4096)
            self.assertNotEqual(0, result.returncode)
            self.assertFalse(result.started)

    def test_wrapped_git_is_rejected_before_any_process_starts(self) -> None:
        for executable in ("git", "GIT.EXE"):
            for command in ("status", "diff"):
                argv = ["uv", "run", executable, command, "--no-ext-diff", "--no-textconv"]
                with self.subTest(argv=argv), self.assertRaises(HarnessError):
                    _validate_command_safety(argv, Path("/workspace"), "checks.full", 0)
                with patch("scripts.command_runner.subprocess.Popen", side_effect=AssertionError("wrapper started")):
                    result = run_bounded_command(argv, cwd=Path("/workspace"),
                                                 timeout_seconds=5, max_output_bytes=4096)
                self.assertFalse(result.started)
                self.assertNotEqual(0, result.returncode)

    def test_status_does_not_update_regular_or_linked_worktree_index(self) -> None:
        for linked in (False, True):
            with self.subTest(linked=linked), TemporaryDirectory() as temp:
                root = Path(temp)
                self.git(root, "init", "-q")
                (root / "value.txt").write_text("first\n")
                self.git(root, "add", ".")
                self.git(root, "-c", "user.name=Test", "-c", "user.email=test@example.test", "commit", "-qm", "base")
                workspace = root
                if linked:
                    workspace = root / "worktree"
                    self.git(root, "worktree", "add", "-qb", "test", str(workspace))
                index_name = subprocess.run(["git", "rev-parse", "--git-path", "index"], cwd=workspace,
                                            check=True, capture_output=True, text=True).stdout.strip()
                index = workspace / index_name
                before = index.stat().st_mtime_ns
                target = workspace / "value.txt"
                stat = target.stat()
                os.utime(target, (stat.st_atime, stat.st_mtime - 10))
                result = run_bounded_command(["git", "status", "--porcelain"], cwd=workspace,
                                             timeout_seconds=5, max_output_bytes=4096)
                self.assertEqual(0, result.returncode, result.output)
                self.assertEqual(before, index.stat().st_mtime_ns)

    def test_malformed_configuration_is_not_treated_as_no_callback(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.git(root, "init", "-q")
            (root / ".git/config").write_text("[broken\n")
            result = run_bounded_command(["git", "status"], cwd=root,
                                         timeout_seconds=5, max_output_bytes=4096)
            self.assertNotEqual(0, result.returncode)
            self.assertFalse(result.started)

    def test_linked_worktree_callbacks_are_detected(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.git(root, "init", "-q")
            self.git(root, "-c", "user.name=Test", "-c", "user.email=test@example.test", "commit", "--allow-empty", "-qm", "base")
            worktree = root / "worktree"
            self.git(root, "worktree", "add", "-qb", "test", str(worktree))
            self.git(root, "config", "extensions.worktreeConfig", "true")
            self.git(worktree, "config", "--worktree", "filter.evil.clean", "cat")
            result = run_bounded_command(["git", "status"], cwd=worktree,
                                         timeout_seconds=5, max_output_bytes=4096)
            self.assertFalse(result.started)
            self.assertNotEqual(0, result.returncode)

    def test_preflight_output_limit_is_a_failure(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.git(root, "init", "-q")
            self.git(root, "config", "filter." + "x" * 300 + ".clean", "cat")
            result = run_bounded_command(["git", "status"], cwd=root,
                                         timeout_seconds=5, max_output_bytes=32)
            self.assertTrue(result.output_limited)
            self.assertFalse(result.started)
            self.assertNotEqual(0, result.returncode)

    def test_preflight_timeout_preserves_timeout_return_code(self) -> None:
        with patch("scripts.command_runner.run_bounded_command", return_value=CommandResult(124, "", timed_out=True)):
            result = run_bounded_command(["git", "status"], cwd=Path("/workspace"),
                                         timeout_seconds=5, max_output_bytes=4096)
        self.assertEqual(124, result.returncode)
        self.assertTrue(result.timed_out)
        self.assertFalse(result.started)

    def test_command_line_helpers_cannot_override_read_only_inspection(self) -> None:
        for setting, command in (("core.fsmonitor", "status"), ("diff.external", "diff"),
                                 ("diff.evil.command", "diff"), ("diff.evil.textconv", "diff")):
            with self.subTest(setting=setting), TemporaryDirectory() as temp:
                root = Path(temp)
                self.git(root, "init", "-q")
                (root / ".gitattributes").write_text("*.txt diff=evil\n")
                (root / "value.txt").write_text("first\n")
                self.git(root, "add", ".")
                self.git(root, "-c", "user.name=Test", "-c", "user.email=test@example.test", "commit", "-qm", "base")
                (root / "value.txt").write_text("changed\n")
                marker = root / "callback-executed"
                argv = ["git", "-c", f"{setting}=touch '{marker}'", command]
                if setting.endswith("textconv"):
                    argv.append("--textconv")
                result = run_bounded_command(argv, cwd=root, timeout_seconds=5, max_output_bytes=4096)
                self.assertEqual(0, result.returncode, result.output)
                self.assertFalse(marker.exists())

    def test_option_shaped_paths_after_separator_are_preserved(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.git(root, "init", "-q")
            target = root / "--ignore-submodules-file.txt"
            target.write_text("first\n")
            other = root / "other.txt"
            other.write_text("unrelated-first\n")
            self.git(root, "add", ".")
            self.git(root, "-c", "user.name=Test", "-c", "user.email=test@example.test", "commit", "-qm", "base")
            target.write_text("changed\n")
            other.write_text("unrelated-changed\n")
            result = run_bounded_command(["git", "diff", "--no-ext-diff", "--no-textconv", "--", target.name], cwd=root,
                                         timeout_seconds=5, max_output_bytes=4096)
            self.assertEqual(0, result.returncode, result.output)
            self.assertIn("+changed", result.output)
            self.assertNotIn("unrelated-changed", result.output)

    def test_submodule_callbacks_do_not_run_during_parent_inspection(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            source, parent = root / "source", root / "parent"
            source.mkdir()
            parent.mkdir()
            self.git(source, "init", "-q")
            (source / ".gitattributes").write_text("*.txt filter=evil\n")
            (source / "value.txt").write_text("first\n")
            self.git(source, "add", ".")
            self.git(source, "-c", "user.name=Test", "-c", "user.email=test@example.test", "commit", "-qm", "base")
            self.git(parent, "init", "-q")
            self.git(parent, "-c", "protocol.file.allow=always", "submodule", "add", str(source), "child")
            self.git(parent, "-c", "user.name=Test", "-c", "user.email=test@example.test", "commit", "-qam", "base")
            child = parent / "child"
            marker = root / "callback-executed"
            self.git(child, "config", "filter.evil.clean", f"touch '{marker}' && cat")
            (child / "value.txt").write_text("changed\n")
            for command in ("status", "diff"):
                result = run_bounded_command(["git", command, "--ignore-submodules=none"], cwd=parent,
                                             timeout_seconds=5, max_output_bytes=4096)
                self.assertEqual(0, result.returncode, result.output)
                self.assertFalse(marker.exists())
