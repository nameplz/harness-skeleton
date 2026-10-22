from __future__ import annotations

from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from io import BytesIO
from types import SimpleNamespace
from unittest.mock import Mock, patch

from evals.native_config import BinaryPin
from scripts.command_runner import CommandResult
from scripts.isolated_hook_runner import (
    MAX_HOOK_INPUT_BYTES,
    MAX_HOOK_SOURCE_BYTES,
    build_command,
    main,
    resolve_hook,
    run_hook,
    _validate_workspace_tree,
)


class IsolatedHookRunnerTests(unittest.TestCase):
    def test_resolve_hook_requires_a_regular_file_inside_the_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            hook = root / ".codex/hooks/harness_hook.py"
            hook.parent.mkdir(parents=True)
            hook.write_text("pass\n", encoding="utf-8")

            self.assertEqual(hook.resolve(), resolve_hook(root, ".codex/hooks/harness_hook.py"))
            for invalid in ("/tmp/hook.py", "../hook.py", ".codex/../outside.py", ""):
                with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                    resolve_hook(root, invalid)

            external = root.parent / f"{root.name}-external.py"
            external.write_text("pass\n", encoding="utf-8")
            try:
                (root / "linked.py").symlink_to(external)
                with self.assertRaisesRegex(ValueError, "symlink"):
                    resolve_hook(root, "linked.py")
            finally:
                external.unlink()

    def test_resolve_hook_rejects_hardlinks_and_oversized_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            scratch = Path(temporary)
            root = scratch / "candidate"
            root.mkdir(mode=0o700)
            external = scratch / "external.py"
            external.write_text("pass\n", encoding="utf-8")
            linked = root / "linked.py"
            linked.hardlink_to(external)
            with self.assertRaisesRegex(ValueError, "hardlink"):
                resolve_hook(root, "linked.py")

            large = root / "large.py"
            large.write_bytes(b" " * (MAX_HOOK_SOURCE_BYTES + 1))
            with self.assertRaisesRegex(ValueError, "size"):
                resolve_hook(root, "large.py")

    def test_build_command_reads_a_protected_hook_snapshot_with_the_original_filename(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            scratch = Path(temporary).resolve()
            root = scratch / "candidate"
            root.mkdir()
            original = root / ".codex/hooks/hook.py"
            original.parent.mkdir(parents=True)
            original.write_text("pass\n", encoding="utf-8")
            snapshot_root = scratch / "snapshot"
            snapshot_root.mkdir()
            snapshot = snapshot_root / "hook.py"
            snapshot.write_text("pass\n", encoding="utf-8")
            environment = {
                "PATH": "/trusted/python:/usr/bin:/bin",
                "HOME": str(root / ".harness/home"),
                "TMPDIR": str(root / ".harness/tmp"),
                "PYTHONDONTWRITEBYTECODE": "1",
            }

            command = build_command(Path("/trusted/codex"), root, original, snapshot_root, snapshot, environment)

        self.assertEqual(command[:4], ["/trusted/codex", "sandbox", "--permission-profile", "harness-eval"])
        self.assertIn(str(snapshot_root), " ".join(command))
        self.assertIn(str(snapshot), command)
        self.assertIn(str(original), command)
        self.assertIn("exec(compile", " ".join(command))

    def test_build_command_runs_only_the_hook_inside_the_codex_sandbox(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            hook = root / ".codex/hooks/hook.py"
            hook.parent.mkdir(parents=True)
            hook.write_text("pass\n", encoding="utf-8")
            snapshot_root = root / "snapshot"
            snapshot_root.mkdir()
            snapshot = snapshot_root / "hook.py"
            snapshot.write_text("pass\n", encoding="utf-8")
            environment = {
                "PATH": "/trusted/python:/usr/bin:/bin",
                "HOME": str(root / ".eval-home"),
                "TMPDIR": str(root / ".eval-tmp"),
                "PYTHONDONTWRITEBYTECODE": "1",
            }

            command = build_command(Path("/trusted/codex"), root, hook, snapshot_root, snapshot, environment)

        self.assertEqual(command[:4], ["/trusted/codex", "sandbox", "--permission-profile", "harness-eval"])
        self.assertEqual(command[command.index("-C") + 1], str(root))
        self.assertEqual(command[command.index("/usr/bin/env") + 1], "-i")
        self.assertIn("HOME=" + str(root / ".eval-home"), command)
        self.assertIn("TMPDIR=" + str(root / ".eval-tmp"), command)
        self.assertNotIn("CODEX_HOME", " ".join(command))
        self.assertIn(str(hook), command)
        self.assertEqual(command[command.index("-I"):command.index("-I") + 2], ["-I", "-B"])
        self.assertIn("-c", command)

    def test_build_command_rejects_host_codex_home_or_secret_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            hook = root / "hook.py"
            hook.write_text("pass\n", encoding="utf-8")
            snapshot_root = root / "snapshot"
            snapshot_root.mkdir()
            snapshot = snapshot_root / "hook.py"
            snapshot.write_text("pass\n", encoding="utf-8")
            environment = {
                "PATH": "/trusted/python:/usr/bin:/bin",
                "HOME": str(root),
                "TMPDIR": str(root),
                "PYTHONDONTWRITEBYTECODE": "1",
                "CODEX_HOME": str(Path.home() / ".codex"),
                "OPENAI_API_KEY": "must-not-be-forwarded",
            }

            with self.assertRaisesRegex(ValueError, "allowlist"):
                build_command(Path("/trusted/codex"), root, hook, snapshot_root, snapshot, environment)

    def test_run_hook_uses_a_secret_free_environment_and_bounded_event_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            scratch = Path(temporary).resolve()
            root = scratch / "candidate"
            root.mkdir(mode=0o700)
            (root / ".codex/hooks").mkdir(parents=True)
            (root / ".codex/hooks/hook.py").write_text("pass\n", encoding="utf-8")
            (root / ".harness").mkdir(mode=0o700)
            codex = BinaryPin(Path("/trusted/codex"), "a" * 64)
            node = BinaryPin(Path("/trusted/node"), "b" * 64)
            run = Mock(return_value=CommandResult(0, '{"decision":"allow"}'))
            event = b'{"hook_event_name":"PermissionRequest"}'

            with patch("scripts.isolated_hook_runner._trusted_codex", return_value=(codex, node, (1,), (2,))), \
                    patch("scripts.isolated_hook_runner._verify_cli_identity") as verify, \
                    patch("scripts.isolated_hook_runner.run_bounded_command", run):
                result = run_hook(root, ".codex/hooks/hook.py", scratch_root=scratch,
                                  event_input=event, timeout_seconds=12)

        self.assertEqual(result.returncode, 0)
        args, kwargs = run.call_args
        self.assertEqual(args[0][0:4], [str(codex.path), "sandbox", "--permission-profile", "harness-eval"])
        self.assertEqual(kwargs["timeout_seconds"], 12)
        self.assertEqual(kwargs["input_bytes"], event)
        self.assertEqual(set(kwargs["env"]), {"PATH", "HOME", "TMPDIR", "PYTHONDONTWRITEBYTECODE"})
        self.assertNotIn("CODEX_HOME", kwargs["env"])
        self.assertNotIn(str(Path.home() / ".codex/auth.json"), " ".join(args[0]))
        self.assertEqual([call.args[0] for call in verify.call_args_list], [codex, node])

    def test_run_bounded_command_keeps_devnull_default_and_forwards_only_supplied_bytes(self) -> None:
        from scripts.command_runner import run_bounded_command

        for options, expected in (({}, subprocess.DEVNULL), ({"input_bytes": b"event"}, b"event")):
            process = Mock()
            process.poll.return_value = 0
            process.returncode = 0
            process.stdout.read.side_effect = [b"ok", b""]

            def capture_stdin(_command, **kwargs):
                stream = kwargs["stdin"]
                if options:
                    self.assertEqual(stream.read(), expected)
                    stream.seek(0)
                else:
                    self.assertIs(expected, stream)
                return process

            with self.subTest(options=options), patch(
                "scripts.command_runner.subprocess.Popen", side_effect=capture_stdin
            ) as popen:
                run_bounded_command(["python"], cwd=Path("."), timeout_seconds=1,
                                    max_output_bytes=32, **options)

            self.assertIsNotNone(popen.call_args.kwargs["stdin"])

    def test_runner_rejects_unbounded_or_invalid_hook_events_before_start(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            nested = (b'{"hook_event_name":"SessionStart","value":' + b"[" * 10000
                      + b"0" + b"]" * 10000 + b"}")
            for event in (b"{}", b"[]", b"{" + b" " * MAX_HOOK_INPUT_BYTES, nested):
                with self.subTest(size=len(event)), patch("scripts.isolated_hook_runner.run_hook") as run, \
                        patch("scripts.isolated_hook_runner.sys.stdin",
                              SimpleNamespace(buffer=BytesIO(event), isatty=lambda: False)), \
                        patch("scripts.isolated_hook_runner.sys.stderr"):
                    self.assertEqual(main(["--workspace", str(root), "--scratch-root", str(root),
                                           "--hook", "hook.py"]), 125)
                run.assert_not_called()

    def test_runner_forwards_only_a_bounded_json_hook_event(self) -> None:
        event = b'{"hook_event_name":"SessionStart","session_id":"synthetic"}'
        result = CommandResult(0, '{"ok":true}')
        with tempfile.TemporaryDirectory() as temporary, \
                patch("scripts.isolated_hook_runner.run_hook", return_value=result) as run, \
                patch("scripts.isolated_hook_runner.sys.stdin",
                      SimpleNamespace(buffer=BytesIO(event), isatty=lambda: False)), \
                patch("scripts.isolated_hook_runner.sys.stdout"):
            self.assertEqual(main(["--workspace", temporary, "--scratch-root", temporary,
                                  "--hook", "hook.py"]), 0)

        run.assert_called_once_with(Path(temporary), "hook.py", scratch_root=Path(temporary),
                                    event_input=event, timeout_seconds=180)

    def test_runner_rejects_terminal_stdin_without_waiting_for_an_event(self) -> None:
        stdin = SimpleNamespace(buffer=BytesIO(), isatty=lambda: True)
        with patch("scripts.isolated_hook_runner.run_hook") as run, \
                patch("scripts.isolated_hook_runner.sys.stdin", stdin), \
                patch("scripts.isolated_hook_runner.sys.stderr"):
            self.assertEqual(main(["--workspace", "/tmp/candidate", "--scratch-root", "/tmp",
                                  "--hook", "hook.py"]), 125)
        run.assert_not_called()

    def test_workspace_scratch_symlink_is_rejected_before_the_codex_runner_starts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            scratch = Path(temporary).resolve()
            root = scratch / "candidate"
            root.mkdir(mode=0o700)
            (root / ".codex/hooks").mkdir(parents=True)
            (root / ".codex/hooks/hook.py").write_text("pass\n", encoding="utf-8")
            outside = root.parent / f"{root.name}-outside"
            outside.mkdir()
            try:
                (root / ".harness").symlink_to(outside, target_is_directory=True)
                with patch("scripts.isolated_hook_runner._trusted_codex") as trusted, \
                        self.assertRaisesRegex(ValueError, "symlink"):
                    run_hook(root, ".codex/hooks/hook.py", scratch_root=scratch,
                             event_input=b'{"hook_event_name":"SessionStart"}')
                trusted.assert_not_called()
            finally:
                outside.rmdir()

    def test_workspace_must_be_inside_the_operator_scratch_root_and_hardlink_free(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            scratch = Path(temporary).resolve()
            outside_root = scratch.parent / f"{scratch.name}-outside"
            outside_root.mkdir()
            (outside_root / ".harness").mkdir()
            (outside_root / "hook.py").write_text("pass\n", encoding="utf-8")
            with patch("scripts.isolated_hook_runner._trusted_codex") as trusted, \
                    self.assertRaisesRegex(ValueError, "under the operator scratch root"):
                run_hook(outside_root, "hook.py", scratch_root=scratch,
                         event_input=b'{"hook_event_name":"SessionStart"}')
            trusted.assert_not_called()
            import shutil
            shutil.rmtree(outside_root)

            root = scratch / "candidate"
            root.mkdir(mode=0o700)
            (root / ".harness").mkdir(mode=0o700)
            (root / "hook.py").write_text("pass\n", encoding="utf-8")
            external = scratch / "host-file"
            external.write_text("synthetic\n", encoding="utf-8")
            (root / "alias").hardlink_to(external)
            with patch("scripts.isolated_hook_runner._trusted_codex") as trusted, \
                    self.assertRaisesRegex(ValueError, "hardlink"):
                run_hook(root, "hook.py", scratch_root=scratch,
                         event_input=b'{"hook_event_name":"SessionStart"}')
            trusted.assert_not_called()

    def test_workspace_and_harness_scratch_must_be_private(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            scratch = Path(temporary).resolve()
            root = scratch / "candidate"
            root.mkdir(mode=0o700)
            harness = root / ".harness"
            harness.mkdir(mode=0o700)
            (root / "hook.py").write_text("pass\n", encoding="utf-8")
            root.chmod(0o755)
            with patch("scripts.isolated_hook_runner._trusted_codex") as trusted, \
                    self.assertRaisesRegex(ValueError, "workspace must be private"):
                run_hook(root, "hook.py", scratch_root=scratch,
                         event_input=b'{"hook_event_name":"SessionStart"}')
            trusted.assert_not_called()
            root.chmod(0o700)
            harness.chmod(0o755)
            with patch("scripts.isolated_hook_runner._trusted_codex") as trusted, \
                    self.assertRaisesRegex(ValueError, "workspace .harness directory must be private"):
                run_hook(root, "hook.py", scratch_root=scratch,
                         event_input=b'{"hook_event_name":"SessionStart"}')
            trusted.assert_not_called()

    def test_workspace_entry_limit_is_checked_while_scanning(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            consumed = []
            device = root.stat().st_dev

            class Entries:
                def __enter__(self):
                    return self

                def __exit__(self, *_args):
                    return False

                def __iter__(self):
                    for index in range(10):
                        consumed.append(index)
                        metadata = SimpleNamespace(st_mode=stat.S_IFREG, st_nlink=1, st_dev=device)
                        yield SimpleNamespace(path=str(root / f"entry-{index}"),
                                               stat=lambda *, follow_symlinks: metadata)

            with patch("scripts.isolated_hook_runner.MAX_WORKSPACE_ENTRIES", 1), \
                    patch("scripts.isolated_hook_runner.os.scandir", return_value=Entries()), \
                    self.assertRaisesRegex(ValueError, "entry limit"):
                _validate_workspace_tree(root)
            self.assertEqual(consumed, [0, 1])


if __name__ == "__main__":
    unittest.main()
