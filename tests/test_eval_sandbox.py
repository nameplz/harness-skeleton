import hashlib
import json
from pathlib import Path
import unittest
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from evals.native_runtime import runtime_readable_roots, sandbox_options, tool_environment
from evals.native_config import BinaryPin
from scripts.check_eval_sandbox import _hook_probe, _trusted_codex, check, validate_observation
from scripts.command_runner import CommandResult


class EvalSandboxTests(unittest.TestCase):
    def observation(self):
        return {
            "candidate_write": "allowed",
            "synthetic_sentinel_open": "denied",
            "host_config_open": "denied",
            "host_auth_open": "denied",
            "outside_write": "denied",
            "loopback_bind": "denied",
            "descendant_sentinel_open": "denied",
            "descendant_outside_write": "denied",
        }

    def test_accepts_only_the_observed_candidate_tool_boundary(self):
        self.assertTrue(validate_observation(self.observation(), host_config_present=True, host_auth_present=True))

    def test_authentication_path_must_be_denied_when_present(self):
        observation = self.observation()
        observation["host_auth_open"] = "allowed"
        self.assertFalse(validate_observation(observation, host_config_present=True, host_auth_present=True))

    def test_absent_authentication_file_is_reported_as_unmeasured(self):
        observation = self.observation()
        observation["host_auth_open"] = "not_present"
        self.assertTrue(validate_observation(observation, host_config_present=True, host_auth_present=False))

    def test_absent_host_config_is_reported_as_unmeasured(self):
        observation = self.observation()
        observation["host_config_open"] = "not_present"
        self.assertTrue(validate_observation(observation, host_config_present=False, host_auth_present=True))

    def test_rejects_missing_extra_or_unexpected_observations(self):
        observation = self.observation()
        observation.pop("loopback_bind")
        self.assertFalse(validate_observation(observation, host_config_present=True, host_auth_present=True))
        observation = self.observation()
        observation["mcp"] = "disabled"
        self.assertFalse(validate_observation(observation, host_config_present=True, host_auth_present=True))

    def test_rejects_a_candidate_write_failure_or_any_boundary_escape(self):
        for key, value in (("candidate_write", "denied"), ("synthetic_sentinel_open", "allowed"),
                           ("host_config_open", "allowed"), ("outside_write", "allowed"),
                           ("loopback_bind", "allowed"), ("descendant_sentinel_open", "allowed"),
                           ("descendant_outside_write", "allowed")):
            with self.subTest(key=key):
                observation = self.observation()
                observation[key] = value
                self.assertFalse(validate_observation(observation, host_config_present=True, host_auth_present=True))

    def run_check(self, root, runner, *, include_host_files=True, scratch_symlink=False,
                  node_runtime=False, identity_verifier=None):
        if scratch_symlink:
            (root / "outside").mkdir()
            (root / ".harness").symlink_to(root / "outside", target_is_directory=True)
        else:
            (root / ".harness").mkdir()
        home = root / "operator-home"
        codex_home = home / ".codex"
        codex_home.mkdir(parents=True)
        if include_host_files:
            (codex_home / "config.toml").write_text("host-config-secret\n")
            (codex_home / "auth.json").write_text("host-auth-secret\n")
        pin = BinaryPin(Path("/trusted/codex"), "a" * 64)
        node = BinaryPin(Path("/trusted/node"), "b" * 64) if node_runtime else None
        identity_verifier = identity_verifier or Mock()
        with patch("scripts.check_eval_sandbox.PROJECT_ROOT", root), \
                patch.object(Path, "home", return_value=home), \
                patch("scripts.check_eval_sandbox._host_loopback_bind_works", return_value=True), \
                patch("scripts.check_eval_sandbox._hook_probe", return_value=self.observation()), \
                patch("scripts.check_eval_sandbox._trusted_codex", return_value=(pin, node, (1,), (2,) if node else None)), \
                patch("scripts.check_eval_sandbox._verify_cli_identity", new=identity_verifier), \
                patch("scripts.check_eval_sandbox.run_bounded_command", side_effect=runner):
            return check()

    def test_trusted_codex_pins_the_node_runtime_selected_by_isolated_path(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            codex = root / "codex.js"
            codex.write_bytes(b"#!/usr/bin/env node\nconsole.log('codex');\n")
            codex.chmod(0o755)
            node = root / "node"
            node.write_bytes(b"\x7fELF-test-node\n")
            node.chmod(0o755)

            def identity(pin):
                metadata = pin.path.stat()
                return (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns,
                        metadata.st_mode, metadata.st_uid, metadata.st_gid, metadata.st_nlink)

            with patch("scripts.check_eval_sandbox.shutil.which",
                       side_effect=lambda name, path=None: str(codex if name == "codex" else node)) as which, \
                    patch("scripts.check_eval_sandbox.trusted_binary_identity", side_effect=identity):
                codex_pin, node_pin, _, _ = _trusted_codex({"PATH": temporary})
            codex_sha256 = hashlib.sha256(codex.read_bytes()).hexdigest()
            node_sha256 = hashlib.sha256(node.read_bytes()).hexdigest()

        self.assertEqual(codex_pin.path, codex.resolve())
        self.assertEqual(codex_pin.sha256, codex_sha256)
        self.assertEqual(node_pin.path, node.resolve())
        self.assertEqual(node_pin.sha256, node_sha256)
        which.assert_any_call("node", path=temporary)

    def test_codex_resolution_requires_a_trusted_installed_binary(self):
        with TemporaryDirectory() as temporary:
            executable = Path(temporary) / "codex"
            executable.write_text("#!/usr/bin/env node\n")
            executable.chmod(0o755)
            with patch("scripts.check_eval_sandbox.shutil.which", return_value=str(executable)), \
                    patch("scripts.check_eval_sandbox.trusted_binary_identity", side_effect=ValueError("untrusted")), \
                    self.assertRaisesRegex(ValueError, "untrusted"):
                _trusted_codex({"PATH": temporary})

    def test_missing_host_credentials_do_not_qualify_the_sandbox(self):
        with TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, "credential access is unmeasured"):
                self.run_check(Path(temporary), lambda *_args, **_kwargs: None, include_host_files=False)

    def test_scratch_root_rejects_a_symlink_without_writing_outside(self):
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(ValueError, "scratch root"):
                self.run_check(root, lambda *_args, **_kwargs: self.fail("probe must not start"),
                               scratch_symlink=True)
            self.assertEqual([], list((root / "outside").iterdir()))

    def test_success_rechecks_codex_and_node_identity_after_probe(self):
        verify = Mock()
        with TemporaryDirectory() as temporary:
            report = self.run_check(Path(temporary), lambda argv, **kwargs: self._probe_result(argv, kwargs),
                                    node_runtime=True, identity_verifier=verify)
        self.assertTrue(report["passed"])
        self.assertEqual(report["codex_runtime_binary_sha256"], "b" * 64)
        self.assertEqual([args[0].path for args, _ in verify.call_args_list],
                         [Path("/trusted/codex"), Path("/trusted/node")])

    def test_changed_binary_identity_after_probe_fails_closed(self):
        verify = Mock(side_effect=[None, ValueError("binary changed")])
        calls = []

        def runner(argv, **kwargs):
            calls.append(argv)
            return self._probe_result(argv, kwargs)

        with TemporaryDirectory() as temporary, self.assertRaisesRegex(ValueError, "binary changed"):
            self.run_check(Path(temporary), runner, node_runtime=True, identity_verifier=verify)
        self.assertEqual(2, len(calls))

    def _probe_result(self, argv, kwargs):
        if argv[1] == "sandbox":
            candidate = Path(argv[argv.index("-C") + 1])
            (candidate / "probe-write.txt").write_text("ok")
            return CommandResult(0, json.dumps(self.observation()))
        return CommandResult(0, "codex-cli 0.163.0\n")

    def test_check_launches_the_harness_sandbox_with_isolated_paths_and_environment(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            return self._probe_result(argv, kwargs)

        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = self.run_check(root, runner)

        self.assertTrue(report["passed"])
        self.assertEqual(report["profile"], "harness-eval")
        self.assertEqual(report["codex_cli_binary_sha256"], "a" * 64)
        self.assertIsNone(report["codex_runtime_binary_sha256"])
        self.assertEqual(len(calls), 2)
        command, kwargs = calls[0]
        self.assertEqual(command[:4], ["/trusted/codex", "sandbox", "--permission-profile", "harness-eval"])
        self.assertEqual(command[4], "-C")
        candidate = Path(command[5])
        self.assertEqual(kwargs["cwd"], candidate)
        options = list(sandbox_options(writable=True, readable_roots=runtime_readable_roots()))
        self.assertEqual(command[6:6 + len(options)], options)
        env_index = command.index("/usr/bin/env")
        self.assertEqual(command[env_index + 1], "-i")
        self.assertEqual(command[env_index + 2:env_index + 2 + len(tool_environment(candidate))],
                         [f"{key}={value}" for key, value in tool_environment(candidate).items()])
        self.assertEqual(kwargs["env"], tool_environment(candidate))
        self.assertNotIn("exec", command)
        self.assertNotIn("host-config-secret", json.dumps(report))
        self.assertNotIn("host-auth-secret", json.dumps(report))
        self.assertFalse(any("host-config-secret" in value or "host-auth-secret" in value for value in command))

    def test_check_records_the_hook_child_boundary_separately(self):
        with TemporaryDirectory() as temporary:
            report = self.run_check(Path(temporary), lambda argv, **kwargs: self._probe_result(argv, kwargs))

        self.assertTrue(report["passed"])
        self.assertEqual(self.observation(), report["hook_probe"]["observed"])
        self.assertEqual("sandboxed_launcher_probe_only", report["scope"]["hooks"])

    def test_hook_probe_runs_candidate_code_through_the_isolated_runner(self):
        observation = self.observation()
        result = CommandResult(0, json.dumps(observation))
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "candidate"
            candidate.mkdir()
            (candidate / ".harness").mkdir()
            sentinel = root / "sentinel"
            sentinel.write_text("synthetic-only\n", encoding="utf-8")
            outside = root / "outside"
            host_config = root / "host-config"
            host_auth = root / "host-auth"
            host_config.write_text("synthetic config\n", encoding="utf-8")
            host_auth.write_text("synthetic auth\n", encoding="utf-8")
            def execute_probe(workspace, hook_path, *, scratch_root, event_input, timeout_seconds):
                (workspace / "probe-write.txt").write_text("ok\n", encoding="utf-8")
                return result

            with patch("scripts.isolated_hook_runner.run_hook", side_effect=execute_probe) as run:
                observed = _hook_probe(candidate, sentinel, outside, host_config, host_auth,
                                       config_openable=True, auth_openable=True, scratch_root=root)

            hook_source = (candidate / ".codex/hooks/sandbox_probe.py").read_text(encoding="utf-8")

        self.assertEqual(observation, observed)
        run.assert_called_once_with(
            candidate,
            ".codex/hooks/sandbox_probe.py",
            scratch_root=root,
            event_input=b'{"hook_event_name":"SessionStart"}',
            timeout_seconds=30,
        )
        self.assertIn(str(sentinel), hook_source)
        self.assertIn(str(host_auth), hook_source)
        self.assertIn("json.load(sys.stdin)", hook_source)
        self.assertIn("hook_event_name", hook_source)
        self.assertNotIn("host-auth-secret", hook_source)

    def test_hook_probe_fails_when_any_protected_path_is_accessible(self):
        observation = self.observation()
        observation["host_auth_open"] = "allowed"
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            candidate = root / "candidate"
            candidate.mkdir()
            (candidate / ".harness").mkdir()
            sentinel = root / "sentinel"
            sentinel.touch()
            with patch("scripts.isolated_hook_runner.run_hook",
                       return_value=CommandResult(0, json.dumps(observation))), \
                    self.assertRaisesRegex(ValueError, "hook probe"):
                _hook_probe(candidate, sentinel, root / "outside", root / "config", root / "auth",
                            config_openable=True, auth_openable=True, scratch_root=root)

    def test_check_fails_closed_on_incomplete_or_invalid_probe_results(self):
        failures = (
            CommandResult(1, "failed"),
            CommandResult(124, "timed out", timed_out=True),
            CommandResult(125, "truncated", output_limited=True),
            CommandResult(0, '{"candidate_write":"allowed"}'),
        )
        for result in failures:
            with self.subTest(result=result), TemporaryDirectory() as temporary:
                with self.assertRaises(ValueError):
                    self.run_check(Path(temporary), lambda *_args, **_kwargs: result)

    def test_trusted_codex_resolves_from_the_runner_allowlisted_path(self):
        with TemporaryDirectory() as temporary:
            codex = Path(temporary) / "codex"
            codex.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            codex.chmod(0o755)
            environment = {"PATH": temporary}
            with patch("scripts.check_eval_sandbox.shutil.which", return_value=str(codex)) as which, \
                    patch("scripts.check_eval_sandbox._pin_executable",
                          return_value=(BinaryPin(codex, "a" * 64), b"", (1,))):
                _trusted_codex(environment)

        which.assert_called_once_with("codex", path=temporary)


if __name__ == "__main__":
    unittest.main()
