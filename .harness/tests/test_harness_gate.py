from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from scripts.harness import load_config, run_checks
from scripts.harness_gate import evidence_matches, gate, gate_errors, install_gate
from scripts.harness_common import HarnessError


class HarnessGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"
        self.root.mkdir()
        shutil.copytree(ROOT / "scripts", self.root / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copytree(ROOT / ".harness/githooks", self.root / ".harness/githooks")
        (self.root / ".gitignore").write_text(".harness/state/\n__pycache__/\n")
        (self.root / "app.py").write_text("VALUE = 1\n")
        (self.root / "tests").mkdir()
        (self.root / "tests/test_app.py").write_text("assert True\nassert 1\n")
        (self.root / "check.py").write_text(
            "from pathlib import Path\nimport sys\n"
            "profile = sys.argv[1]\n"
            "with Path('.git/counts').open('a') as f: f.write(profile + '\\n')\n"
            "sys.exit(Path('.git/fail-' + profile).exists())\n"
        )
        self.config()
        self.bin = Path(self.temp.name) / "bin"
        self.bin.mkdir()
        (self.bin / "python3").symlink_to(sys.executable)
        self.env = {**os.environ, "PATH": str(self.bin) + os.pathsep + os.environ.get("PATH", ""),
                    "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
        for key in list(self.env):
            if key in {"GIT_CONFIG_COUNT", "GIT_INDEX_FILE"} or key.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")):
                del self.env[key]
        self.git("init", "-q")
        self.git("config", "user.name", "Harness Test")
        self.git("config", "user.email", "harness@example.test")
        self.git("add", ".")
        self.git("commit", "-qm", "baseline")
        install_gate(self.root)

    def git(self, *args: str, ok: bool = True, env: dict | None = None) -> subprocess.CompletedProcess:
        result = subprocess.run(["git", *args], cwd=self.root, env=env or self.env,
                                capture_output=True, text=True, timeout=30)
        if ok:
            self.assertEqual(0, result.returncode, result.stderr)
        return result

    def config(self, *, empty: bool = False) -> None:
        command = lambda profile: [] if empty else [[sys.executable, "check.py", profile]]
        (self.root / ".harness/config.toml").write_text(
            "schema = 2\n[checks]\n" +
            f"quick = {json.dumps(command('quick'))}\nfull = {json.dumps(command('full'))}\n"
        )

    def change(self) -> None:
        (self.root / "app.py").write_text("VALUE = 2\n")
        self.git("add", "app.py")

    def counts(self) -> list[str]:
        path = self.root / ".git/counts"
        return path.read_text().splitlines() if path.exists() else []

    def test_ac1_mv1_empty_profiles_block_commit_with_setup(self) -> None:
        self.config(empty=True)
        self.change()
        self.assertFalse(run_checks(self.root, "quick")["ok"])
        cache = self.root / ".harness/state/last-check-quick.json"
        self.assertFalse(json.loads(cache.read_text())["ok"])
        head = self.git("rev-parse", "HEAD").stdout
        result = self.git("commit", "-m", "blocked", ok=False)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("checks.quick/full", result.stderr)
        self.assertIn("doctor --bootstrap", result.stderr)
        self.assertEqual(head, self.git("rev-parse", "HEAD").stdout)

    def test_ac2_mv2_t1_runs_quick_and_failed_check_blocks_commit(self) -> None:
        self.change()
        (self.root / ".git/fail-quick").touch()
        head = self.git("rev-parse", "HEAD").stdout
        result = self.git("commit", "-m", "blocked", ok=False)
        self.assertNotEqual(0, result.returncode)
        self.assertEqual(["quick"], self.counts())
        self.assertIn("check-1", result.stderr)
        self.assertIn("check --quick", result.stderr)
        self.assertEqual(head, self.git("rev-parse", "HEAD").stdout)

    def test_ac3_mv2_test_weakening_requires_full_despite_quick_cache(self) -> None:
        (self.root / "tests/test_app.py").write_text("assert True\n")
        self.git("add", "tests/test_app.py")
        self.assertTrue(run_checks(self.root, "quick")["ok"])
        self.git("commit", "-m", "full required")
        self.assertEqual(["quick", "full"], self.counts())

    def test_ac4_mv3_full_cache_satisfies_quick_without_rerunning(self) -> None:
        self.change()
        result = subprocess.run([sys.executable, "scripts/harness.py", "check", "--full"],
                                cwd=self.root, env=self.env, capture_output=True, text=True, timeout=20)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertTrue(json.loads(result.stdout)["ok"])
        self.assertTrue(evidence_matches(self.root, "quick"))
        self.git("commit", "-m", "cached")
        self.assertEqual(["full"], self.counts())

    def test_ac5_mv3_one_byte_change_invalidates_cache(self) -> None:
        self.change()
        self.assertTrue(run_checks(self.root, "quick")["ok"])
        (self.root / "app.py").write_text("VALUE = 3\n")
        self.git("add", "app.py")
        self.assertFalse(evidence_matches(self.root, "quick"))
        self.git("commit", "-m", "changed")
        self.assertEqual(["quick", "quick"], self.counts())

    def test_ac6_mv2_commit_all_and_path_work_without_index_lock_conflicts(self) -> None:
        for arguments in (("-a", "-m", "all"), ("-m", "path", "--", "app.py")):
            with self.subTest(arguments=arguments):
                (self.root / "app.py").write_text((self.root / "app.py").read_text() + "# change\n")
                self.git("commit", *arguments)
                self.assertFalse((self.root / ".git/index.lock").exists())
        self.assertEqual(["quick", "quick"], self.counts())

    def test_ac7_mv2_no_interpreter_blocks_commit(self) -> None:
        self.change()
        empty = Path(self.temp.name) / "empty-bin"
        empty.mkdir()
        env = {**self.env, "PATH": str(empty)}
        result = subprocess.run([shutil.which("git"), "commit", "-m", "blocked"],
                                cwd=self.root, env=env, capture_output=True, text=True, timeout=10)
        self.assertNotEqual(0, result.returncode)
        self.assertIn("Python 3.11", result.stderr)
        self.assertEqual([], self.counts())

    def test_ac8_mv3_stop_reuses_cache_on_second_call(self) -> None:
        spec = importlib.util.spec_from_file_location("gate_test_hook", ROOT / "scripts/hooks/agent_hook.py")
        hook = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(hook)
        self.change()
        payload = {"hook_event_name": "Stop", "cwd": str(self.root)}
        self.assertIsNone(hook.handle_event(payload))
        with patch.object(hook, "_run_check") as run:
            self.assertIsNone(hook.handle_event(payload))
            run.assert_not_called()
        self.assertEqual(["quick"], self.counts())

    def test_ac9_install_preserves_other_hooks_path_unless_forced(self) -> None:
        self.git("config", "core.hooksPath", "custom-hooks")
        with self.assertRaisesRegex(HarnessError, "custom-hooks"):
            install_gate(self.root)
        self.assertEqual("custom-hooks", self.git("config", "--local", "--get", "core.hooksPath").stdout.strip())
        install_gate(self.root, force=True)
        self.assertEqual([], gate_errors(self.root))

    def test_mv3_head_config_failure_and_invalid_cache_do_not_match(self) -> None:
        self.change()
        self.assertTrue(run_checks(self.root, "full")["ok"])
        self.git("commit", "-m", "cached")
        self.assertFalse(evidence_matches(self.root, "full"))
        self.assertTrue(run_checks(self.root, "quick")["ok"])
        self.config(empty=True)
        self.assertFalse(evidence_matches(self.root, "quick"))
        self.config()
        (self.root / ".git/fail-quick").touch()
        self.assertFalse(run_checks(self.root, "quick")["ok"])
        self.assertFalse(evidence_matches(self.root, "quick"))
        cache = self.root / ".harness/state/last-check-quick.json"
        record = json.loads(cache.read_text())
        self.assertFalse(record["ok"])
        self.assertEqual(["check-1"], record["failed_checks"])
        self.assertIn("finished_at", record)
        cache.write_text("invalid")
        self.assertFalse(evidence_matches(self.root, "quick"))

    def test_mv3_unavailable_or_error_evidence_never_writes_cache(self) -> None:
        for status in ("unavailable", "error"):
            evidence = {"status": status, "head": None, "dirty": None, "diff_sha256": None}
            with self.subTest(status=status), patch("scripts.harness.capture_workspace", return_value=evidence):
                run_checks(self.root, "quick")
            self.assertFalse((self.root / ".harness/state").exists())

    def test_mv2_risk_error_requires_full(self) -> None:
        self.change()
        with patch("scripts.harness_gate.inspect_git_risk", side_effect=HarnessError("unknown")):
            self.assertTrue(gate(self.root)[0])
        self.assertEqual(["full"], self.counts())

    def test_gate_installation_requires_executable_hook(self) -> None:
        hook = self.root / ".harness/githooks/pre-commit"
        hook.chmod(0o644)
        self.assertTrue(gate_errors(self.root))

    def test_ac9_install_preserves_effective_global_hooks_setting(self) -> None:
        self.git("config", "--unset", "core.hooksPath")
        global_config = Path(self.temp.name) / "gitconfig"
        global_config.write_text("[core]\n hooksPath = global-hooks\n")
        with patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": str(global_config)}):
            with self.assertRaisesRegex(HarnessError, "global-hooks"):
                install_gate(self.root)
            install_gate(self.root, force=True)
            self.assertEqual([], gate_errors(self.root))


if __name__ == "__main__":
    unittest.main()
