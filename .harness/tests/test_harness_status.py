from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts.harness import main, run_checks, status
from scripts.harness_gate import evidence_matches


class HarnessStatusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
        self.environment = patch.dict(os.environ, self.env)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def git(self, *args: str) -> str:
        result = subprocess.run(["git", *args], cwd=self.root, env=self.env,
                                capture_output=True, text=True, timeout=10, check=True)
        return result.stdout.strip()

    def repository(self) -> None:
        self.git("init", "-q")
        self.git("config", "user.name", "Harness Test")
        self.git("config", "user.email", "harness@example.test")
        (self.root / ".gitignore").write_text(".harness/state/\n")
        (self.root / "app.py").write_text("VALUE = 1\n")
        self.git("add", ".")
        self.git("commit", "-qm", "baseline")

    def configure(self, *, empty: bool = False) -> None:
        path = self.root / ".harness/config.toml"
        path.parent.mkdir(exist_ok=True)
        (self.root / "check.py").write_text("print('checked')\n")
        commands = [] if empty else [[sys.executable, "check.py"]]
        path.write_text("schema = 2\n[checks]\n" +
                        f"quick = {json.dumps(commands)}\nfull = {json.dumps(commands)}\n")

    def cli(self, *args: str) -> str:
        output = StringIO()
        with (redirect_stdout(output) if "--json" in args else redirect_stderr(output)):
            code = main(["status", "--root", str(self.root), *args])
        self.assertEqual(0, code)
        return output.getvalue()

    def snapshot(self) -> dict[str, bytes]:
        return {str(path.relative_to(self.root)): path.read_bytes()
                for path in self.root.rglob("*") if path.is_file()}

    def test_wp08_ac1_four_states_in_temporary_repositories(self) -> None:
        outside = json.loads(self.cli("--json"))
        self.assertEqual("unavailable", outside["repository"])
        self.assertIsNone(outside["branch"])
        self.assertIsNone(outside["dirty"])
        self.assertEqual("unknown", outside["risk"]["level"])
        self.repository()
        for empty in (False, True):
            if empty:
                self.configure(empty=True)
            unconfigured = json.loads(self.cli("--json"))
            self.assertEqual("available", unconfigured["repository"])
            self.assertEqual("unconfigured", unconfigured["profiles"]["status"])
            self.assertFalse(unconfigured["gate"]["installed"])
            self.assertFalse(unconfigured["checks"]["quick"]["evidence_matches"])
        self.configure()
        self.assertTrue(run_checks(self.root, "quick")["ok"])
        self.assertTrue(run_checks(self.root, "full")["ok"])
        matching = json.loads(self.cli("--json"))
        self.assertEqual("configured", matching["profiles"]["status"])
        for check in matching["checks"].values():
            self.assertEqual("passed", check["last_result"])
            self.assertIsInstance(check["finished_at"], (int, float))
            self.assertTrue(check["evidence_matches"])
        (self.root / "app.py").write_text("VALUE = 2\n")
        stale = json.loads(self.cli("--json"))
        self.assertTrue(stale["dirty"])
        for check in stale["checks"].values():
            self.assertEqual("passed", check["last_result"])
            self.assertFalse(check["evidence_matches"])
        text = self.cli()
        self.assertLessEqual(len(text.splitlines()), 10)
        self.assertIn("no matching pass", text)

    def test_wp08_ac2_json_fields_and_read_only_cli(self) -> None:
        self.repository()
        self.configure()
        self.assertTrue(run_checks(self.root, "full")["ok"])
        before = self.snapshot()
        with patch("scripts.harness.run_checks") as run, \
                patch("scripts.harness_gate.save_check") as save, \
                patch("scripts.harness_gate.install_gate") as install:
            report = json.loads(self.cli("--json"))
            self.assertLessEqual(len(self.cli().splitlines()), 10)
            run.assert_not_called()
            save.assert_not_called()
            install.assert_not_called()
        self.assertEqual(before, self.snapshot())
        self.assertEqual(self.git("branch", "--show-current"), report["branch"])
        self.assertEqual({"status", "quick_checks", "full_checks"}, set(report["profiles"]))
        self.assertEqual({"installed", "errors", "next_action"}, set(report["gate"]))
        self.assertEqual({"quick", "full"}, set(report["checks"]))
        self.assertIn("level", report["risk"])
        self.assertEqual("unavailable", report["checks"]["quick"]["last_result"])
        self.assertTrue(report["checks"]["quick"]["evidence_matches"])
        self.assertTrue(evidence_matches(self.root, "quick"))
        with patch("scripts.harness_gate.gate_errors", return_value=[]) as gate_errors:
            self.assertTrue(status(self.root)["gate"]["installed"])
            gate_errors.assert_called_once_with(self.root)

    def test_wp08_invalid_config_failed_and_unreadable_cache(self) -> None:
        self.repository()
        self.configure()
        self.assertTrue(run_checks(self.root, "quick")["ok"])
        cache = self.root / ".harness/state/last-check-quick.json"
        record = json.loads(cache.read_text())
        record["ok"] = False
        cache.write_text(json.dumps(record))
        report = status(self.root)
        self.assertEqual("failed", report["checks"]["quick"]["last_result"])
        self.assertFalse(report["checks"]["quick"]["evidence_matches"])
        for malformed in ("invalid", "[]", "x" * (64 * 1024 + 1)):
            cache.write_text(malformed)
            report = status(self.root)
            self.assertEqual("unavailable", report["checks"]["quick"]["last_result"])
            self.assertFalse(report["checks"]["quick"]["evidence_matches"])
        cache.unlink()
        cache.symlink_to(self.root.parent / "external-cache.json")
        self.assertEqual("unavailable", status(self.root)["checks"]["quick"]["last_result"])
        config = self.root / ".harness/config.toml"
        config.write_text("schema = [")
        report = status(self.root)
        self.assertEqual("invalid", report["profiles"]["status"])
        self.assertEqual("unknown", report["risk"]["level"])
        self.assertIn("Profiles: invalid", self.cli())


if __name__ == "__main__":
    unittest.main()
