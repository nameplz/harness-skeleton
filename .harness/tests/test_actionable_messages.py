from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts.harness import doctor, main, run_checks, status
from scripts.harness_gate import gate
from scripts.hooks.agent_hook import handle_event
from tests.test_harness_doctor import _write_doctor_files


class ActionableMessagesTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory(prefix="harness actionable ")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        environment = patch.dict(os.environ, {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull})
        environment.start()
        self.addCleanup(environment.stop)
        self.git("init", "-q")
        (self.root / ".gitignore").write_text(".harness/state/\n")
        (self.root / "app.txt").write_text("baseline\n")
        self.git("add", ".")
        self.git("-c", "user.name=Test", "-c", "user.email=test@example.test", "commit", "-qm", "baseline")

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.root, capture_output=True, text=True, check=True)

    def configure(self, script="print('ok')\n"):
        (self.root / "check.py").write_text(script)
        config = self.root / ".harness/config.toml"
        config.parent.mkdir(exist_ok=True)
        commands = json.dumps([[sys.executable, "check.py"]])
        config.write_text(f"schema = 2\n[checks]\nquick = {commands}\nfull = {commands}\n")

    def action(self, report):
        self.assertIsInstance(report["next_action"], str)
        self.assertTrue(report["next_action"].strip())

    def cli(self, *args):
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main([*args, "--root", str(self.root)])
        return code, out.getvalue(), err.getvalue()

    def test_wp09_ac1_mv1_unconfigured(self):
        for empty in (False, True):
            with self.subTest(empty=empty):
                if empty:
                    self.configure()
                    (self.root / ".harness/config.toml").write_text("schema = 2\n[checks]\nquick = []\nfull = []\n")
                code, out, err = self.cli("check")
                self.assertEqual(1, code)
                report = json.loads(out)
                self.assertEqual("unconfigured", report["status"])
                self.action(report)
                self.assertIn("Validation profile setup", report["next_action"])
                self.assertTrue(err.rstrip().splitlines()[-1].startswith("Next: "))
                self.action(status(self.root)["profiles"])

    def test_wp09_ac1_invalid_config(self):
        self.configure()
        (self.root / ".harness/config.toml").write_text("schema = [")
        code, out, err = self.cli("check")
        self.assertEqual(2, code)
        report = json.loads(out)
        self.assertIn("error", report)
        self.action(report)
        self.assertIn("Next: ", err)
        for report in (doctor(self.root), status(self.root)):
            self.action(report)
            self.action(report["config"] if "config" in report else report["profiles"])

    def test_wp09_ac1_mv6_check_failure(self):
        self.configure("raise SystemExit(7)\n")
        report = run_checks(self.root, "quick")
        self.assertFalse(report["ok"])
        self.assertEqual(7, report["checks"][0]["returncode"])
        self.action(report)
        self.action(report["checks"][0])
        self.action(status(self.root)["checks"]["quick"])

    def test_wp09_ac1_mv3_changed_evidence(self):
        self.configure("from pathlib import Path\nPath('app.txt').write_text('changed')\n")
        report = run_checks(self.root, "quick")
        self.assertTrue(report["checks"][0]["passed"])
        self.assertFalse(report["evidence_unchanged"])
        self.assertFalse(report["ok"])
        self.action(report)
        self.assertIn("workspace changes", report["next_action"])
        self.action(status(self.root)["checks"]["quick"])

    def test_wp09_ac1_mv2_gate_not_installed(self):
        _write_doctor_files(self.root)
        self.configure()
        report = doctor(self.root)
        self.assertFalse(report["ok"])
        self.action(report)
        self.assertIn("install-gate", report["next_action"])
        state = status(self.root)
        self.assertFalse(state["gate"]["installed"])
        self.action(state["gate"])
        argv = shlex.split(state["gate"]["next_action"])
        self.assertEqual(["install-gate", "--root", str(self.root)], argv[2:])
        self.assertTrue(Path(argv[0]).is_file())
        self.assertTrue(Path(argv[1]).is_file())

    def test_wp09_ac1_missing_interpreter_preserves_doctor_action(self):
        _write_doctor_files(self.root)
        self.configure()
        with patch("scripts.harness_doctor.shutil.which", return_value=None):
            report = doctor(self.root)
        self.assertFalse(report["ok"])
        self.action(report)
        self.assertEqual("install Python 3.11 or newer on PATH (python3, python, or py -3), then update adapter hooks", report["next_action"])

    def test_wp09_ac2_gate_json_and_text_streams(self):
        passed, detail = gate(self.root)
        self.assertFalse(passed)
        self.assertTrue(detail.splitlines()[-1].startswith("Next: "))
        code, out, err = self.cli("gate", "--json")
        self.assertEqual(1, code)
        report = json.loads(out)
        self.assertFalse(report["ok"])
        self.action(report)
        self.assertEqual(detail, report["detail"])
        self.assertTrue(err.rstrip().splitlines()[-1].startswith("Next: "))
        code, out, err = self.cli("gate")
        self.assertEqual(1, code)
        self.assertEqual("", out)
        self.assertIn("Next: ", err)
        code, out, err = self.cli("status")
        self.assertEqual(0, code)
        self.assertEqual("", out)
        self.assertIn("Next: ", err)
        code, out, err = self.cli("doctor")
        self.assertEqual(1, code)
        self.action(json.loads(out))
        self.assertIn("Next: ", err)

    def test_wp09_hook_denial_last_line_for_all_event_shapes(self):
        for event in ("PreToolUse", "PermissionRequest"):
            response = handle_event({"hook_event_name": event, "tool_name": "Bash", "tool_input": {"command": "rm -rf x"}})
            output = response["hookSpecificOutput"]
            reason = output["permissionDecisionReason"] if event == "PreToolUse" else output["decision"]["message"]
            self.assertTrue(reason.splitlines()[-1].startswith("Next: "))
        with patch.dict(os.environ, {"CLAUDE_PROJECT_DIR": str(self.root)}), patch("scripts.hooks.agent_hook._run_check", return_value=(False, "failed")):
            response = handle_event({"hook_event_name": "Stop"})
        self.assertEqual("block", response["decision"])
        self.assertTrue(response["reason"].splitlines()[-1].startswith("Next: "))

    def test_wp09_gate_all_refusal_paths_and_success_json(self):
        for name, script in (("empty", None), ("invalid", None), ("failed", "raise SystemExit(8)\n"),
                             ("changed", "from pathlib import Path\nPath('app.txt').write_text('changed')\n")):
            with self.subTest(name=name):
                self.configure(script or "print('ok')\n")
                if name in {"empty", "invalid"}:
                    (self.root / ".harness/config.toml").write_text("schema = [" if name == "invalid" else "schema = 2\n[checks]\nquick = []\nfull = []\n")
                code, out, err = self.cli("gate", "--json")
                self.assertEqual(1, code)
                report = json.loads(out)
                self.action(report)
                self.assertTrue(err.rstrip().splitlines()[-1].startswith("Next: "))
        self.configure()
        code, out, err = self.cli("gate", "--json")
        self.assertEqual(0, code)
        self.assertTrue(json.loads(out)["ok"])
        self.assertIn("validation passed", err)

    def test_wp09_retry_command_quotes_paths_and_keeps_trusted_config(self):
        self.configure("raise SystemExit(7)\n")
        report = run_checks(self.root, "quick", config_root=self.root)
        command = report["next_action"].split("then run ", 1)[1]
        argv = shlex.split(command)
        self.assertEqual(["check", "--root", str(self.root), "--quick", "--config-root", str(self.root)], argv[2:])
        completed = subprocess.run(argv, cwd=self.root.parent, capture_output=True, text=True, check=False)
        self.assertEqual(1, completed.returncode)
        self.assertEqual(7, json.loads(completed.stdout)["checks"][0]["returncode"])
