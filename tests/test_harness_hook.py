from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tomllib
import unittest
from tempfile import TemporaryDirectory
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / ".codex/hooks"))

from harness_hook import handle_event  # noqa: E402
from scripts.harness import CHECK_QUICK_TIMEOUT_SECONDS  # noqa: E402


class HarnessHookTests(unittest.TestCase):
    def test_validation_hook_timeout_exceeds_quick_profile_ceiling(self) -> None:
        config = tomllib.loads((ROOT / ".codex/config.toml").read_text(encoding="utf-8"))
        hooks = config["hooks"]
        for event in ("PreToolUse", "Stop"):
            with self.subTest(event=event):
                timeout = hooks[event][0]["hooks"][0]["timeout"]
                self.assertGreater(timeout, CHECK_QUICK_TIMEOUT_SECONDS)

    def test_configured_hook_entrypoint_runs_from_a_nested_directory(self) -> None:
        config = tomllib.loads((ROOT / ".codex/config.toml").read_text(encoding="utf-8"))
        command = config["hooks"]["Stop"][0]["hooks"][0]["command"]
        completed = subprocess.run(
            command,
            cwd=ROOT / "docs",
            input=json.dumps({"hook_event_name": "Stop", "stop_hook_active": True}),
            capture_output=True,
            text=True,
            check=False,
            shell=True,
        )

        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertEqual("", completed.stdout)

    def test_hook_resolves_the_repository_root_from_a_nested_cwd(self) -> None:
        with patch("harness_hook._run_quick_check", return_value=(False, "failed")) as quick_check:
            result = handle_event({"hook_event_name": "Stop", "cwd": str(ROOT / "docs")})

        quick_check.assert_called_once_with(ROOT)
        self.assertEqual("block", result["decision"])

    def write_config(self, root: Path, script: Path) -> None:
        config = root / ".harness/config.toml"
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text(
            "schema = 2\n[checks]\n"
            f"quick = [[{json.dumps(sys.executable)}, {json.dumps(script.name)}]]\n"
            f"full = [[{json.dumps(sys.executable)}, {json.dumps(script.name)}]]\n",
            encoding="utf-8",
        )

    def test_pre_tool_use_blocks_destructive_command_with_codex_schema(self) -> None:
        result = handle_event(
            {
                "hook_event_name": "PreToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "rm -rf /tmp/something"},
            }
        )

        self.assertEqual("PreToolUse", result["hookSpecificOutput"]["hookEventName"])
        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_permission_request_denies_force_reset_using_event_schema(self) -> None:
        result = handle_event(
            {
                "hook_event_name": "PermissionRequest",
                "tool_name": "Bash",
                "tool_input": {"command": "git reset --hard HEAD"},
            }
        )

        output = result["hookSpecificOutput"]
        self.assertEqual("PermissionRequest", output["hookEventName"])
        self.assertEqual({"behavior": "deny", "message": "Blocked dangerous Bash command: hard git reset."}, output["decision"])

    def test_commit_and_stop_run_quick_checks_and_redact_failures(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            script = root / "check.py"
            script.write_text(
                "import sys\nprint('token=sample-secret customer@example.test')\nsys.exit(2)\n",
                encoding="utf-8",
            )
            self.write_config(root, script)

            for event, extra in (
                ("PreToolUse", {"tool_name": "Bash", "tool_input": {"command": "git commit -m x"}}),
                ("Stop", {}),
            ):
                with self.subTest(event=event):
                    result = handle_event({"hook_event_name": event, "cwd": str(root), **extra})
                    reason = result["hookSpecificOutput"]["permissionDecisionReason"] if event == "PreToolUse" else result["reason"]
                    if event == "PreToolUse":
                        self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])
                    else:
                        self.assertEqual("block", result["decision"])
                    self.assertNotIn("sample-secret", reason)
                    self.assertNotIn("customer@example.test", reason)

    def test_stop_hook_active_skips_validation(self) -> None:
        result = handle_event({"hook_event_name": "Stop", "stop_hook_active": True})

        self.assertIsNone(result)

    def test_hooks_without_a_project_config_are_inert(self) -> None:
        with TemporaryDirectory() as temp:
            result = handle_event(
                {
                    "hook_event_name": "Stop",
                    "cwd": temp,
                }
            )

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
