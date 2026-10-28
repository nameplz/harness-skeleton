from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib
import unittest
from tempfile import TemporaryDirectory
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/hooks"))

from agent_hook import CHECK_TIMEOUT_SECONDS, HARNESS_SCRIPT, handle_event  # noqa: E402
from scripts.harness import CHECK_QUICK_TIMEOUT_SECONDS, CHECK_TOTAL_TIMEOUT_SECONDS  # noqa: E402


class HarnessHookTests(unittest.TestCase):
    def test_wp05_ac1_claude_pre_tool_use_returns_deny_json(self) -> None:
        with TemporaryDirectory() as temp:
            result = subprocess.run(
                [sys.executable, str(ROOT / "scripts/hooks/agent_hook.py")],
                input=json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                                  "tool_input": {"command": "rm -rf x"}, "cwd": temp}),
                capture_output=True, text=True, check=False,
            )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("deny", json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"])

    def test_wp05_ac2_stop_reentry_has_no_output(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts/hooks/agent_hook.py")],
            input=json.dumps({"hook_event_name": "Stop", "stop_hook_active": True}),
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("", result.stdout)

    def test_wp05_ac3_claude_project_dir_precedes_nested_cwd_and_git_root(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            nested = root / "nested"
            nested.mkdir()
            with patch.dict(os.environ, {"CLAUDE_PROJECT_DIR": str(root)}), \
                    patch("agent_hook._resolve_project_root") as resolve, \
                    patch("agent_hook.evidence_matches", return_value=False), \
                    patch("agent_hook._run_check", return_value=(True, "")) as check:
                self.assertIsNone(handle_event({"hook_event_name": "Stop", "cwd": str(nested)}))
                check.assert_called_once_with(root, "quick")
                resolve.assert_not_called()
            with patch.dict(os.environ, {"CLAUDE_PROJECT_DIR": str(root / "missing")}):
                result = handle_event({"hook_event_name": "Stop", "cwd": str(nested)})
                self.assertEqual("block", result["decision"])

    def test_wp05_ac6_moved_hook_runs_without_adapters(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            shutil.copytree(ROOT / "scripts", root / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
            result = subprocess.run(
                [sys.executable, str(root / "scripts/hooks/agent_hook.py")],
                input=json.dumps({"hook_event_name": "Stop", "cwd": str(root)}),
                capture_output=True, text=True, check=False,
            )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("", result.stdout)

    def test_validation_hook_timeout_exceeds_quick_profile_ceiling(self) -> None:
        config = tomllib.loads((ROOT / ".codex/config.toml").read_text(encoding="utf-8"))
        hooks = config["hooks"]
        for event in ("PreToolUse", "Stop"):
            with self.subTest(event=event):
                timeout = hooks[event][0]["hooks"][0]["timeout"]
                self.assertGreater(timeout, CHECK_QUICK_TIMEOUT_SECONDS)

    def test_stop_timeout_covers_quick_validation(self) -> None:
        config = tomllib.loads((ROOT / ".codex/config.toml").read_text(encoding="utf-8"))
        self.assertEqual(180, CHECK_TIMEOUT_SECONDS["quick"])
        self.assertEqual(180, config["hooks"]["Stop"][0]["hooks"][0]["timeout"])

    def test_commit_delegates_to_git_gate_without_agent_checks(self) -> None:
        with patch("agent_hook._run_check") as check, patch("agent_hook.subprocess.run") as run:
            result = handle_event({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                                   "tool_input": {"command": "git commit -m x"}, "cwd": str(ROOT)})
        self.assertIsNone(result)
        check.assert_not_called()
        run.assert_not_called()

    def test_stop_runs_only_quick_without_risk(self) -> None:
        with patch("agent_hook._resolve_project_root", return_value=ROOT), patch(
            "agent_hook.subprocess.run", return_value=subprocess.CompletedProcess([], 0, '{"ok": true}', "")
        ) as run:
            self.assertIsNone(handle_event({"hook_event_name": "Stop", "cwd": str(ROOT)}))
            run.assert_called_once()
            self.assertIn("--quick", run.call_args.args[0])
            self.assertEqual(180, run.call_args.kwargs["timeout"])

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
        with patch("agent_hook._run_check", return_value=(False, "failed")) as quick_check:
            result = handle_event({"hook_event_name": "Stop", "cwd": str(ROOT / "docs")})

        quick_check.assert_called_once_with(ROOT, "quick")
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
        self.assertEqual({"behavior": "deny", "message": "Blocked dangerous Bash command: hard git reset.\nNext: Use a command without the blocked destructive operation"}, output["decision"])

    def test_stop_runs_checks_and_redacts_failures(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            script = root / "check.py"
            script.write_text(
                "import sys\nprint('token=sample-secret customer@example.test')\nsys.exit(2)\n",
                encoding="utf-8",
            )
            self.write_config(root, script)

            for event, extra in (
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

    def test_git_commit_spellings_leave_validation_to_git_gate(self) -> None:
        for command in (
            "git commit -m x", "git -C 'my repo' commit -m x", "git -Crepo commit",
            '"git" --no-pager commit -m x', "git --git-dir=.git commit",
            "git -c core.quotepath=false commit", "git status && git commit -m x",
            "git status\ngit commit -m x", "/usr/bin/git --no-optional-locks commit",
            "git --no-lazy-fetch commit -m x", "GIT.EXE --no-pager commit -m x",
        ):
            with self.subTest(command=command), patch(
                "agent_hook._run_check", return_value=(False, "failed")
            ) as check:
                result = handle_event({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                                       "tool_input": {"command": command}, "cwd": str(ROOT)})
                check.assert_not_called()
                self.assertIsNone(result)

    def test_commit_text_in_arguments_or_comments_does_not_trigger_validation(self) -> None:
        for command in (
            "echo 'git commit'", "git commit-msg", "git status # git commit",
            "echo ';' git commit", "git -C 'git commit' status", "git -C",
            "git status --format='git commit'", "echo 'unterminated",
        ):
            with self.subTest(command=command), patch("agent_hook._run_check") as check:
                result = handle_event({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                                       "tool_input": {"command": command}})
                self.assertIsNone(result)
                check.assert_not_called()

    def test_invalid_hook_payload_reports_an_error_without_echoing_input(self) -> None:
        for payload in ("not-json private-input", "[]"):
            with self.subTest(payload=payload):
                result = subprocess.run([sys.executable, str(ROOT / "scripts/hooks/agent_hook.py")],
                                        input=payload, capture_output=True, text=True, check=False)
                self.assertNotEqual(0, result.returncode)
                self.assertIn("invalid hook payload", result.stderr)
                self.assertNotIn("private-input", result.stderr)
                self.assertEqual("", result.stdout)

    def test_hooks_without_a_project_config_are_inert(self) -> None:
        with TemporaryDirectory() as temp:
            result = handle_event(
                {
                    "hook_event_name": "Stop",
                    "cwd": temp,
                }
            )

        self.assertIsNone(result)

    def test_unconfigured_quick_profile_does_not_block_bootstrap_work(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            config = root / ".harness/config.toml"
            config.parent.mkdir(parents=True)
            config.write_text("schema = 2\n[checks]\nquick = []\nfull = []\n", encoding="utf-8")

            result = handle_event({"hook_event_name": "Stop", "cwd": str(root)})

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
