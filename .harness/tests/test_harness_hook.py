from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tomllib
import unittest
from tempfile import TemporaryDirectory
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / ".codex/hooks"))

from harness_hook import CHECK_TIMEOUT_SECONDS, HARNESS_SCRIPT, handle_event  # noqa: E402
from scripts.harness import CHECK_QUICK_TIMEOUT_SECONDS, CHECK_TOTAL_TIMEOUT_SECONDS  # noqa: E402


class HarnessHookTests(unittest.TestCase):
    def test_validation_hook_timeout_exceeds_quick_profile_ceiling(self) -> None:
        config = tomllib.loads((ROOT / ".codex/config.toml").read_text(encoding="utf-8"))
        hooks = config["hooks"]
        for event in ("PreToolUse", "Stop"):
            with self.subTest(event=event):
                timeout = hooks[event][0]["hooks"][0]["timeout"]
                self.assertGreater(timeout, CHECK_QUICK_TIMEOUT_SECONDS)

    def test_full_hook_timeout_covers_risk_and_full_validation(self) -> None:
        config = tomllib.loads((ROOT / ".codex/config.toml").read_text(encoding="utf-8"))
        timeout = config["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"]
        self.assertGreater(CHECK_TIMEOUT_SECONDS["full"], CHECK_TOTAL_TIMEOUT_SECONDS)
        self.assertGreater(timeout, CHECK_TIMEOUT_SECONDS["full"] + 20)
        self.assertEqual(180, CHECK_TIMEOUT_SECONDS["quick"])
        self.assertEqual(180, config["hooks"]["Stop"][0]["hooks"][0]["timeout"])

    def test_commit_selects_profile_from_risk_and_fails_closed(self) -> None:
        cases = [
            (0, {"level": tier}, "quick" if tier in {"T0", "T1"} else "full", tier)
            for tier in ("T0", "T1", "T2", "T3")
        ] + [
            (2, {"level": "T1"}, "full", "unknown"),
            (0, "not-json", "full", "unknown"),
            (0, [], "full", "unknown"),
            (0, {}, "full", "unknown"),
            (0, {"level": "T4"}, "full", "unknown"),
            (0, {"level": []}, "full", "unknown"),
        ]
        for returncode, report, profile, tier in cases:
            with self.subTest(report=report, returncode=returncode), patch(
                "harness_hook._resolve_project_root", return_value=ROOT
            ), patch("harness_hook.subprocess.run") as run:
                run.side_effect = [
                    subprocess.CompletedProcess([], returncode,
                                                report if isinstance(report, str) else json.dumps(report), ""),
                    subprocess.CompletedProcess([], 1, json.dumps({"ok": False, "error": "x" * 5000}), ""),
                ]
                result = handle_event({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                                       "tool_input": {"command": "git commit -m x"}, "cwd": str(ROOT)})
                self.assertEqual(2, run.call_count)
                risk_call, check_call = run.call_args_list
                self.assertEqual([sys.executable, str(HARNESS_SCRIPT), "risk", "--root", str(ROOT)],
                                 risk_call.args[0])
                self.assertEqual([sys.executable, str(HARNESS_SCRIPT), "check", f"--{profile}",
                                  "--root", str(ROOT)], check_call.args[0])
                self.assertFalse(risk_call.kwargs["shell"])
                self.assertFalse(check_call.kwargs["shell"])
                self.assertEqual(CHECK_TIMEOUT_SECONDS[profile], check_call.kwargs["timeout"])
                output = result["hookSpecificOutput"]
                self.assertEqual("deny", output["permissionDecision"])
                self.assertIn(profile, output["permissionDecisionReason"])
                self.assertIn(tier, output["permissionDecisionReason"])
                self.assertLessEqual(len(output["permissionDecisionReason"]), 4000)

    def test_risk_execution_failure_runs_full(self) -> None:
        for error in (OSError("unavailable"), subprocess.TimeoutExpired("risk", 10)):
            with self.subTest(error=error), patch("harness_hook._resolve_project_root", return_value=ROOT), patch(
                "harness_hook.subprocess.run", side_effect=[
                    error, subprocess.CompletedProcess([], 0, '{"ok": true}', "")
                ]
            ) as run:
                result = handle_event({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                                       "tool_input": {"command": "git commit"}, "cwd": str(ROOT)})
                self.assertIsNone(result)
                self.assertIn("--full", run.call_args.args[0])

    def test_unconfigured_full_does_not_block_or_report_success(self) -> None:
        with patch("harness_hook._resolve_project_root", return_value=ROOT), patch(
            "harness_hook.subprocess.run", side_effect=[
                subprocess.CompletedProcess([], 0, '{"level": "T3"}', ""),
                subprocess.CompletedProcess([], 1, '{"ok": false, "status": "unconfigured"}', ""),
            ]
        ) as run:
            result = handle_event({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                                   "tool_input": {"command": "git commit"}, "cwd": str(ROOT)})
            self.assertIsNone(result)
            self.assertIn("--full", run.call_args.args[0])

    def test_stop_runs_only_quick_without_risk(self) -> None:
        with patch("harness_hook._resolve_project_root", return_value=ROOT), patch(
            "harness_hook.subprocess.run", return_value=subprocess.CompletedProcess([], 0, '{"ok": true}', "")
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
        with patch("harness_hook._run_check", return_value=(False, "failed")) as quick_check:
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
        self.assertEqual({"behavior": "deny", "message": "Blocked dangerous Bash command: hard git reset."}, output["decision"])

    def test_commit_and_stop_run_checks_and_redact_failures(self) -> None:
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

    def test_git_commit_spellings_trigger_validation(self) -> None:
        for command in (
            "git commit -m x", "git -C 'my repo' commit -m x", "git -Crepo commit",
            '"git" --no-pager commit -m x', "git --git-dir=.git commit",
            "git -c core.quotepath=false commit", "git status && git commit -m x",
            "git status\ngit commit -m x", "/usr/bin/git --no-optional-locks commit",
            "git --no-lazy-fetch commit -m x", "GIT.EXE --no-pager commit -m x",
        ):
            with self.subTest(command=command), patch(
                "harness_hook._run_check", return_value=(False, "failed")
            ) as check, patch("harness_hook._commit_risk_tier", return_value="T1"):
                result = handle_event({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                                       "tool_input": {"command": command}, "cwd": str(ROOT)})
                check.assert_called_once_with(ROOT, "quick")
                self.assertEqual("deny", result["hookSpecificOutput"]["permissionDecision"])

    def test_commit_text_in_arguments_or_comments_does_not_trigger_validation(self) -> None:
        for command in (
            "echo 'git commit'", "git commit-msg", "git status # git commit",
            "echo ';' git commit", "git -C 'git commit' status", "git -C",
            "git status --format='git commit'", "echo 'unterminated",
        ):
            with self.subTest(command=command), patch("harness_hook._run_check") as check:
                result = handle_event({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                                       "tool_input": {"command": command}})
                self.assertIsNone(result)
                check.assert_not_called()

    def test_invalid_hook_payload_reports_an_error_without_echoing_input(self) -> None:
        for payload in ("not-json private-input", "[]"):
            with self.subTest(payload=payload):
                result = subprocess.run([sys.executable, str(ROOT / ".codex/hooks/harness_hook.py")],
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
