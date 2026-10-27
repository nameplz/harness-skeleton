from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from contextlib import redirect_stdout
from io import StringIO
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from scripts.harness import HarnessError, _trusted_check_command, load_config, main, run_checks, sanitize_log  # noqa: E402
from scripts.command_runner import CommandResult, run_bounded_command  # noqa: E402
from scripts.harness_risk import MAX_DIFF_BYTES, _git_output, classify_risk, inspect_git_risk  # noqa: E402


class HarnessRiskTests(unittest.TestCase):
    def test_risk_tiers_select_expected_review_routes(self) -> None:
        cases = (
            (["docs/README.md"], "", "T0", False, False),
            (["src/app.py"], "+return value", "T1", False, False),
            (["src/app.py", "src/store.py"], "+return value", "T1", False, False),
            ([".codex/config.toml"], "+enabled = true", "T3", True, True),
        )

        for paths, diff, level, code_review, security_review in cases:
            with self.subTest(paths=paths):
                result = classify_risk(paths, diff)

                self.assertEqual(level, result.level)
                self.assertEqual(code_review, result.code_review)
                self.assertEqual(security_review, result.security_review)

    def test_harness_path_tiers_follow_local_validation_policy(self) -> None:
        cases = (
            (".harness/config.toml", "", "T2"),
            (".harness/tests/test_x.py", "+assert ready", "T1"),
            (".harness/tests/test_x.py", "-assert ready", "T2"),
            ("AGENTS.md", "+guide", "T0"),
            (".agents/skills/harness/SKILL.md", "+guide", "T0"),
            ("packages/foo/AGENTS.md", "+guide", "T0"),
            (".codex/hooks/harness_hook.py", "", "T3"),
            ("scripts/harness_risk.py", "", "T3"),
            (".github/workflows/ci.yml", "", "T3"),
        )
        for path, diff, tier in cases:
            with self.subTest(path=path, diff=diff):
                result = classify_risk([path], diff, security_paths=[], security_keywords=[])
                self.assertEqual(tier, result.level)
                self.assertEqual(diff == "-assert ready", "test_weakening" in result.reasons)
        for path in (".harness/task-template.md", "deploy/app.py", ".github/issue_template.md",
                     ".codex/agents/reviewer.toml", "scripts/verify_ci.py",
                     "scripts/github_expression_scanner.py", "scripts/ci_action_policy.py",
                     "scripts/project_validation.py", "scripts/check_project.py"):
            with self.subTest(path=path):
                self.assertNotEqual("T3", classify_risk([path], "").level)

    def test_documentation_keywords_do_not_raise_risk(self) -> None:
        cases = (
            (["README.md"], "+See https://example.test for details"),
            (["README"], '+Add an authorization explanation and token glossary'),
            (["docs/guide.adoc"], '+Add an authorization explanation and token glossary'),
            (["docs/guide"], '+Add an authorization explanation and token glossary'),
            (["docs/security.md"], '+"authorization" and "token" are protocol terms'),
        )

        for paths, diff in cases:
            with self.subTest(paths=paths):
                result = classify_risk(paths, diff)
                self.assertEqual("T0", result.level)
                self.assertFalse(result.code_review)
                self.assertFalse(result.security_review)

    def test_text_file_outside_known_documentation_locations_keeps_hard_escalation(self) -> None:
        result = classify_risk(["src/runner.txt"], "+subprocess.run(command)")

        self.assertEqual("T3", result.level)
        self.assertTrue(result.security_review)

    def test_two_implementation_files_are_hint_not_t2(self) -> None:
        result = classify_risk(["src/app.py", "src/store.py"], "+return value")

        self.assertEqual("T1", result.level)
        self.assertFalse(result.code_review)
        self.assertIn("changes span 2 implementation files", result.hints)

    def test_soft_security_keywords_only_add_hints(self) -> None:
        result = classify_risk(["src/client.py"], "+token = read_token()\n+open(path).write_text(data)")

        self.assertEqual("T1", result.level)
        self.assertFalse(result.security_review)
        self.assertTrue(any("token" in hint for hint in result.hints))
        self.assertTrue(any("open(" in hint for hint in result.hints))

    def test_hard_security_keywords_escalate_but_hints_do_not(self) -> None:
        for diff in (
            "+subprocess.run(command)",
            "+os.system(command)",
            "+shell=True",
            "+Popen(command, shell = True)",
            "+api_secret = read_secret()",
        ):
            with self.subTest(diff=diff):
                result = classify_risk(["src/runner.py"], diff)
                self.assertEqual("T3", result.level)
                self.assertTrue(result.security_review)

    def test_hard_security_path_precedes_documentation_only(self) -> None:
        result = classify_risk([".github/workflows/README.md"], "+See https://example.test")

        self.assertEqual("T3", result.level)
        self.assertTrue(result.security_review)

    def test_hard_complexity_signals_raise_t2(self) -> None:
        cases = (
            (["package.json", "src/app.py"], "+return value", "changed dependency declarations"),
            (["requirements.txt"], "+requests==2.0", "changed dependency declarations"),
            (["src/api/client.py"], "+return value", "changed a public API area"),
            (["src/app.py"], "+introduces a new subsystem", "complex change marker"),
        )

        for paths, diff, reason in cases:
            with self.subTest(paths=paths, diff=diff):
                result = classify_risk(paths, diff)
                self.assertEqual("T2", result.level)
                self.assertTrue(result.code_review)
                self.assertFalse(result.security_review)
                self.assertTrue(any(reason in item for item in result.reasons))

    def test_project_risk_rules_are_additive_and_path_patterns_are_validated(self) -> None:
        result = classify_risk(
            ["src/payments/ledger.py"],
            "+update the ledger",
            security_paths=["src/payments/**"],
            security_keywords=["ledger boundary"],
        )
        self.assertEqual("T3", result.level)
        self.assertTrue(result.security_review)
        self.assertTrue(any("src/payments/ledger.py" in reason for reason in result.reasons))

        with self.assertRaises(HarnessError):
            classify_risk(["src/file.py"], "", security_paths=["../outside/**"])

        custom_hard = classify_risk(["src/file.py"], "+ledger boundary", security_keywords=["ledger boundary"])
        self.assertEqual("T3", custom_hard.level)
        custom_hint = classify_risk(["src/file.py"], "+cache layer", security_hint_keywords=["cache layer"])
        self.assertEqual("T1", custom_hint.level)
        self.assertIn("cache layer", custom_hint.hints[0])

    def test_unsafe_diff_paths_fail_closed(self) -> None:
        for path in ("../outside.txt", "/tmp/outside.txt", "C:\\outside.txt", "src/../secret.py"):
            with self.subTest(path=path), self.assertRaises(HarnessError):
                classify_risk([path], "+change")

    def test_sensitive_directory_root_paths_require_security_review(self) -> None:
        for path in ("auth", "security", "migrations"):
            with self.subTest(path=path):
                result = classify_risk([path], "+change")

                self.assertEqual("T3", result.level)
                self.assertTrue(result.security_review)

    def test_no_diff_is_a_trivial_result(self) -> None:
        result = classify_risk([], "")

        self.assertEqual("T0", result.level)
        self.assertFalse(result.code_review)
        self.assertFalse(result.security_review)

    def test_risk_command_scans_tracked_and_untracked_git_changes(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.run_git(root, "init", "-q")
            self.run_git(root, "config", "user.name", "Harness Test")
            self.run_git(root, "config", "user.email", "harness@example.test")
            tracked = root / "src/app.py"
            tracked.parent.mkdir(parents=True)
            tracked.write_text("def app():\n    return True\n", encoding="utf-8")
            self.run_git(root, "add", "src/app.py")
            self.run_git(root, "-c", "user.name=Harness Test", "-c", "user.email=harness@example.test", "commit", "-qm", "baseline")

            tracked.write_text(
                "def app():\n    return run_external_process()\n",
                encoding="utf-8",
            )
            untracked = root / "src/auth/session.py"
            untracked.parent.mkdir(parents=True)
            untracked.write_text("secret=DO_NOT_PRINT\n", encoding="utf-8")

            output = StringIO()
            with redirect_stdout(output):
                exit_code = main(["risk", "--root", str(root)])
            report = json.loads(output.getvalue())

            self.assertEqual(0, exit_code)
            self.assertEqual("T3", report["level"])
            self.assertTrue(report["code_review"])
            self.assertTrue(report["security_review"])
            self.assertIn("src/auth/session.py", report["changed_paths"])
            self.assertNotIn("DO_NOT_PRINT", output.getvalue())

    def test_risk_command_supports_a_git_repository_without_a_commit(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.run_git(root, "init", "-q")
            sensitive = root / "auth/session.py"
            sensitive.parent.mkdir(parents=True)
            sensitive.write_text("def validate():\n    return True\n", encoding="utf-8")
            self.run_git(root, "add", "auth/session.py")
            output = StringIO()

            with redirect_stdout(output):
                exit_code = main(["risk", "--root", str(root)])

            report = json.loads(output.getvalue())
            self.assertEqual(0, exit_code)
            self.assertEqual("T3", report["level"])
            self.assertIn("auth/session.py", report["changed_paths"])

    def test_risk_scan_escalates_both_sides_of_sensitive_renames(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.run_git(root, "init", "-q")
            self.run_git(root, "config", "user.name", "Harness Test")
            self.run_git(root, "config", "user.email", "harness@example.test")
            config = root / ".harness/config.toml"
            config.parent.mkdir(parents=True)
            config.write_text("schema = 2\n", encoding="utf-8")
            self.run_git(root, "add", ".")
            self.run_git(root, "commit", "-qm", "baseline")
            config.replace(root / "safe.txt")
            self.run_git(root, "add", "-A")
            assessment = inspect_git_risk(
                root,
                load_config_fn=lambda _root: SimpleNamespace(security_paths=(), security_keywords=()),
            )

            self.assertEqual("T2", assessment.level)
            self.assertTrue(assessment.code_review)
            self.assertFalse(assessment.security_review)
            self.assertIn(".harness/config.toml", assessment.changed_paths)
            self.assertIn("safe.txt", assessment.changed_paths)

    def run_git(self, root: Path, *arguments: str) -> None:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            shell=False,
            env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1"},
        )
        self.assertEqual(0, completed.returncode, completed.stderr)


class HarnessCheckTests(unittest.TestCase):
    def test_selftest_uses_isolated_harness_suite_and_propagates_failure(self) -> None:
        for code in (0, 1):
            with self.subTest(code=code), patch(
                "scripts.harness.run_bounded_command", return_value=CommandResult(code, "Ran 1 test in 0.001s\n\nOK\n")
            ) as run, redirect_stdout(StringIO()):
                self.assertEqual(code, main(["selftest"]))
                command = run.call_args.args[0]
                self.assertEqual([sys.executable, "-I", "-m", "unittest", "discover"], command[:5])
                self.assertEqual(str(ROOT / ".harness/tests"), command[6])
                self.assertEqual(str(ROOT / ".harness"), command[8])

    def test_selftest_rejects_empty_or_incomplete_suite(self) -> None:
        for output in ("", "Ran 0 tests in 0.001s\n\nOK\n"):
            with self.subTest(output=output), patch(
                "scripts.harness.run_bounded_command", return_value=CommandResult(0, output)
            ), redirect_stdout(StringIO()):
                self.assertNotEqual(0, main(["selftest"]))

    def test_skeleton_profiles_start_unconfigured(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_config(root, [], [])
            config = load_config(root)
            self.assertEqual((), config.quick)
            self.assertEqual((), config.full)

    def write_config(self, root: Path, quick: list[list[str]], full: list[list[str]]) -> Path:
        config = root / ".harness/config.toml"
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text(
            "schema = 2\n\n[checks]\n"
            f"quick = {json.dumps(quick)}\n"
            f"full = {json.dumps(full)}\n",
            encoding="utf-8",
        )
        return config

    def test_check_runs_explicit_argv_and_redacts_captured_output(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            script = root / "check.py"
            script.write_text(
                "print('token=sample-secret customer@example.test')\n",
                encoding="utf-8",
            )
            command = [sys.executable, "check.py"]
            self.write_config(root, [command], [command])

            report = run_checks(root, "quick")

            self.assertTrue(report["ok"])
            self.assertEqual("quick", report["profile"])
            self.assertEqual(0, report["checks"][0]["returncode"])
            self.assertNotIn("sample-secret", report["checks"][0]["output"])

    def test_check_with_missing_or_empty_profile_is_unconfigured(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            missing = run_checks(root, "quick")
            self.assertFalse(missing["ok"])
            self.assertEqual("unconfigured", missing["status"])
            self.assertIn("define checks.quick/full; see .agents/skills/harness/SKILL.md (Validation profile setup)", missing["error"])
            output = StringIO()
            with redirect_stdout(output):
                self.assertEqual(1, main(["check", "--quick", "--root", str(root)]))
            self.assertEqual("unconfigured", json.loads(output.getvalue())["status"])

            self.write_config(root, [], [])
            empty = run_checks(root, "full")
            self.assertFalse(empty["ok"])
            self.assertEqual("unconfigured", empty["status"])
            self.assertIn("no validation commands", empty["error"])
            self.assertIn("define checks.quick/full; see .agents/skills/harness/SKILL.md (Validation profile setup)", empty["error"])

    def test_test_discovery_can_import_project_namespace_packages(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "src"
            tests = root / "tests"
            source.mkdir()
            tests.mkdir()
            (tests / "__init__.py").write_text("", encoding="utf-8")
            (source / "value.py").write_text("VALUE = 42\n", encoding="utf-8")
            (tests / "test_value.py").write_text(
                "import unittest\nfrom src.value import VALUE\n"
                "class ValueTests(unittest.TestCase):\n"
                "    def test_value(self): self.assertEqual(42, VALUE)\n",
                encoding="utf-8",
            )
            command = [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-t", "."]
            self.write_config(root, [command], [command])

            report = run_checks(root, "quick")

            self.assertTrue(report["ok"], report["checks"])
            self.assertEqual(0, report["checks"][0]["returncode"])

    def test_check_rejects_unittest_that_exits_before_reporting_completion(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            tests = root / "tests"
            tests.mkdir()
            (tests / "test_early_exit.py").write_text("import os\nos._exit(0)\n", encoding="utf-8")
            command = [sys.executable, "-m", "unittest", "discover", "-s", "tests"]
            self.write_config(root, [command], [command])

            report = run_checks(root, "quick")

            self.assertFalse(report["ok"])
            self.assertEqual(125, report["checks"][0]["returncode"])
            self.assertIn("without a successful unittest summary", report["checks"][0]["output"])
            self.assertNotIn("customer@example.test", report["checks"][0]["output"])

    def test_unittest_summary_guard_is_a_heuristic_not_an_execution_attestation(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            tests = root / "tests"
            tests.mkdir()
            (tests / "test_forged_summary.py").write_text(
                "import os\n"
                "print('Ran 1 test in 0.0s\\n\\nOK', flush=True)\n"
                "os._exit(0)\n",
                encoding="utf-8",
            )
            command = [sys.executable, "-m", "unittest", "discover", "-s", "tests"]
            self.write_config(root, [command], [command])

            report = run_checks(root, "quick")

            self.assertTrue(report["ok"])
            self.assertTrue(report["checks"][0]["passed"])

    def test_wp02_ac1_mv6_preserves_posix_virtualenv_interpreter(self) -> None:
        self.assertEqual(
            [".venv/bin/python", "-I", "-m", "unittest", "discover"],
            _trusted_check_command([".venv/bin/python", "-m", "unittest", "discover"]),
        )

    def test_wp02_ac2_mv6_preserves_windows_virtualenv_interpreter(self) -> None:
        self.assertEqual(
            [r".venv\Scripts\python.exe", "-I", "-m", "unittest"],
            _trusted_check_command([r".venv\Scripts\python.exe", "-m", "unittest"]),
        )

    def test_wp02_ac3_mv6_bare_python_names_use_host_interpreter(self) -> None:
        for executable in ("python", "python3", "python3.12", "py", "python.exe", "py.exe"):
            with self.subTest(executable=executable):
                self.assertEqual(
                    [sys.executable, "-I", "-m", "unittest"],
                    _trusted_check_command([executable, "-m", "unittest"]),
                )

    def test_wp02_mv6_module_isolation_preserves_paths_and_existing_flags(self) -> None:
        for executable in (".venv/bin/python3.12", r".venv\Scripts\python.exe", sys.executable):
            for module in ("unittest", "compileall"):
                with self.subTest(executable=executable, module=module):
                    command = [executable, "-m", module, "-q"]
                    isolated = [executable, "-I", *command[1:]]
                    self.assertEqual(isolated, _trusted_check_command(command))
                    self.assertEqual(isolated, _trusted_check_command(isolated))
        self.assertEqual(
            [".venv/bin/python", "-m", "pytest"],
            _trusted_check_command([".venv/bin/python", "-m", "pytest"]),
        )

    def test_wp02_mv6_path_interpreter_still_uses_trusted_doctor(self) -> None:
        self.assertEqual(
            [sys.executable, "-I", str(ROOT / "scripts/harness.py"), "doctor", "--root", "."],
            _trusted_check_command([".venv/bin/python", "scripts/harness.py", "doctor", "--root", "."]),
        )

    def test_check_uses_isolated_stdlib_unittest_despite_candidate_module_shadowing(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            tests = root / "tests"
            tests.mkdir()
            (root / "unittest.py").write_text(
                "print('Ran 1 test in 0.0s\\n\\nOK')\n",
                encoding="utf-8",
            )
            (tests / "test_failure.py").write_text(
                "import unittest\nclass Failure(unittest.TestCase):\n"
                "    def test_failure(self): self.fail('real stdlib unittest ran')\n",
                encoding="utf-8",
            )
            command = [sys.executable, "-m", "unittest", "discover", "-s", "tests"]
            self.write_config(root, [command], [command])

            report = run_checks(root, "quick")

            self.assertFalse(report["ok"])
            self.assertNotEqual(0, report["checks"][0]["returncode"])
            self.assertNotIn("Ran 1 test in 0.0s", report["checks"][0]["output"])

    def test_check_uses_isolated_stdlib_compileall_despite_candidate_shadowing(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            scripts = root / "scripts"
            hooks = root / ".codex/hooks"
            scripts.mkdir()
            hooks.mkdir(parents=True)
            (root / "compileall.py").write_text("print('fake compileall')\n", encoding="utf-8")
            (scripts / "broken.py").write_text("def broken(:\n", encoding="utf-8")
            command = [sys.executable, "-m", "compileall", "-q", "scripts", ".codex/hooks"]
            self.write_config(root, [command], [command])

            report = run_checks(root, "quick")

            self.assertFalse(report["ok"])
            self.assertNotEqual(0, report["checks"][0]["returncode"])
            self.assertNotIn("fake compileall", report["checks"][0]["output"])

    def test_check_runs_the_trusted_harness_for_configured_doctor_command(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            script_dir = root / "scripts"
            script_dir.mkdir()
            (script_dir / "harness.py").write_text("print('candidate doctor bypass')\n", encoding="utf-8")
            command = [sys.executable, "scripts/harness.py", "doctor", "--root", "."]
            self.write_config(root, [command], [command])

            report = run_checks(root, "quick")

            self.assertFalse(report["ok"])
            self.assertNotEqual(0, report["checks"][0]["returncode"])
            self.assertNotIn("candidate doctor bypass", report["checks"][0]["output"])

    def test_check_can_load_validation_commands_from_a_trusted_root(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp) / "candidate"
            trusted = Path(temp) / "trusted"
            root.mkdir()
            trusted.mkdir()
            tests = root / "tests"
            tests.mkdir()
            (tests / "test_failure.py").write_text(
                "import unittest\nclass Failure(unittest.TestCase):\n"
                "    def test_failure(self): self.fail('trusted command was used')\n",
                encoding="utf-8",
            )
            fake = root / "check.py"
            fake.write_text("print('candidate config passed')\n", encoding="utf-8")
            self.write_config(root, [[sys.executable, "check.py"]], [[sys.executable, "check.py"]])
            self.write_config(trusted, [[sys.executable, "-m", "unittest", "discover", "-s", "tests"]], [[sys.executable, "-m", "unittest", "discover", "-s", "tests"]])

            report = run_checks(root, "quick", config_root=trusted)

            self.assertFalse(report["ok"])
            self.assertNotIn("candidate config passed", report["checks"][0]["output"])

    def test_nonzero_check_is_reported_as_failure_without_leaking_secrets(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            script = root / "check.py"
            script.write_text(
                "import sys\nprint('password=sample-secret', file=sys.stderr)\nsys.exit(4)\n",
                encoding="utf-8",
            )
            command = [sys.executable, "check.py"]
            self.write_config(root, [command], [command])

            report = run_checks(root, "quick")

            self.assertFalse(report["ok"])
            self.assertEqual(4, report["checks"][0]["returncode"])
            self.assertNotIn("sample-secret", report["checks"][0]["output"])

    def test_config_change_during_check_invalidates_evidence(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            path = self.write_config(root, [["true"]], [["true"]])

            def changed(*args, **kwargs):
                path.write_text(path.read_text(encoding="utf-8") + "\n# changed\n", encoding="utf-8")
                return CommandResult(0, "")

            with patch("scripts.harness.run_bounded_command", side_effect=changed):
                report = run_checks(root, "quick")
            self.assertFalse(report["ok"])
            self.assertFalse(report["evidence_unchanged"])
            self.assertNotEqual(report["evidence"]["config_sha256"],
                                report["evidence_after"]["config_sha256"])

    def test_timed_out_check_is_reported_and_sanitized(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            command = [sys.executable, "check.py"]
            self.write_config(root, [command], [command])
            (root / "check.py").write_text(
                "import time\nprint('token=sample-secret', flush=True)\ntime.sleep(10)\n",
                encoding="utf-8",
            )

            with patch("scripts.harness.CHECK_TIMEOUT_SECONDS", 0.05):
                report = run_checks(root, "quick")

            self.assertFalse(report["ok"])
            self.assertEqual(124, report["checks"][0]["returncode"])
            self.assertNotIn("sample-secret", report["checks"][0]["output"])

    @unittest.skipUnless(os.name == "posix", "process-group cleanup is POSIX-specific")
    def test_timed_out_check_terminates_child_processes(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            marker = root / "child-survived.txt"
            (root / "check.py").write_text(
                "import subprocess, sys, time\n"
                "subprocess.Popen([sys.executable, '-c', \"import time; time.sleep(0.7); open('child-survived.txt', 'w').write('alive')\"])\n"
                "time.sleep(10)\n",
                encoding="utf-8",
            )
            command = [sys.executable, "check.py"]
            self.write_config(root, [command], [command])

            with patch("scripts.harness.CHECK_TIMEOUT_SECONDS", 0.1):
                report = run_checks(root, "quick")
            time.sleep(0.9)

            self.assertEqual(124, report["checks"][0]["returncode"])
            self.assertFalse(marker.exists())

    def test_check_output_is_bounded(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "check.py").write_text("print('x' * 100_000)\n", encoding="utf-8")
            command = [sys.executable, "check.py"]
            self.write_config(root, [command], [command])

            with patch("scripts.harness.MAX_COMMAND_OUTPUT_BYTES", 4096):
                report = run_checks(root, "quick")

            self.assertFalse(report["ok"])
            self.assertEqual(125, report["checks"][0]["returncode"])
            self.assertIn("output exceeded", report["checks"][0]["output"])

    def test_check_profile_has_an_aggregate_runtime_limit(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_config(root, [["true"]], [["true"], ["true"]])

            with (
                patch("scripts.harness.CHECK_TOTAL_TIMEOUT_SECONDS", 5),
                patch("scripts.harness.time.monotonic", side_effect=[0, 0, 6]),
                patch("scripts.harness.capture_workspace", return_value={"head": None, "dirty": None, "diff_sha256": None}),
                patch(
                    "scripts.harness.run_bounded_command",
                    return_value=SimpleNamespace(returncode=0, output="", timed_out=False, output_limited=False),
                ) as run_command,
            ):
                report = run_checks(root, "full")

            self.assertFalse(report["ok"])
            self.assertEqual(2, len(report["checks"]))
            self.assertEqual(124, report["checks"][1]["returncode"])
            run_command.assert_called_once()

    def test_quick_profile_fits_within_hook_timeout_budget(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_config(root, [["true"]], [["true"]])

            with (
                patch("scripts.harness.CHECK_QUICK_TIMEOUT_SECONDS", 3),
                patch("scripts.harness.time.monotonic", side_effect=[0, 0]),
                patch("scripts.harness.capture_workspace", return_value={"head": None, "dirty": None, "diff_sha256": None}),
                patch(
                    "scripts.harness.run_bounded_command",
                    return_value=SimpleNamespace(returncode=0, output="", timed_out=False, output_limited=False),
                ) as run_command,
            ):
                report = run_checks(root, "quick")

            self.assertTrue(report["ok"])
            self.assertEqual(3, run_command.call_args.kwargs["timeout_seconds"])

    def test_standard_validation_commands_are_allowed(self) -> None:
        commands = [
            ["ruff", "format", "--check", "."],
            ["git", "diff", "--check"],
            ["git", "status"],
            ["npm", "test"],
            ["pytest", "-q"],
            ["go", "test", "./..."],
        ]
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_config(root, commands, commands)
            self.assertEqual(tuple(map(tuple, commands)), load_config(root).quick)

    def test_removed_command_heuristics_do_not_reject_valid_argv(self) -> None:
        commands = [
            ["ruff", "check", ".", "--fix"],
            ["python", "-m", "timeit", "pass"],
            ["git", "log", "--oneline"],
            ["git", "diff", "--ext-diff", "--output=result.patch"],
        ]
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_config(root, commands, commands)
            self.assertEqual(tuple(map(tuple, commands)), load_config(root).full)

    def test_wp01_ac1_mv6_validation_arguments_and_runners_are_allowed(self) -> None:
        commands = [
            ["pytest", "-k", "add"],
            ["pytest", "-k", "migrate"],
            ["pytest", "-m", "seed"],
            ["pytest", "tests/ci"],
            ["go", "test", "./internal/migration"],
            ["npm", "run", "watch"],
            ["npm", "run", "test:ci"],
            ["uv", "run", "pytest"],
            ["npx", "pytest", "-k", "add"],
            ["poetry", "run", "pytest", "tests/ci"],
            ["pipx", "run", "pytest"],
            ["python3.13", "-I", "-m", "pytest", "-k", "add"],
            ["npm", "--offline", "run", "test:ci"],
            ["uv", "run", "--no-sync", "pytest"],
            ["npm", "-w", "pkg", "run", "test"],
            ["npm", "--prefix", "web", "run", "test"],
            ["uv", "--directory", "svc", "run", "pytest"],
            ["uv", "run", "--directory", "svc", "pytest"],
            ["npm", "run", "pytest", "-k", "add"],
            ["tool", "check", "publish"],
        ]
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_config(root, commands, commands)
            config = load_config(root)
            self.assertEqual(tuple(map(tuple, commands)), config.quick)
            self.assertEqual(tuple(map(tuple, commands)), config.full)

    def test_wp01_ac2_mv6_unsafe_operations_and_nested_runners_are_rejected(self) -> None:
        commands = [
            [manager, operation, "x"]
            for manager, operations in {
                "npm": "install i ci add publish login",
                "pnpm": "install i ci add publish login",
                "yarn": "install i ci add publish login",
                "pip": "install uninstall",
                "pip3": "install uninstall",
                "uv": "add install publish remove",
                "poetry": "add install publish remove",
                "cargo": "add install publish remove",
                "tool": "deploy migrate seed login publish",
            }.items()
            for operation in operations.split()
        ] + [
            ["npm", "ci"], ["npm", "install"],
            ["migrate"], ["seed"],
            ["uv", "pip", "install", "x"], ["uv", "pip", "uninstall", "x"],
            ["npx", "prisma", "migrate", "deploy"],
            ["prisma", "migrate", "deploy"],
            ["npm", "run", "prisma", "migrate", "deploy"],
            ["uv", "run", "pip", "install", "x"],
            ["poetry", "run", "pip", "install", "x"],
            ["pipx", "run", "pip", "install", "x"],
            ["python3.13", "-I", "-m", "pip", "install", "x"],
            ["uv", "run", "python", "-m", "pip", "install", "x"],
            ["npm.exe", "--offline", "install", "x"],
            ["uv", "run", "env", "pytest"],
            ["uv", "run", "--no-sync", "pip", "install", "x"],
            ["npm", "run", "--silent", "prisma", "migrate", "deploy"],
            ["npm", "--prefix", "web", "ci"],
            ["npm", "--prefix", "web", "install"],
            ["pnpm", "--dir", "web", "install"],
            ["yarn", "--cwd", "web", "add", "x"],
            ["uv", "--directory", "svc", "add", "x"],
            ["pip", "--log", "x.log", "install", "x"],
            ["npm", "--prefix", "web", "run", "prisma", "migrate", "deploy"],
            ["npm", "-w", "pkg", "run", "prisma", "migrate", "deploy"],
            ["uv", "--directory", "svc", "run", "pip", "install", "x"],
            ["npm", "--prefix=web", "ci"],
            ["npm", "-wpkg", "ci"],
            ["npm", "--omit", "dev", "ci"],
            ["npm", "--include", "dev", "install"],
            ["pnpm", "--reporter", "silent", "install"],
            ["cargo", "-Z", "x", "install", "y"],
        ]
        with TemporaryDirectory() as temp:
            root = Path(temp)
            for command in commands:
                with self.subTest(command=command):
                    self.write_config(root, [command], [["pytest"]])
                    with self.assertRaises(HarnessError):
                        load_config(root)

    def test_invalid_or_shell_config_fails_closed(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_config(root, [["sh", "-c", "echo unsafe"]], [["python", "-m", "pytest"]])

            with self.assertRaises(HarnessError):
                load_config(root)

    def test_wrapped_shells_and_inline_interpreters_fail_closed(self) -> None:
        commands = (
            ["bash", "-c", "x"],
            ["python", "-c", "x"],
            ["node", "-e", "x"],
            ["/usr/bin/env", "FOO=1", "pytest"],
            ["../outside/test.py"],
            ["env", "sh", "-c", "echo unsafe"],
            ["env", "python", "-c", "print('unsafe')"],
            ["python3.13", "-cprint('unsafe')"],
            ["python3.12", "--eval=print('unsafe')"],
            ["python.exe", "-cprint('unsafe')"],
            ["node", "--eval=process.exit(0)"],
            ["node.exe", "-econsole.log('unsafe')"],
            ["node20", "-pprocess.exit(0)"],
            ["ruby", "-eputs('unsafe')"],
            ["sh", "-ec", "echo unsafe"],
            ["pwsh", "-EncodedCommand", "cHJpbnQ= "],
            ["powershell.exe", "-EncodedCommand", "cHJpbnQ="],
            ["bash.exe", "-ec", "echo unsafe"],
        )
        with TemporaryDirectory() as temp:
            root = Path(temp)
            for command in commands:
                with self.subTest(command=command):
                    self.write_config(root, [command], [["python", "-m", "pytest"]])
                    with self.assertRaises(HarnessError):
                        load_config(root)

    def test_command_paths_cannot_escape_workspace(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            command = [sys.executable, "../outside.py"]
            self.write_config(root, [command], [command])

            with self.assertRaises(HarnessError):
                load_config(root)

    def test_path_option_values_cannot_escape_workspace(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            command = [sys.executable, "-m", "pytest", "--root=../outside"]
            self.write_config(root, [command], [command])

            with self.assertRaises(HarnessError):
                load_config(root)

    def test_url_lookalikes_cannot_bypass_workspace_confinement(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            commands = (
                [sys.executable, "/tmp/outside://evil.py"],
                [sys.executable, "../outside://evil.py"],
                [sys.executable, "--root=../outside://evil.py"],
                [sys.executable, "C://outside/evil.py"],
                [sys.executable, "C:///outside"],
                [sys.executable, "C:////outside"],
            )
            for command in commands:
                with self.subTest(command=command):
                    self.write_config(root, [command], [command])
                    with self.assertRaises(HarnessError):
                        load_config(root)

    def test_valid_urls_remain_allowed_as_check_arguments(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            command = [sys.executable, "-m", "pytest", "--base-url=https://example.test/app"]
            self.write_config(root, [command], [command])

            self.assertEqual(tuple(command), load_config(root).quick[0])

    def test_short_path_options_and_file_uris_cannot_escape_workspace(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            commands = (
                ["ruby", "-I../outside", "check.rb"],
                ["ruby", "-I=../outside", "check.rb"],
                ["ruby", "-I", "../outside", "check.rb"],
                ["ruby", "-r../outside", "check.rb"],
                ["python", "-m", "pytest", "file:///tmp/outside.py"],
                ["python", "-m", "pytest", "--root=file:///tmp/outside.py"],
                ["python", "-m", "pytest", "-Ifile:///tmp/outside.py"],
            )
            for command in commands:
                with self.subTest(command=command):
                    self.write_config(root, [command], [command])
                    with self.assertRaises(HarnessError):
                        load_config(root)

    def test_python_timeit_cannot_be_hidden_behind_environment_launcher(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            command = ["env", "python", "-m", "timeit", "print(1)"]
            self.write_config(root, [command], [command])

            with self.assertRaises(HarnessError):
                load_config(root)

    def test_environment_launcher_cannot_replace_the_executable_path(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            command = ["env", "PATH=/tmp/outside", "python", "check.py"]
            self.write_config(root, [command], [command])

            with self.assertRaises(HarnessError):
                load_config(root)

    def test_embedded_assignment_paths_cannot_escape_workspace(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            command = ["python", "-m", "pytest", "-o", "cache_dir=/tmp/outside"]
            self.write_config(root, [command], [command])

            with self.assertRaises(HarnessError):
                load_config(root)

    def test_validation_process_drops_git_environment_overrides(self) -> None:
        environment = {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "alias.pwn",
            "GIT_CONFIG_VALUE_0": "!sh",
            "GIT_CONFIG_PARAMETERS": "'diff.external=sh -c touch /tmp/proof'",
            "GIT_EXTERNAL_DIFF": "sh -c touch /tmp/proof",
            "GIT_SSH_COMMAND": "sh -c touch /tmp/proof",
        }
        code = "import json, os; print(json.dumps({key: os.environ.get(key) for key in "
        code += repr(tuple(environment)) + "}))"
        with TemporaryDirectory() as temp, patch.dict(os.environ, environment):
            result = run_bounded_command(
                [sys.executable, "-c", code],
                cwd=Path(temp),
                timeout_seconds=5,
                max_output_bytes=1024,
            )

        self.assertEqual(0, result.returncode)
        observed = json.loads(result.output)
        self.assertEqual("8", observed["GIT_CONFIG_COUNT"])
        self.assertEqual("core.hooksPath", observed["GIT_CONFIG_KEY_0"])
        self.assertEqual(os.devnull, observed["GIT_CONFIG_VALUE_0"])
        self.assertNotEqual("alias.pwn", observed["GIT_CONFIG_KEY_0"])
        self.assertIsNone(observed["GIT_CONFIG_PARAMETERS"])
        self.assertIsNone(observed["GIT_EXTERNAL_DIFF"])
        self.assertIsNone(observed["GIT_SSH_COMMAND"])

    def test_bounded_runner_accepts_explicit_environment_without_dropping_git_guards(self) -> None:
        code = "import json, os; print(json.dumps([os.environ.get('HOME'), os.environ.get('CODEX_HOME'), os.environ.get('GIT_CONFIG_COUNT')]))"
        with TemporaryDirectory() as temp:
            home = str(Path(temp) / "home")
            codex_home = str(Path(temp) / "codex")
            result = run_bounded_command(
                [sys.executable, "-c", code],
                cwd=Path(temp),
                timeout_seconds=5,
                max_output_bytes=1024,
                env={"HOME": home, "CODEX_HOME": codex_home, "GIT_EXTERNAL_DIFF": "unsafe"},
            )

        self.assertEqual(0, result.returncode)
        self.assertEqual([home, codex_home, "8"], json.loads(result.output))

    def test_bounded_runner_drops_host_secrets_and_interpreter_injection_variables(self) -> None:
        forbidden = {
            "OPENAI_API_KEY": "secret-openai",
            "GITHUB_TOKEN": "secret-github",
            "AWS_SECRET_ACCESS_KEY": "secret-aws",
            "PYTHONPATH": "/attacker/python",
            "PYTHONHOME": "/attacker/python-home",
            "LD_PRELOAD": "/attacker/lib.so",
            "BASH_ENV": "/attacker/bashrc",
        }
        code = "import json, os; print(json.dumps({key: os.environ.get(key) for key in "
        code += repr(tuple(forbidden)) + "}))"
        with TemporaryDirectory() as temp, patch.dict(os.environ, forbidden):
            result = run_bounded_command(
                [sys.executable, "-c", code],
                cwd=Path(temp),
                timeout_seconds=5,
                max_output_bytes=1024,
                env={"PATH": os.environ["PATH"], **forbidden},
            )

        self.assertEqual(0, result.returncode)
        self.assertEqual({key: None for key in forbidden}, json.loads(result.output))

    def test_existing_extensionless_and_text_symlink_arguments_cannot_escape_workspace(self) -> None:
        with TemporaryDirectory() as temp, TemporaryDirectory() as outside:
            root = Path(temp)
            for name in ("secret", "notes.txt"):
                (Path(outside) / name).write_text("outside", encoding="utf-8")
                (root / name).symlink_to(Path(outside) / name)

            for argument in ("secret", "--config=secret", "notes.txt", "--config=notes.txt"):
                with self.subTest(argument=argument):
                    command = [sys.executable, "-m", "pytest", argument]
                    self.write_config(root, [command], [command])

                    with self.assertRaises(HarnessError):
                        load_config(root)

    def test_windows_absolute_paths_cannot_escape_workspace(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            for windows_path in ("C:\\outside\\config.txt", "C:relative.txt", "\\\\server\\share\\config.txt"):
                with self.subTest(path=windows_path):
                    command = [sys.executable, windows_path]
                    self.write_config(root, [command], [command])

                    with self.assertRaises(HarnessError):
                        load_config(root)

    def test_unknown_schema_fields_and_inline_shells_fail_closed(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            config = self.write_config(root, [["python", "-m", "pytest"]], [["python", "-m", "pytest"]])
            config.write_text(config.read_text(encoding="utf-8").replace("schema = 2", "schema = 99"), encoding="utf-8")

            with self.assertRaises(HarnessError):
                load_config(root)

            self.write_config(root, [["python", "-c", "print('unsafe')"]], [["python", "-m", "pytest"]])
            with self.assertRaises(HarnessError):
                load_config(root)

    def test_command_symlink_cannot_escape_workspace(self) -> None:
        with TemporaryDirectory() as temp, TemporaryDirectory() as outside:
            root = Path(temp)
            outside_script = Path(outside) / "check.py"
            outside_script.write_text("print('outside')", encoding="utf-8")
            (root / "check.py").symlink_to(outside_script)
            command = [sys.executable, "check.py"]
            self.write_config(root, [command], [command])

            with self.assertRaises(HarnessError):
                load_config(root)

    def test_executable_path_symlink_cannot_escape_workspace(self) -> None:
        with TemporaryDirectory() as temp, TemporaryDirectory() as outside:
            root = Path(temp)
            outside_script = Path(outside) / "check.sh"
            outside_script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            (root / "check.sh").symlink_to(outside_script)
            command = ["./check.sh"]
            self.write_config(root, [command], [command])

            with self.assertRaises(HarnessError):
                load_config(root)

    def test_absolute_script_executable_cannot_escape_workspace(self) -> None:
        with TemporaryDirectory() as temp, TemporaryDirectory() as outside:
            root = Path(temp)
            outside_script = Path(outside) / "check.sh"
            outside_script.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            command = [str(outside_script)]
            self.write_config(root, [command], [command])

            with self.assertRaises(HarnessError):
                load_config(root)

    def test_absolute_extensionless_executable_cannot_escape_workspace(self) -> None:
        with TemporaryDirectory() as temp, TemporaryDirectory() as outside:
            root = Path(temp)
            outside_executable = Path(outside) / "validator"
            outside_executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            command = [str(outside_executable)]
            self.write_config(root, [command], [command])

            with self.assertRaises(HarnessError):
                load_config(root)

    def test_non_eval_pytest_plugin_argument_remains_allowed(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            command = ["python", "-m", "pytest", "-p", "no:cacheprovider"]
            self.write_config(root, [command], [command])

            self.assertEqual(command, list(load_config(root).quick[0]))

    def test_command_arguments_are_redacted_in_report(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            script = root / "check.py"
            script.write_text("print('token=sample-secret')\n", encoding="utf-8")
            command = [sys.executable, "check.py", "--token=sample-secret"]
            self.write_config(root, [command], [command])

            report = run_checks(root, "quick")

            self.assertTrue(report["ok"])
            self.assertNotIn("sample-secret", json.dumps(report))

    def test_sanitize_log_redacts_database_urls_jwts_and_pem_keys(self) -> None:
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature-value"
        pem = "-----BEGIN PRIVATE KEY-----\nPRIVATE-MATERIAL\n-----END PRIVATE KEY-----"
        result = sanitize_log(
            "postgres://app:db-password@db.example.test/app "
            + jwt
            + "\n"
            + pem
        )

        for secret in ("app:db-password", jwt, "PRIVATE-MATERIAL"):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, result)

    def test_sanitize_log_redacts_complete_quoted_and_multitoken_credentials(self) -> None:
        cases = (
            ('password: "super secret value"', "super secret value"),
            ("--token=super secret value", "super secret value"),
            ("token=[bracketed-secret] trailing", "bracketed-secret"),
        )
        for value, secret in cases:
            with self.subTest(value=value):
                result = sanitize_log(value)
                self.assertNotIn(secret, result)
                self.assertNotIn("] secret", result)

    def test_attached_multitoken_option_values_are_redacted_as_a_unit(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            values = ("super secret value", "super secret\nsecond-line")
            for value in values:
                with self.subTest(value=value):
                    command = [sys.executable, "check.py", f"--token={value}"]
                    self.write_config(root, [command], [command])
                    (root / "check.py").write_text(
                        "import sys\nprint(sys.argv[1])\n",
                        encoding="utf-8",
                    )

                    report = run_checks(root, "quick")

                    self.assertNotIn(value, json.dumps(report))
                    self.assertNotIn("second-line", json.dumps(report))

    def test_git_output_runner_enforces_the_diff_size_limit_before_capture(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            limited = CommandResult(125, "partial", output_limited=True)
            with patch("scripts.harness_risk.run_bounded_command", return_value=limited) as run_command:
                with self.assertRaisesRegex(HarnessError, "risk scan limit"):
                    _git_output(root, ["diff", "--binary"])

        self.assertEqual(MAX_DIFF_BYTES, run_command.call_args.kwargs["max_output_bytes"])

    def test_environment_secret_names_are_redacted(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            script = root / "check.py"
            script.write_text(
                "print('AWS_SECRET_ACCESS_KEY=aws-secret AWS_SESSION_TOKEN=session-secret SSH_PRIVATE_KEY=private-secret')\n",
                encoding="utf-8",
            )
            command = [sys.executable, "check.py"]
            self.write_config(root, [command], [command])

            report = run_checks(root, "quick")

            self.assertTrue(report["ok"])
            self.assertNotIn("aws-secret", report["checks"][0]["output"])
            self.assertNotIn("session-secret", report["checks"][0]["output"])
            self.assertNotIn("private-secret", report["checks"][0]["output"])

    def test_check_cli_selects_profile_and_returns_failure_status(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            script = root / "check.py"
            script.write_text("raise SystemExit(3)\n", encoding="utf-8")
            command = [sys.executable, "check.py"]
            self.write_config(root, [command], [command])
            output = StringIO()

            with redirect_stdout(output):
                exit_code = main(["check", "--full", "--root", str(root)])

            report = json.loads(output.getvalue())
            self.assertEqual(1, exit_code)
            self.assertFalse(report["ok"])
            self.assertEqual("full", report["profile"])

    def test_risk_command_uses_additive_project_rules(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.run_git(root, "init", "-q")
            self.run_git(root, "config", "user.name", "Harness Test")
            self.run_git(root, "config", "user.email", "harness@example.test")
            config = self.write_config(root, [["true"]], [["true"]])
            config.write_text(
                config.read_text(encoding="utf-8")
                + '\n[risk]\nsecurity_paths = ["src/payments/**"]\nsecurity_keywords = ["payment boundary"]\n',
                encoding="utf-8",
            )
            self.run_git(root, "add", ".harness/config.toml")
            self.run_git(root, "-c", "user.name=Harness Test", "-c", "user.email=harness@example.test", "commit", "-qm", "baseline")
            payment = root / "src/payments/ledger.py"
            payment.parent.mkdir(parents=True)
            payment.write_text("def update():\n    return True\n", encoding="utf-8")
            output = StringIO()

            with redirect_stdout(output):
                exit_code = main(["risk", "--root", str(root)])

            report = json.loads(output.getvalue())
            self.assertEqual(0, exit_code)
            self.assertEqual("T3", report["level"])
            self.assertTrue(report["security_review"])

    def test_risk_command_serializes_project_security_hints(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.run_git(root, "init", "-q")
            self.run_git(root, "config", "user.name", "Harness Test")
            self.run_git(root, "config", "user.email", "harness@example.test")
            config = self.write_config(root, [["true"]], [["true"]])
            config.write_text(
                config.read_text(encoding="utf-8")
                + '\n[risk]\nsecurity_hint_keywords = ["cache signal"]\n',
                encoding="utf-8",
            )
            source = root / "src/client.py"
            source.parent.mkdir(parents=True)
            source.write_text("return None\n", encoding="utf-8")
            self.run_git(root, "add", ".")
            self.run_git(root, "-c", "user.name=Harness Test", "-c", "user.email=harness@example.test", "commit", "-qm", "baseline")
            source.write_text("cache signal = True\n", encoding="utf-8")
            output = StringIO()

            with redirect_stdout(output):
                exit_code = main(["risk", "--root", str(root)])

            report = json.loads(output.getvalue())
            self.assertEqual(0, exit_code)
            self.assertEqual("T1", report["level"])
            self.assertTrue(any("cache signal" in hint for hint in report["hints"]))

    def test_schema_two_config_accepts_optional_security_hint_keywords(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            config = self.write_config(root, [["true"]], [["true"]])
            config.write_text(
                config.read_text(encoding="utf-8")
                + '\n[risk]\nsecurity_hint_keywords = ["network client"]\n',
                encoding="utf-8",
            )

            loaded = load_config(root)

            self.assertEqual(("network client",), loaded.security_hint_keywords)

    def test_invalid_security_hint_keywords_fail_closed(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            config = self.write_config(root, [["true"]], [["true"]])
            config.write_text(
                config.read_text(encoding="utf-8")
                + '\n[risk]\nsecurity_hint_keywords = "token"\n',
                encoding="utf-8",
            )

            with self.assertRaisesRegex(HarnessError, "security_hint_keywords"):
                load_config(root)

    def run_git(self, root: Path, *arguments: str) -> None:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            shell=False,
            env={**os.environ, "GIT_CONFIG_NOSYSTEM": "1"},
        )
        self.assertEqual(0, completed.returncode, completed.stderr)
