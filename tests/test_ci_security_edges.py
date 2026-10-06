from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.check_ci_security import _parse_workflow_yaml, check_workflow_text  # noqa: E402


PINNED_CHECKOUT = "11bd71901bbe5b1630ceea73d27597364c9af683"


class CiSecurityEdgeTests(unittest.TestCase):
    def test_checkout_rejects_case_insensitive_credential_key_override(self) -> None:
        body = (
            "permissions: {}\n"
            f"jobs:\n  t:\n    permissions: {{}}\n    runs-on: ubuntu-24.04\n    steps:\n"
            f"      - uses: actions/checkout@{PINNED_CHECKOUT}\n"
            "        with:\n          persist-credentials: false\n          PERSIST-CREDENTIALS: true\n"
        )

        errors = check_workflow_text(Path("workflow.yml"), body)

        self.assertTrue(any("checkout credentials" in error for error in errors), errors)

    def test_malformed_job_permissions_return_a_policy_error(self) -> None:
        text = (
            "permissions: {}\n"
            "jobs:\n  t:\n    permissions:\n      contents:\n        nested: value\n"
            "    runs-on: ubuntu-24.04\n    steps: []\n"
        )

        errors = check_workflow_text(Path("workflow.yml"), text)

        self.assertTrue(any("permission" in error for error in errors), errors)

    def test_multiple_yaml_documents_fail_closed(self) -> None:
        text = "on:\n  push:\n    branches: [main]\n---\npermissions:\n  contents: write\n"

        errors = check_workflow_text(Path("workflow.yml"), text)

        self.assertTrue(any("workflow YAML" in error for error in errors), errors)

    def test_external_actions_must_use_a_github_repository_reference(self) -> None:
        cases = (
            f"docker://evil/image@{PINNED_CHECKOUT}",
            f"https://github.com/actions/checkout@{PINNED_CHECKOUT}",
        )
        for action_ref in cases:
            text = (
                "permissions: {}\njobs:\n  t:\n    permissions: {}\n"
                "    runs-on: ubuntu-24.04\n    steps:\n"
                f"      - uses: {action_ref}\n"
            )
            with self.subTest(action_ref=action_ref):
                errors = check_workflow_text(Path("workflow.yml"), text)
                self.assertTrue(any("full commit SHA" in error for error in errors), errors)

    def test_github_expression_scanner_respects_quoted_closing_delimiters(self) -> None:
        cases = (
            ("format('}}', 'x') && github.token", "github.token access"),
            ("format('}}', github['token'])", "bracket access"),
            ("format('}}', toJSON(github))", "serialization"),
            ("format('it''s }}', 'x') && github.token", "github.token access"),
        )
        for expression, reason in cases:
            text = (
                "permissions: {}\njobs:\n  t:\n    permissions: {}\n"
                "    runs-on: ubuntu-24.04\n    steps:\n"
                f"      - run: echo ${{{{ {expression} }}}}\n"
            )
            with self.subTest(expression=expression):
                errors = check_workflow_text(Path("workflow.yml"), text)
                self.assertTrue(any(reason in error for error in errors), errors)

    def test_malformed_github_expression_fails_closed(self) -> None:
        text = (
            "permissions: {}\njobs:\n  t:\n    permissions: {}\n"
            "    runs-on: ubuntu-24.04\n    steps:\n"
            "      - run: echo ${{ format('unterminated }} && github.token\n"
        )

        errors = check_workflow_text(Path("workflow.yml"), text)

        self.assertTrue(any("GitHub expression is malformed" in error for error in errors), errors)

    def test_quoted_github_token_text_is_not_treated_as_expression_code(self) -> None:
        text = (
            "permissions: {}\njobs:\n  t:\n    permissions: {}\n"
            "    runs-on: ubuntu-24.04\n    steps:\n"
            "      - run: echo ${{ format('github.token', '}}') }}\n"
        )

        errors = check_workflow_text(Path("workflow.yml"), text)

        self.assertFalse(any("github.token access" in error for error in errors), errors)

    def test_unbraced_if_expressions_cannot_access_sensitive_github_context(self) -> None:
        cases = (
            ("github.token", "github.token access"),
            ("github['token']", "bracket access"),
            ("toJSON(github)", "serialization"),
        )
        for expression, reason in cases:
            text = (
                "permissions: {}\njobs:\n  t:\n    permissions: {}\n"
                f"    if: {expression}\n    runs-on: ubuntu-24.04\n    steps: []\n"
            )
            with self.subTest(expression=expression):
                errors = check_workflow_text(Path("workflow.yml"), text)
                self.assertTrue(any(reason in error for error in errors), errors)

    def test_unbraced_if_expression_cannot_access_secrets_context(self) -> None:
        text = (
            "permissions: {}\njobs:\n  t:\n    permissions: {}\n"
            "    if: secrets.GITHUB_TOKEN\n    runs-on: ubuntu-24.04\n    steps: []\n"
        )

        errors = check_workflow_text(Path("workflow.yml"), text)

        self.assertTrue(any("secrets access" in error for error in errors), errors)

    def test_unbraced_if_expression_ignores_sensitive_text_inside_string_literals(self) -> None:
        text = (
            "permissions: {}\njobs:\n  t:\n    permissions: {}\n"
            "    if: contains(github.ref, 'github.token')\n"
            "    runs-on: ubuntu-24.04\n    steps: []\n"
        )

        errors = check_workflow_text(Path("workflow.yml"), text)

        self.assertFalse(any("github.token access" in error for error in errors), errors)

    def test_secrets_text_inside_expression_literals_is_not_access(self) -> None:
        cases = (
            "      - run: echo ${{ format('secrets', 'x') }}\n",
            "    if: contains(github.ref, 'secrets')\n",
        )
        for expression in cases:
            text = (
                "permissions: {}\njobs:\n  t:\n    permissions: {}\n"
                "    runs-on: ubuntu-24.04\n    steps:\n"
                f"{expression}"
            )
            with self.subTest(expression=expression):
                errors = check_workflow_text(Path("workflow.yml"), text)
                self.assertFalse(any("secrets access" in error for error in errors), errors)

    def test_github_object_filters_cannot_expose_context(self) -> None:
        expressions = (
            "join(github.*, ',')",
            "toJSON(github.*)",
        )
        for expression in expressions:
            text = (
                "permissions: {}\njobs:\n  t:\n    permissions: {}\n"
                "    runs-on: ubuntu-24.04\n    steps:\n"
                f"      - run: echo ${{{{ {expression} }}}}\n"
            )
            with self.subTest(expression=expression):
                errors = check_workflow_text(Path("workflow.yml"), text)
                self.assertTrue(any("object filter" in error for error in errors), errors)

    def test_quoted_github_object_filter_text_is_not_expression_code(self) -> None:
        text = (
            "permissions: {}\njobs:\n  t:\n    permissions: {}\n"
            "    runs-on: ubuntu-24.04\n    steps:\n"
            "      - run: echo ${{ format('github.*', 'x') }}\n"
        )

        errors = check_workflow_text(Path("workflow.yml"), text)

        self.assertFalse(any("object filter" in error for error in errors), errors)

    def test_workflow_trigger_mappings_reject_path_filters(self) -> None:
        target = (
            "on:\n  pull_request_target:\n    branches: [main]\n"
            "    types: [opened, synchronize, reopened, ready_for_review, edited, labeled, unlabeled]\n"
            "    paths-ignore: ['.github/**']\n"
            "  push:\n    branches: [main]\n    paths-ignore: ['.github/**']\n"
        )

        errors = check_workflow_text(Path(".github/workflows/harness-ci.yml"), target)

        self.assertTrue(any("limited to reviewed PR events" in error for error in errors), errors)

    def test_trusted_workflow_without_a_trigger_fails_closed(self) -> None:
        errors = check_workflow_text(
            Path(".github/workflows/harness-ci.yml"),
            "permissions: {}\njobs: {}\n",
        )

        self.assertTrue(any("must declare an approved trigger" in error for error in errors), errors)

    def test_yaml_boolean_trigger_aliases_cannot_mask_the_real_on_key(self) -> None:
        types = "[opened, synchronize, reopened, ready_for_review, edited, labeled, unlabeled]"
        cases = (
            f"on:\n  pull_request_target:\n    branches: [main]\n    types: {types}\n"
            "true:\n  push:\n    branches: [main]\n",
            "true:\n  push:\n    branches: [main]\n",
            '"on":\n  pull_request_target:\n    branches: [main]\n'
            f"    types: {types}\n"
            "yes:\n  push:\n    branches: [main]\n",
            '"on":\n  pull_request_target:\n    branches: [main]\n'
            f"    types: {types}\n"
            "y:\n  push:\n    branches: [main]\n",
        )
        for text in cases:
            with self.subTest(text=text):
                errors = check_workflow_text(Path(".github/workflows/harness-ci.yml"), text)
                self.assertTrue(errors, errors)

    def test_explicit_string_tag_cannot_bypass_duplicate_yaml_key_check(self) -> None:
        text = "permissions:\n  contents: write\n!!str permissions: {}\n"

        errors = check_workflow_text(Path("workflow.yml"), text)

        self.assertTrue(errors, errors)

    def test_non_string_yaml_keys_fail_closed(self) -> None:
        cases = (
            "permissions:\n  null: write\n  ~: {}\n",
            "permissions:\n  1: write\n  01: {}\n",
            "permissions:\n  !!int 1: write\n",
        )
        for text in cases:
            with self.subTest(text=text):
                self.assertTrue(check_workflow_text(Path("workflow.yml"), text))

    def test_local_action_symlinks_cannot_escape_actions_directory(self) -> None:
        with TemporaryDirectory() as temp, TemporaryDirectory() as outside:
            root = Path(temp)
            actions = root / ".github/actions"
            actions.mkdir(parents=True)
            (actions / "external").symlink_to(Path(outside), target_is_directory=True)
            text = (
                "permissions: {}\njobs:\n  t:\n    permissions: {}\n"
                "    runs-on: ubuntu-24.04\n    steps:\n      - uses: ./.github/actions/external\n"
            )

            errors = check_workflow_text(Path(".github/workflows/test.yml"), text, root=root)

            self.assertTrue(any("local action path" in error for error in errors), errors)

    def test_workflows_reject_private_cross_repository_prs_before_checkout(self) -> None:
        for workflow_path, job_name in (
            (".github/workflows/harness-ci.yml", "security-policy"),
            (".github/workflows/project-ci.yml", "source-package"),
        ):
            workflow = (ROOT / workflow_path).read_text(encoding="utf-8")
            steps = _parse_workflow_yaml(workflow)["jobs"][job_name]["steps"]
            guard_index = next(
                index for index, step in enumerate(steps)
                if step.get("name") == "Reject private cross-repository PR sources"
            )
            checkout_index = next(
                index for index, step in enumerate(steps)
                if step.get("name") == "Checkout pull request source"
            )
            with self.subTest(workflow=workflow_path):
                guard = steps[guard_index]
                self.assertLess(guard_index, checkout_index)
                self.assertIn("head.repo.private == true", guard.get("if", ""))
                self.assertIn("head.repo.full_name !=", guard.get("if", ""))
                self.assertIn("exit 1", guard.get("run", ""))

    def test_candidate_code_is_downloaded_only_in_permissionless_jobs(self) -> None:
        for workflow_path, package_name, execution_name in (
            (".github/workflows/harness-ci.yml", "security-policy", "harness-core"),
            (".github/workflows/project-ci.yml", "source-package", "project-validation"),
        ):
            workflow = (ROOT / workflow_path).read_text(encoding="utf-8")
            self.assertEqual([], check_workflow_text(Path(workflow_path), workflow))
            jobs = _parse_workflow_yaml(workflow)["jobs"]
            package = jobs[package_name]
            execution = jobs[execution_name]
            package_actions = [step.get("uses", "") for step in package["steps"]]
            execution_actions = [step.get("uses", "") for step in execution["steps"]]
            upload = next(step for step in package["steps"] if "actions/upload-artifact@" in step.get("uses", ""))
            download = next(step for step in execution["steps"] if "actions/download-artifact@" in step.get("uses", ""))
            artifact_settings = upload["with"]
            with self.subTest(workflow=workflow_path):
                self.assertEqual("read", package["permissions"]["contents"])
                self.assertEqual({}, execution["permissions"])
                self.assertTrue(any(action.startswith("actions/upload-artifact@") for action in package_actions))
                self.assertTrue(any(action.startswith("actions/download-artifact@") for action in execution_actions))
                self.assertFalse(any(action.startswith("actions/checkout@") for action in execution_actions))
                self.assertTrue(any("git init candidate" in step.get("run", "") for step in execution["steps"]))
                self.assertEqual(1, artifact_settings["retention-days"])
                self.assertIn(".tar", artifact_settings["path"])
                self.assertEqual(0, artifact_settings["compression-level"])
                self.assertEqual(upload["with"]["name"], download["with"]["name"])

                package_runs = "\n".join(step.get("run", "") for step in package["steps"])
                self.assertIn("--directory candidate --exclude=.git .", package_runs)
                if workflow_path.endswith("project-ci.yml"):
                    self.assertIn("--directory trusted --exclude=.git .", package_runs)

        policy = _parse_workflow_yaml(
            (ROOT / ".github/workflows/harness-ci.yml").read_text(encoding="utf-8")
        )["jobs"]["security-policy"]
        policy_runs = "\n".join(step.get("run", "") for step in policy["steps"])
        self.assertIn('GIT_CONFIG_KEY_0="http.https://github.com/.extraheader"', policy_runs)
        self.assertIn("git -C candidate fetch", policy_runs)
        self.assertNotIn("python3 candidate/", policy_runs)

    def test_source_archives_keep_hidden_files_and_executable_modes_without_git_metadata(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            (source / ".git").mkdir(parents=True)
            (source / ".codex").mkdir()
            (source / ".git" / "metadata").write_text("private metadata", encoding="utf-8")
            (source / ".codex" / "config.toml").write_text("schema = 2\n", encoding="utf-8")
            executable = source / "run-checks.sh"
            executable.write_text("#!/bin/sh\n", encoding="utf-8")
            executable.chmod(0o755)
            archive = root / "source.tar"
            extracted = root / "extracted"
            extracted.mkdir()

            subprocess.run(
                ["tar", "--create", "--file", str(archive), "--directory", str(source), "--exclude=.git", "."],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    "tar", "--extract", "--file", str(archive), "--directory", str(extracted),
                    "--no-same-owner", "--no-same-permissions",
                ],
                check=True,
                capture_output=True,
            )

            self.assertFalse((extracted / ".git").exists())
            self.assertTrue((extracted / ".codex/config.toml").is_file())
            self.assertTrue((extracted / "run-checks.sh").stat().st_mode & 0o111)
