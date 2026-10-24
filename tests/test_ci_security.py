from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest
from tempfile import TemporaryDirectory
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.check_ci_security import (  # noqa: E402
    MAX_WORKFLOW_BYTES,
    check_security_policy,
    check_workflow_text,
    is_sensitive_path,
)

PINNED_ACTION = "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683"


def setup_project(root: Path, *, quick: list[list[str]] | None = None, full: list[list[str]] | None = None) -> None:
    config = root / ".harness/config.toml"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(
        "schema = 2\n\n[checks]\n"
        f"quick = {json.dumps(quick if quick is not None else [["python", "-m", "unittest"]])}\n"
        f"full = {json.dumps(full if full is not None else [["python", "-m", "unittest"]])}\n",
        encoding="utf-8",
    )
    workflow = root / ".github/workflows/ci.yml"
    workflow.parent.mkdir(parents=True, exist_ok=True)
    workflow.write_text(valid_workflow(), encoding="utf-8")


def valid_workflow(*, name: str = "CI", job_id: str = "verify", job_name: str | None = None,
                   runner: str = "ubuntu-24.04", extra: str = "") -> str:
    display_name = f"    name: {job_name}\n" if job_name else ""
    return (
        f"name: {name}\n"
        "on:\n  pull_request:\n  push:\n    branches: [main]\n"
        "permissions: {}\n"
        "jobs:\n"
        f"  {job_id}:\n"
        f"{display_name}"
        f"    runs-on: {runner}\n"
        "    timeout-minutes: 15\n"
        "    permissions: {}\n"
        "    steps:\n"
        f"      - uses: {PINNED_ACTION}\n"
        "        with:\n          persist-credentials: false\n"
        "      - run: python -I scripts/harness.py check --full\n"
        f"{extra}"
    )


class CiSecurityTests(unittest.TestCase):
    def test_full_profile_workflows_accept_project_specific_job_names(self) -> None:
        examples = (
            valid_workflow(name="Python CI", job_id="pytest", runner="ubuntu-24.04"),
            valid_workflow(name="Node CI", job_id="node_validation", runner="windows-latest"),
            valid_workflow(name="Go CI", job_id="go-tests", runner="macos-15"),
            "name: Monorepo CI\non:\n  pull_request:\npermissions: {}\njobs:\n"
            "  package-a:\n    runs-on: ubuntu-22.04\n    timeout-minutes: 10\n    steps:\n"
            "      - run: echo package A\n  package-b:\n    needs: package-a\n"
            "    runs-on: ubuntu-22.04\n    timeout-minutes: 20\n    steps:\n"
            f"      - uses: {PINNED_ACTION}\n        with:\n          persist-credentials: false\n"
            "      - run: python -I scripts/harness.py check --full\n",
        )
        for body in examples:
            with self.subTest(workflow=body[:24]):
                self.assertEqual([], check_workflow_text(Path(".github/workflows/ci.yml"), body))

    def test_full_profile_requires_isolated_python(self) -> None:
        body = valid_workflow().replace("python -I scripts/harness.py", "python scripts/harness.py")
        errors = check_workflow_text(Path("ci.yml"), body)
        self.assertTrue(any("no job runs scripts/harness.py check --full" in error for error in errors), errors)

    def test_full_profile_rejects_python_import_path_overrides(self) -> None:
        body = valid_workflow().replace(
            "permissions: {}", "env:\n  PYTHONPATH: .ci-hooks\npermissions: {}", 1
        )
        errors = check_workflow_text(Path("ci.yml"), body)
        self.assertTrue(any("interpreter environment" in error for error in errors), errors)

    def test_only_current_hosted_runner_labels_are_accepted(self) -> None:
        for runner in ("ubuntu-99.99", "macos-99", "xcode-99", "org-custom-runner"):
            with self.subTest(runner=runner):
                errors = check_workflow_text(Path("ci.yml"), valid_workflow(runner=runner))
                self.assertTrue(any("GitHub-hosted runner" in error for error in errors), errors)

    def test_ci_policy_returns_json_contract_and_actual_full_job_ids(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            setup_project(root, quick=[["python", "-m", "unittest"]], full=[["python", "-m", "unittest"]])
            (root / ".github/workflows/ci.yml").write_text(
                valid_workflow(name="Project CI", job_id="project-tests", job_name="Project tests"),
                encoding="utf-8",
            )
            result = check_security_policy(root=root)
            self.assertTrue(result["ok"], result["errors"])
            self.assertEqual("configured", result["status"])
            self.assertEqual("Project tests", result["required_checks"][0]["job_name"])
            self.assertEqual("project-tests", result["required_checks"][0]["job_id"])
            self.assertTrue({"workflows", "checks", "errors", "warnings"}.issubset(result))

    def test_yaml_and_duplicate_mapping_keys_fail_closed(self) -> None:
        for body in (
            "jobs: [invalid\n",
            "name: CI\nname: duplicate\non:\n  pull_request:\njobs: {}\n",
            "on:\n  pull_request:\n---\non:\n  push:\n    branches: [main]\n",
        ):
            with self.subTest(body=body):
                errors = check_workflow_text(Path("ci.yml"), body)
                self.assertTrue(errors)

    def test_standard_shorthand_trigger_forms_are_supported(self) -> None:
        mapping_triggers = "on:\n  pull_request:\n  push:\n    branches: [main]\n"
        for trigger in ("on: pull_request\n", "on: [pull_request]\n"):
            with self.subTest(trigger=trigger):
                body = valid_workflow().replace(mapping_triggers, trigger)
                self.assertEqual([], check_workflow_text(Path("ci.yml"), body))
        push_only = valid_workflow().replace(mapping_triggers, "on: [push]\n")
        self.assertTrue(any("push" in error for error in check_workflow_text(Path("ci.yml"), push_only)))

    def test_yml_and_yaml_are_both_scanned_and_symlinks_rejected(self) -> None:
        with TemporaryDirectory() as temp, TemporaryDirectory() as outside:
            root = Path(temp)
            setup_project(root)
            yaml = root / ".github/workflows/second.yaml"
            yaml.write_text(valid_workflow(name="Second CI", job_id="second"), encoding="utf-8")
            self.assertEqual(2, len(check_security_policy(root=root)["workflows"]))
            linked = root / ".github/workflows/link.yml"
            linked.symlink_to(Path(outside) / "external.yml")
            (Path(outside) / "external.yml").write_text(valid_workflow(), encoding="utf-8")
            result = check_security_policy(root=root)
            self.assertFalse(result["ok"])
            self.assertTrue(any("symlink" in error for error in result["errors"]))

    def test_missing_workflow_or_profiles_is_unconfigured_and_not_success(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            config = root / ".harness/config.toml"
            config.parent.mkdir(parents=True)
            config.write_text("schema = 2\n\n[checks]\nquick = []\nfull = []\n", encoding="utf-8")
            result = check_security_policy(root=root)
            self.assertFalse(result["ok"])
            self.assertEqual("unconfigured", result["status"])
            self.assertTrue(any("Full" in error or "full" in error for error in result["errors"]))

    def test_manual_only_ci_with_profiles_is_unconfigured(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            setup_project(root)
            workflow = valid_workflow().replace(
                "on:\n  pull_request:\n  push:\n    branches: [main]\n",
                "on:\n  workflow_dispatch:\n",
            )
            (root / ".github/workflows/ci.yml").write_text(workflow, encoding="utf-8")
            result = check_security_policy(root=root)
        self.assertFalse(result["ok"])
        self.assertEqual("unconfigured", result["status"])
        self.assertTrue(any("pull_request validation workflow" in error for error in result["errors"]))

    def test_push_only_full_job_does_not_satisfy_pr_validation(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            setup_project(root)
            workflow = valid_workflow().replace(
                "  verify:\n", "  verify:\n    if: github.event_name == 'push'\n"
            )
            (root / ".github/workflows/ci.yml").write_text(workflow, encoding="utf-8")
            result = check_security_policy(root=root)
        self.assertFalse(result["ok"])
        self.assertEqual("unconfigured", result["status"])
        self.assertEqual([], result["required_checks"])
        self.assertTrue(any("no pull_request job" in error for error in result["errors"]))

    def test_pr_workflow_without_full_profile_is_unconfigured(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            setup_project(root)
            (root / ".github/workflows/ci.yml").write_text(
                valid_workflow().replace("python -I scripts/harness.py check --full", "echo ok"),
                encoding="utf-8",
            )
            result = check_security_policy(root=root)
        self.assertFalse(result["ok"])
        self.assertEqual("unconfigured", result["status"])
        self.assertTrue(any("no job runs" in error for error in result["errors"]))

    def test_missing_config_is_unconfigured_but_invalid_config_is_invalid(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.assertEqual("unconfigured", check_security_policy(root=root)["status"])
            config = root / ".harness/config.toml"
            config.parent.mkdir(parents=True)
            config.write_text("schema = 1\n\n[checks]\nquick = []\nfull = []\n", encoding="utf-8")
            result = check_security_policy(root=root)
        self.assertEqual("invalid", result["status"])
        self.assertFalse(result["ok"])

    def test_security_policy_rejects_write_permissions_secrets_and_github_token(self) -> None:
        token = "$" + "{{ github.token }}"
        secret = "$" + "{{ secrets.TEST_TOKEN }}"
        for edit, expected in (
            ("permissions: {}", "permissions:\n  contents: write"),
            ("- run: python -I scripts/harness.py check --full", f"- run: echo {secret}\n      - run: python -I scripts/harness.py check --full"),
            ("- run: python -I scripts/harness.py check --full", f"- run: echo {token}\n      - run: python -I scripts/harness.py check --full"),
        ):
            with self.subTest(expected=expected):
                body = valid_workflow().replace(edit, expected, 1)
                errors = check_workflow_text(Path("ci.yml"), body)
                self.assertTrue(errors, errors)

    def test_permissions_reject_write_all_and_job_level_writes(self) -> None:
        cases = (
            valid_workflow().replace("permissions: {}", "permissions: write-all", 1),
            valid_workflow().replace(
                "    permissions: {}", "    permissions:\n      contents: write", 1
            ),
        )
        for body in cases:
            with self.subTest(body=body[:80]):
                self.assertTrue(check_workflow_text(Path("ci.yml"), body))

    def test_read_only_workflow_permissions_are_valid(self) -> None:
        body = valid_workflow().replace("permissions: {}", "permissions:\n  contents: read", 1)
        self.assertEqual([], check_workflow_text(Path("ci.yml"), body))

    def test_sensitive_github_context_syntaxes_are_rejected(self) -> None:
        expressions = (
            "${{ secrets }}",
            "${{ toJSON(secrets) }}",
            "${{ github.token }}",
            "${{ toJSON(github) }}",
            "${{ github['token'] }}",
            "${{ github[format('to', 'ken')] }}",
            "${{ join(github.*, ',') }}",
        )
        for expression in expressions:
            with self.subTest(expression=expression):
                body = valid_workflow().replace(
                    "- run: python -I scripts/harness.py check --full",
                    f"- run: {json.dumps('echo ' + expression)}\n      - run: python -I scripts/harness.py check --full",
                )
                self.assertTrue(check_workflow_text(Path("ci.yml"), body))

    def test_malformed_github_expressions_fail_closed(self) -> None:
        expression = "$" + "{{ format('unterminated }"
        body = valid_workflow().replace(
            "- run: python -I scripts/harness.py check --full",
            f"- run: {json.dumps('echo ' + expression)}\n      - run: python -I scripts/harness.py check --full",
        )
        errors = check_workflow_text(Path("ci.yml"), body)
        self.assertTrue(any("GitHub expression is malformed" in error for error in errors), errors)

    def test_workflow_scope_secrets_are_rejected_for_pull_request_jobs(self) -> None:
        secret = "$" + "{{ secrets.TEST_TOKEN }}"
        body = valid_workflow().replace(
            "permissions: {}", f'env:\n  TOKEN: "{secret}"\npermissions: {{}}', 1
        )
        errors = check_workflow_text(Path("ci.yml"), body)
        self.assertTrue(any("secrets context" in error for error in errors), errors)

    def test_full_profile_comment_cannot_stand_in_for_the_command(self) -> None:
        body = valid_workflow().replace(
            "- run: python -I scripts/harness.py check --full",
            "- run: |\n          # python -I scripts/harness.py check --full\n          npm test",
        )
        errors = check_workflow_text(Path("ci.yml"), body)
        self.assertTrue(any("no job runs scripts/harness.py check --full" in error for error in errors), errors)

    def test_full_profile_command_rejects_shell_comments_and_expression_expansion(self) -> None:
        body = valid_workflow().replace(
            "      - run: python -I scripts/harness.py check --full",
            "      - run: |\n          python -I scripts/harness.py check --full # ${{ env.EXTRA }}",
        )
        self.assertTrue(check_workflow_text(Path("ci.yml"), body))

    def test_full_profile_rejects_loader_environment_and_prior_github_env_writes(self) -> None:
        cases = (
            valid_workflow().replace("    timeout-minutes:", "    env:\n      LD_PRELOAD: /tmp/pwn.so\n    timeout-minutes:"),
            valid_workflow().replace("    timeout-minutes:", "    env:\n      DYLD_INSERT_LIBRARIES: /tmp/pwn.dylib\n    timeout-minutes:"),
            valid_workflow(extra=(
                "      - run: a=GITHUB_; b=PATH; n=\"$a$b\"; printf '/tmp\\n' >> \"${!n}\"\n"
                "      - run: python -I scripts/harness.py check --full\n"
            )),
            valid_workflow(extra=(
                "      - run: a=$(printf '\\x47ITHUB_'); b=PATH; n=\"$a$b\"; printf '/tmp\\n' >> \"${!n}\"\n"
                "      - run: python -I scripts/harness.py check --full\n"
            )),
            valid_workflow(extra=(
                "      - run: echo /tmp >> \"$GITHUB_PATH\"\n"
                "      - run: python -I scripts/harness.py check --full\n"
            )),
        )
        for body in cases:
            with self.subTest(body=body):
                self.assertTrue(check_workflow_text(Path("ci.yml"), body))

    def test_pull_request_jobs_reject_execution_containers(self) -> None:
        cases = (
            "    container: attacker/image:latest\n",
            "    container:\n      image: attacker/image:latest\n      options: --privileged\n",
            "    container:\n      image: attacker/image@sha256:" + "a" * 64 + "\n"
            "      volumes: ['/:/host']\n      env:\n        LD_PRELOAD: /tmp/pwn.so\n",
            "    services:\n      db:\n        image: attacker/db:latest\n",
        )
        for container in cases:
            with self.subTest(container=container):
                body = valid_workflow().replace("    timeout-minutes:", container + "    timeout-minutes:")
                self.assertTrue(check_workflow_text(Path("ci.yml"), body))

    def test_pull_request_jobs_cannot_request_deployment_environments(self) -> None:
        body = valid_workflow().replace("    timeout-minutes:", "    environment:\n      name: production\n    timeout-minutes:")
        errors = check_workflow_text(Path("ci.yml"), body)
        self.assertTrue(any("deployment environment" in error for error in errors), errors)

    def test_full_job_must_not_use_a_matrix_check_name(self) -> None:
        body = valid_workflow().replace(
            "    runs-on:", "    strategy:\n      matrix:\n        os: [ubuntu-24.04, ubuntu-22.04]\n    runs-on:", 1
        )
        errors = check_workflow_text(Path("ci.yml"), body)
        self.assertTrue(any("matrix" in error for error in errors), errors)

    def test_checkout_must_use_the_current_pull_request_repository_root(self) -> None:
        for option, value in (("repository", "attacker/project"), ("ref", "main"), ("path", "tmp"),
                              ("sparse-checkout", "scripts/**"), ("github-server-url", "https://example.test")):
            with self.subTest(option=option):
                body = valid_workflow().replace(
                    "          persist-credentials: false\n",
                    f"          persist-credentials: false\n          {option}: {value}\n",
                    1,
                )
                errors = check_workflow_text(Path("ci.yml"), body)
                self.assertTrue(any("current pull request" in error for error in errors), errors)
        body = valid_workflow().replace(
            "          persist-credentials: false\n",
            "          persist-credentials: false\n          clean: false\n",
            1,
        )
        errors = check_workflow_text(Path("ci.yml"), body)
        self.assertTrue(any("workspace cleaning enabled" in error for error in errors), errors)

    def test_full_profile_requires_one_unconditional_checkout_before_validation(self) -> None:
        checkout = (
            f"      - uses: {PINNED_ACTION}\n"
            "        with:\n          persist-credentials: false\n"
        )
        full = "      - run: python -I scripts/harness.py check --full\n"
        cases = (
            valid_workflow().replace(checkout, "", 1),
            valid_workflow().replace(checkout + full, full + checkout, 1),
            valid_workflow().replace(
                "        with:\n          persist-credentials: false\n",
                "        if: false\n        with:\n          persist-credentials: false\n",
                1,
            ),
        )
        expected = ("exactly one actions/checkout", "before Full validation", "cannot be conditional")
        for body, message in zip(cases, expected):
            with self.subTest(message=message):
                errors = check_workflow_text(Path("ci.yml"), body)
                self.assertTrue(any(message in error for error in errors), errors)

    def test_reusable_workflow_jobs_reject_normal_job_fields(self) -> None:
        body = valid_workflow() + (
            "  reusable:\n"
            "    uses: owner/repo/.github/workflows/checks.yml@" + "a" * 40 + "\n"
            "    runs-on: ubuntu-24.04\n"
            "    timeout-minutes: 15\n"
            "    steps:\n"
            "      - run: python -I scripts/harness.py check --full\n"
        )
        errors = check_workflow_text(Path("ci.yml"), body)
        self.assertTrue(any("reusable workflow job reusable has unsupported keys" in error for error in errors), errors)

    def test_reusable_workflow_jobs_cannot_receive_pull_request_secrets(self) -> None:
        body = valid_workflow() + (
            "  reusable:\n"
            "    uses: owner/repo/.github/workflows/checks.yml@" + "a" * 40 + "\n"
            "    secrets: inherit\n"
        )
        errors = check_workflow_text(Path("ci.yml"), body)
        self.assertTrue(any("cannot receive secrets" in error for error in errors), errors)

    def test_pull_request_validation_uses_inline_jobs(self) -> None:
        body = valid_workflow() + (
            "  reusable:\n"
            "    uses: owner/repo/.github/workflows/checks.yml@" + "a" * 40 + "\n"
        )
        errors = check_workflow_text(Path("ci.yml"), body)
        self.assertTrue(any("not supported in pull_request validation" in error for error in errors), errors)

    def test_reusable_workflow_jobs_accept_supported_call_settings(self) -> None:
        body = (
            "name: Release\non:\n  push:\n    branches: [main]\njobs:\n  deploy:\n"
            "    uses: owner/repo/.github/workflows/deploy.yml@" + "a" * 40 + "\n"
            "    concurrency: release\n    permissions:\n      contents: read\n    cache-mode: read\n"
        )
        self.assertEqual([], check_workflow_text(Path("release.yml"), body))

    def test_reusable_workflow_reference_and_allowed_values_are_validated(self) -> None:
        prefix = "name: Release\non:\n  push:\n    branches: [main]\njobs:\n  deploy:\n"
        body = prefix + "    uses: owner/repo/workflows/deploy.yml@" + "a" * 40 + "\n"
        errors = check_workflow_text(Path("release.yml"), body)
        self.assertTrue(any(".github/workflows/*.yml" in error for error in errors), errors)

        valid_ref = "    uses: owner/repo/.github/workflows/deploy.yml@" + "a" * 40 + "\n"
        for fields, expected in (("    with: []\n", "invalid with value"),
                                 ("    needs: 42\n", "invalid needs value")):
            with self.subTest(fields=fields):
                errors = check_workflow_text(Path("release.yml"), prefix + valid_ref + fields)
                self.assertTrue(any(expected in error for error in errors), errors)

    def test_local_reusable_workflow_reference_must_exist_under_workflows(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            body = (
                "name: Release\non:\n  push:\n    branches: [main]\njobs:\n  deploy:\n"
                "    uses: ./.github/workflows/deploy.yml\n"
            )
            errors = check_workflow_text(Path("release.yml"), body, root=root)
            self.assertTrue(any(".yml or .yaml file" in error for error in errors), errors)
            nul_path = body.replace(
                "uses: ./.github/workflows/deploy.yml",
                r'uses: "./.github/workflows/deploy\u0000.yml"',
            )
            self.assertTrue(check_workflow_text(Path("release.yml"), nul_path, root=root))
            target = root / ".github/workflows/deploy.yml"
            target.parent.mkdir(parents=True)
            with target.open("wb") as oversized:
                oversized.truncate(MAX_WORKFLOW_BYTES + 1)
            errors = check_workflow_text(Path("release.yml"), body, root=root)
            self.assertTrue(any("invalid or too large" in error for error in errors), errors)
            target.write_text("name: Deploy\non: push\njobs: {}\n", encoding="utf-8")
            errors = check_workflow_text(Path("release.yml"), body, root=root)
            self.assertTrue(any("must declare workflow_call" in error for error in errors), errors)
            target.write_text("name: Deploy\non: workflow_call\njobs: {}\n", encoding="utf-8")
            self.assertEqual([], check_workflow_text(Path("release.yml"), body, root=root))

    def test_full_profile_shell_failure_suppression_is_not_accepted(self) -> None:
        cases = [
            valid_workflow().replace(
                "python -I scripts/harness.py check --full",
                f"python -I scripts/harness.py check --full{suffix}",
            )
            for suffix in (" || true", " || echo failed", "; true")
        ]
        cases.extend((
            valid_workflow().replace(
                "- run: python -I scripts/harness.py check --full",
                "- run: |\n          set +e\n          python -I scripts/harness.py check --full\n          echo ignored",
            ),
            valid_workflow().replace(
                "- run: python -I scripts/harness.py check --full",
                "- run: |\n          if false; then\n            python -I scripts/harness.py check --full\n          fi",
            ),
        ))
        for body in cases:
            with self.subTest(body=body[-100:]):
                errors = check_workflow_text(Path("ci.yml"), body)
                self.assertTrue(any("no job runs scripts/harness.py check --full" in error for error in errors), errors)

    def test_full_profile_effective_directory_and_shell_are_constrained(self) -> None:
        cases = (
            valid_workflow().replace(
                "permissions: {}", "defaults:\n  run:\n    working-directory: untrusted\npermissions: {}", 1
            ),
            valid_workflow().replace(
                "    runs-on:", "    defaults:\n      run:\n        working-directory: untrusted\n    runs-on:", 1
            ),
            valid_workflow().replace(
                "- run: python -I scripts/harness.py check --full",
                "- run: python -I scripts/harness.py check --full\n        working-directory: untrusted",
            ),
            valid_workflow().replace(
                "permissions: {}", "defaults:\n  run:\n    shell: \"bash -c 'source {0} || true'\"\npermissions: {}", 1
            ),
            valid_workflow().replace(
                "    runs-on:",
                "    defaults:\n      run:\n        shell: \"bash -c 'source {0} || true'\"\n    runs-on:", 1,
            ),
            valid_workflow().replace(
                "- run: python -I scripts/harness.py check --full",
                "- run: python -I scripts/harness.py check --full\n        shell: \"bash -c 'source {0} || true'\"",
            ),
        )
        for body in cases:
            with self.subTest(body=body[-120:]):
                errors = check_workflow_text(Path("ci.yml"), body)
                self.assertTrue(any("repository root" in error or "unsupported shell" in error for error in errors), errors)

    def test_security_policy_rejects_untrusted_interpolation_into_run(self) -> None:
        event = "$" + "{{ github.event.pull_request.title }}"
        body = valid_workflow().replace(
            "- run: python -I scripts/harness.py check --full",
            f"- run: echo {event}\n      - run: python -I scripts/harness.py check --full",
        )
        errors = check_workflow_text(Path("ci.yml"), body)
        self.assertTrue(any("untrusted event data" in error for error in errors), errors)

    def test_nested_pr_event_data_cannot_be_interpolated_into_run_scripts(self) -> None:
        expressions = (
            "github.event['pull_request']['title']",
            "fromJSON(toJSON(github.event.pull_request)).title",
        )
        for expression in expressions:
            with self.subTest(expression=expression):
                interpolation = "$" + "{{ " + expression + " }}"
                body = valid_workflow().replace(
                    "- run: python -I scripts/harness.py check --full",
                    f"- run: {json.dumps('echo ' + interpolation)}\n      - run: python -I scripts/harness.py check --full",
                )
                errors = check_workflow_text(Path("ci.yml"), body)
                self.assertTrue(any("untrusted event data" in error for error in errors), errors)

    def test_untrusted_pr_event_data_cannot_flow_through_environment_variables(self) -> None:
        expression = "$" + "{{ github.event.pull_request.title }}"
        body = valid_workflow().replace(
            "permissions: {}", f'env:\n  TITLE: "{expression}"\npermissions: {{}}', 1
        )
        errors = check_workflow_text(Path("ci.yml"), body)
        self.assertTrue(any("untrusted event data" in error for error in errors), errors)

    def test_security_policy_rejects_unpinned_actions_and_persisted_checkout_credentials(self) -> None:
        cases = (
            valid_workflow(extra="      - uses: actions/checkout@v4\n"),
            valid_workflow(extra=f"      - uses: {PINNED_ACTION}\n        with:\n          persist-credentials: true\n"),
            valid_workflow(extra="      - uses: ./../outside\n"),
        )
        for body in cases:
            with self.subTest(body=body[-70:]):
                self.assertTrue(check_workflow_text(Path("ci.yml"), body))

    def test_local_actions_must_stay_under_github_actions(self) -> None:
        body = valid_workflow(extra="      - uses: ./ci/action\n")
        errors = check_workflow_text(Path("ci.yml"), body)
        self.assertTrue(any("local action path" in error for error in errors), errors)

    def test_ci_policy_rejects_target_event_self_hosted_runner_and_path_filters(self) -> None:
        cases = (
            valid_workflow().replace("pull_request:", "pull_request_target:"),
            valid_workflow(runner="[self-hosted, linux]"),
            valid_workflow(runner="[ubuntu-24.04, macos-15]"),
            valid_workflow(runner="ubuntu-24.04-private"),
            valid_workflow().replace("pull_request:", "pull_request:\n    paths: ['src/**']"),
            valid_workflow().replace("pull_request:", "pull_request:\n    branches: [never]"),
            valid_workflow().replace("pull_request:", "pull_request:\n    branches-ignore: [main]"),
            valid_workflow().replace("pull_request:", "pull_request:\n    branches: ['**', '!main']"),
        )
        for body in cases:
            with self.subTest(body=body[:70]):
                self.assertTrue(check_workflow_text(Path("ci.yml"), body))

    def test_pull_request_target_validation_is_rejected_without_full_profile_command(self) -> None:
        body = (
            "name: Legacy tests\non:\n  pull_request_target:\njobs:\n  tests:\n"
            "    runs-on: ubuntu-24.04\n    timeout-minutes: 10\n    steps:\n"
            "      - run: pytest\n"
        )
        errors = check_workflow_text(Path(".github/workflows/legacy.yml"), body)
        self.assertTrue(any("pull_request_target" in error for error in errors), errors)

    def test_pull_request_target_external_actions_are_not_treated_as_safe(self) -> None:
        body = (
            "name: Metadata\non:\n  pull_request_target:\njobs:\n  label:\n"
            "    runs-on: ubuntu-24.04\n    steps:\n"
            f"      - uses: actions/github-script@{PINNED_ACTION}\n"
        )
        errors = check_workflow_text(Path(".github/workflows/metadata.yml"), body)
        self.assertTrue(any("pull_request_target" in error for error in errors), errors)

    def test_actions_in_non_pr_workflows_are_still_pinned(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            setup_project(root)
            (root / ".github/workflows/manual.yml").write_text(
                "name: Manual\non:\n  workflow_dispatch:\njobs:\n  deploy:\n"
                "    runs-on: ubuntu-24.04\n    timeout-minutes: 15\n    steps:\n"
                "      - uses: actions/checkout@v4\n        with:\n          persist-credentials: false\n",
                encoding="utf-8",
            )
            result = check_security_policy(root=root)
        self.assertFalse(result["ok"])
        self.assertTrue(any("full commit SHA" in error for error in result["errors"]))

    def test_external_reusable_workflows_are_pinned_too(self) -> None:
        body = (
            "name: Manual\non:\n  workflow_dispatch:\njobs:\n  deploy:\n"
            "    uses: owner/repo/.github/workflows/deploy.yml@v1\n"
        )
        errors = check_workflow_text(Path("manual.yml"), body)
        self.assertTrue(any("reusable workflow must be pinned" in error for error in errors), errors)

    def test_local_composite_actions_must_pin_nested_external_actions(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            setup_project(root)
            action = root / ".github/actions/check/action.yml"
            action.parent.mkdir(parents=True)
            action.write_text(
                "name: Check\nruns:\n  using: composite\n  steps:\n"
                "    - uses: owner/action@v1\n",
                encoding="utf-8",
            )
            result = check_security_policy(root=root)
        self.assertFalse(result["ok"])
        self.assertTrue(any("full commit SHA" in error for error in result["errors"]))

    def test_full_job_rejects_local_node_actions_before_validation(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            setup_project(root)
            action = root / ".github/actions/node/action.yml"
            action.parent.mkdir(parents=True)
            action.write_text("name: node\nruns:\n  using: node20\n  main: index.js\n", encoding="utf-8")
            (action.parent / "index.js").write_text("process.env.GITHUB_PATH", encoding="utf-8")
            workflow = valid_workflow().replace(
                "      - run: python -I scripts/harness.py check --full\n",
                "      - uses: ./.github/actions/node\n"
                "      - run: python -I scripts/harness.py check --full\n",
            )
            (root / ".github/workflows/ci.yml").write_text(workflow, encoding="utf-8")
            result = check_security_policy(root=root)
        self.assertFalse(result["ok"], result["errors"])
        self.assertTrue(any("local action" in error and "before Full" in error
                            for error in result["errors"]))

    def test_composite_action_rejects_untrusted_event_interpolation(self) -> None:
        cases = (
            ('    - run: echo "${{ github.event.pull_request.head.ref }}"\n      shell: bash\n',
             "untrusted event data"),
            ("    - run: 'echo \"${{ github[\"event\"][\"pull_request\"][\"title\"] }}\"'\n"
             "      shell: bash\n", "broad GitHub context"),
            ("    - if: secrets.API_KEY\n      run: echo safe\n      shell: bash\n", "secrets context"),
            ('    - run: echo "${{ github.token }}"\n      shell: bash\n', "github.token"),
        )
        for steps, expected in cases:
            with self.subTest(expected=expected), TemporaryDirectory() as temp:
                root = Path(temp)
                setup_project(root)
                action = root / ".github/actions/unsafe/action.yml"
                action.parent.mkdir(parents=True)
                action.write_text(
                    "name: unsafe\nruns:\n  using: composite\n  steps:\n" + steps,
                    encoding="utf-8",
                )
                workflow = valid_workflow().replace(
                    "      - run: python -I scripts/harness.py check --full\n",
                    "      - uses: ./.github/actions/unsafe\n"
                    "      - run: python -I scripts/harness.py check --full\n",
                )
                (root / ".github/workflows/ci.yml").write_text(workflow, encoding="utf-8")
                result = check_security_policy(root=root)
            self.assertFalse(result["ok"])
            self.assertTrue(any(expected in error for error in result["errors"]), result["errors"])

    def test_unreferenced_deployment_action_secrets_do_not_block_pr_ci(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            setup_project(root)
            action = root / ".github/actions/deploy/action.yml"
            action.parent.mkdir(parents=True)
            action.write_text(
                "name: deploy\nruns:\n  using: composite\n  steps:\n"
                "    - run: deploy\n      shell: bash\n      env:\n        TOKEN: ${{ secrets.DEPLOY_TOKEN }}\n",
                encoding="utf-8",
            )
            result = check_security_policy(root=root)
        self.assertTrue(result["ok"], result["errors"])

    def test_docker_actions_require_digest_pinned_images(self) -> None:
        digest = "a" * 64
        for image, expected_ok in (("docker://alpine:latest", False),
                                   (f"docker://alpine@sha256:{digest}", True)):
            with self.subTest(step_image=image):
                body = valid_workflow(extra=f"      - uses: {image}\n")
                errors = check_workflow_text(Path("ci.yml"), body)
                self.assertEqual(expected_ok, not errors, errors)
        cases = (
            ("docker://alpine:latest", None, False),
            (f"docker://alpine@sha256:{digest}", None, True),
            ("Dockerfile", f"FROM alpine@sha256:{digest}\n", True),
            ("Dockerfile", f"FROM alpine@sha256:{digest} AS base\nFROM base\n", True),
            ("Dockerfile", "FROM alpine:3.20\n", False),
        )
        for image, dockerfile, expected_ok in cases:
            with self.subTest(image=image, dockerfile=dockerfile), TemporaryDirectory() as temp:
                root = Path(temp)
                setup_project(root)
                action = root / ".github/actions/docker/action.yml"
                action.parent.mkdir(parents=True)
                action.write_text(
                    f"name: docker\nruns:\n  using: docker\n  image: {image}\n",
                    encoding="utf-8",
                )
                if dockerfile is not None:
                    (action.parent / "Dockerfile").write_text(dockerfile, encoding="utf-8")
                workflow = valid_workflow() + (
                    "  deploy:\n    if: github.event_name == 'push'\n"
                    "    runs-on: ubuntu-24.04\n    timeout-minutes: 15\n    steps:\n"
                    "      - uses: ./.github/actions/docker\n      - run: echo done\n"
                )
                (root / ".github/workflows/ci.yml").write_text(workflow, encoding="utf-8")
                result = check_security_policy(root=root)
                self.assertEqual(expected_ok, result["ok"], result["errors"])

    def test_full_profile_cannot_be_skipped_ignored_or_a_noop(self) -> None:
        cases = (
            valid_workflow().replace("    timeout-minutes: 15", "    if: false\n    timeout-minutes: 15"),
            valid_workflow().replace("python -I scripts/harness.py check --full", "echo all tests passed"),
            valid_workflow().replace("python -I scripts/harness.py check --full", "python -I scripts/harness.py check --full\n        continue-on-error: true"),
            valid_workflow().replace("    timeout-minutes: 15", ""),
        )
        for body in cases:
            with self.subTest(body=body[-90:]):
                self.assertTrue(check_workflow_text(Path("ci.yml"), body))

    def test_all_pull_request_validation_steps_reject_ignored_failures(self) -> None:
        job_level = valid_workflow().replace(
            "  verify:\n", "  verify:\n    continue-on-error: true\n", 1
        )
        step_level = valid_workflow().replace(
            f"      - uses: {PINNED_ACTION}\n",
            "      - run: pytest\n        continue-on-error: true\n"
            f"      - uses: {PINNED_ACTION}\n",
            1,
        )
        for body in (job_level, step_level):
            with self.subTest(body=body[:100]):
                errors = check_workflow_text(Path("ci.yml"), body)
                self.assertTrue(any("cannot ignore failures" in error for error in errors), errors)

    def test_pull_request_cache_access_cannot_write(self) -> None:
        for mode, expected_ok in (("write", False), ("write-only", False),
                                  ("read", True), ("none", True)):
            with self.subTest(scope="workflow", mode=mode):
                body = valid_workflow().replace(
                    "permissions: {}", f"cache-mode: {mode}\npermissions: {{}}", 1
                )
                self.assertEqual(expected_ok, not check_workflow_text(Path("ci.yml"), body))
            with self.subTest(scope="job", mode=mode):
                body = valid_workflow().replace(
                    "    timeout-minutes: 15", f"    cache-mode: {mode}\n    timeout-minutes: 15", 1
                )
                self.assertEqual(expected_ok, not check_workflow_text(Path("ci.yml"), body))

        push_only = valid_workflow() + (
            "  deploy:\n    if: github.event_name == 'push'\n    cache-mode: write\n"
            "    runs-on: ubuntu-24.04\n    timeout-minutes: 15\n    steps:\n      - run: ./deploy\n"
        )
        self.assertEqual([], check_workflow_text(Path("ci.yml"), push_only))

    def test_referenced_composite_action_steps_cannot_ignore_failures(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            setup_project(root)
            action = root / ".github/actions/ignored/action.yml"
            action.parent.mkdir(parents=True)
            action.write_text(
                "name: ignored\nruns:\n  using: composite\n  steps:\n"
                "    - run: echo tolerated\n      shell: bash\n      continue-on-error: true\n",
                encoding="utf-8",
            )
            workflow = valid_workflow().replace(
                "      - run: python -I scripts/harness.py check --full\n",
                "      - run: python -I scripts/harness.py check --full\n"
                "      - uses: ./.github/actions/ignored\n",
            )
            (root / ".github/workflows/ci.yml").write_text(workflow, encoding="utf-8")
            result = check_security_policy(root=root)
        self.assertFalse(result["ok"], result["errors"])
        self.assertTrue(any("composite action steps cannot ignore failures" in error
                            for error in result["errors"]), result["errors"])

    def test_push_only_workflows_require_scoped_branch_or_literal_tag_filters(self) -> None:
        job = "jobs:\n  deploy:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: ./deploy\n"
        invalid = (
            "on: [push]\n",
            "on:\n  push:\n",
            "on:\n  push:\n    branches: ['**']\n",
            "on:\n  push:\n    branches: ['**/**']\n",
            "on:\n  push:\n    branches: ['*release']\n",
            "on:\n  push:\n    branches: [main]\n    tags: ['**']\n",
            "on:\n  push:\n    branches: [main]\n    tags-ignore: [v1.*]\n",
        )
        for trigger in invalid:
            with self.subTest(trigger=trigger):
                errors = check_workflow_text(Path("deploy.yml"), "name: Deploy\n" + trigger + job)
                self.assertTrue(any("push" in error for error in errors), errors)

        valid = (
            "on:\n  push:\n    branches: [main, release/*]\n",
            "on:\n  push:\n    tags: [v1.2.3, v2.0.0]\n",
            "on:\n  push:\n    branches: [main]\n    tags: [v1.2.3]\n",
        )
        for trigger in valid:
            with self.subTest(trigger=trigger):
                self.assertEqual([], check_workflow_text(Path("deploy.yml"), "name: Deploy\n" + trigger + job))

    def test_ci_dependencies_must_exist_and_be_acyclic(self) -> None:
        body = valid_workflow().replace("  verify:", "  verify:\n    needs: absent")
        errors = check_workflow_text(Path("ci.yml"), body)
        self.assertTrue(any("dependency" in error for error in errors), errors)

    def test_full_job_cannot_depend_on_a_conditional_gate(self) -> None:
        body = valid_workflow().replace(
            "  verify:",
            "  gate:\n    if: false\n    runs-on: ubuntu-24.04\n    timeout-minutes: 5\n"
            "    steps:\n      - run: echo ready\n  verify:\n    needs: gate",
        )
        errors = check_workflow_text(Path("ci.yml"), body)
        self.assertTrue(any("depends on conditional job gate" in error for error in errors), errors)

    def test_duplicate_required_check_identities_are_invalid(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            setup_project(root)
            (root / ".github/workflows/other.yaml").write_text(
                valid_workflow(name="CI", job_id="other", job_name="verify"), encoding="utf-8"
            )
            result = check_security_policy(root=root)
        self.assertFalse(result["ok"])
        self.assertTrue(any("ambiguous required check identity" in error for error in result["errors"]))

    def test_job_id_cannot_alias_another_required_job_display_name(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            setup_project(root)
            workflow = valid_workflow(name="CI", job_id="foo", job_name="A").replace(
                "      - run: python -I scripts/harness.py check --full\n",
                "      - run: python -I scripts/harness.py check --full\n"
                "  bar:\n    name: foo\n    runs-on: ubuntu-24.04\n    timeout-minutes: 15\n"
                "    permissions: {}\n    steps:\n      - run: python -I scripts/harness.py check --full\n",
            )
            (root / ".github/workflows/ci.yml").write_text(workflow, encoding="utf-8")
            result = check_security_policy(root=root)
        self.assertFalse(result["ok"])
        self.assertTrue(any("ambiguous required check identity" in error for error in result["errors"]))

    def test_non_full_job_cannot_reuse_a_required_full_check_name(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            setup_project(root)
            workflow = valid_workflow(job_id="full", job_name="Actual") + (
                "  decoy:\n    name: full\n    runs-on: ubuntu-24.04\n"
                "    timeout-minutes: 10\n    permissions: {}\n    steps:\n      - run: echo decoy\n"
            )
            (root / ".github/workflows/ci.yml").write_text(workflow, encoding="utf-8")
            result = check_security_policy(root=root)
        self.assertFalse(result["ok"])
        self.assertTrue(any("ambiguous required check identity" in error for error in result["errors"]))

    def test_existing_manual_deploy_job_does_not_collide_with_pr_full_check(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            setup_project(root, quick=[["python", "-m", "unittest"]], full=[["python", "-m", "unittest"]])
            (root / ".github/workflows/deploy.yml").write_text(
                "name: CI\non:\n  workflow_dispatch:\njobs:\n  verify:\n"
                "    name: verify\n    runs-on: ubuntu-24.04\n    steps:\n      - run: deploy\n",
                encoding="utf-8",
            )
            result = check_security_policy(root=root)
        self.assertTrue(result["ok"], result["errors"])

    def test_security_sensitive_paths_remain_t3_inputs(self) -> None:
        for path in (
            ".agents",
            ".github",
            ".harness",
            ".codex",
            ".github/workflows/ci.yml",
            ".harness/config.toml",
            "nested/AGENTS.md",
            ".github\\workflows\\ci.yml",
            "scripts/check_ci_security.py",
            "scripts/ci_action_policy.py",
            "scripts/harness_doctor.py",
            "scripts/verify_ci.py",
        ):
            self.assertTrue(is_sensitive_path(path))
        self.assertFalse(is_sensitive_path("docs/guide.md"))

    def test_unexpected_config_loader_errors_are_not_reported_as_bad_user_config(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            setup_project(root)
            with patch("scripts.harness.load_config", side_effect=RuntimeError("programmer error")):
                with self.assertRaisesRegex(RuntimeError, "programmer error"):
                    check_security_policy(root=root)


if __name__ == "__main__":
    unittest.main()
