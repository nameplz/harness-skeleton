from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.check_ci_security import (  # noqa: E402
    changed_files_from_event,
    collect_changed_file_list,
    check_security_policy,
    check_workflow_text,
    _parse_workflow_yaml,
)
from scripts.check_ci_security import collaborator_permission  # noqa: E402
from scripts.command_runner import CommandResult  # noqa: E402


PINNED_SHA = "11bd71901bbe5b1630ceea73d27597364c9af683"


class CiSecurityTests(unittest.TestCase):
    def write_workflow(self, root: Path, body: str) -> None:
        workflow = root / ".github/workflows/harness-ci.yml"
        workflow.parent.mkdir(parents=True, exist_ok=True)
        lines = body.splitlines()
        if not any(line in {"on:", '"on":', "'on':"} for line in lines):
            lines[0:0] = ["on:", "  push:", "    branches: [main]"]
        if "jobs:\n  t:\n" in body and "runs-on:" not in body:
            lines.insert(lines.index("  t:") + 1, "    runs-on: ubuntu-24.04")
        if "jobs:\n  t:\n" in body and "permissions:" not in body:
            lines.insert(lines.index("jobs:"), "permissions: {}")
            job_index = lines.index("  t:")
            lines.insert(job_index + 1, "    permissions: {}")
        index = 0
        while index < len(lines):
            line = lines[index]
            if line.lstrip().startswith("- uses: actions/checkout@"):
                indent = len(line) - len(line.lstrip())
                if index + 1 >= len(lines) or lines[index + 1] != " " * (indent + 2) + "with:":
                    lines[index + 1:index + 1] = [
                        " " * (indent + 2) + "with:",
                        " " * (indent + 4) + "persist-credentials: false",
                    ]
                    index += 2
            index += 1
        workflow.write_text("\n".join(lines) + ("\n" if body.endswith("\n") else ""), encoding="utf-8")

    def write_event(
        self,
        root: Path,
        filenames: list[str] | None = None,
        *,
        labels: list[str] | None = None,
    ) -> Path:
        event = root / "event.json"
        event.write_text(
            json.dumps(
                {
                    "action": "labeled" if labels else "opened",
                    "label": {"name": labels[0]} if labels else None,
                    "sender": {"login": "trusted-maintainer"},
                    "pull_request": {
                        "changed_files": [{"filename": name} for name in filenames or []],
                        "labels": [{"name": name} for name in labels or []],
                    }
                }
            ),
            encoding="utf-8",
        )
        return event

    def test_unpinned_external_action_fails(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_workflow(root, "jobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n")
            event = self.write_event(root)

            errors = check_security_policy(root=root, event_path=event)

            self.assertTrue(any("full commit SHA" in error for error in errors))

    def test_workflow_symlink_fails_closed(self) -> None:
        with TemporaryDirectory() as temp, TemporaryDirectory() as external:
            root = Path(temp)
            workflow = root / ".github/workflows/harness-ci.yml"
            workflow.parent.mkdir(parents=True)
            trusted_workflow = Path(external) / "workflow.yml"
            trusted_workflow.write_text("jobs: {}\n", encoding="utf-8")
            workflow.symlink_to(trusted_workflow)
            event = self.write_event(root, [".github/workflows/harness-ci.yml"])

            errors = check_security_policy(root=root, event_path=event)

            self.assertTrue(any("cannot be a symlink" in error for error in errors))

    def test_full_sha_pinned_action_passes(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_workflow(
                root,
                f"jobs:\n  t:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: actions/checkout@{PINNED_SHA}\n        with:\n          persist-credentials: false\n",
            )
            event = self.write_event(root)

            errors = check_security_policy(root=root, event_path=event)

            self.assertEqual([], errors)

    def test_forbidden_workflow_features_fail(self) -> None:
        cases = [
            "on:\n  workflow_dispatch:\n",
            "permissions:\n  contents: write\n",
            "permissions: write-all\n",
            "permissions:\n  id-token: write\n",
            "runs-on: self-hosted\n",
            "run: echo ${{ secrets.TOKEN }}\n",
        ]
        for body in cases:
            with self.subTest(body=body), TemporaryDirectory() as temp:
                root = Path(temp)
                self.write_workflow(root, body)
                event = self.write_event(root)

                errors = check_security_policy(root=root, event_path=event)

                self.assertNotEqual([], errors)

    def test_structural_yaml_checks_quoted_uses_secret_expressions_and_permissions(self) -> None:
        cases = [
            (
                'jobs:\n  t:\n    steps:\n      - "uses": actions/checkout@v4\n',
                "full commit SHA",
            ),
            (
                'jobs:\n  t:\n    steps:\n      - run: "echo ${{ secrets[\'TOKEN\'] }}"\n',
                "secrets",
            ),
            (
                '"permissions": { "contents": write }\n',
                "write permissions",
            ),
            (
                "permissions:\n  contents: write\n  contents: read\n",
                "workflow YAML",
            ),
        ]
        for body, expected in cases:
            with self.subTest(expected=expected), TemporaryDirectory() as temp:
                root = Path(temp)
                self.write_workflow(root, body)
                event = self.write_event(root)

                errors = check_security_policy(root=root, event_path=event)

                self.assertTrue(any(expected in error for error in errors), errors)

    def test_sensitive_github_expressions_are_rejected_in_every_yaml_form(self) -> None:
        cases = (
            '${{ secrets }}',
            '${{ toJSON(secrets) }}',
            '${{ github.token }}',
            '${{ toJSON(github) }}',
            '${{ github["token"] }}',
            "${{ github['token'] }}",
            "${{ github[format('to', 'ken')] }}",
        )
        for expression in cases:
            with self.subTest(expression=expression):
                text = (
                    "jobs:\n  t:\n    runs-on: ubuntu-24.04\n    steps:\n"
                    f"      - run: {json.dumps('echo ' + expression)}\n"
                )
                errors = check_workflow_text(Path("workflow.yml"), text)
                self.assertTrue(errors, expression)

    def test_github_token_is_allowed_only_in_the_exact_trusted_policy_step(self) -> None:
        workflow = (ROOT / ".github/workflows/harness-ci.yml").read_text(encoding="utf-8")
        self.assertEqual([], check_workflow_text(Path(".github/workflows/harness-ci.yml"), workflow))

        changed = workflow.replace(
            'python3 trusted/scripts/check_ci_security.py --root candidate --event "$GITHUB_EVENT_PATH" --changed-files "$CHANGED_FILES"',
            'echo "${{ github.token }}"',
        )
        errors = check_workflow_text(Path(".github/workflows/harness-ci.yml"), changed)
        self.assertTrue(any("github.token" in error for error in errors), errors)

    def test_dynamic_or_non_hosted_runners_are_rejected(self) -> None:
        cases = (
            "${{ inputs.runner }}",
            "[ubuntu-24.04, self-hosted]",
            "{group: custom, labels: ubuntu-24.04}",
            None,
        )
        for runner in cases:
            with self.subTest(runner=runner):
                runner_line = f"    runs-on: {runner}\n" if runner is not None else ""
                body = f"jobs:\n  t:\n{runner_line}    steps: []\n"
                errors = check_workflow_text(Path("workflow.yml"), body)
                self.assertTrue(any("runs-on" in error for error in errors), errors)

    def test_checkout_requires_disabled_credentials_and_no_custom_credentials(self) -> None:
        cases = (
            "",
            "        with:\n          persist-credentials: true\n",
            "        with:\n          persist-credentials: false\n          token: ${{ github.token }}\n",
            "        with:\n          persist-credentials: false\n          ssh-key: private\n",
            "        with:\n          persist-credentials: false\n          ssh-token: private\n",
            "        with:\n          persist-credentials: false\n          TOKEN: private\n",
            "        with:\n          persist-credentials: false\n          SSH-KEY: private\n",
            "        with:\n          persist-credentials: false\n          SSH-TOKEN: private\n",
        )
        for options in cases:
            with self.subTest(options=options):
                body = (
                    "permissions: {}\n"
                    f"jobs:\n  t:\n    permissions: {{}}\n    runs-on: ubuntu-24.04\n    steps:\n"
                    f"      - uses: actions/checkout@{PINNED_SHA}\n{options}"
                )
                errors = check_workflow_text(Path("workflow.yml"), body)
                self.assertTrue(any("checkout credentials" in error for error in errors), errors)

    def test_checkout_with_credentials_disabled_passes_structural_policy(self) -> None:
        body = (
            "permissions: {}\n"
            f"jobs:\n  t:\n    permissions: {{}}\n    runs-on: ubuntu-24.04\n    steps:\n"
            f"      - uses: actions/checkout@{PINNED_SHA}\n"
            "        with:\n          persist-credentials: false\n"
        )
        self.assertEqual([], check_workflow_text(Path("workflow.yml"), body))

    def test_only_trusted_policy_job_may_receive_read_permissions(self) -> None:
        candidate_workflow = (
            "permissions: {}\n"
            "jobs:\n  project-validation:\n"
            "    permissions:\n      contents: read\n"
            "    runs-on: ubuntu-24.04\n    steps: []\n"
        )
        errors = check_workflow_text(Path(".github/workflows/project-ci.yml"), candidate_workflow)
        self.assertTrue(any("permissions must be empty" in error for error in errors), errors)

    def test_workflow_level_permissions_must_be_empty(self) -> None:
        text = (
            "permissions:\n  contents: read\n"
            "jobs:\n  project-validation:\n"
            "    permissions: {}\n    runs-on: ubuntu-24.04\n    steps: []\n"
        )
        errors = check_workflow_text(Path(".github/workflows/project-ci.yml"), text)
        self.assertTrue(any("workflow permissions must be empty" in error for error in errors), errors)

    def test_unparseable_workflow_yaml_fails_closed(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_workflow(root, "jobs: [this is not valid YAML\n")
            event = self.write_event(root)

            errors = check_security_policy(root=root, event_path=event)

            self.assertTrue(any("workflow YAML" in error for error in errors))

    def test_yaml_date_scalars_remain_valid_workflow_values(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_workflow(root, "run: echo 2026-10-05\n")
            event = self.write_event(root)

            errors = check_security_policy(root=root, event_path=event)

            self.assertEqual([], errors)

    def test_security_sensitive_pr_changes_fail(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_workflow(root, f"jobs:\n  t:\n    steps:\n      - uses: actions/checkout@{PINNED_SHA}\n")
            event = self.write_event(root, [".harness/ci.json"])

            errors = check_security_policy(root=root, event_path=event)

            self.assertTrue(any("security-sensitive" in error for error in errors))

    def test_sensitive_directory_roots_are_gated(self) -> None:
        for filename in (
            ".github",
            ".github/workflows",
            ".github/actions",
            ".harness",
            ".codex",
            ".codex/hooks",
        ):
            with self.subTest(filename=filename), TemporaryDirectory() as temp:
                root = Path(temp)
                self.write_workflow(root, f"jobs:\n  t:\n    steps:\n      - uses: actions/checkout@{PINNED_SHA}\n")
                event = self.write_event(root, [filename])

                errors = check_security_policy(root=root, event_path=event)

                self.assertTrue(any("security-sensitive" in error for error in errors))

    def test_local_action_files_are_security_sensitive(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_workflow(
                root,
                f"jobs:\n  t:\n    steps:\n      - uses: ./.github/actions/check@main\n      - uses: actions/checkout@{PINNED_SHA}\n",
            )
            event = self.write_event(root, [".github/actions/check/action.yml"])

            errors = check_security_policy(root=root, event_path=event)

            self.assertTrue(any("security-sensitive" in error for error in errors))

    def test_local_action_reference_cannot_traverse_outside_the_checkout(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_workflow(
                root,
                f"jobs:\n  t:\n    steps:\n      - uses: ./../outside-action\n      - uses: actions/checkout@{PINNED_SHA}\n",
            )
            event = self.write_event(root)

            errors = check_security_policy(root=root, event_path=event)

            self.assertTrue(any("local action path cannot escape" in error for error in errors), errors)

    def test_local_actions_must_live_under_the_sensitive_github_actions_directory(self) -> None:
        text = (
            "permissions: {}\n"
            "jobs:\n  t:\n    permissions: {}\n    runs-on: ubuntu-24.04\n    steps:\n"
            "      - uses: ./ci/action\n"
        )
        errors = check_workflow_text(Path(".github/workflows/harness-ci.yml"), text)
        self.assertTrue(any("local actions must live under .github/actions/" in error for error in errors), errors)

    def test_workflow_directory_cannot_be_replaced_with_a_file(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_workflow(root, f"jobs:\n  t:\n    steps:\n      - uses: actions/checkout@{PINNED_SHA}\n")
            (root / ".github/workflows/harness-ci.yml").unlink()
            (root / ".github/workflows").rmdir()
            (root / ".github/workflows").write_text("untrusted", encoding="utf-8")
            event = self.write_event(root, [".github/workflows"])

            errors = check_security_policy(root=root, event_path=event)

            self.assertTrue(any("must be a directory" in error for error in errors))

    def test_trusted_maintenance_label_allows_sensitive_changes(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_workflow(root, f"jobs:\n  t:\n    steps:\n      - uses: actions/checkout@{PINNED_SHA}\n")
            event = self.write_event(
                root,
                ["scripts/check_ci_security.py", ".harness/config.toml"],
                labels=["harness-trusted-maintenance"],
            )

            with patch("scripts.check_ci_security.collaborator_permission", return_value="maintain"):
                errors = check_security_policy(
                    root=root,
                    event_path=event,
                    github_token="test-token",
                    repository="owner/repo",
                )

            self.assertEqual([], errors)

    def test_stale_maintenance_label_does_not_authorize_new_commits(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_workflow(root, f"jobs:\n  t:\n    steps:\n      - uses: actions/checkout@{PINNED_SHA}\n")
            event = self.write_event(root, [".harness/config.toml"], labels=["harness-trusted-maintenance"])
            payload = json.loads(event.read_text(encoding="utf-8"))
            payload["action"] = "synchronize"
            event.write_text(json.dumps(payload), encoding="utf-8")

            with patch("scripts.check_ci_security.collaborator_permission") as permission_lookup:
                errors = check_security_policy(
                    root=root,
                    event_path=event,
                    github_token="test-token",
                    repository="owner/repo",
                )

            permission_lookup.assert_not_called()
            self.assertTrue(any("security-sensitive" in error for error in errors))

    def test_unprivileged_actor_cannot_authorize_maintenance_label(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_workflow(root, f"jobs:\n  t:\n    steps:\n      - uses: actions/checkout@{PINNED_SHA}\n")
            event = self.write_event(root, [".harness/config.toml"], labels=["harness-trusted-maintenance"])

            with patch("scripts.check_ci_security.collaborator_permission", return_value="write"):
                errors = check_security_policy(
                    root=root,
                    event_path=event,
                    github_token="test-token",
                    repository="owner/repo",
                )

            self.assertTrue(any("security-sensitive" in error for error in errors))
            self.assertTrue(any("not an admin or maintainer" in error for error in errors))

    def test_collaborator_permission_preserves_maintain_role_name(self) -> None:
        class Response:
            def __enter__(self) -> Response:
                return self

            def __exit__(self, *_args: object) -> None:
                return None

            def read(self) -> bytes:
                return b'{"permission":"write","role_name":"maintain"}'

        with patch("scripts.check_ci_security.urllib.request.urlopen", return_value=Response()) as open_url:
            permission = collaborator_permission("owner/repo", "maintainer", "test-token")

        self.assertEqual("maintain", permission)
        request = open_url.call_args.args[0]
        self.assertEqual(
            "https://api.github.com/repos/owner/repo/collaborators/maintainer/permission",
            request.full_url,
        )
        self.assertEqual("2026-03-10", request.get_header("X-github-api-version"))

    def test_trusted_maintenance_label_does_not_bypass_workflow_safety(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_workflow(root, "jobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n")
            event = self.write_event(
                root,
                [".github/workflows/harness-ci.yml"],
                labels=["harness-trusted-maintenance"],
            )

            with patch("scripts.check_ci_security.collaborator_permission", return_value="maintain"):
                errors = check_security_policy(
                    root=root,
                    event_path=event,
                    github_token="test-token",
                    repository="owner/repo",
                )

            self.assertTrue(any("full commit SHA" in error for error in errors))
            self.assertFalse(any("security-sensitive" in error for error in errors))

    def test_trusted_maintenance_label_does_not_allow_unsafe_changed_paths(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_workflow(root, f"jobs:\n  t:\n    steps:\n      - uses: actions/checkout@{PINNED_SHA}\n")
            event = self.write_event(
                root,
                ["../scripts/check_ci_security.py"],
                labels=["harness-trusted-maintenance"],
            )

            errors = check_security_policy(root=root, event_path=event)

            self.assertTrue(any("unsafe changed path" in error for error in errors))

    def test_external_nul_delimited_changed_file_list_is_used(self) -> None:
        with TemporaryDirectory() as temp, TemporaryDirectory() as external:
            root = Path(temp)
            self.write_workflow(root, f"jobs:\n  t:\n    steps:\n      - uses: actions/checkout@{PINNED_SHA}\n")
            event = self.write_event(root)
            changed_files = Path(external) / "changed-files.nul"
            changed_files.write_bytes(b".harness/config.toml\0scripts/check_ci_security.py\0")

            errors = check_security_policy(root=root, event_path=event, changed_files_path=changed_files)

            self.assertEqual(2, sum("security-sensitive" in error for error in errors))

    def test_changed_file_list_inside_candidate_checkout_is_rejected(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_workflow(root, f"jobs:\n  t:\n    steps:\n      - uses: actions/checkout@{PINNED_SHA}\n")
            event = self.write_event(root)
            changed_files = root / ".harness-changed-files.nul"
            changed_files.write_bytes(b".harness/config.toml\0")

            errors = check_security_policy(root=root, event_path=event, changed_files_path=changed_files)

            self.assertTrue(any("outside candidate checkout" in error for error in errors))

    def test_git_changed_path_capture_fails_closed_at_size_limit(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            event = {"pull_request": {"base": {"sha": "a" * 40}, "head": {"sha": "b" * 40}}}
            limited = CommandResult(125, "partial", output_limited=True)
            with patch("scripts.check_ci_security.run_bounded_command", return_value=limited) as run_command:
                with self.assertRaisesRegex(ValueError, "changed path list exceeds"):
                    changed_files_from_event(root=root, event=event)

        self.assertEqual(1024 * 1024, run_command.call_args.kwargs["max_output_bytes"])

    def test_workflow_changed_path_collector_uses_bounded_binary_git_diff(self) -> None:
        with TemporaryDirectory() as temp, TemporaryDirectory() as external:
            root = Path(temp)
            output = Path(external) / "changed-files.nul"
            result = CommandResult(0, "src/main.py\0docs/readme.md\0")
            with patch("scripts.check_ci_security.run_bounded_command", return_value=result) as run_command:
                collect_changed_file_list(
                    root=root,
                    base_sha="a" * 40,
                    head_sha="b" * 40,
                    output_path=output,
                )

            self.assertEqual(b"src/main.py\0docs/readme.md\0", output.read_bytes())
            argv = run_command.call_args.args[0]
            self.assertIn("--no-ext-diff", argv)
            self.assertIn("--no-textconv", argv)
            self.assertIn("--no-renames", argv)
            self.assertIn("-z", argv)
            self.assertEqual(60, run_command.call_args.kwargs["timeout_seconds"])
            self.assertEqual(1024 * 1024, run_command.call_args.kwargs["max_output_bytes"])

    def test_workflow_changed_path_collector_fails_closed_before_writing(self) -> None:
        with TemporaryDirectory() as temp, TemporaryDirectory() as external:
            root = Path(temp)
            output = Path(external) / "changed-files.nul"
            limited = CommandResult(125, "partial", output_limited=True)
            with patch("scripts.check_ci_security.run_bounded_command", return_value=limited):
                with self.assertRaisesRegex(ValueError, "exceeds 1 MiB"):
                    collect_changed_file_list(
                        root=root,
                        base_sha="a" * 40,
                        head_sha="b" * 40,
                        output_path=output,
                    )
            self.assertFalse(output.exists())

            with self.assertRaisesRegex(ValueError, "full Git commit SHAs"):
                collect_changed_file_list(
                    root=root,
                    base_sha="not-a-sha",
                    head_sha="b" * 40,
                    output_path=output,
                )

    def test_workflow_changed_path_collector_reads_real_commit_paths(self) -> None:
        with TemporaryDirectory() as temp, TemporaryDirectory() as external:
            root = Path(temp)
            output = Path(external) / "changed-files.nul"
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "Harness Test"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "harness@example.test"], cwd=root, check=True)
            (root / "base.txt").write_text("base\n", encoding="utf-8")
            subprocess.run(["git", "add", "base.txt"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)
            base_sha = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True
            ).stdout.strip()
            (root / "file with spaces.txt").write_text("changed\n", encoding="utf-8")
            subprocess.run(["git", "add", "file with spaces.txt"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "change"], cwd=root, check=True)
            head_sha = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True
            ).stdout.strip()

            collect_changed_file_list(
                root=root,
                base_sha=base_sha,
                head_sha=head_sha,
                output_path=output,
            )

            self.assertEqual(b"file with spaces.txt\0", output.read_bytes())

    def test_workflow_changed_path_collector_reports_both_sides_of_sensitive_rename(self) -> None:
        with TemporaryDirectory() as temp, TemporaryDirectory() as external:
            root = Path(temp)
            output = Path(external) / "changed-files.nul"
            sensitive = root / ".github/workflows/harness-ci.yml"
            sensitive.parent.mkdir(parents=True)
            sensitive.write_text("name: trusted workflow\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.name", "Harness Test"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "harness@example.test"], cwd=root, check=True)
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "base"], cwd=root, check=True)
            base_sha = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True
            ).stdout.strip()
            renamed = root / "safe.txt"
            sensitive.replace(renamed)
            subprocess.run(["git", "add", "-A"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-qm", "rename"], cwd=root, check=True)
            head_sha = subprocess.run(
                ["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True
            ).stdout.strip()

            collect_changed_file_list(root=root, base_sha=base_sha, head_sha=head_sha, output_path=output)

            self.assertEqual(
                {".github/workflows/harness-ci.yml", "safe.txt"},
                set(output.read_bytes().decode("utf-8").split("\0")[:-1]),
            )

    def test_workflow_changed_path_collector_requires_external_regular_output(self) -> None:
        with TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaisesRegex(ValueError, "outside candidate checkout"):
                collect_changed_file_list(
                    root=root,
                    base_sha="a" * 40,
                    head_sha="b" * 40,
                    output_path=root / "changed-files.nul",
                )

    def test_missing_changed_file_list_fails_closed(self) -> None:
        with TemporaryDirectory() as temp, TemporaryDirectory() as external:
            root = Path(temp)
            self.write_workflow(root, f"jobs:\n  t:\n    steps:\n      - uses: actions/checkout@{PINNED_SHA}\n")
            event = self.write_event(root)

            errors = check_security_policy(
                root=root,
                event_path=event,
                changed_files_path=Path(external) / "missing.nul",
            )

            self.assertTrue(any("could not safely read changed paths" in error for error in errors))

    def test_trusted_harness_entrypoints_are_sensitive(self) -> None:
        for filename in (
            "scripts/harness.py",
            "scripts/command_runner.py",
            "scripts/validate_project.py",
            "scripts/check_pr_contract.py",
        ):
            with self.subTest(filename=filename), TemporaryDirectory() as temp:
                root = Path(temp)
                self.write_workflow(root, f"jobs:\n  t:\n    steps:\n      - uses: actions/checkout@{PINNED_SHA}\n")
                event = self.write_event(root, [filename])

                errors = check_security_policy(root=root, event_path=event)

                self.assertTrue(any("security-sensitive" in error for error in errors))

    def test_security_workflow_writes_changed_paths_outside_candidate(self) -> None:
        workflow = (ROOT / ".github/workflows/harness-ci.yml").read_text(encoding="utf-8")

        self.assertIn("${{ runner.temp }}/harness-changed-files.nul", workflow)
        self.assertIn("--changed-files \"$CHANGED_FILES\"", workflow)
        self.assertIn("--collect-changed-files", workflow)
        self.assertIn("Initialize changed file list", workflow)
        self.assertNotIn('git -C candidate diff --name-only', workflow)
        self.assertNotIn("workflow_dispatch:", workflow)
        self.assertNotIn("> candidate/.harness-changed-files.txt", workflow)
        self.assertIn("GITHUB_TOKEN: ${{ github.token }}", workflow)
        self.assertIn("pull-requests: read", workflow)

    def test_repository_and_project_validation_workflows_are_separate(self) -> None:
        harness_workflow = (ROOT / ".github/workflows/harness-ci.yml").read_text(encoding="utf-8")
        project_workflow = (ROOT / ".github/workflows/project-ci.yml").read_text(encoding="utf-8")

        self.assertIn("runs-on: ubuntu-24.04", harness_workflow)
        self.assertIn("runs-on: ubuntu-24.04", project_workflow)
        self.assertIn("pull_request_target:", harness_workflow)
        self.assertIn("pull_request_target:", project_workflow)
        self.assertIn("harness-core:", harness_workflow)
        self.assertNotIn("project-validation:", harness_workflow)
        self.assertIn("project-validation:", project_workflow)
        self.assertIn("trusted/scripts/harness.py check --full", project_workflow)
        self.assertIn("--config-root trusted", project_workflow)
        self.assertNotIn("unittest", project_workflow)
        self.assertNotIn("test_harness.py", project_workflow)
        self.assertIn("permissions: {}", project_workflow)
        self.assertIn("source-package:", project_workflow)
        self.assertIn("download-artifact", project_workflow)
        self.assertIn("upload-artifact", project_workflow)
        self.assertIn("candidate-source.tar", project_workflow)
        self.assertIn("trusted-source.tar", project_workflow)
        self.assertIn("retention-days: 1", project_workflow)
        self.assertIn("git init candidate", project_workflow)
        self.assertEqual(3, project_workflow.count("persist-credentials: false"))
        self.assertNotIn("GITHUB_TOKEN", project_workflow)
        self.assertNotIn("secrets.", project_workflow)

    def test_repository_ci_runs_candidate_checks_through_trusted_isolated_harness(self) -> None:
        workflow = (ROOT / ".github/workflows/harness-ci.yml").read_text(encoding="utf-8")

        self.assertIn('"${RUNNER_TEMP}/trusted-source.tar"', workflow)
        self.assertIn('"${RUNNER_TEMP}/candidate-source.tar"', workflow)
        self.assertIn("trusted-source.tar", workflow)
        self.assertIn("candidate-source.tar", workflow)
        self.assertIn("python3 -I trusted/scripts/harness.py check --full", workflow)
        self.assertIn("--root candidate --config-root trusted", workflow)
        self.assertNotIn("python3 -m unittest", workflow)
        self.assertNotIn("python3 -m py_compile", workflow)
        self.assertNotIn("python3 scripts/harness.py doctor", workflow)

    def test_only_protected_triggers_use_trusted_main_for_checkouts(self) -> None:
        for workflow in (
            (ROOT / ".github/workflows/harness-ci.yml").read_text(encoding="utf-8"),
            (ROOT / ".github/workflows/project-ci.yml").read_text(encoding="utf-8"),
        ):
            trusted = workflow.split("- name: Checkout trusted", 1)[1].split("- name:", 1)[0]
            with self.subTest(workflow=workflow[:40]):
                self.assertNotIn("workflow_dispatch:", workflow)
                self.assertIn("refs/heads/main", trusted)
                self.assertNotIn("github.sha", trusted)

    def test_pr_workflow_definition_must_come_from_the_base_branch(self) -> None:
        pull_request = "on:\n  pull_request:\n    branches: [main]\n"
        errors = check_workflow_text(Path(".github/workflows/harness-ci.yml"), pull_request)
        self.assertTrue(any("trusted pull_request_target" in error for error in errors), errors)

        wrong_ref = (
            "on:\n  pull_request_target:\n    branches: [release]\n"
            "    types: [opened, synchronize, reopened, ready_for_review, edited, labeled, unlabeled]\n"
        )
        errors = check_workflow_text(Path(".github/workflows/harness-ci.yml"), wrong_ref)
        self.assertTrue(any("limited to reviewed PR events on main" in error for error in errors), errors)

        malformed_types = (
            "on:\n  pull_request_target:\n    branches: [main]\n"
            "    types: [{name: opened}]\n"
        )
        errors = check_workflow_text(Path(".github/workflows/harness-ci.yml"), malformed_types)
        self.assertTrue(errors)


if __name__ == "__main__":
    unittest.main()
