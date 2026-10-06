#!/usr/bin/env python3
"""Check GitHub Actions workflow safety for Harness CI."""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

try:
    from .command_runner import run_bounded_command
    from .github_expression_scanner import extract_github_expressions
except ImportError:  # Direct script invocation from the scripts directory.
    from command_runner import run_bounded_command
    from github_expression_scanner import extract_github_expressions

FULL_SHA_RE = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*@[0-9a-f]{40}")
FORBIDDEN_WORKFLOW_PATTERNS = (
    (re.compile(r"\bworkflow_dispatch\b", re.IGNORECASE), "manual workflow dispatch is forbidden"),
    (re.compile(r"\bself-hosted\b", re.IGNORECASE), "self-hosted runners are forbidden"),
    (re.compile(r"\b(deploy|publish|migration)\b", re.IGNORECASE), "deploy/publish/migration terms are forbidden"),
)
SENSITIVE_PREFIXES = (".github/workflows/", ".github/actions/", ".harness/", ".codex/")
SENSITIVE_DIRECTORY_PATHS = frozenset(
    {".github", ".github/workflows", ".github/actions", ".harness", ".codex"}
)
SENSITIVE_SCRIPT_PATTERNS = ("*validation*.py", "validate*.py", "check_*.py")
SENSITIVE_SCRIPT_PATHS = frozenset(
    {
        "scripts/harness.py",
        "scripts/harness_common.py",
        "scripts/harness_risk.py",
        "scripts/command_runner.py",
    }
)
TRUSTED_MAINTENANCE_LABEL = "harness-trusted-maintenance"
MAX_CHANGED_FILES_BYTES = 1024 * 1024
MAX_WORKFLOW_BYTES = 1024 * 1024
WORKFLOW_PARSE_TIMEOUT_SECONDS = 5
TRUSTED_LABEL_PERMISSIONS = frozenset({"admin", "maintain"})
HOSTED_RUNNER_LABELS = frozenset({"ubuntu-24.04"})
TRUSTED_POLICY_JOB_PERMISSIONS = frozenset({("contents", "read"), ("pull-requests", "read")})
TRUSTED_SOURCE_PACKAGE_PERMISSIONS = frozenset({("contents", "read")})
TRUSTED_READ_ONLY_JOBS = {
    (".github/workflows/harness-ci.yml", "security-policy"): TRUSTED_POLICY_JOB_PERMISSIONS,
    (".github/workflows/project-ci.yml", "source-package"): TRUSTED_SOURCE_PACKAGE_PERMISSIONS,
}
TRUSTED_PULL_REQUEST_WORKFLOWS = frozenset(
    {".github/workflows/harness-ci.yml", ".github/workflows/project-ci.yml"}
)
PULL_REQUEST_TARGET_TYPES = frozenset(
    {"opened", "synchronize", "reopened", "ready_for_review", "edited", "labeled", "unlabeled"}
)
GITHUB_TOKEN_RE = re.compile(
    r"\bgithub\s*(?:\.\s*token\b|\[\s*['\"]?\s*token\s*['\"]?\s*\])",
    re.IGNORECASE,
)
GITHUB_INDEX_RE = re.compile(r"\bgithub\s*\[", re.IGNORECASE)
GITHUB_OBJECT_FILTER_RE = re.compile(r"\bgithub\s*\.\s*\*", re.IGNORECASE)
GITHUB_SERIALIZATION_RE = re.compile(r"\btojson\s*\(\s*github\s*\)", re.IGNORECASE)
GIT_SHA_RE = re.compile(r"[0-9a-fA-F]{40}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event")
    parser.add_argument("--root", default=".")
    parser.add_argument("--changed-files")
    parser.add_argument("--collect-changed-files", action="store_true")
    parser.add_argument("--base-sha")
    parser.add_argument("--head-sha")
    parser.add_argument("--output")
    return parser.parse_args()


def workflow_files(root: Path) -> list[Path]:
    workflows = root / ".github/workflows"
    if not workflows.exists():
        return []
    return sorted([*workflows.glob("*.yml"), *workflows.glob("*.yaml")])


def check_security_policy(
    *,
    root: Path,
    event_path: Path,
    changed_files_path: Path | None = None,
    github_token: str | None = None,
    repository: str | None = None,
) -> list[str]:
    root = root.resolve()
    errors: list[str] = []
    for relative in (".github", ".github/workflows", ".github/actions"):
        path = root / relative
        if path.is_symlink():
            errors.append(f"{relative} cannot be a symlink")
            return errors
        if path.exists() and not path.is_dir():
            errors.append(f"{relative} must be a directory")
            return errors
    for workflow in workflow_files(root):
        if workflow.is_symlink():
            errors.append(f"{workflow.relative_to(root)} cannot be a symlink")
            continue
        try:
            workflow.resolve(strict=True).relative_to(root)
        except (OSError, RuntimeError, ValueError):
            errors.append(f"{workflow.relative_to(root)} must remain inside candidate checkout")
            continue
        try:
            if workflow.stat().st_size > MAX_WORKFLOW_BYTES:
                errors.append(f"{workflow.relative_to(root)} exceeds the workflow size limit")
                continue
            text = workflow.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            errors.append(f"{workflow.relative_to(root)} could not be read safely")
            continue
        errors.extend(check_workflow_text(workflow.relative_to(root), text, root=root))

    try:
        event = read_event(event_path)
        changed = changed_files_from_event(
            root=root,
            event=event,
            changed_files_path=changed_files_path,
        )
    except (OSError, UnicodeError, ValueError, subprocess.SubprocessError) as error:
        errors.append(f"could not safely read changed paths: {error}")
        return errors

    safe_changed: list[str] = []
    for filename in changed:
        if not is_safe_changed_path(filename):
            errors.append(f"PR contains unsafe changed path: {filename!r}")
        else:
            safe_changed.append(filename)

    sensitive = [filename for filename in safe_changed if is_sensitive_path(filename)]
    if not sensitive:
        return errors

    authorized, reason = trusted_maintenance_authorized(
        event=event,
        github_token=github_token or os.environ.get("GITHUB_TOKEN"),
        repository=repository or os.environ.get("GITHUB_REPOSITORY"),
    )
    if authorized:
        return errors
    errors.extend(f"PR changes security-sensitive path: {filename}" for filename in sensitive)
    if has_trusted_maintenance_label(event):
        errors.append(f"trusted maintenance label was not authorized: {reason}")
    return errors


def read_event(event_path: Path) -> dict[str, Any]:
    event = json.loads(event_path.read_text(encoding="utf-8"))
    if not isinstance(event, dict):
        raise ValueError("event payload must be a JSON object")
    return event


def has_trusted_maintenance_label(event: dict[str, Any]) -> bool:
    pull_request = event.get("pull_request")
    if not isinstance(pull_request, dict):
        return False
    labels = pull_request.get("labels")
    if not isinstance(labels, list):
        return False
    return any(
        isinstance(label, dict) and label.get("name") == TRUSTED_MAINTENANCE_LABEL
        for label in labels
    )


def trusted_maintenance_authorized(
    *,
    event: dict[str, Any],
    github_token: str | None,
    repository: str | None,
) -> tuple[bool, str]:
    """Authorize only a fresh label action made by an admin or maintainer."""

    if not has_trusted_maintenance_label(event):
        return False, "label is absent"
    if event.get("action") != "labeled":
        return False, "the label must be applied in this workflow event"
    label = event.get("label")
    if not isinstance(label, dict) or label.get("name") != TRUSTED_MAINTENANCE_LABEL:
        return False, "this event did not apply the trusted maintenance label"
    sender = event.get("sender")
    username = sender.get("login") if isinstance(sender, dict) else None
    if not isinstance(username, str) or not re.fullmatch(r"[A-Za-z0-9-]+", username):
        return False, "label actor is missing or invalid"
    if not isinstance(repository, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        return False, "trusted repository is missing or invalid"
    if not github_token:
        return False, "GitHub token is unavailable"

    try:
        permission = collaborator_permission(repository, username, github_token)
    except (OSError, urllib.error.URLError, json.JSONDecodeError, ValueError):
        return False, "GitHub could not verify the label actor's repository permission"
    if permission not in TRUSTED_LABEL_PERMISSIONS:
        return False, "label actor is not an admin or maintainer"
    return True, "authorized"


def collaborator_permission(repository: str, username: str, token: str) -> str | None:
    encoded_username = urllib.parse.quote(username, safe="")
    request = urllib.request.Request(
        f"https://api.github.com/repos/{repository}/collaborators/{encoded_username}/permission",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2026-03-10",
        },
    )
    with urllib.request.urlopen(request, timeout=10) as response:
        result = json.loads(response.read().decode("utf-8"))
    if not isinstance(result, dict):
        return None
    role_name = result.get("role_name")
    if role_name == "maintain":
        return "maintain"
    permission = result.get("permission")
    return permission if isinstance(permission, str) else None


def check_workflow_text(relative: Path, text: str, *, root: Path | None = None) -> list[str]:
    errors: list[str] = []
    try:
        workflow = _parse_workflow_yaml(text)
    except (OSError, ValueError, subprocess.SubprocessError):
        return [f"{relative}: workflow YAML is invalid or could not be parsed safely"]

    for value in _string_values(workflow):
        for pattern, reason in FORBIDDEN_WORKFLOW_PATTERNS:
            if pattern.search(value):
                message = f"{relative}: {reason}"
                if message not in errors:
                    errors.append(message)

    errors.extend(_check_workflow_triggers(relative, workflow))
    errors.extend(_check_github_expressions(relative, workflow))
    errors.extend(_check_job_runners(relative, workflow))

    for mapping in _mappings(workflow):
        action_ref = mapping.get("uses")
        if action_ref is not None:
            if not isinstance(action_ref, str):
                errors.append(f"{relative}: action reference must be a string")
            elif action_ref.startswith("../"):
                errors.append(f"{relative}: local action path cannot escape the checkout")
            elif action_ref.startswith("./") and not _is_safe_local_action_reference(action_ref, root=root):
                errors.append(f"{relative}: local action path cannot escape the checkout")
            elif action_ref.startswith("./") and not _is_sensitive_local_action_reference(action_ref):
                errors.append(f"{relative}: local actions must live under .github/actions/")
            elif not action_ref.startswith("./") and not FULL_SHA_RE.fullmatch(action_ref):
                errors.append(f"{relative}: external action must be pinned to full commit SHA: {action_ref}")
            elif _is_checkout_action(action_ref):
                errors.extend(_check_checkout_credentials(relative, mapping))

        if "permissions" in mapping:
            errors.extend(_check_permissions(relative, mapping["permissions"]))
    return errors


def _check_workflow_triggers(relative: Path, workflow: dict[str, Any]) -> list[str]:
    triggers = workflow.get("on")
    if triggers is None:
        if relative.as_posix().startswith(".github/workflows/"):
            return [f"{relative}: workflow must declare an approved trigger"]
        return []
    if not isinstance(triggers, dict):
        return [f"{relative}: workflow triggers must be a mapping"]

    errors: list[str] = []
    if "pull_request" in triggers:
        errors.append(f"{relative}: PR workflows must use the trusted pull_request_target event")
    allowed_events = {"push", "pull_request_target"}
    if set(triggers) - allowed_events:
        errors.append(f"{relative}: workflow event is not approved")

    has_target = "pull_request_target" in triggers
    target = triggers.get("pull_request_target")
    if has_target:
        if relative.as_posix() not in TRUSTED_PULL_REQUEST_WORKFLOWS:
            errors.append(f"{relative}: pull_request_target is restricted to trusted CI workflows")
        if (
            not isinstance(target, dict)
            or set(target) != {"branches", "types"}
            or target.get("branches") != ["main"]
            or not isinstance(target.get("types"), list)
            or not all(isinstance(event_type, str) for event_type in target["types"])
            or frozenset(target["types"]) != PULL_REQUEST_TARGET_TYPES
        ):
            errors.append(f"{relative}: pull_request_target must be limited to reviewed PR events on main")

    has_push = "push" in triggers
    push = triggers.get("push")
    if has_push and (
        not isinstance(push, dict)
        or set(push) != {"branches"}
        or push.get("branches") != ["main"]
    ):
        errors.append(f"{relative}: push workflows must be limited to main")
    if not has_target and not has_push:
        errors.append(f"{relative}: workflow must use a trusted CI trigger")
    return errors


def _check_github_expressions(relative: Path, workflow: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    def inspect(value: Any, path: tuple[str | int, ...] = ()) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                inspect(item, (*path, str(key)))
        elif isinstance(value, list):
            for index, item in enumerate(value):
                inspect(item, (*path, index))
        elif isinstance(value, str):
            expressions, malformed = extract_github_expressions(value)
            if not expressions and not malformed and path and path[-1] == "if":
                expressions, malformed = extract_github_expressions(f"${{{{ {value} }}}}")
            if malformed:
                errors.append(f"{relative}: GitHub expression is malformed")
            for expression, code in expressions:
                if re.search(r"\bsecrets\b", code, re.IGNORECASE):
                    errors.append(f"{relative}: secrets access is forbidden in CI workflow")
                elif GITHUB_OBJECT_FILTER_RE.search(code):
                    errors.append(f"{relative}: object filters over the github context are forbidden")
                elif GITHUB_INDEX_RE.search(code):
                    errors.append(f"{relative}: bracket access to the github context is forbidden")
                elif GITHUB_TOKEN_RE.search(code):
                    if not _is_allowed_policy_token_expression(workflow, path, value, expression):
                        errors.append(f"{relative}: github.token access is forbidden outside the trusted policy step")
                elif GITHUB_SERIALIZATION_RE.search(code):
                    errors.append(f"{relative}: serialization of the github context is forbidden")

    inspect(workflow)
    return list(dict.fromkeys(errors))


def _is_allowed_policy_token_expression(
    workflow: dict[str, Any],
    path: tuple[str | int, ...],
    value: str,
    expression: str,
) -> bool:
    jobs = workflow.get("jobs")
    job = jobs.get("security-policy") if isinstance(jobs, dict) else None
    steps = job.get("steps") if isinstance(job, dict) else None
    if not isinstance(steps, list):
        return False
    normalized_expression = re.sub(r"\s+", "", expression).casefold()
    expected_run = """if [ "$GITHUB_EVENT_NAME" = "pull_request_target" ]; then
  export GIT_CONFIG_COUNT=1
  export GIT_CONFIG_KEY_0="http.https://github.com/.extraheader"
  export GIT_CONFIG_VALUE_0="AUTHORIZATION: basic $(printf 'x-access-token:%s' "$GITHUB_TOKEN" | base64 --wrap=0)"
  git -C candidate remote add base "https://github.com/${BASE_REPO}.git"
  git -C candidate fetch --no-tags --depth=1 base "$BASE_SHA"
  python3 trusted/scripts/check_ci_security.py --collect-changed-files --root candidate --base-sha "$BASE_SHA" --head-sha "$HEAD_SHA" --output "$CHANGED_FILES"
fi
python3 trusted/scripts/check_ci_security.py --root candidate --event "$GITHUB_EVENT_PATH" --changed-files "$CHANGED_FILES"
if [ "$GITHUB_EVENT_NAME" = "pull_request_target" ]; then
  python3 trusted/scripts/check_pr_contract.py --event "$GITHUB_EVENT_PATH"
fi"""
    for index, step in enumerate(steps):
        if path != ("jobs", "security-policy", "steps", index, "env", "GITHUB_TOKEN"):
            continue
        if not isinstance(step, dict) or set(step) != {"name", "env", "run"}:
            return False
        env = step.get("env")
        return (
            normalized_expression == "github.token"
            and value == "${{ github.token }}"
            and step.get("name") == "Check security policy"
            and step.get("run") == expected_run
            and isinstance(env, dict)
            and env == {
                "GITHUB_TOKEN": "${{ github.token }}",
                "CHANGED_FILES": "${{ runner.temp }}/harness-changed-files.nul",
                "BASE_REPO": "${{ github.event.pull_request.base.repo.full_name }}",
                "BASE_SHA": "${{ github.event.pull_request.base.sha }}",
                "HEAD_SHA": "${{ github.event.pull_request.head.sha }}",
            }
        )
    return False


def _check_job_runners(relative: Path, workflow: dict[str, Any]) -> list[str]:
    jobs = workflow.get("jobs")
    if jobs is None:
        return []
    if not isinstance(jobs, dict):
        return [f"{relative}: jobs must be a mapping"]
    errors: list[str] = []
    if workflow.get("permissions") != {}:
        errors.append(f"{relative}: workflow permissions must be empty")
    for name, job in jobs.items():
        runner = job.get("runs-on") if isinstance(job, dict) else None
        if not isinstance(name, str) or not isinstance(runner, str) or runner not in HOSTED_RUNNER_LABELS:
            errors.append(f"{relative}: every job must use a fixed GitHub-hosted runs-on label")
        permissions = job.get("permissions") if isinstance(job, dict) else None
        expected_permissions = TRUSTED_READ_ONLY_JOBS.get((relative.as_posix(), name), frozenset())
        valid_entries = isinstance(permissions, dict) and all(
            isinstance(scope, str) and isinstance(level, str)
            for scope, level in permissions.items()
        )
        if not valid_entries or frozenset(permissions.items()) != expected_permissions:
            errors.append(f"{relative}: job permissions must be empty except for approved read-only source jobs")
    return errors


def _is_checkout_action(action_ref: str) -> bool:
    action_name = action_ref.rsplit("@", 1)[0] if "@" in action_ref else action_ref
    return action_name.casefold() == "actions/checkout"


def _check_checkout_credentials(relative: Path, step: dict[str, Any]) -> list[str]:
    options = step.get("with")
    if not isinstance(options, dict) or not all(isinstance(key, str) for key in options):
        return [f"{relative}: actions/checkout credentials must not persist"]
    normalized_keys = [key.casefold() for key in options]
    if len(set(normalized_keys)) != len(normalized_keys):
        return [f"{relative}: actions/checkout credentials must not persist"]
    if "persist-credentials" not in options or options["persist-credentials"] is not False:
        return [f"{relative}: actions/checkout credentials must not persist"]
    sensitive_options = set(normalized_keys)
    if sensitive_options & {"token", "ssh-key", "ssh-token"}:
        return [f"{relative}: custom checkout credentials are forbidden"]
    return []


def _is_safe_local_action_reference(action_ref: str, *, root: Path | None = None) -> bool:
    if not action_ref.startswith("./") or "\\" in action_ref:
        return False
    parts = action_ref[2:].split("/")
    if not parts or any(part in {"", ".", ".."} for part in parts):
        return False
    if bool(re.match(r"^[A-Za-z]:", parts[0])) or any(
        ord(character) < 32 or ord(character) == 127 for character in action_ref
    ):
        return False
    if root is None:
        return True
    workspace = root.resolve(strict=True)
    actions_root = (workspace / ".github/actions").resolve(strict=False)
    target = (workspace / action_ref[2:]).resolve(strict=False)
    try:
        target.relative_to(actions_root)
    except ValueError:
        return False
    return True


def _is_sensitive_local_action_reference(action_ref: str) -> bool:
    return action_ref == "./.github/actions" or action_ref.startswith("./.github/actions/")


def _parse_workflow_yaml(text: str) -> dict[str, Any]:
    if len(text.encode("utf-8")) > MAX_WORKFLOW_BYTES:
        raise ValueError("workflow exceeds the size limit")
    ruby_script = r"""
source = STDIN.read
stream = Psych.parse_stream(source)
abort "workflow must have exactly one YAML document" unless stream && stream.children.length == 1
document = stream.children.first
abort "workflow root must be a mapping" unless document.root.is_a?(Psych::Nodes::Mapping)
root_keys = document.root.children.each_slice(2).map(&:first)
boolean_aliases = %w[true yes y false no n on off]
root_scalar_keys = root_keys.select { |key| key.is_a?(Psych::Nodes::Scalar) }
plain_boolean_root_keys = root_scalar_keys.select { |key| key.plain && boolean_aliases.include?(key.value.downcase) }
abort "workflow root has an ambiguous boolean key" if plain_boolean_root_keys.any? { |key| key.value.downcase != "on" }
plain_on = plain_boolean_root_keys.any? { |key| key.value.downcase == "on" }
string_on = root_scalar_keys.any? { |key| key.value.casecmp?("on") && !key.plain }
abort "workflow root has ambiguous trigger keys" if plain_on && string_on
def check_unique(node, root_mapping = false)
  case node
  when Psych::Nodes::Mapping
    keys = {}
    node.children.each_slice(2) do |key, value|
      abort "workflow mapping keys must be scalar strings" unless key.is_a?(Psych::Nodes::Scalar)
      abort "explicit YAML mapping-key tags are unsupported" if key.tag
      if key.plain
        normalized_key = key.value.downcase
        if %w[true yes y on false no n off].include?(normalized_key)
          abort "ambiguous YAML boolean mapping key" unless root_mapping && normalized_key == "on"
          identity = [:boolean, %w[true yes y on].include?(normalized_key)]
        elsif %w[null ~].include?(normalized_key) || !key.value.match?(/\A[A-Za-z_][A-Za-z0-9_.-]*\z/)
          abort "workflow mapping keys must be strings"
        else
          identity = [:scalar, key.value]
        end
      else
        identity = [:scalar, key.value]
      end
      check_unique(value)
      abort "duplicate YAML mapping key" if keys.key?(identity)
      keys[identity] = true
    end
  when Psych::Nodes::Sequence
    node.children.each { |child| check_unique(child) }
  end
end
check_unique(document.root, true)
workflow = YAML.safe_load(source, permitted_classes: [Date, Time], aliases: false)
abort "workflow root must be a mapping" unless workflow.is_a?(Hash)
if plain_on && workflow.key?(true)
  workflow["on"] = workflow.delete(true)
end
STDOUT.write(JSON.generate(workflow))
""".strip()
    completed = subprocess.run(
        ["ruby", "-rjson", "-ryaml", "-rdate", "-e", ruby_script],
        input=text,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=WORKFLOW_PARSE_TIMEOUT_SECONDS,
        shell=False,
        check=False,
    )
    if completed.returncode != 0:
        raise ValueError("workflow YAML parser rejected the document")
    workflow = json.loads(completed.stdout)
    if not isinstance(workflow, dict):
        raise ValueError("workflow root must be a mapping")
    return workflow


def _mappings(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        return [value, *(mapping for item in value.values() for mapping in _mappings(item))]
    if isinstance(value, list):
        return [mapping for item in value for mapping in _mappings(item)]
    return []


def _string_values(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [text for key, item in value.items() for text in [*_string_values(key), *_string_values(item)]]
    if isinstance(value, list):
        return [text for item in value for text in _string_values(item)]
    return []


def _check_permissions(relative: Path, value: Any) -> list[str]:
    if isinstance(value, str):
        level = value.casefold()
        if level == "write-all":
            return [f"{relative}: write-all permissions are forbidden"]
        if level == "read-all":
            return []
        return [f"{relative}: permission declaration is not recognized"]
    if not isinstance(value, dict):
        return [f"{relative}: permission declaration is not a mapping"]

    errors: list[str] = []
    for scope, level in value.items():
        if not isinstance(scope, str) or not isinstance(level, str):
            errors.append(f"{relative}: permission declaration is not recognized")
        elif level.casefold() == "write":
            errors.append(f"{relative}: write permissions are forbidden")
        elif level.casefold() not in {"read", "none"}:
            errors.append(f"{relative}: permission declaration is not recognized")
    return errors


def changed_files_from_event(
    *,
    root: Path,
    event: dict[str, Any],
    changed_files_path: Path | None = None,
) -> list[str]:
    if changed_files_path is not None:
        return read_changed_file_list(root=root, changed_files_path=changed_files_path)

    files = files_from_event_payload(event)
    if files or has_event_file_list(event):
        return files

    pull_request = event.get("pull_request")
    if not isinstance(pull_request, dict):
        return []
    base = pull_request.get("base")
    head = pull_request.get("head")
    base_sha = base.get("sha") if isinstance(base, dict) else None
    head_sha = head.get("sha") if isinstance(head, dict) else None
    if not isinstance(base_sha, str) or not isinstance(head_sha, str) or not GIT_SHA_RE.fullmatch(base_sha) or not GIT_SHA_RE.fullmatch(head_sha):
        raise ValueError("pull request base/head commit must be full Git commit SHAs")

    completed = run_bounded_command(
        ["git", "diff", "--no-renames", "--no-ext-diff", "--no-textconv", "--name-only", "-z", base_sha, head_sha],
        cwd=root,
        timeout_seconds=60,
        max_output_bytes=MAX_CHANGED_FILES_BYTES,
    )
    if completed.output_limited:
        raise ValueError("Git changed path list exceeds 1 MiB")
    if completed.timed_out:
        raise ValueError("Git changed path list timed out")
    if completed.returncode != 0:
        raise ValueError("git could not determine pull request changed paths")
    if "\ufffd" in completed.output:
        raise ValueError("changed path list is not valid UTF-8")
    return split_nul_delimited_paths(completed.output)


def collect_changed_file_list(
    *,
    root: Path,
    base_sha: str,
    head_sha: str,
    output_path: Path,
) -> None:
    candidate_root = root.resolve(strict=True)
    if not GIT_SHA_RE.fullmatch(base_sha) or not GIT_SHA_RE.fullmatch(head_sha):
        raise ValueError("base and head must be full Git commit SHAs")
    output = output_path.resolve(strict=False)
    try:
        output.relative_to(candidate_root)
    except ValueError:
        pass
    else:
        raise ValueError("changed file list must be outside candidate checkout")
    if output_path.is_symlink():
        raise ValueError("changed file list cannot be a symlink")
    if not output.parent.is_dir() or (output.exists() and not output.is_file()):
        raise ValueError("changed file list output must have an existing directory parent")

    completed = run_bounded_command(
        ["git", "diff", "--no-renames", "--no-ext-diff", "--no-textconv", "--name-only", "-z", base_sha, head_sha],
        cwd=candidate_root,
        timeout_seconds=60,
        max_output_bytes=MAX_CHANGED_FILES_BYTES,
    )
    if completed.output_limited:
        raise ValueError("Git changed path list exceeds 1 MiB")
    if completed.timed_out:
        raise ValueError("Git changed path list timed out")
    if completed.returncode != 0:
        raise ValueError("git could not determine pull request changed paths")
    if "\ufffd" in completed.output:
        raise ValueError("changed path list is not valid UTF-8")
    paths = split_nul_delimited_paths(completed.output)
    if any(not path for path in paths):
        raise ValueError("changed path list contains an empty path")
    output.write_bytes("\0".join(paths).encode("utf-8") + (b"\0" if paths else b""))


def read_changed_file_list(*, root: Path, changed_files_path: Path) -> list[str]:
    candidate_root = root.resolve(strict=True)
    changed_list = changed_files_path.resolve(strict=True)
    try:
        changed_list.relative_to(candidate_root)
    except ValueError:
        pass
    else:
        raise ValueError("changed file list must be outside candidate checkout")
    if not changed_list.is_file():
        raise ValueError("changed file list must be a regular file")
    if changed_list.stat().st_size > MAX_CHANGED_FILES_BYTES:
        raise ValueError("changed file list exceeds 1 MiB")
    return split_nul_delimited_paths(changed_list.read_bytes().decode("utf-8", errors="strict"))


def split_nul_delimited_paths(output: str) -> list[str]:
    paths = output.split("\0")
    if paths and paths[-1] == "":
        paths.pop()
    return paths


def files_from_event_payload(event: dict[str, Any]) -> list[str]:
    candidates: list[Any] = []
    if isinstance(event.get("changed_files"), list):
        candidates.extend(event["changed_files"])
    if isinstance(event.get("files"), list):
        candidates.extend(event["files"])
    pull_request = event.get("pull_request")
    if isinstance(pull_request, dict):
        for key in ("changed_files", "files"):
            if isinstance(pull_request.get(key), list):
                candidates.extend(pull_request[key])

    files: list[str] = []
    for item in candidates:
        if isinstance(item, str):
            files.append(item)
        elif isinstance(item, dict) and isinstance(item.get("filename"), str):
            files.append(item["filename"])
    return files


def has_event_file_list(event: dict[str, Any]) -> bool:
    if any(isinstance(event.get(key), list) for key in ("changed_files", "files")):
        return True
    pull_request = event.get("pull_request")
    return isinstance(pull_request, dict) and any(
        isinstance(pull_request.get(key), list) for key in ("changed_files", "files")
    )


def is_safe_changed_path(filename: str) -> bool:
    if not filename or "\\" in filename or filename.startswith("/"):
        return False
    if re.match(r"^[A-Za-z]:", filename):
        return False
    if any(ord(character) < 32 or ord(character) == 127 for character in filename):
        return False
    return all(part not in {"", ".", ".."} for part in filename.split("/"))


def is_sensitive_path(filename: str) -> bool:
    if filename in SENSITIVE_DIRECTORY_PATHS or filename in SENSITIVE_SCRIPT_PATHS:
        return True
    if filename.startswith(SENSITIVE_PREFIXES):
        return True
    if filename.startswith("scripts/"):
        basename = filename.rsplit("/", 1)[-1]
        return any(fnmatch.fnmatch(basename, pattern) for pattern in SENSITIVE_SCRIPT_PATTERNS)
    return False


def main() -> int:
    args = parse_args()
    if args.collect_changed_files:
        if args.event or args.changed_files or not args.base_sha or not args.head_sha or not args.output:
            print("CI security policy failed: changed-path collection arguments are incomplete")
            return 2
        try:
            collect_changed_file_list(
                root=Path(args.root),
                base_sha=args.base_sha,
                head_sha=args.head_sha,
                output_path=Path(args.output),
            )
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            print(f"CI security policy failed: could not safely collect changed paths: {error}")
            return 1
        print("Changed path list collected safely")
        return 0
    if not args.event:
        print("CI security policy failed: --event is required")
        return 2
    errors = check_security_policy(
        root=Path(args.root),
        event_path=Path(args.event),
        changed_files_path=Path(args.changed_files) if args.changed_files else None,
    )
    if not errors:
        print("CI security policy passed")
        return 0
    print("CI security policy failed:")
    for error in errors:
        print(f"- {error}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
