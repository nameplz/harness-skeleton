#!/usr/bin/env python3
"""Check GitHub Actions workflow safety for Harness CI."""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import subprocess
from pathlib import Path
from typing import Any


FULL_SHA_RE = re.compile(r"@[0-9a-f]{40}$")
USES_RE = re.compile(r"uses:\s*([^\s#]+)")
WRITE_PERMISSION_RE = re.compile(r"^\s*[A-Za-z-]+:\s*write\s*$", re.MULTILINE)
FORBIDDEN_WORKFLOW_PATTERNS = (
    (re.compile(r"\bpull_request_target\b"), "pull_request_target is forbidden"),
    (re.compile(r"\bsecrets\."), "secrets.* is forbidden in CI workflow"),
    (re.compile(r"\bid-token:\s*write\b"), "OIDC id-token: write is forbidden"),
    (re.compile(r"\bself-hosted\b"), "self-hosted runners are forbidden"),
    (re.compile(r"\bpermissions:\s*write-all\b"), "write-all permissions are forbidden"),
    (WRITE_PERMISSION_RE, "write permissions are forbidden"),
    (re.compile(r"\b(deploy|publish|migration)\b", re.IGNORECASE), "deploy/publish/migration terms are forbidden"),
)
SENSITIVE_PREFIXES = (".github/workflows/", ".harness/", ".codex/hooks/")
SENSITIVE_SCRIPT_PATTERNS = ("*validation*.py", "check_*.py")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event", required=True)
    parser.add_argument("--root", default=".")
    return parser.parse_args()


def workflow_files(root: Path) -> list[Path]:
    workflows = root / ".github/workflows"
    if not workflows.exists():
        return []
    return sorted([*workflows.glob("*.yml"), *workflows.glob("*.yaml")])


def check_security_policy(*, root: Path, event_path: Path) -> list[str]:
    root = root.resolve()
    errors: list[str] = []
    for workflow in workflow_files(root):
        text = workflow.read_text(encoding="utf-8")
        errors.extend(check_workflow_text(workflow.relative_to(root), text))

    changed = changed_files_from_event(root=root, event_path=event_path)
    for filename in changed:
        if is_sensitive_path(filename):
            errors.append(f"PR changes security-sensitive path: {filename}")
    return errors


def check_workflow_text(relative: Path, text: str) -> list[str]:
    errors: list[str] = []
    for pattern, reason in FORBIDDEN_WORKFLOW_PATTERNS:
        if pattern.search(text):
            errors.append(f"{relative}: {reason}")

    for action_ref in USES_RE.findall(text):
        if action_ref.startswith("./") or action_ref.startswith("../"):
            continue
        if not FULL_SHA_RE.search(action_ref):
            errors.append(f"{relative}: external action must be pinned to full commit SHA: {action_ref}")
    return errors


def changed_files_from_event(*, root: Path, event_path: Path) -> list[str]:
    changed_file = root / ".harness-changed-files.txt"
    if changed_file.exists():
        return [line.strip() for line in changed_file.read_text(encoding="utf-8").splitlines() if line.strip()]

    try:
        event = json.loads(event_path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return []

    files = files_from_event_payload(event)
    if files:
        return files

    pull_request = event.get("pull_request")
    if not isinstance(pull_request, dict):
        return []
    base = pull_request.get("base")
    head = pull_request.get("head")
    base_sha = base.get("sha") if isinstance(base, dict) else None
    head_sha = head.get("sha") if isinstance(head, dict) else None
    if not isinstance(base_sha, str) or not isinstance(head_sha, str):
        return []

    completed = subprocess.run(
        ["git", "diff", "--name-only", base_sha, head_sha],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=60,
        shell=False,
    )
    if completed.returncode != 0:
        return []
    return [line.strip() for line in completed.stdout.splitlines() if line.strip()]


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


def is_sensitive_path(filename: str) -> bool:
    normalized = filename.replace("\\", "/")
    if normalized.startswith(SENSITIVE_PREFIXES):
        return True
    if normalized == "scripts/run_ci_setup.py":
        return True
    if normalized.startswith("scripts/"):
        basename = normalized.rsplit("/", 1)[-1]
        return any(fnmatch.fnmatch(basename, pattern) for pattern in SENSITIVE_SCRIPT_PATTERNS)
    return False


def main() -> int:
    args = parse_args()
    errors = check_security_policy(root=Path(args.root), event_path=Path(args.event))
    if not errors:
        print("CI security policy passed")
        return 0
    print("CI security policy failed:")
    for error in errors:
        print(f"- {error}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
