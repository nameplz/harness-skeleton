#!/usr/bin/env bash
set -euo pipefail

payload_file="${TMPDIR:-/tmp}/codex-pre-commit-validation.$$"
cat > "$payload_file"

python3 - "$payload_file" <<'PY'
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path


VALIDATION_SCRIPTS = (
    ("lint", ["npm", "run", "lint"]),
    ("build", ["npm", "run", "build"]),
    ("test", ["npm", "run", "test"]),
)


def load_payload(path: str) -> dict:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def extract_command(payload: dict) -> str:
    tool_input = payload.get("tool_input") or payload.get("input") or {}
    if isinstance(tool_input, dict):
        command = tool_input.get("command") or tool_input.get("cmd") or ""
        return command if isinstance(command, str) else ""
    return ""


def is_git_commit(command: str) -> bool:
    return bool(re.search(r"(^|[;&|]\s*)git\s+commit(\s|$)", command))


def load_package_scripts(cwd: Path) -> set[str]:
    package_json = cwd / "package.json"
    if not package_json.exists():
        return set()
    try:
        data = json.loads(package_json.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return set()
    scripts = data.get("scripts", {})
    return set(scripts) if isinstance(scripts, dict) else set()


def run_command(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=120,
    )


def deny(reason: str) -> None:
    print(
        json.dumps(
            {
                "decision": "block",
                "reason": reason,
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                },
            },
            ensure_ascii=False,
        )
    )


def main() -> int:
    payload = load_payload(sys.argv[1])
    command = extract_command(payload)
    if not is_git_commit(command):
        return 0

    cwd = Path(payload.get("cwd") or ".").resolve()
    package_scripts = load_package_scripts(cwd)
    commands = [
        (script_name, command_parts)
        for script_name, command_parts in VALIDATION_SCRIPTS
        if script_name in package_scripts
    ]
    if not commands:
        return 0

    failures: list[str] = []
    for script_name, command_parts in commands:
        result = run_command(command_parts, cwd)
        if result.returncode != 0:
            output = "\n".join(part for part in (result.stdout, result.stderr) if part).strip()
            failures.append(
                f"`{' '.join(command_parts)}` failed with exit code {result.returncode}.\n"
                f"{output[-3000:]}"
            )

    if failures:
        deny(
            "Pre-commit validation failed. Fix lint/build/test before committing:\n\n"
            + "\n\n".join(failures)
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
PY

status=$?
rm -f "$payload_file"
exit "$status"
