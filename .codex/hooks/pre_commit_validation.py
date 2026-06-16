#!/usr/bin/env python3
"""Codex PreToolUse hook that validates before `git commit` commands."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

HOOK_DIR = Path(__file__).resolve().parent
if str(HOOK_DIR) not in sys.path:
    sys.path.insert(0, str(HOOK_DIR))

import project_validation


GIT_COMMIT_PATTERN = re.compile(
    r"(^|[;&|]\s*)(rtk\s+(proxy\s+)?)?git(\s+-c\s+\S+\s+\S+)*\s+commit\b"
)


def is_git_commit_command(command: str) -> bool:
    """Return True when a Bash command attempts a git commit."""
    return GIT_COMMIT_PATTERN.search(command.strip()) is not None


def _extract_command(payload: dict[str, Any]) -> str:
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return ""
    command = tool_input.get("command")
    return command if isinstance(command, str) else ""


def _deny(reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                "Pre-commit validation failed. Fix the issue before committing.\n\n"
                f"{reason}"
            ),
        }
    }


def evaluate_payload(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Run validation before Codex executes a Bash git commit command."""
    if payload.get("tool_name") != "Bash":
        return None

    if not is_git_commit_command(_extract_command(payload)):
        return None

    cwd = Path(str(payload.get("cwd") or ".")).resolve()
    reason = project_validation.validation_failure(cwd)
    if reason is None:
        return None
    return _deny(reason)


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        return 0

    result = evaluate_payload(payload)
    if result is not None:
        print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
