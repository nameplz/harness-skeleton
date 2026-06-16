#!/usr/bin/env python3
"""Codex hook policy for blocking clearly dangerous shell commands."""

from __future__ import annotations

import json
import re
import sys
from typing import Any


BLOCKED_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"\brm\s+-[A-Za-z]*r[A-Za-z]*f[A-Za-z]*\s+(/|\.|\.\.|~|\$HOME)(\s|$)"),
        "rm -rf against a broad filesystem target",
    ),
    (
        re.compile(r"\brm\s+-[A-Za-z]*f[A-Za-z]*r[A-Za-z]*\s+(/|\.|\.\.|~|\$HOME)(\s|$)"),
        "rm -rf against a broad filesystem target",
    ),
    (re.compile(r"\bgit\s+reset\s+--hard\b"), "git reset --hard"),
    (re.compile(r"\bgit\s+push\b[^\n]*\s--force(?:-with-lease)?\b"), "force push"),
    (re.compile(r"\bdrop\s+table\b", re.IGNORECASE), "DROP TABLE"),
    (re.compile(r"\bmkfs(?:\.[A-Za-z0-9_-]+)?\b"), "filesystem formatting"),
    (re.compile(r"\bdd\b[^\n]*\bof=/dev/"), "raw disk write with dd"),
    (re.compile(r":\s*\(\)\s*\{"), "fork bomb pattern"),
)


def evaluate_command(command: str) -> str | None:
    """Return a block reason when a command violates repository policy."""
    normalized = command.strip()
    for pattern, label in BLOCKED_PATTERNS:
        if pattern.search(normalized):
            return f"Blocked dangerous command: {label}."
    return None


def _extract_command(payload: dict[str, Any]) -> str:
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, dict):
        return ""
    command = tool_input.get("command")
    return command if isinstance(command, str) else ""


def _pre_tool_use_deny(reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def _permission_request_deny(reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": {
                "behavior": "deny",
                "message": reason,
            },
        }
    }


def evaluate_payload(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Evaluate a Codex hook payload and return hook JSON when blocked."""
    if payload.get("tool_name") != "Bash":
        return None

    reason = evaluate_command(_extract_command(payload))
    if reason is None:
        return None

    event_name = payload.get("hook_event_name")
    if event_name == "PermissionRequest":
        return _permission_request_deny(reason)
    return _pre_tool_use_deny(reason)


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
