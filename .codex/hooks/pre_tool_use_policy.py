#!/usr/bin/env python3
"""Block dangerous Bash commands before Codex runs them."""

from __future__ import annotations

import json
import re
import sys


DANGEROUS_PATTERNS = (
    (re.compile(r"\brm\s+-[^\n;]*r[^\n;]*f\b"), "recursive force deletion"),
    (re.compile(r"\bgit\s+push\b[^\n;]*\s--force(?:-with-lease)?\b"), "forced git push"),
    (re.compile(r"\bgit\s+reset\s+--hard\b"), "hard git reset"),
    (re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE), "DROP TABLE statement"),
)


def _read_payload() -> dict:
    try:
        return json.load(sys.stdin)
    except json.JSONDecodeError:
        return {}


def _extract_command(payload: dict) -> str:
    tool_input = payload.get("tool_input") or payload.get("input") or {}
    if isinstance(tool_input, dict):
        command = tool_input.get("command") or tool_input.get("cmd") or ""
        return command if isinstance(command, str) else ""
    return ""


def main() -> int:
    command = _extract_command(_read_payload())
    for pattern, reason in DANGEROUS_PATTERNS:
        if pattern.search(command):
            print(
                json.dumps(
                    {
                        "decision": "block",
                        "reason": f"Blocked dangerous Bash command: {reason}. Ask the user for explicit approval and use a safer alternative.",
                    },
                    ensure_ascii=False,
                )
            )
            return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
