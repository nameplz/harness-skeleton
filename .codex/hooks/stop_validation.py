#!/usr/bin/env python3
"""Codex Stop hook for lightweight project validation."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

HOOK_DIR = Path(__file__).resolve().parent
if str(HOOK_DIR) not in sys.path:
    sys.path.insert(0, str(HOOK_DIR))

from project_validation import select_validation_commands, validation_failure


def _continue() -> dict[str, Any]:
    return {"continue": True}


def _continue_with_validation_feedback(reason: str) -> dict[str, Any]:
    return {
        "decision": "block",
        "reason": f"Project validation failed. Address this before finishing:\n\n{reason}",
    }


def evaluate_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("stop_hook_active") is True:
        return _continue()

    cwd = Path(str(payload.get("cwd") or ".")).resolve()
    reason = validation_failure(cwd)
    if reason is None:
        return _continue()
    return _continue_with_validation_feedback(reason)


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        payload = {}

    print(json.dumps(evaluate_payload(payload)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
