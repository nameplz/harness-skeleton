"""Shared project validation helpers for Codex and Git hooks."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path


VALIDATION_SCRIPT_ORDER = ("lint", "build", "test")


def select_validation_commands(cwd: Path) -> list[list[str]]:
    """Select available validation commands without assuming a project stack."""
    package_json = cwd / "package.json"
    if not package_json.exists():
        return []

    try:
        package_data = json.loads(package_json.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []

    scripts = package_data.get("scripts")
    if not isinstance(scripts, dict):
        return []

    return [
        ["npm", "run", script_name]
        for script_name in VALIDATION_SCRIPT_ORDER
        if script_name in scripts
    ]


def run_validation(commands: list[list[str]], cwd: Path) -> tuple[bool, str]:
    """Run validation commands in order and return the first failure."""
    for command in commands:
        result = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode != 0:
            command_text = " ".join(command)
            output = (result.stdout + "\n" + result.stderr).strip()
            if len(output) > 2000:
                output = output[-2000:]
            return False, f"`{command_text}` failed.\n\n{output}"
    return True, ""


def validation_failure(cwd: Path) -> str | None:
    """Return a failure reason when configured validation does not pass."""
    commands = select_validation_commands(cwd)
    if not commands:
        return None

    passed, reason = run_validation(commands, cwd)
    return None if passed else reason
