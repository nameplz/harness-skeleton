"""Shared project validation helpers for Codex and Git hooks."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path


VALIDATION_SCRIPT_ORDER = ("lint", "build", "test")
HARNESS_VALIDATION_FILE = Path(".harness") / "validation.json"
VALIDATION_TIMEOUT_SECONDS = 300


class ValidationConfigError(ValueError):
    """Raised when .harness/validation.json cannot be used safely."""


def _read_harness_validation_commands(path: Path) -> list[list[str]]:
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValidationConfigError(f"invalid JSON: {exc.msg}") from exc

    if not isinstance(config, dict):
        raise ValidationConfigError("top-level value must be an object")

    commands = config.get("commands")
    if not isinstance(commands, list):
        raise ValidationConfigError("commands must be a list")

    selected = []
    for index, item in enumerate(commands):
        if not isinstance(item, dict):
            raise ValidationConfigError(f"commands[{index}] must be an object")

        command = item.get("command")
        if not isinstance(command, list):
            raise ValidationConfigError(f"commands[{index}].command must be a list[str]")
        if not command:
            raise ValidationConfigError(f"commands[{index}].command must be non-empty")
        if not all(isinstance(arg, str) and arg for arg in command):
            raise ValidationConfigError(f"commands[{index}].command must be a list[str]")

        selected.append(command)

    return selected


def select_validation_commands(cwd: Path) -> list[list[str]]:
    """Select available validation commands without assuming a project stack."""
    harness_validation = cwd / HARNESS_VALIDATION_FILE
    if harness_validation.exists():
        return _read_harness_validation_commands(harness_validation)

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
        command_text = " ".join(command)
        try:
            result = subprocess.run(
                command,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=VALIDATION_TIMEOUT_SECONDS,
            )
        except FileNotFoundError:
            return False, f"`{command_text}` failed: command not found."
        except subprocess.TimeoutExpired:
            return False, (
                f"`{command_text}` timed out after "
                f"{VALIDATION_TIMEOUT_SECONDS} seconds."
            )

        if result.returncode != 0:
            output = (result.stdout + "\n" + result.stderr).strip()
            if len(output) > 2000:
                output = output[-2000:]
            return False, f"`{command_text}` failed.\n\n{output}"
    return True, ""


def validation_failure(cwd: Path) -> str | None:
    """Return a failure reason when configured validation does not pass."""
    try:
        commands = select_validation_commands(cwd)
    except ValidationConfigError as exc:
        return f"Invalid .harness/validation.json: {exc}"

    if not commands:
        return None

    passed, reason = run_validation(commands, cwd)
    return None if passed else reason
