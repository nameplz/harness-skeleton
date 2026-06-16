"""Shared project validation helpers for Codex and Git hooks.

This hook-side module delegates to scripts/harness_validation.py so Codex hooks
and CLI validation share one command-selection implementation.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import harness_validation


HARNESS_VALIDATION_FILE = harness_validation.HARNESS_VALIDATION_FILE
VALIDATION_TIMEOUT_SECONDS = harness_validation.VALIDATION_TIMEOUT_SECONDS
VALIDATION_SCRIPT_ORDER = harness_validation.VALIDATION_SCRIPT_ORDER
ValidationConfigError = harness_validation.ValidationConfigError


def _read_harness_validation_commands(path: Path) -> list[list[str]]:
    """Read command arrays from .harness/validation.json via shared helpers."""
    return harness_validation.read_harness_validation_commands(path)


def select_validation_commands(cwd: Path) -> list[list[str]]:
    """Select available validation commands via the Harness validation module."""
    return harness_validation.select_validation_commands(cwd)


def run_validation(commands: list[list[str]], cwd: Path) -> tuple[bool, str]:
    """Run validation commands in order and return the first failure."""
    return harness_validation.run_validation(commands, cwd)


def validation_failure(cwd: Path) -> str | None:
    """Return a failure reason when configured validation does not pass."""
    return harness_validation.validation_failure(cwd)
