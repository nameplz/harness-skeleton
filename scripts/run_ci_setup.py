#!/usr/bin/env python3
"""Run trusted Harness CI setup commands."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from harness_validation import HarnessCommand, HarnessValidationError, validate_command_item


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--config")
    return parser.parse_args()


def load_ci_config(path: Path) -> tuple[HarnessCommand, ...]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise HarnessValidationError(f"Config not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise HarnessValidationError(f"Invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise HarnessValidationError("ci config must be a JSON object")
    if data.get("schemaVersion") != 1:
        raise HarnessValidationError("ci schemaVersion must be 1")

    setup = data.get("setupCommands", [])
    if not isinstance(setup, list):
        raise HarnessValidationError("setupCommands must be a list")
    cache = data.get("cache", [])
    if not isinstance(cache, list):
        raise HarnessValidationError("cache must be a list")
    for item in cache:
        validate_cache_item(item)
    return tuple(validate_command_item(item) for item in setup)


def validate_cache_item(item: Any) -> None:
    if not isinstance(item, dict):
        raise HarnessValidationError("cache entry must be an object")
    for key in ("name", "path"):
        if not isinstance(item.get(key), str) or not item[key]:
            raise HarnessValidationError(f"cache.{key} must be non-empty string")
    key_files = item.get("keyFiles", [])
    if not isinstance(key_files, list) or not all(isinstance(value, str) for value in key_files):
        raise HarnessValidationError("cache.keyFiles must be list[str]")


def run_setup_command(root: Path, command: HarnessCommand) -> int:
    completed = subprocess.run(
        list(command.command),
        cwd=root,
        capture_output=True,
        text=True,
        timeout=600,
        shell=False,
    )
    if completed.stdout:
        print(completed.stdout, end="")
    if completed.stderr:
        print(completed.stderr, end="", file=sys.stderr)
    if completed.returncode != 0:
        print(f"{command.name} failed with exit code {completed.returncode}", file=sys.stderr)
    return completed.returncode


def main() -> int:
    args = parse_args()
    root = Path(args.root).resolve()
    config_path = Path(args.config).resolve() if args.config else root / ".harness/ci.json"
    if not config_path.exists():
        print("No Harness CI setup config found")
        return 0

    try:
        commands = load_ci_config(config_path)
    except HarnessValidationError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    for command in commands:
        returncode = run_setup_command(root, command)
        if returncode != 0:
            return returncode
    print("Harness CI setup complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
