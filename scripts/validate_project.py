#!/usr/bin/env python3
"""Run Harness project validation commands."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import harness_validation


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Harness validation commands")
    parser.add_argument("--root", default=".", help="Project root to validate")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    try:
        commands = harness_validation.select_validation_commands(root)
    except harness_validation.ValidationConfigError as exc:
        print(f"Invalid .harness/validation.json: {exc}", file=sys.stderr)
        return 1

    if not commands:
        print("No validation commands configured.")
        return 0

    passed, reason = harness_validation.run_validation(commands, root)
    if not passed:
        print(f"Project validation failed.\n\n{reason}", file=sys.stderr)
        return 1

    print("Project validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
