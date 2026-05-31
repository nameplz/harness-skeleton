#!/usr/bin/env python3
"""Configure Harness validation for a project root."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import harness_validation


def _print_config(config: dict) -> None:
    print(json.dumps(config, indent=2, ensure_ascii=False))


def _print_placeholder_error(placeholders: list[harness_validation.PlaceholderOccurrence]) -> None:
    print("Unresolved Harness placeholders remain. Fill the project spec first:", file=sys.stderr)
    for item in placeholders:
        print(f"- {item.relative_path}:{item.line}: {item.text}", file=sys.stderr)
    print("Use --allow-placeholders only for an intentional early setup.", file=sys.stderr)


def _print_commands(config: dict) -> None:
    print("Configured validation:")
    for item in config.get("commands", []):
        print(f"- {item['name']}: {' '.join(item['command'])}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Configure Harness validation")
    parser.add_argument("--root", default=".", help="Project root to configure")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print detected config without writing files",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing .harness/validation.json",
    )
    parser.add_argument(
        "--allow-placeholders",
        action="store_true",
        help="Allow unresolved AGENTS.md/docs placeholders while configuring",
    )
    args = parser.parse_args()

    root = Path(args.root).resolve()
    if not root.exists():
        print(f"ERROR: root does not exist: {root}", file=sys.stderr)
        return 1

    placeholders = harness_validation.find_unresolved_placeholders(root)
    if placeholders and not args.allow_placeholders:
        _print_placeholder_error(placeholders)
        return 2

    config = harness_validation.build_validation_config(root)
    if not config.get("commands"):
        print("No safe validation commands were detected.", file=sys.stderr)
        return 1

    validation_path = root / harness_validation.HARNESS_VALIDATION_FILE
    if validation_path.exists() and not args.force and not args.dry_run:
        print(
            f"ERROR: {validation_path} already exists. Use --force to overwrite.",
            file=sys.stderr,
        )
        return 1

    if args.dry_run:
        _print_config(config)
        return 0

    written = harness_validation.write_validation_config(root, config)
    print(f"Created {written}")
    print(f"Detected: {config['language']} / {config['stack']} / {config['package_manager']}")
    _print_commands(config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
