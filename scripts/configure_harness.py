#!/usr/bin/env python3
"""Create default Harness config files for a concrete project."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from harness_validation import check_docs


VALIDATION_CONFIG = {
    "schemaVersion": 1,
    "mode": "language-neutral",
    "profiles": [],
    "commands": [],
    "checks": {"docs": True, "deploy": True, "phase": True},
}

CI_CONFIG = {
    "schemaVersion": 1,
    "setupCommands": [],
    "cache": [],
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--allow-placeholders", action="store_true")
    return parser.parse_args()


def write_json(path: Path, data: dict, *, dry_run: bool, force: bool) -> str:
    if path.exists() and not force:
        return f"skip existing {path}"
    if dry_run:
        return f"would write {path}"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return f"wrote {path}"


def main() -> int:
    args = parse_args()
    root = Path(args.root).resolve()
    if not args.allow_placeholders:
        placeholder_errors = [error for error in check_docs(root, configured=True) if "placeholder" in error]
        if placeholder_errors:
            print("Unresolved placeholders found. Use --allow-placeholders for skeleton setup:")
            for error in placeholder_errors:
                print(f"- {error}")
            return 1

    outputs = [
        write_json(
            root / ".harness/validation.json",
            VALIDATION_CONFIG,
            dry_run=args.dry_run,
            force=args.force,
        ),
        write_json(
            root / ".harness/ci.json",
            CI_CONFIG,
            dry_run=args.dry_run,
            force=args.force,
        ),
    ]
    for output in outputs:
        print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
