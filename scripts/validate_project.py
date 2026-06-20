#!/usr/bin/env python3
"""Validate a Harness target project."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from harness_validation import result_to_json, validate_project


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--config")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    result = validate_project(
        root=Path(args.root),
        strict=args.strict,
        config_path=Path(args.config) if args.config else None,
        run_commands=True,
    )
    if args.json:
        print(json.dumps(result_to_json(result), ensure_ascii=False, indent=2))
    elif result.ok:
        print("Harness validation passed")
    else:
        print("Harness validation failed:")
        for error in result.errors:
            print(f"- {error}")
    return 0 if result.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
