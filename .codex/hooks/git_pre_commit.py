#!/usr/bin/env python3
"""Git pre-commit entrypoint for project validation."""

from __future__ import annotations

import sys
from pathlib import Path

HOOK_DIR = Path(__file__).resolve().parent
if str(HOOK_DIR) not in sys.path:
    sys.path.insert(0, str(HOOK_DIR))

import project_validation


def main() -> int:
    reason = project_validation.validation_failure(Path.cwd())
    if reason is None:
        return 0

    print(f"Pre-commit validation failed.\n\n{reason}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
