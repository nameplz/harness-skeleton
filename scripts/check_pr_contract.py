#!/usr/bin/env python3
"""Validate pull request title and body from GITHUB_EVENT_PATH JSON."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


ALLOWED_TYPES = ("feat", "fix", "refactor", "docs", "test", "chore", "perf", "ci")
TITLE_RE = re.compile(rf"^({'|'.join(ALLOWED_TYPES)}): .+$")
REQUIRED_SECTIONS = ("작업 목적", "변경 범위", "테스트 내용", "검증 결과", "영향 범위", "롤백 방법")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event", required=True)
    return parser.parse_args()


def check_event_file(event_path: Path) -> list[str]:
    event = json.loads(event_path.read_text(encoding="utf-8"))
    pull_request = event.get("pull_request")
    if not isinstance(pull_request, dict):
        return []

    title = pull_request.get("title")
    body = pull_request.get("body") or ""
    errors: list[str] = []
    if not isinstance(title, str) or not TITLE_RE.match(title):
        errors.append(
            "PR title must match '<type>: <구체적인 변경 목적>'; "
            f"allowed types: {', '.join(ALLOWED_TYPES)}"
        )
    if not isinstance(body, str):
        body = ""
    for section in REQUIRED_SECTIONS:
        if not has_section(body, section):
            errors.append(f"PR body missing required section: {section}")
    return errors


def has_section(body: str, section: str) -> bool:
    pattern = re.compile(rf"^\s*#+\s*{re.escape(section)}\s*$", re.MULTILINE)
    return bool(pattern.search(body))


def main() -> int:
    args = parse_args()
    errors = check_event_file(Path(args.event))
    if not errors:
        print("PR contract passed")
        return 0
    print("PR contract failed:")
    for error in errors:
        print(f"- {error}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
