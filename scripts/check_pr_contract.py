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
ISSUE_RE = re.compile(
    r"\b(?:closes|fixes|resolves|refs)\s+#[1-9][0-9]*\b"
    r"|https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/issues/[1-9][0-9]*\b",
    re.IGNORECASE,
)
MARKUP_SENTINEL = "\u2060"


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
    body = _visible_markdown(body)
    for section in REQUIRED_SECTIONS:
        if not has_section(body, section):
            errors.append(f"PR body missing required section or content: {section}")
    if not ISSUE_RE.search(body):
        errors.append("PR body must reference a task issue with Closes/Refs #<number> or a GitHub issue URL")
    return errors


def has_section(body: str, section: str) -> bool:
    headings = list(re.finditer(r"(?m)^ {0,3}(#{1,6})[ \t]+(.+?)[ \t]*#*[ \t]*$", body))
    for index, heading in enumerate(headings):
        if heading.group(2) != section:
            continue
        end = next((other.start() for other in headings[index + 1:]
                    if len(other.group(1)) <= len(heading.group(1))), len(body))
        content = re.sub(r"(?m)^ {0,3}#{1,6}[ \t]+.*$", "", body[heading.end():end])
        if content.replace(MARKUP_SENTINEL, "").strip():
            return True
    return False


def _visible_markdown(body: str) -> str:
    # Preserve token/line boundaries so removing code/comments cannot manufacture headings.
    def mask(match: re.Match[str]) -> str:
        return "\n".join(MARKUP_SENTINEL for _ in range(match.group().count("\n") + 1))

    body = re.sub(r"<!--.*?(?:-->|\Z)", mask, body, flags=re.DOTALL)
    visible: list[str] = []
    fence: str | None = None
    for line in body.splitlines():
        marker = re.match(r"^ {0,3}(`{3,}|~{3,})(.*)$", line)
        if fence is None and marker:
            fence = marker.group(1)
        elif fence is not None:
            if marker and marker.group(1)[0] == fence[0] and len(marker.group(1)) >= len(fence) and not marker.group(2).strip():
                fence = None
        elif not line.startswith(("    ", "\t")):
            visible.append(line)
    return re.sub(r"(`+).*?\1", mask, "\n".join(visible), flags=re.DOTALL)


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
