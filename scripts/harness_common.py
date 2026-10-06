"""Shared deterministic errors and log redaction for the Harness CLI."""

from __future__ import annotations

import re


UNQUOTED_MULTILINE_SECRET_RE = re.compile(
    r'''(?im)(["']?\b(?:api[_-]?key|access[_-]?key|private[_-]?key|authorization|password|secret|token|[A-Z0-9_]*(?:API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|AUTHORIZATION|PASSWORD|SECRET|TOKEN)[A-Z0-9_]*)\b["']?[ \t]*[:=][ \t]*)(?!["'])([^\r\n]*(?:\r?\n(?![ \t]*\r?$)[^\r\n]*)*)'''
)
LOG_PATTERNS = (
    re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(
        r'''(?i)([\"']?\b(?:api[_-]?key|access[_-]?key|private[_-]?key|authorization|password|secret|token)\b[\"']?\s*[:=]\s*)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\r\n]+)'''
    ),
    re.compile(
        r'''(?i)([\"']?\b[A-Z0-9_]*(?:API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|AUTHORIZATION|PASSWORD|SECRET|TOKEN)[A-Z0-9_]*[\"']?\s*[:=]\s*)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\r\n]+)'''
    ),
    re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://)[^/\s@]+@"),
    re.compile(r"\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
    re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
    ),
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
)


class HarnessError(ValueError):
    """Raised when Harness input or environment state is invalid."""


def sanitize_log(value: str, *, max_length: int = 4000) -> str:
    if not isinstance(value, str):
        raise HarnessError("log output must be text")
    if not isinstance(max_length, int) or isinstance(max_length, bool) or max_length < 1:
        raise HarnessError("log limit must be a positive integer")
    redacted = UNQUOTED_MULTILINE_SECRET_RE.sub(r"\1[REDACTED]", value)
    replacements = (
        "[REDACTED_AUTHORIZATION]",
        r"\1[REDACTED]",
        r"\1[REDACTED]",
        r"\1[REDACTED]@",
        "[REDACTED_JWT]",
        "[REDACTED_PRIVATE_KEY]",
        "[REDACTED_EMAIL]",
    )
    for pattern, replacement in zip(LOG_PATTERNS, replacements):
        redacted = pattern.sub(replacement, redacted)
    return redacted if len(redacted) <= max_length else redacted[: max_length - 1] + "…"
