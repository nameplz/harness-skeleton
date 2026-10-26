#!/usr/bin/env python3
"""Provide small Codex hook guardrails and configured project validation."""

from __future__ import annotations

import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
HARNESS_SCRIPT = PROJECT_ROOT / "scripts/harness.py"
CHECK_TIMEOUT_SECONDS = {"quick": 180, "full": 930}
DANGEROUS_PATTERNS = (
    (re.compile(r"\brm\s+-[^\n;]*r[^\n;]*f\b"), "recursive force deletion"),
    (re.compile(r"\bgit\s+push\b[^\n;]*\s--force(?:-with-lease)?\b"), "forced git push"),
    (re.compile(r"\bgit\s+reset\s+--hard\b"), "hard git reset"),
    (re.compile(r"\bDROP\s+TABLE\b", re.IGNORECASE), "DROP TABLE statement"),
)
GIT_VALUE_OPTIONS = frozenset({"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env", "--super-prefix", "--exec-path"})
GIT_FLAG_OPTIONS = frozenset({"--no-pager", "--paginate", "-p", "-P", "--bare",
                              "--no-replace-objects", "--no-optional-locks", "--no-lazy-fetch",
                              "--literal-pathspecs", "--glob-pathspecs", "--noglob-pathspecs", "--icase-pathspecs"})

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.harness import sanitize_log  # noqa: E402
from scripts.command_runner import _is_git_executable  # noqa: E402


def extract_command(payload: dict[str, Any]) -> str:
    tool_input = payload.get("tool_input") or payload.get("input") or {}
    if isinstance(tool_input, dict):
        command = tool_input.get("command") or tool_input.get("cmd") or ""
        return command if isinstance(command, str) else ""
    return ""


def _dangerous_reason(command: str) -> str | None:
    for pattern, reason in DANGEROUS_PATTERNS:
        if pattern.search(command):
            return reason
    return None


def _contains_git_commit(command: str) -> bool:
    # shortcut: recognize simple command lists, not shell functions/substitutions; native permissions and CI enforce safety.
    lexer = shlex.shlex(command, posix=False, punctuation_chars=";&|\n")
    lexer.whitespace = " \t\r"
    lexer.whitespace_split = True
    segments: list[list[str]] = [[]]
    try:
        for token in lexer:
            if token and all(char in ";&|\n" for char in token):
                segments.append([])
            else:
                parts = shlex.split(token)
                if len(parts) != 1:
                    return False
                segments[-1].append(parts[0])
    except ValueError:
        return False
    return any(_is_git_commit(tokens) for tokens in segments)


def _is_git_commit(tokens: list[str]) -> bool:
    if not tokens or not _is_git_executable(tokens[0]):
        return False
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token in GIT_VALUE_OPTIONS:
            index += 2
        elif token in GIT_FLAG_OPTIONS or token.startswith(("-C", "-c")) or (
            "=" in token and token.split("=", 1)[0] in GIT_VALUE_OPTIONS
        ):
            index += 1
        else:
            return token == "commit"
    return False


def _hook_response(event: str, reason: str) -> dict[str, Any]:
    safe_reason = sanitize_log(reason)
    if event == "PreToolUse":
        return {
            "hookSpecificOutput": {
                "hookEventName": event,
                "permissionDecision": "deny",
                "permissionDecisionReason": safe_reason,
            }
        }
    if event == "PermissionRequest":
        return {
            "hookSpecificOutput": {
                "hookEventName": event,
                "decision": {"behavior": "deny", "message": safe_reason},
            }
        }
    return {"decision": "block", "reason": safe_reason}


def _run_check(root: Path, profile: str) -> tuple[bool, str]:
    config_path = root / ".harness/config.toml"
    if not (config_path.exists() or config_path.is_symlink()):
        return True, ""
    try:
        completed = subprocess.run(
            [sys.executable, str(HARNESS_SCRIPT), "check", f"--{profile}", "--root", str(root)],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=CHECK_TIMEOUT_SECONDS[profile],
            shell=False,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        detail = "\n".join(
            value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value
            for value in (exc.stdout, exc.stderr)
            if value
        )
        return False, sanitize_log(detail + f"\n{profile} validation timed out")
    except OSError:
        return False, f"{profile} validation could not be started"

    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return False, sanitize_log(completed.stdout + completed.stderr) or f"{profile} validation returned invalid output"
    if not isinstance(report, dict):
        return False, f"{profile} validation returned invalid output"
    if report.get("status") == "unconfigured":
        return True, ""
    if completed.returncode == 0 and report.get("ok") is True:
        return True, ""
    if isinstance(report.get("checks"), list):
        details = [
            f"{item.get('name', 'check')} failed with exit code {item.get('returncode', 'unknown')}:\n"
            f"{item.get('output', '')}"
            for item in report["checks"]
            if isinstance(item, dict) and item.get("passed") is not True
        ]
        if details:
            return False, sanitize_log("\n\n".join(details))
    return False, sanitize_log(str(report.get("error") or f"{profile} validation failed"))


def _commit_risk_tier(root: Path) -> str:
    try:
        completed = subprocess.run(
            [sys.executable, str(HARNESS_SCRIPT), "risk", "--root", str(root)],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            shell=False,
            check=False,
        )
        report = json.loads(completed.stdout)
        if completed.returncode == 0 and isinstance(report, dict):
            tier = report.get("level")
            if isinstance(tier, str) and tier in {"T0", "T1", "T2", "T3"}:
                return tier
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        pass
    return "unknown"


def _resolve_project_root(raw_root: str) -> Path:
    start = Path(raw_root).resolve(strict=True)
    if not start.is_dir():
        raise OSError("not a directory")
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=start,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
            shell=False,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return start
    if completed.returncode != 0:
        return start
    repository = Path(completed.stdout.strip()).resolve(strict=True)
    try:
        start.relative_to(repository)
    except ValueError as exc:
        raise OSError("Git root does not contain the hook working directory") from exc
    return repository


def handle_event(payload: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    event = payload.get("hook_event_name")
    command = extract_command(payload)
    if event in {"PreToolUse", "PermissionRequest"}:
        if payload.get("tool_name") != "Bash":
            return None
        dangerous = _dangerous_reason(command)
        if dangerous:
            return _hook_response(event, f"Blocked dangerous Bash command: {dangerous}.")
        if event != "PreToolUse" or not _contains_git_commit(command):
            return None

    elif event == "Stop":
        if payload.get("stop_hook_active"):
            return None
    else:
        return None

    raw_root = payload.get("cwd") or "."
    if not isinstance(raw_root, str):
        return _hook_response(event, "Project root is invalid; validation was not run.")
    try:
        root = _resolve_project_root(raw_root)
    except (OSError, RuntimeError):
        return _hook_response(event, "Project root is unavailable; validation was not run.")

    tier = _commit_risk_tier(root) if event == "PreToolUse" else None
    profile = "full" if tier in {"T2", "T3", "unknown"} else "quick"
    passed, detail = _run_check(root, profile)
    if passed:
        return None
    risk_detail = f" (tier {tier})" if tier is not None else ""
    reason = f"Configured {profile} validation{risk_detail} failed. Fix the failures before committing or finishing."
    if detail:
        reason += "\n\n" + detail
    return _hook_response(event, reason)


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, OSError):
        print("invalid hook payload: expected a JSON object", file=sys.stderr)
        return 1
    if not isinstance(payload, dict):
        print("invalid hook payload: expected a JSON object", file=sys.stderr)
        return 1
    response = handle_event(payload)
    if response is not None:
        print(json.dumps(response, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
