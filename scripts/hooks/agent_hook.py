#!/usr/bin/env python3
"""Provide small agent hook guardrails and configured project validation."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
HARNESS_SCRIPT = PROJECT_ROOT / "scripts/harness.py"
CHECK_TIMEOUT_SECONDS = {"quick": 180}
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scripts.command_runner import _git_subcommand_index  # noqa: E402
from scripts.harness import _harness_command, sanitize_log  # noqa: E402
from scripts.harness_gate import evidence_matches  # noqa: E402


def extract_command(payload: dict[str, Any]) -> str:
    tool_input = payload.get("tool_input") or payload.get("input") or {}
    if isinstance(tool_input, dict):
        command = tool_input.get("command") or tool_input.get("cmd") or ""
        return command if isinstance(command, str) else ""
    return ""


def _shell_commands(command: str) -> list[list[str]]:
    # Keep quotes until command boundaries are found, then parse each argv.
    lexer = shlex.shlex(command, posix=False, punctuation_chars=";&|\n")
    lexer.whitespace = " \t\r"
    lexer.whitespace_split = True
    commands: list[list[str]] = []
    words: list[str] = []
    try:
        for token in lexer:
            if all(char in ";&|\n" for char in token):
                try:
                    argv = shlex.split(" ".join(words))
                except ValueError:
                    words.append(token)
                    continue
                if argv:
                    commands.append(argv)
                words = []
            else:
                words.append(token)
        if words:
            commands.append(shlex.split(" ".join(words)))
    except ValueError:
        # A malformed tail must not erase earlier commands or suppress feedback.
        fragment = " ".join([*words, lexer.token]).split()
        if fragment:
            commands.append(fragment)
    return commands


def _options(arguments: list[str], value_options: set[str]) -> tuple[set[str], list[str]]:
    flags: set[str] = set()
    operands: list[str] = []
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        index += 1
        if argument == "--":
            operands.extend(arguments[index:])
            break
        if argument.startswith("--"):
            option, separator, _ = argument.partition("=")
            if option in value_options:
                if not separator:
                    index += 1
            else:
                flags.add(option)
        elif argument.startswith("-") and argument != "-":
            for position, char in enumerate(argument[1:], start=1):
                option = "-" + char
                if option in value_options:
                    if position == len(argument) - 1:
                        index += 1
                    break
                flags.add(option)
        else:
            operands.append(argument)
    return flags, operands


def _dangerous_reason(command: str) -> str | None:
    prefix_value_options = {
        "sudo": {"-u", "--user", "-g", "--group", "-h", "--host", "-p", "--prompt", "-C", "--close-from", "-T", "--command-timeout", "-R", "--chroot", "-D", "--chdir", "-r", "--role", "-t", "--type"},
        "doas": {"-u", "-C"},
        "env": {"-u", "--unset", "-C", "--chdir", "-S", "--split-string"},
        "command": set(), "exec": {"-a"}, "nohup": set(),
        "time": {"-f", "--format", "-o", "--output"},
        "nice": {"-n", "--adjustment"},
        "xargs": {"-a", "--arg-file", "-d", "--delimiter", "-E", "-e", "--eof", "-I", "-i", "--replace", "-L", "-l", "--max-lines", "-n", "--max-args", "-P", "--max-procs", "-s", "--max-chars", "--process-slot-var"},
    }
    for argv in _shell_commands(command):
        index = 0
        while index < len(argv):
            if re.match(r"[a-zA-Z_][a-zA-Z0-9_]*=", argv[index]):
                index += 1
                continue
            prefix = Path(argv[index]).name
            if prefix not in prefix_value_options:
                break
            value_options = prefix_value_options[prefix]
            index += 1
            while index < len(argv) and argv[index].startswith("-"):
                option = argv[index]
                index += 1
                if option == "--":
                    break
                if option.startswith("--"):
                    name, separator, _ = option.partition("=")
                    if name in value_options and not separator:
                        index += 1
                else:
                    for position, char in enumerate(option[1:], start=1):
                        if "-" + char in value_options:
                            if position == len(option) - 1:
                                index += 1
                            break
        argv = argv[index:]
        if not argv:
            continue
        executable = Path(argv[0]).name
        if executable in {"sh", "bash", "zsh", "dash", "ksh", "fish", "pwsh", "powershell", "cmd", "cmd.exe"}:
            continue
        if executable == "rm":
            flags, _ = _options(argv[1:], set())
            if flags & {"-r", "-R", "--recursive"} and flags & {"-f", "--force"}:
                return "recursive force deletion"
        if executable == "git":
            arguments = argv[1:]
            subcommand_index = _git_subcommand_index(arguments)
            globals_ = arguments if subcommand_index is None else arguments[:subcommand_index]
            for index, argument in enumerate(globals_):
                if argument == "-c" and index + 1 < len(globals_):
                    setting = globals_[index + 1]
                elif argument.startswith("-c"):
                    setting = argument[2:]
                else:
                    continue
                if setting.split("=", 1)[0].lower() == "core.hookspath":
                    return "commit gate bypass via core.hooksPath"
            if subcommand_index is None:
                continue
            subcommand = arguments[subcommand_index]
            arguments = arguments[subcommand_index + 1:]
            if subcommand == "push":
                flags, operands = _options(arguments, {"-o", "--push-option", "--repo", "--receive-pack", "--exec"})
                if flags & {"-f", "--force", "--force-with-lease"} or any(value.startswith("+") for value in operands):
                    return "forced git push"
            elif subcommand == "commit":
                flags, _ = _options(arguments, {"-m", "--message", "-F", "--file", "-C", "--reuse-message", "-c", "--reedit-message",
                                                 "--author", "--date", "--cleanup", "-t", "--template", "--trailer", "--pathspec-from-file"})
                if flags & {"-n", "--no-verify"}:
                    return "commit gate bypass via --no-verify"
            elif subcommand == "clean":
                flags, _ = _options(arguments, {"-e", "--exclude"})
                if flags & {"-f", "--force"}:
                    return "forced git clean"
            elif subcommand == "config":
                flags, operands = _options(arguments, {"-f", "--file", "--blob", "--type"})
                if operands and operands[0] in {"set", "unset"}:
                    flags.add("--" + operands.pop(0))
                if (operands and operands[0].lower() == "core.hookspath"
                        and (len(operands) > 1 or flags & {"--unset", "--unset-all", "--set"})
                        and not flags & {"--get", "--get-all", "--get-regexp", "--get-urlmatch"}):
                    return "commit gate bypass via core.hooksPath"
            elif subcommand == "reset" and "--hard" in arguments:
                return "hard git reset"
        if re.search(r"\bDROP\s+TABLE\b", " ".join(argv), re.IGNORECASE):
            return "DROP TABLE statement"
    return None


def _hook_response(event: str, reason: str, action: str) -> dict[str, Any]:
    safe_reason = sanitize_log(reason + "\nNext: " + action)
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
            return _hook_response(event, f"Blocked dangerous Bash command: {dangerous}.", "Use a command without the blocked destructive operation")
        return None

    elif event == "Stop":
        if payload.get("stop_hook_active"):
            return None
    else:
        return None

    raw_root = os.environ.get("CLAUDE_PROJECT_DIR") or payload.get("cwd") or "."
    if not isinstance(raw_root, str):
        return _hook_response(event, "Project root is invalid; validation was not run.", "Set cwd or CLAUDE_PROJECT_DIR to an existing project directory")
    try:
        root = (Path(raw_root).resolve(strict=True) if os.environ.get("CLAUDE_PROJECT_DIR")
                else _resolve_project_root(raw_root))
        if not root.is_dir():
            raise OSError("not a directory")
    except (OSError, RuntimeError):
        return _hook_response(event, "Project root is unavailable; validation was not run.", "Set cwd or CLAUDE_PROJECT_DIR to an accessible project directory")

    if evidence_matches(root, "quick"):
        return None
    passed, detail = _run_check(root, "quick")
    if passed:
        return None
    reason = "Configured quick validation failed. Fix the failures before finishing."
    if detail:
        reason += "\n\n" + detail
    return _hook_response(event, reason, _harness_command(root, "check", "--quick"))


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
