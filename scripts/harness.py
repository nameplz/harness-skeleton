#!/usr/bin/env python3
"""Deterministic Harness commands used by Codex and project validation."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import re
import shlex
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path
import tomllib
from typing import Any

try:
    from .command_runner import _git_subcommand_index, _is_git_executable, run_bounded_command
    from .harness_common import HarnessError, sanitize_log
    from .harness_evidence import capture_workspace
    from .harness_risk import (
        _git_output,
        _git_root,
        inspect_git_risk,
        _validate_pattern_list,
    )
except ImportError:  # Direct script invocation from the scripts directory.
    # Isolated mode omits the script directory from sys.path; restore only the
    # directory containing this trusted script, never the candidate workspace.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from command_runner import _git_subcommand_index, _is_git_executable, run_bounded_command
    from harness_common import HarnessError, sanitize_log
    from harness_evidence import capture_workspace
    from harness_risk import (
        _git_output,
        _git_root,
        inspect_git_risk,
        _validate_pattern_list,
    )

MAX_CONFIG_BYTES = 64 * 1024
MAX_COMMAND_COUNT = 40
MAX_COMMAND_ARGUMENTS = 128
CHECK_TIMEOUT_SECONDS = 600
CHECK_QUICK_TIMEOUT_SECONDS = 120
CHECK_TOTAL_TIMEOUT_SECONDS = 900
MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024
UNSAFE_COMMAND_TOKENS = {
    "*": frozenset("deploy migrate seed login publish".split()),
    "npm": frozenset("install i ci add publish login".split()),
    "pnpm": frozenset("install i ci add publish login".split()),
    "yarn": frozenset("install i ci add publish login".split()),
    "pip": frozenset({"install", "uninstall"}),
    "pip3": frozenset({"install", "uninstall"}),
    "uv": frozenset("add install publish remove".split()),
    "poetry": frozenset("add install publish remove".split()),
    "cargo": frozenset("add install publish remove".split()),
}
SHELL_EXECUTABLES = frozenset({"sh", "bash", "zsh", "dash", "fish", "pwsh", "powershell", "cmd", "cmd.exe"})
FILE_URI_RE = re.compile(r"^file:", re.IGNORECASE)
URL_RE = re.compile(r"^(?![a-z]:[/\\])[a-z][a-z0-9.+-]*://", re.IGNORECASE)
PATH_BEARING_SHORT_OPTIONS = ("-I", "-r")
UNITTEST_RUN_RE = re.compile(r"(?m)^Ran ([1-9][0-9]*) tests? in [0-9]+(?:\.[0-9]+)?s$")
UNITTEST_OK_RE = re.compile(r"(?m)^OK(?: \([^\n]+\))?$")


@dataclass(frozen=True)
class HarnessConfig:
    quick: tuple[tuple[str, ...], ...]
    full: tuple[tuple[str, ...], ...]
    security_paths: tuple[str, ...]
    security_keywords: tuple[str, ...]
    security_hint_keywords: tuple[str, ...]
    config_sha256: str


def load_config(root: Path, *, config_root: Path | None = None) -> HarnessConfig:
    """Load and validate the v2 project check and risk configuration."""

    workspace = _resolve_workspace(root)
    config_workspace = workspace if config_root is None else _resolve_workspace(config_root)
    config_path = config_workspace / ".harness/config.toml"
    try:
        resolved_config = config_path.resolve(strict=True)
        resolved_config.relative_to(config_workspace)
        if not resolved_config.is_file():
            raise HarnessError("Harness config must be a regular file")
        with resolved_config.open("rb") as stream:
            raw_bytes = stream.read(MAX_CONFIG_BYTES + 1)
        if len(raw_bytes) > MAX_CONFIG_BYTES:
            raise HarnessError("Harness config exceeds the size limit")
        raw = raw_bytes.decode("utf-8")
    except HarnessError:
        raise
    except (OSError, UnicodeError, ValueError) as exc:
        raise HarnessError("Harness config is unavailable or outside the workspace") from exc

    try:
        data = tomllib.loads(raw)
    except tomllib.TOMLDecodeError as exc:
        raise HarnessError("Harness config is not valid TOML") from exc
    if not isinstance(data, dict) or set(data) - {"schema", "checks", "risk"}:
        raise HarnessError("Harness config contains unsupported top-level fields")
    if data.get("schema") != 2 or isinstance(data.get("schema"), bool):
        raise HarnessError("Harness config schema must be 2")

    checks = data.get("checks")
    if not isinstance(checks, dict) or set(checks) != {"quick", "full"}:
        raise HarnessError("Harness config checks must define quick and full profiles")
    quick = _validate_command_list(checks["quick"], "checks.quick", workspace)
    full = _validate_command_list(checks["full"], "checks.full", workspace)
    risk = data.get("risk", {})
    if not isinstance(risk, dict) or set(risk) - {
        "security_paths", "security_keywords", "security_hint_keywords"
    }:
        raise HarnessError("Harness config risk section contains unsupported fields")
    security_paths = _validate_pattern_list(risk.get("security_paths", []), "security_paths")
    security_keywords = _validate_keyword_list(risk.get("security_keywords", []), "security_keywords")
    security_hint_keywords = _validate_keyword_list(
        risk.get("security_hint_keywords", []), "security_hint_keywords"
    )
    return HarnessConfig(quick, full, security_paths, security_keywords, security_hint_keywords,
                         hashlib.sha256(raw_bytes).hexdigest())


def _resolve_workspace(root: Path) -> Path:
    try:
        workspace = root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise HarnessError("workspace root is unavailable") from exc
    if not workspace.is_dir():
        raise HarnessError("workspace root must be a directory")
    return workspace


def _validate_command_list(raw: Any, field: str, workspace: Path) -> tuple[tuple[str, ...], ...]:
    if not isinstance(raw, list) or len(raw) > MAX_COMMAND_COUNT:
        raise HarnessError(f"{field} must be a list of argv commands")
    commands: list[tuple[str, ...]] = []
    for index, command in enumerate(raw):
        if not isinstance(command, list) or not command or len(command) > MAX_COMMAND_ARGUMENTS:
            raise HarnessError(f"{field}[{index}] must be a non-empty argv list")
        if any(
            not isinstance(argument, str)
            or not argument
            or len(argument) > 4096
            or "\x00" in argument
            or any(ord(char) < 32 and char not in "\t\n\r" for char in argument)
            for argument in command
        ):
            raise HarnessError(f"{field}[{index}] contains an invalid argument")
        _validate_command_safety(command, workspace, field, index)
        commands.append(tuple(command))
    return tuple(commands)


def _validate_command_safety(command: Sequence[str], workspace: Path, field: str, index: int) -> None:
    tokens = {
        _normalize_executable(Path(part.replace("\\", "/")).name.casefold())
        for part in command
    }
    invocation = command
    # shortcut: runner option values and leading options can hide commands, upgrade when option parsing is required.
    while invocation:
        program = _normalize_executable(Path(invocation[0].replace("\\", "/")).name.casefold())
        arguments = invocation[1:]
        subcommand_index = next((i for i, arg in enumerate(arguments) if not arg.startswith("-")), None)
        boundary = next((i for i, arg in enumerate(arguments) if arg in {"run", "--"}), len(arguments))
        candidates = [arg.casefold() for arg in arguments[:boundary] if not arg.startswith("-")]
        subcommand = arguments[subcommand_index].casefold() if subcommand_index is not None else ""
        if program == "env":
            raise HarnessError(f"{field}[{index}] cannot override the validation process environment")
        if program in UNSAFE_COMMAND_TOKENS:
            operations = candidates
        else:
            operations = [arguments[0].casefold()] if arguments and not arguments[0].startswith("-") else []
        if (program in UNSAFE_COMMAND_TOKENS["*"]
                or set(operations) & (UNSAFE_COMMAND_TOKENS["*"] | UNSAFE_COMMAND_TOKENS.get(program, frozenset()))):
            raise HarnessError(f"{field}[{index}] contains a forbidden operation")
        if (re.fullmatch(r"(?:python|pypy)(?:\d+(?:\.\d+)*)?", program)
                and "-m" in arguments
                and (subcommand_index is None or arguments.index("-m") < subcommand_index)):
            invocation = arguments[arguments.index("-m") + 1:]
        elif program == "npx" and subcommand_index is not None:
            invocation = arguments[subcommand_index:]
        elif program in {"npm", "uv", "poetry", "pipx"} and boundary < len(arguments) and arguments[boundary] == "run":
            runner_arguments = arguments[boundary + 1:]
            executable_index = next((i for i, arg in enumerate(runner_arguments) if not arg.startswith("-")), None)
            invocation = runner_arguments[executable_index:] if executable_index is not None else ()
        elif program == "uv" and subcommand == "pip":
            invocation = arguments[subcommand_index:]
        else:
            break
    if _is_git_executable(command[0]):
        arguments = command[1:]
        subcommand_index = _git_subcommand_index(arguments)
        if any(
            argument.startswith("-c")
            or argument in {"--config", "--config-env"}
            or argument.startswith(("--config=", "--config-env="))
            for argument in arguments[:subcommand_index]
        ):
            raise HarnessError(f"{field}[{index}] cannot override safe Git configuration")
        if subcommand_index is None or arguments[subcommand_index] not in {
            "status", "diff", "log", "show", "ls-files", "rev-parse", "grep", "describe", "cat-file"
        }:
            raise HarnessError(f"{field}[{index}] must use a read-only Git subcommand")
    if not _is_git_executable(command[0]) and any(_is_git_executable(argument) for argument in command[1:]):
        raise HarnessError(f"{field}[{index}] must invoke Git directly, not through a wrapper")
    if tokens & SHELL_EXECUTABLES and any(
        _is_inline_shell_flag(part, tokens) for part in command[1:]
    ):
        raise HarnessError(f"{field}[{index}] cannot execute inline shell commands")
    if any(_is_inline_code_executable(token) for token in tokens) and any(
        _is_inline_code_flag(part, tokens) for part in command[1:]
    ):
        raise HarnessError(f"{field}[{index}] cannot execute inline code")
    for arg_index, argument in enumerate(command):
        option_path = _short_option_path(command, arg_index)
        value = option_path if option_path is not None else argument
        if option_path is None and not argument.startswith("-") and "=" in argument:
            _, _, assigned_value = argument.partition("=")
            if _looks_like_path(assigned_value, workspace):
                value = assigned_value
        if FILE_URI_RE.match(argument) or FILE_URI_RE.match(value):
            raise HarnessError(f"{field}[{index}] contains a file URI outside the workspace")
        if option_path is None and argument.startswith("-"):
            _, separator, value = argument.partition("=")
            if FILE_URI_RE.match(value):
                raise HarnessError(f"{field}[{index}] contains a file URI outside the workspace")
            if not separator and not argument.startswith("--") and ("/" in argument or "\\" in argument):
                raise HarnessError(f"{field}[{index}] contains an unsupported short-option path")
            if not separator or URL_RE.match(value) or not _looks_like_path(value, workspace):
                continue
        elif option_path is None and (URL_RE.match(argument) or not _looks_like_path(argument, workspace)):
            continue
        normalized = value.replace("\\", "/")
        if any(part == ".." for part in normalized.split("/")):
            raise HarnessError(f"{field}[{index}] contains a path outside the workspace")
        candidate_path = Path(normalized)
        if arg_index == 0 and candidate_path.is_absolute():
            try:
                if candidate_path.resolve(strict=False) == Path(sys.executable).resolve(strict=False):
                    continue
            except (OSError, RuntimeError):
                pass
        if re.match(r"^[A-Za-z]:", normalized):
            raise HarnessError(f"{field}[{index}] contains a path outside the workspace")
        try:
            resolved_path = (workspace / candidate_path).resolve(strict=False)
            resolved_path.relative_to(workspace)
        except (OSError, RuntimeError, ValueError) as exc:
            raise HarnessError(f"{field}[{index}] contains a path outside the workspace") from exc


def _is_inline_shell_flag(argument: str, executables: set[str]) -> bool:
    value = argument.casefold()
    if value in {"-c", "/c", "-command", "-com"}:
        return True
    powershell = bool(executables & {"pwsh", "powershell"})
    if value.startswith("--"):
        option = value.split("=", 1)[0]
        return option in {"--command", "--com"} or powershell and option == "--encodedcommand"
    if value.startswith("/"):
        return value.split("=", 1)[0] == "/c"
    if powershell and value in {"-e", "-en", "-enc", "-encodedcommand"}:
        return True
    return value.startswith("-") and not value.startswith("--") and "c" in value[1:]


def _is_inline_code_executable(executable: str) -> bool:
    name = _normalize_executable(Path(executable.replace("\\", "/")).name.casefold())
    return bool(
        re.fullmatch(r"python(?:\d+(?:\.\d+)*)?", name)
        or re.fullmatch(r"pypy(?:\d+(?:\.\d+)*)?", name)
        or _is_node_executable(name)
        or re.fullmatch(r"ruby(?:\d+(?:\.\d+)*)?", name)
        or re.fullmatch(r"perl(?:\d+(?:\.\d+)*)?", name)
    )


def _is_node_executable(name: str) -> bool:
    return bool(re.fullmatch(r"node(?:js)?(?:\d+(?:\.\d+)*)?", _normalize_executable(name)))


def _short_option_path(command: Sequence[str], index: int) -> str | None:
    argument = command[index]
    for option in PATH_BEARING_SHORT_OPTIONS:
        if argument == option and index + 1 < len(command):
            return command[index + 1]
        if argument.startswith(option) and len(argument) > len(option):
            return argument[len(option):].removeprefix("=")
    _, separator, value = argument.partition("=")
    if separator and argument.startswith("-") and not argument.startswith("--"):
        return value
    return None


def _normalize_executable(name: str) -> str:
    return name[:-4] if name.endswith(".exe") else name


def _is_inline_code_flag(argument: str, executables: set[str]) -> bool:
    value = argument.casefold()
    if value.startswith("--"):
        option = value.split("=", 1)[0]
        return option in {"--eval", "--execute"} or option == "--print" and any(
            _is_node_executable(executable) for executable in executables
        )
    if value in {"-c", "-e"} or value.startswith(("-c", "-e")) and len(value) > 2:
        return True
    return (
        value == "-p" or value.startswith("-p") and len(value) > 2
    ) and any(_is_node_executable(executable) for executable in executables)


def _looks_like_path(value: str, workspace: Path) -> bool:
    normalized = value.replace("\\", "/")
    if re.match(r"^[A-Za-z]:", normalized) or normalized.startswith("//"):
        return True
    candidate = Path(normalized)
    workspace_candidate = candidate if candidate.is_absolute() else workspace / candidate
    try:
        if workspace_candidate.exists() or workspace_candidate.is_symlink():
            return True
    except OSError:
        return True
    return (
        value in {".", ".."}
        or "/" in normalized
        or value.startswith((".", "~"))
        or candidate.suffix.casefold()
        in {".py", ".sh", ".js", ".mjs", ".cjs", ".json", ".toml"}
    )


def _validate_keyword_list(values: Any, name: str) -> tuple[str, ...]:
    if not isinstance(values, list):
        raise HarnessError(f"{name} must be a list of strings")
    keywords: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value.strip() or len(value) > 256:
            raise HarnessError(f"{name} entries must be non-empty strings")
        keyword = value.strip()
        if any(ord(char) < 32 or ord(char) == 127 for char in keyword):
            raise HarnessError(f"{name} entries cannot contain control characters")
        if keyword.casefold() not in {item.casefold() for item in keywords}:
            keywords.append(keyword)
    return tuple(keywords)


VALIDATION_SETUP = "define checks.quick/full; see .agents/skills/harness/SKILL.md (Validation profile setup)"


def _harness_command(root: Path, command: str, *flags: str) -> str:
    return shlex.join([sys.executable, str(Path(__file__).resolve()), command, "--root", str(root), *flags])


def run_checks(root: Path, profile: str, *, config_root: Path | None = None) -> dict[str, Any]:
    try:
        from .harness_gate import save_check
    except ImportError:
        from harness_gate import save_check
    if profile not in {"quick", "full"}:
        raise HarnessError("check profile must be quick or full")
    workspace = _resolve_workspace(root)
    config_workspace = workspace if config_root is None else _resolve_workspace(config_root)
    config_path = config_workspace / ".harness/config.toml"
    if not config_path.exists() and not config_path.is_symlink():
        return {
            "ok": False,
            "status": "unconfigured",
            "next_action": VALIDATION_SETUP,
            "profile": profile,
            "checks": [],
            "error": "unconfigured: .harness/config.toml is missing; define checks.quick/full; see .agents/skills/harness/SKILL.md (Validation profile setup)",
        }
    config = load_config(workspace, config_root=config_root)
    evidence = {**capture_workspace(workspace), "config_sha256": config.config_sha256}
    commands = config.quick if profile == "quick" else config.full
    if not commands:
        report = {
            "ok": False,
            "status": "unconfigured",
            "next_action": VALIDATION_SETUP,
            "profile": profile,
            "checks": [],
            "evidence": evidence,
            "error": f"unconfigured: checks.{profile} has no validation commands; define checks.quick/full; see .agents/skills/harness/SKILL.md (Validation profile setup)",
        }
        save_check(workspace, report)
        return report
    if evidence.get("status") == "error":
        checks = _unstarted_results(commands, 1, reason="identity_error")
        return {"ok": False, "profile": profile, "checks": checks, "evidence": evidence,
                "evidence_after": None, "evidence_unchanged": False,
                "next_action": "Restore Git workspace access, then run " + _harness_command(workspace, "check", f"--{profile}")}
    results: list[dict[str, Any]] = []
    total_timeout = CHECK_QUICK_TIMEOUT_SECONDS if profile == "quick" else CHECK_TOTAL_TIMEOUT_SECONDS
    deadline = time.monotonic() + total_timeout
    for index, command in enumerate(commands, start=1):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            results.extend(_unstarted_results(commands[index - 1 :], index))
            break
        started_at = time.perf_counter()
        started = True
        timed_out = output_limited = False
        failure_reason: str | None = None
        try:
            trusted_command = _trusted_check_command(command, config_root=config_root)
            completed = run_bounded_command(
                trusted_command,
                cwd=workspace,
                timeout_seconds=min(CHECK_TIMEOUT_SECONDS, remaining),
                max_output_bytes=MAX_COMMAND_OUTPUT_BYTES,
            )
            returncode = completed.returncode
            started = getattr(completed, "started", True)
            output = completed.output
            timed_out, output_limited = completed.timed_out, completed.output_limited
            if completed.output_limited:
                failure_reason = "output_limit"
                returncode = returncode or 125
                output = "check command output exceeded capture limit\n" + output
            elif completed.timed_out:
                failure_reason = "timeout"
                returncode = returncode or 124
                output = "check command timed out or left child processes running\n" + output
            elif returncode == 0 and _is_unittest_command(trusted_command) and not _unittest_completed(output):
                returncode = 125
                failure_reason = "incomplete_unittest"
                output = "unit test process ended without a successful unittest summary\n" + output
        except OSError:
            started = False
            failure_reason = "start_failed"
            returncode = 127
            output = "check command could not be started"
        results.append(
            {
                "name": f"check-{index}",
                "command": _safe_command(command),
                "returncode": returncode,
                "passed": returncode == 0,
                "output": sanitize_log(output),
                "duration_ms": round((time.perf_counter() - started_at) * 1000, 3),
                "started": started,
                "timed_out": timed_out,
                "output_limited": output_limited,
                "failure_reason": failure_reason or ("exit_status" if returncode else None),
            }
        )
    try:
        final_config_sha256 = load_config(workspace, config_root=config_root).config_sha256
    except HarnessError:
        final_config_sha256 = None
    evidence_after = {**capture_workspace(workspace), "config_sha256": final_config_sha256}
    if evidence["config_sha256"] != final_config_sha256 or evidence_after.get("status") == "error":
        unchanged: bool | None = False
    elif evidence.get("status") != evidence_after.get("status"):
        unchanged = False
    elif evidence["diff_sha256"] is None or evidence_after["diff_sha256"] is None:
        unchanged = None
    else:
        unchanged = evidence == evidence_after
    ok = all(item["passed"] for item in results) and unchanged is not False
    report = {"ok": ok, "status": "configured" if ok else "failure",
            "profile": profile, "checks": results, "evidence": evidence,
            "evidence_after": evidence_after, "evidence_unchanged": unchanged}
    if not ok:
        retry_flags = [f"--{profile}"]
        if config_root is not None:
            retry_flags.extend(["--config-root", str(config_root)])
        action = ("Finish workspace changes, then run " if unchanged is False else "Fix the failed checks, then run ") + _harness_command(workspace, "check", *retry_flags)
        report["next_action"] = action
        for item in results:
            if not item["passed"]:
                item["next_action"] = action
    save_check(workspace, report)
    return report


def _is_unittest_command(command: Sequence[str]) -> bool:
    return any(
        command[index] == "-m" and command[index + 1] == "unittest"
        for index in range(len(command) - 1)
    )


def _trusted_check_command(command: Sequence[str], *, config_root: Path | None = None) -> list[str]:
    """Isolate Python validation modules and keep the built-in doctor trusted."""

    if not command or not _is_python_executable(command[0]):
        return list(command)
    tail = list(command[1:])
    module_index = next(
        (index for index in range(len(tail) - 1) if tail[index] == "-m"),
        None,
    )
    if module_index is not None and tail[module_index + 1] in {"unittest", "compileall"}:
        if "-I" not in tail[:module_index]:
            tail.insert(0, "-I")
        executable = command[0] if "/" in command[0] or "\\" in command[0] else sys.executable
        return [executable, *tail]
    if len(tail) >= 2 and tail[0].replace("\\", "/") == "scripts/harness.py" and tail[1] == "doctor":
        doctor_args = list(tail[1:])
        if config_root is not None:
            doctor_args.extend(("--config-root", str(_resolve_workspace(config_root))))
        return [sys.executable, "-I", str(Path(__file__).resolve()), *doctor_args]
    return list(command)


def _is_python_executable(value: str) -> bool:
    executable = Path(value.replace("\\", "/")).name.casefold()
    return re.fullmatch(r"(?:python(?:\d+(?:\.\d+)*)?|py)(?:\.exe)?", executable) is not None


def _unittest_completed(output: str) -> bool:
    summary = UNITTEST_RUN_RE.search(output)
    success = UNITTEST_OK_RE.search(output)
    return summary is not None and success is not None and success.start() > summary.end()


def _unstarted_results(commands: Sequence[Sequence[str]], first_index: int, *, reason: str = "aggregate_timeout") -> list[dict[str, Any]]:
    return [
        {"name": f"check-{index}", "command": _safe_command(command), "returncode": 125 if reason == "identity_error" else 124,
         "passed": False, "output": "workspace identity could not be captured" if reason == "identity_error" else "aggregate validation runtime limit reached",
         "duration_ms": None, "started": False, "timed_out": False,
         "output_limited": False, "failure_reason": reason,
         "next_action": "Restore workspace access or resolve the validation runtime limit; rerun the check profile"}
        for index, command in enumerate(commands, start=first_index)
    ]



def doctor(root: Path, *, config_root: Path | None = None, bootstrap: bool = False) -> dict[str, Any]:
    try:
        from .harness_doctor import doctor as run_doctor
    except ImportError:  # Direct script invocation from the scripts directory.
        try:
            from harness_doctor import doctor as run_doctor
        except ImportError:
            return {"ok": False, "status": "invalid", "root": str(root), "config": {},
                    "git": None, "errors": ["required Harness doctor module is unavailable"],
                    "next_action": "Restore scripts/harness_doctor.py, then run " + _harness_command(root, "doctor")}
    return run_doctor(root, config_root=config_root, bootstrap=bootstrap)


def status(root: Path) -> dict[str, Any]:
    """Inspect session readiness; never run checks or write repository state."""
    try:
        from .harness_gate import evidence_matches, gate_errors, read_check
    except ImportError:
        from harness_gate import evidence_matches, gate_errors, read_check
    workspace = _resolve_workspace(root)
    report: dict[str, Any] = {"repository": "unavailable", "branch": None, "dirty": None}
    try:
        workspace = _git_root(workspace)
        report["repository"] = "available"
        report["branch"] = _git_output(workspace, ["branch", "--show-current"]).strip() or "detached"
        report["dirty"] = bool(_git_output(workspace, ["status", "--porcelain=v1", "-z"]))
    except (HarnessError, OSError, ValueError) as exc:
        report["git_error"] = sanitize_log(str(exc))
    config_report: dict[str, Any] = {"status": "unconfigured", "quick_checks": 0, "full_checks": 0}
    config_path = workspace / ".harness/config.toml"
    if config_path.exists() or config_path.is_symlink():
        try:
            config = load_config(workspace)
            config_report.update(status="configured" if config.quick and config.full else "unconfigured",
                                 quick_checks=len(config.quick), full_checks=len(config.full))
        except (HarnessError, OSError, ValueError) as exc:
            config_report.update(status="invalid", error=sanitize_log(str(exc)))
    if config_report["status"] != "configured":
        config_report["next_action"] = VALIDATION_SETUP
    report["profiles"] = config_report
    errors = gate_errors(workspace)
    report["gate"] = {"installed": not errors, "errors": errors}
    if errors:
        report["gate"]["next_action"] = _harness_command(workspace, "install-gate")
    report["checks"] = {}
    for profile in ("quick", "full"):
        cached = read_check(workspace, profile) or {}
        passed = cached.get("ok")
        report["checks"][profile] = {
            "last_result": "passed" if passed is True else "failed" if passed is False else "unavailable",
            "finished_at": cached.get("finished_at"),
            "evidence_matches": evidence_matches(workspace, profile),
        }
        if passed is False or not report["checks"][profile]["evidence_matches"]:
            report["checks"][profile]["next_action"] = _harness_command(workspace, "check", f"--{profile}")
    try:
        report["risk"] = inspect_git_risk(workspace, load_config_fn=load_config).to_dict()
    except (HarnessError, OSError, ValueError) as exc:
        report["risk"] = {"level": "unknown", "error": sanitize_log(str(exc)),
                          "next_action": _harness_command(workspace, "doctor")}
    if report["repository"] == "unavailable":
        report["next_action"] = "Run status --root with an accessible Git repository"
    elif config_report["status"] != "configured":
        report["next_action"] = config_report["next_action"]
    elif errors:
        report["next_action"] = report["gate"]["next_action"]
    elif any(not check["evidence_matches"] for check in report["checks"].values()):
        report["next_action"] = _harness_command(workspace, "check", "--full")
    return report


def _status_text(report: dict[str, Any]) -> str:
    dirty = report["dirty"]
    lines = [f"Repository: {report['repository']}", f"Branch: {report['branch'] or 'unavailable'}",
             f"Working tree: {'unknown' if dirty is None else 'dirty' if dirty else 'clean'}",
             f"Profiles: {report['profiles']['status']} "
             f"(quick={report['profiles']['quick_checks']}, full={report['profiles']['full_checks']})",
             f"Gate: {'installed' if report['gate']['installed'] else 'unavailable'}"]
    for profile, check in report["checks"].items():
        lines.append(f"{profile}: last={check['last_result']}, "
                     f"current evidence={'matches' if check['evidence_matches'] else 'no matching pass'}")
    lines.append(f"Risk: {report['risk']['level']}")
    if report.get("next_action"):
        lines.append(f"Next: {report['next_action']}")
    return sanitize_log("\n".join(lines))


def _safe_command(command: Sequence[str]) -> list[str]:
    return [sanitize_log(argument) for argument in command]


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run deterministic Harness checks and routing.")
    commands = parser.add_subparsers(dest="command", required=True)
    check = commands.add_parser("check", help="run configured project validation commands")
    profile = check.add_mutually_exclusive_group()
    profile.add_argument("--quick", dest="profile", action="store_const", const="quick")
    profile.add_argument("--full", dest="profile", action="store_const", const="full")
    check.set_defaults(profile="quick")
    check.add_argument("--root", default=".", help="repository or subdirectory to validate")
    check.add_argument("--config-root", help="trusted repository root supplying .harness/config.toml")
    status_command = commands.add_parser("status", help="read session state and cached validation evidence")
    status_command.add_argument("--root", default=".")
    status_command.add_argument("--json", action="store_true", help="print structured session state")
    commands.add_parser("selftest", help="run isolated Harness tests locally")
    risk = commands.add_parser("risk", help="classify the current Git diff")
    risk.add_argument("--root", default=".", help="repository or subdirectory to inspect")
    doctor_command = commands.add_parser("doctor", help="inspect Harness project setup")
    doctor_command.add_argument("--root", default=".", help="project root to inspect")
    doctor_command.add_argument("--config-root", help="trusted repository root supplying .harness/config.toml")
    doctor_command.add_argument("--bootstrap", action="store_true", help="check Harness structure before validation setup")
    gate_command = commands.add_parser("gate", help="require validation before a commit")
    gate_command.add_argument("--root", default=".")
    gate_command.add_argument("--json", action="store_true", help="print structured gate result")
    install = commands.add_parser("install-gate", help="install the Git commit gate")
    install.add_argument("--root", default=".")
    install.add_argument("--force", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        if args.command == "status":
            result = status(Path(args.root))
            print(json.dumps(result, ensure_ascii=False, indent=2) if args.json else _status_text(result),
                  file=sys.stdout if args.json else sys.stderr)
            return 0
        if args.command in {"gate", "install-gate"}:
            try:
                from .harness_gate import gate, install_gate
            except ImportError:
                from harness_gate import gate, install_gate
            if args.command == "install-gate":
                print(install_gate(Path(args.root), force=args.force), file=sys.stderr)
                return 0
            passed, detail = gate(Path(args.root))
            if args.json:
                report = {"ok": passed, "detail": sanitize_log(detail)}
                if not passed:
                    report["next_action"] = sanitize_log(detail.rsplit("\nNext: ", 1)[-1])
                print(json.dumps(report, ensure_ascii=False, indent=2))
            print(sanitize_log(detail), file=sys.stderr)
            return 0 if passed else 1
        if args.command == "selftest":
            root = Path(__file__).resolve().parents[1]
            result = run_bounded_command(
                [sys.executable, "-I", "-m", "unittest", "discover",
                 "-s", str(root / ".harness/tests"), "-t", str(root / ".harness")],
                cwd=root, timeout_seconds=120, max_output_bytes=MAX_COMMAND_OUTPUT_BYTES,
            )
            print(result.output, end="")
            if result.timed_out or result.output_limited or not _unittest_completed(result.output):
                return result.returncode or 1
            return result.returncode
        if args.command == "check":
            result = run_checks(
                Path(args.root),
                args.profile,
                config_root=Path(args.config_root) if args.config_root else None,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2))
            if result.get("next_action"):
                print("Next: " + sanitize_log(result["next_action"]), file=sys.stderr)
            return 0 if result["ok"] else 1
        if args.command == "doctor":
            result = doctor(
                Path(args.root),
                config_root=Path(args.config_root) if args.config_root else None,
                bootstrap=args.bootstrap,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2))
            if result.get("next_action"):
                print("Next: " + sanitize_log(result["next_action"]), file=sys.stderr)
            return 0 if result["ok"] else 1
        if args.command == "risk":
            result = inspect_git_risk(Path(args.root), load_config_fn=load_config)
            print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
            return 0
    except (HarnessError, OSError) as exc:
        action = VALIDATION_SETUP if args.command == "check" else _harness_command(Path(getattr(args, "root", ".")), "doctor", "--bootstrap")
        print(json.dumps({"error": sanitize_log(str(exc)), "next_action": action}, ensure_ascii=False))
        print("Next: " + sanitize_log(action), file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
