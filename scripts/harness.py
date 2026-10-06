#!/usr/bin/env python3
"""Deterministic Harness commands used by Codex and project CI."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
import re
import subprocess
import sys
import time
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
import tomllib
from typing import Any

try:
    from .command_runner import run_bounded_command
    from .harness_common import HarnessError, sanitize_log
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
    from command_runner import run_bounded_command
    from harness_common import HarnessError, sanitize_log
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
UNSAFE_COMMAND_TOKENS = frozenset(
    "add ci deploy external-login install login migrate migration publish reset seed watch".split()
)
SHELL_EXECUTABLES = frozenset({"sh", "bash", "zsh", "dash", "fish", "pwsh", "powershell", "cmd", "cmd.exe"})
SCRIPT_EXECUTABLE_SUFFIXES = frozenset({".py", ".sh", ".bash", ".js", ".mjs", ".cjs", ".ps1", ".bat", ".cmd"})
REQUIRED_PROJECT_FILES = (
    "AGENTS.md", "docs/ARCHITECTURE.md", "docs/ADR.md", ".agents/skills/harness/SKILL.md",
    ".codex/config.toml", ".codex/agents/reviewer.toml", ".codex/agents/security-reviewer.toml",
    ".codex/hooks/harness_hook.py", "scripts/command_runner.py",
    "scripts/harness.py", "scripts/harness_common.py", "scripts/harness_risk.py",
)
REQUIRED_DOC_SCAN_PATHS = ("AGENTS.md", "docs/ARCHITECTURE.md", "docs/ADR.md")
PLACEHOLDER_RE = re.compile(r"\{[^{}\n]+\}")
DEPLOY_FILE_NAMES = frozenset(
    {
        "Dockerfile", "Procfile", "app.yaml", "cloudbuild.yaml", "docker-compose.yml",
        "docker-compose.yaml", "fly.toml", "netlify.toml", "railway.json", "render.yaml",
        "render.yml", "serverless.yml", "vercel.json",
    }
)
DEPLOY_DIR_NAMES = frozenset({"helm", "k8s", "kubernetes", "terraform", ".netlify", ".vercel"})
SENSITIVE_OPTION_RE = re.compile(
    r"^--?(?:api[_-]?key|access[_-]?key|private[_-]?key|authorization|password|secret|token)$", re.IGNORECASE
)
SENSITIVE_VALUE_RE = re.compile(
    r"^(-{1,2}(?:api[_-]?key|access[_-]?key|private[_-]?key|authorization|password|secret|token))=([\s\S]*)$",
    re.IGNORECASE,
)
FILE_URI_RE = re.compile(r"^file:", re.IGNORECASE)
URL_RE = re.compile(r"^(?![a-z]:[/\\])[a-z][a-z0-9.+-]*://", re.IGNORECASE)
PATH_BEARING_SHORT_OPTIONS = ("-I", "-r")
PYTHON_INLINE_MODULES = frozenset({"timeit"})
SAFE_GIT_SUBCOMMANDS = frozenset(
    {"check-ignore", "config", "diff", "ls-files", "rev-parse", "status"}
)
SAFE_GIT_CONFIG_VALUES = {
    "color.diff": frozenset({"auto", "always", "never", "false", "true", "0", "1"}),
    "color.status": frozenset({"auto", "always", "never", "false", "true", "0", "1"}),
    "color.ui": frozenset({"auto", "always", "never", "false", "true", "0", "1"}),
    "core.quotepath": frozenset({"false", "true", "0", "1"}),
}
GIT_HELPER_URL_RE = re.compile(r"^[a-z0-9.+-]+::", re.IGNORECASE)
UNITTEST_RUN_RE = re.compile(r"(?m)^Ran ([1-9][0-9]*) tests? in [0-9]+(?:\.[0-9]+)?s$")
UNITTEST_OK_RE = re.compile(r"(?m)^OK(?: \([^\n]+\))?$")


@dataclass(frozen=True)
class HarnessConfig:
    quick: tuple[tuple[str, ...], ...]
    full: tuple[tuple[str, ...], ...]
    security_paths: tuple[str, ...]
    security_keywords: tuple[str, ...]
    security_hint_keywords: tuple[str, ...]


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
        if resolved_config.stat().st_size > MAX_CONFIG_BYTES:
            raise HarnessError("Harness config exceeds the size limit")
        raw = resolved_config.read_text(encoding="utf-8")
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
    return HarnessConfig(quick, full, security_paths, security_keywords, security_hint_keywords)


def _resolve_workspace(root: Path) -> Path:
    try:
        workspace = root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise HarnessError("workspace root is unavailable") from exc
    if not workspace.is_dir():
        raise HarnessError("workspace root must be a directory")
    return workspace


def _validate_command_list(raw: Any, field: str, workspace: Path) -> tuple[tuple[str, ...], ...]:
    if not isinstance(raw, list) or not raw or len(raw) > MAX_COMMAND_COUNT:
        raise HarnessError(f"{field} must be a non-empty list of argv commands")
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
    forbidden = sorted(tokens & UNSAFE_COMMAND_TOKENS)
    if forbidden:
        raise HarnessError(f"{field}[{index}] contains a forbidden operation")
    executable = _normalize_executable(Path(command[0].replace("\\", "/")).name.casefold())
    if executable == "env":
        raise HarnessError(f"{field}[{index}] cannot override the validation process environment")
    for position, argument in enumerate(command):
        nested_executable = _normalize_executable(Path(argument.replace("\\", "/")).name.casefold())
        if nested_executable == "git":
            _validate_git_command(command[position:], field, index)
    if tokens & SHELL_EXECUTABLES and any(
        _is_inline_shell_flag(part, tokens) for part in command[1:]
    ):
        raise HarnessError(f"{field}[{index}] cannot execute inline shell commands")
    if any(_is_inline_code_executable(token) for token in tokens) and any(
        _is_inline_code_flag(part, tokens) for part in command[1:]
    ):
        raise HarnessError(f"{field}[{index}] cannot execute inline code")
    if _python_timeit_command(command):
        raise HarnessError(f"{field}[{index}] cannot execute inline code")
    if _is_mutating_formatter(command, tokens):
        raise HarnessError(f"{field}[{index}] cannot rewrite source files")

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


def _validate_git_command(command: Sequence[str], field: str, index: int) -> None:
    arguments = command[1:]
    if any(GIT_HELPER_URL_RE.match(argument) for argument in arguments):
        raise HarnessError(f"{field}[{index}] cannot invoke a Git remote helper")
    if any(
        argument == "--exec-path"
        or argument.startswith("--exec-path=")
        or argument == "--upload-pack"
        or argument.startswith("--upload-pack=")
        or argument == "--receive-pack"
        or argument.startswith("--receive-pack=")
        for argument in arguments
    ):
        raise HarnessError(f"{field}[{index}] cannot select a Git helper executable")

    subcommand_index = _git_subcommand_index(arguments)
    if subcommand_index is None:
        if arguments == ["--version"]:
            return
        raise HarnessError(f"{field}[{index}] uses an unsupported Git command")
    subcommand = arguments[subcommand_index].casefold()
    if subcommand not in SAFE_GIT_SUBCOMMANDS:
        raise HarnessError(f"{field}[{index}] uses an unsupported Git command")
    if subcommand == "diff" and any(
        argument.casefold() in {"--ext-diff", "--textconv"}
        or argument.casefold().startswith(("--ext-diff=", "--textconv="))
        for argument in arguments[subcommand_index + 1:]
    ):
        raise HarnessError(f"{field}[{index}] cannot enable external Git diff helpers")

    prefix = arguments[:subcommand_index]
    position = 0
    while position < len(prefix):
        argument = prefix[position]
        setting: str | None = None
        if argument in {"-c", "--config"} and position + 1 < len(prefix):
            setting = prefix[position + 1]
            position += 1
        elif argument.startswith("-c") and len(argument) > 2:
            setting = argument[2:]
        elif argument.startswith("--config="):
            setting = argument.partition("=")[2]
        elif argument == "--config-env" or argument.startswith("--config-env="):
            raise HarnessError(f"{field}[{index}] cannot read external Git configuration")
        if setting is not None and not _git_config_is_safe(setting):
            raise HarnessError(f"{field}[{index}] cannot configure Git external commands")
        position += 1

    if subcommand == "config":
        config_arguments = {argument.casefold() for argument in arguments[subcommand_index + 1:]}
        query_options = {
            "--get", "--get-all", "--get-regexp", "--get-urlmatch", "--list", "-l",
            "--show-origin", "--show-scope",
        }
        write_options = {
            "--add", "--replace-all", "--unset", "--unset-all", "--rename-section",
            "--remove-section", "--edit", "set", "unset",
        }
        if not config_arguments & query_options or config_arguments & write_options:
            raise HarnessError(f"{field}[{index}] cannot modify Git configuration")

    if subcommand == "diff" and "--no-ext-diff" not in arguments[subcommand_index + 1:]:
        raise HarnessError(f"{field}[{index}] must disable external Git diff helpers")
    if subcommand == "diff" and "--no-textconv" not in arguments[subcommand_index + 1:]:
        raise HarnessError(f"{field}[{index}] must disable Git text conversion helpers")
    if subcommand == "diff" and any(
        argument == "--output" or argument.startswith("--output=")
        for argument in arguments[subcommand_index + 1:]
    ):
        raise HarnessError(f"{field}[{index}] cannot write Git diff output to a file")


def _git_subcommand_index(arguments: Sequence[str]) -> int | None:
    options_with_values = {
        "-C",
        "-c",
        "--config",
        "--config-env",
        "--git-dir",
        "--work-tree",
        "--namespace",
        "--super-prefix",
        "--exec-path",
    }
    options_without_values = {
        "--bare", "--no-pager", "--no-replace-objects", "--no-lazy-fetch",
        "--no-optional-locks", "--literal-pathspecs",
    }
    position = 0
    while position < len(arguments):
        argument = arguments[position]
        if argument in options_with_values:
            position += 2
        elif argument in options_without_values or argument.startswith(
            (
                "--config=",
                "--config-env=",
                "--git-dir=",
                "--work-tree=",
                "--namespace=",
                "--super-prefix=",
                "--exec-path=",
            )
        ):
            position += 1
        elif argument.startswith(("-C", "-c")) and len(argument) > 2:
            position += 1
        elif argument.startswith("-"):
            position += 1
        else:
            return position
    return None


def _git_config_is_safe(setting: str) -> bool:
    key, separator, value = setting.partition("=")
    normalized_key = key.strip().casefold()
    if not separator:
        return False
    allowed_values = SAFE_GIT_CONFIG_VALUES.get(normalized_key)
    return allowed_values is not None and value.strip().casefold() in allowed_values


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


def _python_timeit_command(command: Sequence[str]) -> bool:
    for executable_index, item in enumerate(command):
        executable = _normalize_executable(Path(item.replace("\\", "/")).name.casefold())
        if not re.fullmatch(r"(?:python|pypy)(?:\d+(?:\.\d+)*)?", executable):
            continue
        index = executable_index + 1
        while index < len(command):
            argument = command[index].casefold()
            if argument == "-m":
                if index + 1 < len(command) and command[index + 1].casefold() in PYTHON_INLINE_MODULES:
                    return True
                break
            if argument.startswith("-m") and len(argument) > 2:
                if argument[2:] in PYTHON_INLINE_MODULES:
                    return True
                break
            if argument == "--" or not argument.startswith("-"):
                break
            if argument in {"-w", "-x"}:
                index += 2
            else:
                index += 1
    return False


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


def _is_mutating_formatter(command: Sequence[str], tokens: set[str]) -> bool:
    if tokens & {"format", "fmt"}:
        return True
    if ("ruff" in tokens or "eslint" in tokens) and "--fix" in tokens:
        return True
    if "prettier" in tokens and "--write" in tokens:
        return True
    if tokens & {"black", "isort"} and not tokens & {"--check", "--check-only"}:
        return True
    return tuple(command[:2]) in {("go", "fmt"), ("cargo", "fmt")}


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


def run_checks(root: Path, profile: str, *, config_root: Path | None = None) -> dict[str, Any]:
    if profile not in {"quick", "full"}:
        raise HarnessError("check profile must be quick or full")
    workspace = _resolve_workspace(root)
    config = load_config(workspace, config_root=config_root)
    commands = config.quick if profile == "quick" else config.full
    results: list[dict[str, Any]] = []
    total_timeout = CHECK_QUICK_TIMEOUT_SECONDS if profile == "quick" else CHECK_TOTAL_TIMEOUT_SECONDS
    deadline = time.monotonic() + total_timeout
    for index, command in enumerate(commands, start=1):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            results.extend(_deadline_results(commands[index - 1 :], index))
            break
        try:
            trusted_command = _trusted_check_command(command, config_root=config_root)
            completed = run_bounded_command(
                trusted_command,
                cwd=workspace,
                timeout_seconds=min(CHECK_TIMEOUT_SECONDS, remaining),
                max_output_bytes=MAX_COMMAND_OUTPUT_BYTES,
            )
            returncode = completed.returncode
            output = completed.output
            if completed.output_limited:
                output = "check command output exceeded capture limit\n" + output
            elif completed.timed_out:
                output = "check command timed out or left child processes running\n" + output
            elif returncode == 0 and _is_unittest_command(trusted_command) and not _unittest_completed(output):
                returncode = 125
                output = "unit test process ended without a successful unittest summary\n" + output
        except OSError:
            returncode = 127
            output = "check command could not be started"
        results.append(
            {
                "name": f"check-{index}",
                "command": _safe_command(command),
                "returncode": returncode,
                "passed": returncode == 0,
                "output": sanitize_command_output(output, command),
            }
        )
    return {"ok": all(item["passed"] for item in results), "profile": profile, "checks": results}


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
        return [sys.executable, *tail]
    if len(tail) >= 2 and tail[0].replace("\\", "/") == "scripts/harness.py" and tail[1] == "doctor":
        doctor_args = list(tail[1:])
        if config_root is not None:
            doctor_args.extend(("--config-root", str(_resolve_workspace(config_root))))
        return [sys.executable, "-I", str(Path(__file__).resolve()), *doctor_args]
    return list(command)


def _is_python_executable(value: str) -> bool:
    executable = Path(value.replace("\\", "/")).name.casefold()
    return re.fullmatch(r"(?:python(?:\d+(?:\.\d+)*)?|py(?:\.exe)?)", executable) is not None


def _unittest_completed(output: str) -> bool:
    summary = UNITTEST_RUN_RE.search(output)
    success = UNITTEST_OK_RE.search(output)
    return summary is not None and success is not None and success.start() > summary.end()


def _deadline_results(commands: Sequence[Sequence[str]], first_index: int) -> list[dict[str, Any]]:
    return [
        {"name": f"check-{index}", "command": _safe_command(command), "returncode": 124,
         "passed": False, "output": "aggregate validation runtime limit reached"}
        for index, command in enumerate(commands, start=first_index)
    ]


def doctor(root: Path, *, config_root: Path | None = None) -> dict[str, Any]:
    """Report whether this checkout has the files and config needed by Harness."""

    workspace = _resolve_workspace(root)
    errors: list[str] = []
    for relative in REQUIRED_PROJECT_FILES:
        path = workspace / relative
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(workspace)
            if not resolved.is_file():
                errors.append(relative)
        except (OSError, RuntimeError, ValueError):
            errors.append(relative)

    config_report: dict[str, Any] | None = None
    try:
        config = load_config(workspace, config_root=config_root)
        config_report = {"schema": 2, "quick_checks": len(config.quick), "full_checks": len(config.full)}
    except HarnessError:
        errors.append(".harness/config.toml (invalid)")
    errors.extend(_doctor_doc_and_deploy_errors(workspace))

    codex_config = workspace / ".codex/config.toml"
    try:
        resolved_codex = codex_config.resolve(strict=True)
        resolved_codex.relative_to(workspace)
        codex_data = tomllib.loads(resolved_codex.read_text(encoding="utf-8"))
        hooks = codex_data.get("hooks")
        if not isinstance(hooks, dict):
            errors.append(".codex/config.toml (missing hooks)")
        else:
            for event in ("PreToolUse", "PermissionRequest", "Stop"):
                entries = hooks.get(event)
                commands: list[str] = []
                if isinstance(entries, list):
                    for entry in entries:
                        if not isinstance(entry, dict) or not isinstance(entry.get("hooks"), list):
                            continue
                        commands.extend(
                            hook["command"]
                            for hook in entry["hooks"]
                            if isinstance(hook, dict) and isinstance(hook.get("command"), str)
                        )
                if not any(".codex/hooks/harness_hook.py" in command for command in commands):
                    errors.append(f".codex/config.toml (missing {event} Harness hook)")
        errors.extend(_doctor_codex_role_errors(workspace, codex_data))
    except (OSError, RuntimeError, ValueError, tomllib.TOMLDecodeError):
        if ".codex/config.toml" not in errors:
            errors.append(".codex/config.toml (invalid)")

    git_report: dict[str, Any] | None = None
    try:
        repository = _git_root(workspace)
        branch = _git_output(repository, ["branch", "--show-current"]).strip()
        status = _git_output(repository, ["status", "--porcelain=v1", "-z"])
        git_report = {
            "root": str(repository),
            "branch": branch or "detached",
            "changed_paths": sum(bool(item) for item in status.split("\0")),
        }
    except HarnessError:
        errors.append("Git repository unavailable")

    return {
        "ok": not errors,
        "root": str(workspace),
        "config": config_report,
        "git": git_report,
        "errors": list(dict.fromkeys(errors)),
    }


def _doctor_codex_role_errors(root: Path, codex_data: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    agents = codex_data.get("agents")
    codex_dir = root / ".codex"
    try:
        resolved_codex_dir = codex_dir.resolve(strict=True)
        resolved_codex_dir.relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return [".codex/config.toml (invalid role config directory)"]

    for role in ("reviewer", "security_reviewer"):
        role_data = agents.get(role) if isinstance(agents, dict) else None
        if not isinstance(role_data, dict):
            errors.append(f".codex/config.toml (missing {role} role)")
            continue
        config_file = role_data.get("config_file")
        if not isinstance(config_file, str) or not config_file.strip():
            errors.append(f".codex/config.toml ({role} config_file missing)")
            continue
        normalized = config_file.replace("\\", "/")
        relative = PurePosixPath(normalized)
        if (
            normalized.startswith(("/", "~"))
            or re.match(r"^[A-Za-z]:", normalized)
            or "\x00" in normalized
            or any(part in {"", ".", ".."} for part in normalized.split("/"))
        ):
            errors.append(f".codex/config.toml ({role} config_file is unsafe)")
            continue
        role_path = codex_dir.joinpath(*relative.parts)
        try:
            resolved_role_path = role_path.resolve(strict=True)
        except (OSError, RuntimeError):
            errors.append(f".codex/config.toml ({role} config_file unavailable)")
            continue
        try:
            resolved_role_path.relative_to(resolved_codex_dir)
        except ValueError:
            errors.append(f".codex/config.toml ({role} config_file escapes .codex)")
            continue
        try:
            if not resolved_role_path.is_file() or resolved_role_path.stat().st_size > MAX_CONFIG_BYTES:
                errors.append(f".codex/config.toml ({role} config is not a regular TOML file)")
                continue
            role_config = tomllib.loads(resolved_role_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, tomllib.TOMLDecodeError):
            errors.append(f".codex/config.toml ({role} config_file unavailable or invalid TOML)")
            continue
        if role_config.get("sandbox_mode") != "read-only":
            errors.append(f".codex/config.toml ({role} sandbox_mode must be read-only)")
        if not isinstance(role_config.get("developer_instructions"), str) or not role_config[
            "developer_instructions"
        ].strip():
            errors.append(f".codex/config.toml ({role} developer_instructions must be non-empty)")
    return errors


def _doctor_doc_and_deploy_errors(root: Path) -> list[str]:
    errors: list[str] = []
    for relative in REQUIRED_DOC_SCAN_PATHS:
        path = root / relative
        try:
            if PLACEHOLDER_RE.search(path.read_text(encoding="utf-8")):
                errors.append(f"unresolved placeholder: {relative}")
        except (OSError, UnicodeError):
            errors.append(f"could not read project guide: {relative}")

    ignored_roots = {".git", ".worktrees", ".harness", ".pytest_cache", "node_modules", ".next"}
    for current, directories, files in os.walk(
        root,
        topdown=True,
        followlinks=False,
        onerror=lambda _error: errors.append("could not scan deployment layout"),
    ):
        relative = Path(current).relative_to(root)
        if any(part in ignored_roots or part == "deploy" for part in relative.parts):
            directories.clear()
            continue
        for name in directories:
            if name in DEPLOY_DIR_NAMES:
                errors.append(f"deployment directory must live under deploy/: {(relative / name).as_posix()}")
        directories[:] = [name for name in directories if name not in ignored_roots and name != "deploy"]
        for name in files:
            if name in DEPLOY_FILE_NAMES:
                errors.append(f"deployment file must live under deploy/: {(relative / name).as_posix()}")
    return errors


def _safe_command(command: Sequence[str]) -> list[str]:
    redacted: list[str] = []
    redact_next = False
    for argument in command:
        if redact_next:
            redacted.append("[REDACTED]")
            redact_next = False
        elif match := SENSITIVE_VALUE_RE.fullmatch(argument):
            redacted.append(f"{match.group(1)}=[REDACTED]")
        elif SENSITIVE_OPTION_RE.fullmatch(argument):
            redacted.append(argument)
            redact_next = True
        else:
            redacted.append(sanitize_log(argument))
    return redacted


def sanitize_command_output(value: str, command: Sequence[str]) -> str:
    redacted = value
    redact_next = False
    for argument in command:
        if redact_next:
            if argument:
                redacted = redacted.replace(argument, "[REDACTED]")
            redact_next = False
            continue
        match = SENSITIVE_VALUE_RE.fullmatch(argument)
        if match:
            option = re.escape(match.group(1))
            redacted = re.sub(rf"{option}=[\s\S]*", f"{match.group(1)}=[REDACTED]", redacted, flags=re.IGNORECASE)
        elif SENSITIVE_OPTION_RE.fullmatch(argument):
            redact_next = True
    return sanitize_log(redacted)


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
    risk = commands.add_parser("risk", help="classify the current Git diff")
    risk.add_argument("--root", default=".", help="repository or subdirectory to inspect")
    doctor_command = commands.add_parser("doctor", help="inspect Harness project setup")
    doctor_command.add_argument("--root", default=".", help="project root to inspect")
    doctor_command.add_argument("--config-root", help="trusted repository root supplying .harness/config.toml")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        if args.command == "check":
            result = run_checks(
                Path(args.root),
                args.profile,
                config_root=Path(args.config_root) if args.config_root else None,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if result["ok"] else 1
        if args.command == "doctor":
            result = doctor(
                Path(args.root),
                config_root=Path(args.config_root) if args.config_root else None,
            )
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0 if result["ok"] else 1
        if args.command == "risk":
            result = inspect_git_risk(Path(args.root), load_config_fn=load_config)
            print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
            return 0
    except (HarnessError, OSError) as exc:
        print(json.dumps({"error": sanitize_log(str(exc))}, ensure_ascii=False))
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
