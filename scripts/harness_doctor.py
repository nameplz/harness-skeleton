"""Harness bootstrap and project readiness diagnostics."""

from __future__ import annotations

import re
import shlex
import shutil
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any

try:
    from .harness import (
        MAX_CONFIG_BYTES,
        _is_python_executable,
        _resolve_workspace,
        load_config,
    )
    from .harness_common import HarnessError
    from .harness_risk import _git_output, _git_root
except ImportError:  # Direct script invocation from the scripts directory.
    from harness import (
        MAX_CONFIG_BYTES,
        _is_python_executable,
        _resolve_workspace,
        load_config,
    )
    from harness_common import HarnessError
    from harness_risk import _git_output, _git_root

REQUIRED_PROJECT_FILES = (
    "AGENTS.md", "docs/ARCHITECTURE.md", "docs/ADR.md", ".agents/skills/harness/SKILL.md",
    ".harness/task-template.md",
    ".codex/config.toml", ".codex/agents/reviewer.toml", ".codex/agents/security-reviewer.toml",
    ".codex/hooks/harness_hook.py", "scripts/command_runner.py",
    "scripts/harness.py", "scripts/harness_doctor.py", "scripts/harness_common.py", "scripts/harness_risk.py",
    "scripts/harness_evidence.py",
)
REQUIRED_DOC_SCAN_PATHS = ("AGENTS.md", "docs/ARCHITECTURE.md", "docs/ADR.md")
PLACEHOLDER_RE = re.compile(r"\{[^{}\n]+\}")
VALIDATION_SETUP = "define checks.quick/full; see .agents/skills/harness/SKILL.md (Validation profile setup)"


def _valid_harness_hook(hook: Any, workspace: Path) -> bool:
    if not isinstance(hook, dict) or hook.get("type") != "command" or not isinstance(hook.get("command"), str):
        return False
    try:
        argv = shlex.split(hook["command"])
    except ValueError:
        return False
    if len(argv) == 3 and argv[1] == "-I":
        argv = [argv[0], argv[2]]
    return len(argv) == 2 and _is_python_executable(argv[0]) and shutil.which(argv[0]) is not None and argv[1] in {
        ".codex/hooks/harness_hook.py",
        "$(git rev-parse --show-toplevel)/.codex/hooks/harness_hook.py",
        str(workspace / ".codex/hooks/harness_hook.py"),
    }


def doctor(root: Path, *, config_root: Path | None = None, bootstrap: bool = False) -> dict[str, Any]:
    """Report whether this checkout has the files and config needed by Harness."""
    workspace = _resolve_workspace(root)
    errors = _missing_required_file_errors(workspace)
    errors.extend(_doctor_doc_errors(workspace))
    config_report, config_errors = _doctor_config_report(workspace, config_root)
    errors.extend(config_errors)
    profiles_configured = config_report["status"] == "configured"
    if config_report["status"] == "unconfigured" and not bootstrap:
        errors.append(f"validation is unconfigured: {VALIDATION_SETUP}")
    errors.extend(_doctor_codex_errors(workspace))
    git_report, git_errors = _doctor_git_report(workspace)
    errors.extend(git_errors)

    configured = profiles_configured and not errors
    report = {
        "ok": not errors and (bootstrap or configured),
        "status": "configured" if configured else "unconfigured",
        "root": str(workspace),
        "config": config_report,
        "git": git_report,
        "errors": list(dict.fromkeys(errors)),
    }
    if config_report["status"] == "unconfigured":
        report["next_action"] = VALIDATION_SETUP
    return report


def _missing_required_file_errors(workspace: Path) -> list[str]:
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
    return errors


def _doctor_config_report(workspace: Path, config_root: Path | None) -> tuple[dict[str, Any], list[str]]:
    config_workspace = workspace if config_root is None else _resolve_workspace(config_root)
    config_path = config_workspace / ".harness/config.toml"
    report: dict[str, Any] = {"status": "unconfigured", "quick_checks": 0, "full_checks": 0}
    if not config_path.exists() and not config_path.is_symlink():
        return report, []
    try:
        config = load_config(workspace, config_root=config_root)
    except HarnessError:
        return {**report, "status": "invalid"}, [".harness/config.toml (invalid)"]
    return {
        "schema": 2,
        "status": "configured" if config.quick and config.full else "unconfigured",
        "quick_checks": len(config.quick),
        "full_checks": len(config.full),
    }, []


def _doctor_codex_errors(workspace: Path) -> list[str]:
    codex_config = workspace / ".codex/config.toml"
    try:
        resolved_codex = codex_config.resolve(strict=True)
        resolved_codex.relative_to(workspace)
        codex_data = tomllib.loads(resolved_codex.read_text(encoding="utf-8"))
    except (OSError, RuntimeError, ValueError, tomllib.TOMLDecodeError):
        if not codex_config.exists() and not codex_config.is_symlink():
            return []
        return [".codex/config.toml (invalid)"]
    hooks = codex_data.get("hooks")
    if not isinstance(hooks, dict):
        errors = [".codex/config.toml (missing hooks)"]
    else:
        errors = [
            f".codex/config.toml (missing {event} Harness hook)"
            for event in ("PreToolUse", "PermissionRequest", "Stop")
            if not _has_harness_hook(hooks.get(event), event, workspace)
        ]
    errors.extend(_doctor_codex_role_errors(workspace, codex_data))
    return errors


def _has_harness_hook(entries: Any, event: str, workspace: Path) -> bool:
    if not isinstance(entries, list):
        return False
    return any(
        isinstance(entry, dict)
        and isinstance(entry.get("hooks"), list)
        and (event == "Stop" or entry.get("matcher") == "^Bash$")
        and any(_valid_harness_hook(hook, workspace) for hook in entry["hooks"])
        for entry in entries
    )


def _doctor_git_report(workspace: Path) -> tuple[dict[str, Any] | None, list[str]]:
    if shutil.which("git") is None:
        return None, ["Git executable unavailable"]
    try:
        repository = _git_root(workspace)
        branch = _git_output(repository, ["branch", "--show-current"]).strip()
        status = _git_output(repository, ["status", "--porcelain=v1", "-z"])
    except HarnessError:
        return None, ["Git repository unavailable"]
    return {
        "root": str(repository),
        "branch": branch or "detached",
        "changed_paths": sum(bool(item) for item in status.split("\0")),
    }, []


def _doctor_codex_role_errors(root: Path, codex_data: dict[str, Any]) -> list[str]:
    codex_dir = root / ".codex"
    try:
        resolved_codex_dir = codex_dir.resolve(strict=True)
        resolved_codex_dir.relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return [".codex/config.toml (invalid role config directory)"]
    agents = codex_data.get("agents")
    return [error for role in ("reviewer", "security_reviewer")
            for error in _doctor_role_errors(role, agents, codex_dir, resolved_codex_dir)]


def _doctor_role_errors(role: str, agents: Any, codex_dir: Path,
                        resolved_codex_dir: Path) -> list[str]:
    role_data = agents.get(role) if isinstance(agents, dict) else None
    if not isinstance(role_data, dict):
        return [f".codex/config.toml (missing {role} role)"]
    config_file = role_data.get("config_file")
    if not isinstance(config_file, str) or not config_file.strip():
        return [f".codex/config.toml ({role} config_file missing)"]
    normalized = config_file.replace("\\", "/")
    relative = PurePosixPath(normalized)
    if (normalized.startswith(("/", "~")) or re.match(r"^[A-Za-z]:", normalized)
            or "\x00" in normalized or any(part in {"", ".", ".."} for part in normalized.split("/"))):
        return [f".codex/config.toml ({role} config_file is unsafe)"]
    role_path = codex_dir.joinpath(*relative.parts)
    try:
        resolved_role_path = role_path.resolve(strict=True)
    except (OSError, RuntimeError):
        return [f".codex/config.toml ({role} config_file unavailable)"]
    try:
        resolved_role_path.relative_to(resolved_codex_dir)
    except ValueError:
        return [f".codex/config.toml ({role} config_file escapes .codex)"]
    try:
        if not resolved_role_path.is_file() or resolved_role_path.stat().st_size > MAX_CONFIG_BYTES:
            return [f".codex/config.toml ({role} config is not a regular TOML file)"]
        role_config = tomllib.loads(resolved_role_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        return [f".codex/config.toml ({role} config_file unavailable or invalid TOML)"]
    errors: list[str] = []
    if role_config.get("sandbox_mode") != "read-only":
        errors.append(f".codex/config.toml ({role} sandbox_mode must be read-only)")
    if not isinstance(role_config.get("developer_instructions"), str) or not role_config[
        "developer_instructions"
    ].strip():
        errors.append(f".codex/config.toml ({role} developer_instructions must be non-empty)")
    return errors


def _doctor_doc_errors(root: Path) -> list[str]:
    errors: list[str] = []
    for relative in REQUIRED_DOC_SCAN_PATHS:
        path = root / relative
        try:
            if PLACEHOLDER_RE.search(path.read_text(encoding="utf-8")):
                errors.append(f"unresolved placeholder: {relative}")
        except (OSError, UnicodeError):
            errors.append(f"could not read project guide: {relative}")

    return errors
