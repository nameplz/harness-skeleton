"""Harness bootstrap and project readiness diagnostics."""

from __future__ import annotations

import json
import re
import shlex
import shutil
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote, urlsplit

try:
    from .command_runner import run_bounded_command
    from .harness import (
        MAX_CONFIG_BYTES,
        _harness_command,
        _is_python_executable,
        _resolve_workspace,
        load_config,
    )
    from .harness_common import HarnessError
    from .harness_risk import _git_output, _git_root
except ImportError:  # Direct script invocation from the scripts directory.
    from command_runner import run_bounded_command
    from harness import (
        MAX_CONFIG_BYTES,
        _harness_command,
        _is_python_executable,
        _resolve_workspace,
        load_config,
    )
    from harness_common import HarnessError
    from harness_risk import _git_output, _git_root

REQUIRED_PROJECT_FILES = (
    "AGENTS.md", "docs/ARCHITECTURE.md", "docs/ADR.md", ".agents/skills/harness/SKILL.md",
    ".harness/task-template.md",
    "scripts/hooks/agent_hook.py", "scripts/command_runner.py",
    "scripts/harness.py", "scripts/harness_doctor.py", "scripts/harness_common.py", "scripts/harness_risk.py",
    "scripts/harness_evidence.py",
    "scripts/harness_gate.py", ".harness/githooks/pre-commit",
)
REQUIRED_DOC_SCAN_PATHS = ("AGENTS.md", "docs/ARCHITECTURE.md", "docs/ADR.md")
PLACEHOLDER_RE = re.compile(r"\{[^{}\n]+\}")
VALIDATION_SETUP = "define checks.quick/full; see .agents/skills/harness/SKILL.md (Validation profile setup)"


def _hook_command(hook: Any) -> tuple[tuple[str, ...], str] | None:
    if not isinstance(hook, dict) or hook.get("type") != "command" or not isinstance(hook.get("command"), str):
        return None
    try:
        argv = shlex.split(hook["command"])
    except ValueError:
        return None
    if not argv or not _is_python_executable(argv[0]):
        return None
    interpreter = (argv.pop(0),)
    if Path(interpreter[0].replace("\\", "/")).name.casefold() in {"py", "py.exe"}:
        if not argv or argv.pop(0) != "-3":
            return None
        interpreter += ("-3",)
    if argv and argv[0] == "-I":
        argv.pop(0)
    return (interpreter, argv[0]) if len(argv) == 1 else None


def _valid_harness_hook(hook: Any, workspace: Path, *, claude: bool = False) -> bool:
    command = _hook_command(hook)
    if command is None:
        return False
    interpreter, script = command
    paths = {"${CLAUDE_PROJECT_DIR}/scripts/hooks/agent_hook.py"} if claude else {
        "scripts/hooks/agent_hook.py",
        "$(git rev-parse --show-toplevel)/scripts/hooks/agent_hook.py",
        str(workspace / "scripts/hooks/agent_hook.py"),
    }
    return shutil.which(interpreter[0]) is not None and script in paths


def _interpreter_issue(interpreter: tuple[str, ...], workspace: Path) -> str | None:
    if "/" in interpreter[0] or "\\" in interpreter[0]:
        return "interpreter must be a name on PATH, not a path; version check was not run"
    executable = shutil.which(interpreter[0])
    if executable is None:
        return "not found on PATH"
    try:
        result = run_bounded_command(
            [executable, *interpreter[1:], "-I", "-c",
             "import sys; print('%s.%s' % sys.version_info[:2]); sys.exit(sys.version_info < (3, 11))"],
            cwd=workspace, timeout_seconds=5, max_output_bytes=1024,
        )
    except OSError:
        return "Python 3.11 or newer required (version check could not start)"
    version = re.fullmatch(r"(\d+)\.(\d+)", result.output.strip())
    if version and tuple(map(int, version.groups())) < (3, 11):
        return f"Python 3.11 or newer required (reported {version[0]})"
    if result.returncode != 0 or not version or result.timed_out or result.output_limited:
        return "Python 3.11 or newer required (version check failed)"
    return None


def _doctor_interpreter_report(workspace: Path) -> tuple[list[str], str | None]:
    errors: list[str] = []
    checked: dict[tuple[str, ...], str | None] = {}
    for relative in (".codex/config.toml", ".claude/settings.json"):
        try:
            text = _read_adapter_file(workspace, relative)
            data = tomllib.loads(text) if relative.endswith(".toml") else json.loads(text)
        except (OSError, UnicodeError, RuntimeError, ValueError):
            continue  # Adapter diagnostics report missing or invalid configuration.
        hooks = data.get("hooks") if isinstance(data, dict) else None
        if not isinstance(hooks, dict):
            continue
        for event in ("PreToolUse", "Stop"):
            entries = hooks.get(event)
            for entry in entries if isinstance(entries, list) else []:
                commands = entry.get("hooks") if isinstance(entry, dict) else None
                for hook in commands if isinstance(commands, list) else []:
                    command = _hook_command(hook)
                    if command is None:
                        continue
                    interpreter, _ = command
                    if interpreter not in checked:
                        checked[interpreter] = _interpreter_issue(interpreter, workspace)
                    if checked[interpreter]:
                        errors.append(f"{relative} (Harness hook interpreter {' '.join(interpreter)}: {checked[interpreter]})")
    if not errors:
        return [], None
    for candidate in (("python3",), ("python",), ("py", "-3")):
        if candidate not in checked:
            checked[candidate] = _interpreter_issue(candidate, workspace)
        if checked[candidate] is None:
            return errors, f"set adapter hook interpreter to {' '.join(candidate)} (Python 3.11+)"
    return errors, "install Python 3.11 or newer on PATH (python3, python, or py -3), then update adapter hooks"


def doctor(root: Path, *, config_root: Path | None = None, bootstrap: bool = False) -> dict[str, Any]:
    """Report whether this checkout has the files and config needed by Harness."""
    workspace = _resolve_workspace(root)
    errors = _missing_required_file_errors(workspace)
    errors.extend(_doctor_doc_errors(workspace, allow_placeholders=bootstrap))
    config_report, config_errors = _doctor_config_report(workspace, config_root)
    errors.extend(config_errors)
    profiles_configured = config_report["status"] == "configured"
    if config_report["status"] == "unconfigured" and not bootstrap:
        errors.append(f"validation is unconfigured: {VALIDATION_SETUP}")
    adapter_warnings: list[str] = []
    for adapter in (".codex", ".claude"):
        path = workspace / adapter
        if path.exists() or path.is_symlink():
            errors.extend(_doctor_codex_errors(workspace) if adapter == ".codex"
                          else _doctor_claude_errors(workspace))
            adapter_warnings.extend(_doctor_model_warnings(workspace, adapter))
    interpreter_errors, interpreter_action = _doctor_interpreter_report(workspace)
    errors.extend(interpreter_errors)
    git_report, git_errors = _doctor_git_report(workspace)
    errors.extend(git_errors)
    try:
        from .harness_gate import gate_errors
    except ImportError:
        from harness_gate import gate_errors
    gate_warnings = gate_errors(workspace)
    if not bootstrap:
        errors.extend(gate_warnings)

    configured = profiles_configured and not errors and not gate_warnings
    report = {
        "ok": not errors and (bootstrap or configured),
        "status": "configured" if configured else "unconfigured",
        "root": str(workspace),
        "config": config_report,
        "git": git_report,
        "errors": list(dict.fromkeys(errors)),
        "warnings": (gate_warnings if bootstrap else []) + adapter_warnings,
    }
    if config_report["status"] == "unconfigured":
        report["next_action"] = VALIDATION_SETUP
    if interpreter_action:
        report["next_action"] = (report.get("next_action", "") + "; " + interpreter_action).lstrip("; ")
    if config_report["status"] != "configured":
        config_report["next_action"] = VALIDATION_SETUP
    if not report["ok"] and "next_action" not in report:
        report["next_action"] = (_harness_command(workspace, "install-gate") if gate_warnings and len(errors) == len(gate_warnings)
                                 else "Fix the reported setup errors, then run " + _harness_command(workspace, "doctor", "--bootstrap"))
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
    try:
        codex_data = tomllib.loads(_read_adapter_file(workspace, ".codex/config.toml"))
    except (OSError, UnicodeError, RuntimeError, ValueError, tomllib.TOMLDecodeError):
        return [".codex/config.toml (invalid)"]
    hooks = codex_data.get("hooks")
    if not isinstance(hooks, dict):
        errors = [".codex/config.toml (missing hooks)"]
    else:
        errors = [
            f".codex/config.toml (missing {event} Harness hook)"
            for event in ("PreToolUse", "Stop")
            if not _has_harness_hook(hooks.get(event), event, workspace)
        ]
    errors.extend(_doctor_codex_role_errors(workspace, codex_data))
    return errors


def _has_harness_hook(entries: Any, event: str, workspace: Path, *, claude: bool = False) -> bool:
    if not isinstance(entries, list):
        return False
    return any(
        isinstance(entry, dict)
        and isinstance(entry.get("hooks"), list)
        and (event == "Stop" or entry.get("matcher") == ("Bash" if claude else "^Bash$"))
        and any(_valid_harness_hook(hook, workspace, claude=claude) for hook in entry["hooks"])
        for entry in entries
    )


def _read_adapter_file(workspace: Path, relative: str) -> str:
    path = (workspace / relative).resolve(strict=True)
    path.relative_to((workspace / relative.split("/", 1)[0]).resolve(strict=True))
    path.relative_to(workspace)
    if not path.is_file() or path.stat().st_size > MAX_CONFIG_BYTES:
        raise ValueError("adapter file must be a bounded regular file")
    return path.read_text(encoding="utf-8")


def _doctor_claude_errors(workspace: Path) -> list[str]:
    errors: list[str] = []
    try:
        data = json.loads(_read_adapter_file(workspace, ".claude/settings.json"))
        hooks = data.get("hooks") if isinstance(data, dict) else None
        if not isinstance(hooks, dict):
            errors.append(".claude/settings.json (missing hooks)")
        else:
            errors.extend(
                f".claude/settings.json (missing {event} Harness hook)"
                for event in ("PreToolUse", "Stop")
                if not _has_harness_hook(hooks.get(event), event, workspace, claude=True)
            )
    except (OSError, UnicodeError, RuntimeError, ValueError):
        errors.append(".claude/settings.json (invalid)")
    for role in ("reviewer", "security-reviewer"):
        relative = f".claude/agents/{role}.md"
        try:
            text = _read_adapter_file(workspace, relative)
            metadata, instructions = _claude_frontmatter(text)
            tools = re.findall(r"(?m)^tools:[ \t]*([^\n]*)$", metadata)
            names = [name.strip() for name in tools[0].split(",")] if len(tools) == 1 else []
            if not names or not set(names) <= {"Read", "Grep", "Glob"}:
                errors.append(f"{relative} (tools must be limited to Read, Grep, Glob)")
            if not instructions.strip():
                errors.append(f"{relative} (review instructions must be non-empty)")
        except (OSError, UnicodeError, RuntimeError, ValueError):
            errors.append(f"{relative} (invalid)")
    return errors


def _claude_frontmatter(text: str) -> tuple[str, str]:
    # shortcut: shipped agent metadata uses scalar fields; support richer YAML only when required.
    match = re.match(r"\A---\r?\n(.*?)\r?\n---\r?\n(.*)\Z", text, re.S)
    if not match:
        raise ValueError("agent frontmatter missing")
    if any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*:[ \t]*[^\r\n]*", line)
           for line in match[1].splitlines() if line.strip()):
        raise ValueError("agent frontmatter must use scalar fields")
    return match[1], match[2]


def _doctor_model_warnings(workspace: Path, adapter: str) -> list[str]:
    warnings: list[str] = []
    directory = workspace / adapter
    files = [directory / ("config.toml" if adapter == ".codex" else "settings.json")]
    files.extend((directory / "agents").glob("*.toml" if adapter == ".codex" else "*.md"))
    for path in files:
        try:
            text = _read_adapter_file(workspace, path.relative_to(workspace).as_posix())
            if path.suffix == ".md":
                text, _ = _claude_frontmatter(text)
                pinned = bool(re.search(r'(?m)^\s*(?:model|(?:model_)?reasoning_effort)\s*:', text))
            else:
                data = json.loads(text) if path.suffix == ".json" else tomllib.loads(text)
                pinned = _has_model_setting(data)
            if pinned:
                warnings.append(f"{path.relative_to(workspace)} (model/reasoning setting overrides runtime defaults)")
        except (OSError, UnicodeError, RuntimeError, ValueError):
            pass  # Adapter validation reports invalid files separately.
    return warnings


def _has_model_setting(data: Any) -> bool:
    if isinstance(data, dict):
        return any(key == "model" or key.endswith("reasoning_effort") or _has_model_setting(value)
                   for key, value in data.items())
    return isinstance(data, list) and any(_has_model_setting(value) for value in data)


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


def _doctor_doc_errors(root: Path, *, allow_placeholders: bool = False) -> list[str]:
    errors: list[str] = []
    for relative in REQUIRED_DOC_SCAN_PATHS:
        path = root / relative
        try:
            if PLACEHOLDER_RE.search(path.read_text(encoding="utf-8")) and not allow_placeholders:
                errors.append(f"unresolved placeholder: {relative}")
        except (OSError, UnicodeError):
            errors.append(f"could not read project guide: {relative}")

    for relative in ("AGENTS.md", "CLAUDE.md", ".agents/skills/harness/SKILL.md"):
        path = root / relative
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            errors.append(f"could not read project guide: {relative}")
            continue
        text = re.sub(r"(?ms)^(`{3,}|~{3,})[^\n]*\n.*?^\1[ \t]*(?:\n|$)", "", text)
        text = re.sub(r"`[^`\n]*`", "", text)
        targets = re.findall(r"\[[^\]\n]*\]\(\s*(<[^>\n]+>|[^\s)]+)(?:\s+[\"'][^\"']*[\"'])?\s*\)", text)
        targets.extend(re.findall(r"(?m)^\s*\[[^\]\n]+\]:\s*(<[^>\n]+>|[^\s]+)", text))
        for target in targets:
            target = target.removeprefix("<").removesuffix(">")
            try:
                link = urlsplit(target)
                if link.scheme or link.netloc or not link.path or link.path.startswith("/"):
                    continue
                exists = (path.parent / unquote(link.path)).exists()
            except (OSError, ValueError):
                exists = False
            if not exists:
                errors.append(f"broken relative link: {relative} -> {target}")
    return errors
