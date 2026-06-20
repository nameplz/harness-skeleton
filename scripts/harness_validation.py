#!/usr/bin/env python3
"""Shared validation helpers for Harness skeleton tooling."""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class HarnessValidationError(ValueError):
    """Raised when Harness config is invalid."""


@dataclass(frozen=True)
class HarnessCommand:
    name: str
    command: tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class ValidationConfig:
    schema_version: int
    mode: str
    profiles: tuple[str, ...]
    commands: tuple[HarnessCommand, ...]
    checks: dict[str, bool]


@dataclass
class ValidationResult:
    root: Path
    configured: bool
    profiles: list[str]
    errors: list[str]
    command_results: list[dict[str, Any]]

    @property
    def ok(self) -> bool:
        return not self.errors


DEFAULT_CHECKS = {"docs": True, "deploy": True, "phase": True}
DEFAULT_CONFIG = ValidationConfig(
    schema_version=1,
    mode="language-neutral",
    profiles=(),
    commands=(),
    checks=DEFAULT_CHECKS.copy(),
)

DOC_FILES = ("docs/PRD.md", "docs/ARCHITECTURE.md", "docs/ADR.md")
PLACEHOLDER_RE = re.compile(r"\{[^{}\n]+\}")
PROFILE_EVIDENCE = {
    "node": ("package.json", "tsconfig.json", "next.config.js", "next.config.mjs", "vite.config.ts"),
    "python": ("pyproject.toml", "requirements.txt", "setup.py", "setup.cfg"),
    "go": ("go.mod",),
    "rust": ("Cargo.toml",),
}
DEPLOY_FILE_NAMES = {
    "Dockerfile",
    "Procfile",
    "app.yaml",
    "cloudbuild.yaml",
    "docker-compose.yml",
    "docker-compose.yaml",
    "fly.toml",
    "netlify.toml",
    "railway.json",
    "render.yaml",
    "render.yml",
    "serverless.yml",
    "vercel.json",
}
DEPLOY_DIR_NAMES = {"helm", "k8s", "kubernetes", "terraform", ".netlify", ".vercel"}
UNSAFE_TOKENS = {
    "add",
    "ci",
    "deploy",
    "external-login",
    "install",
    "login",
    "migrate",
    "migration",
    "publish",
    "reset",
    "seed",
    "watch",
}
FORMATTER_TOKENS = {"format", "fmt"}


def detect_profiles(root: Path) -> list[str]:
    root = root.resolve()
    profiles: list[str] = []
    for profile, markers in PROFILE_EVIDENCE.items():
        if any((root / marker).exists() for marker in markers):
            profiles.append(profile)
    return profiles


def active_profiles(root: Path, configured_profiles: list[str] | tuple[str, ...]) -> list[str]:
    seen: set[str] = set()
    profiles: list[str] = []
    for profile in [*detect_profiles(root), *configured_profiles]:
        if profile not in seen:
            seen.add(profile)
            profiles.append(profile)
    return profiles


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise HarnessValidationError(f"Config not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise HarnessValidationError(f"Invalid JSON in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise HarnessValidationError(f"Config must be a JSON object: {path}")
    return data


def load_validation_config(path: Path) -> ValidationConfig:
    data = load_json(path)
    if data.get("schemaVersion") != 1:
        raise HarnessValidationError("validation schemaVersion must be 1")
    if data.get("mode") != "language-neutral":
        raise HarnessValidationError('validation mode must be "language-neutral"')

    profiles = data.get("profiles", [])
    if not isinstance(profiles, list) or not all(isinstance(item, str) for item in profiles):
        raise HarnessValidationError("profiles must be a list of strings")

    commands_raw = data.get("commands", [])
    if not isinstance(commands_raw, list):
        raise HarnessValidationError("commands must be a list")
    commands = tuple(validate_command_item(item) for item in commands_raw)

    checks_raw = data.get("checks", DEFAULT_CHECKS)
    if not isinstance(checks_raw, dict):
        raise HarnessValidationError("checks must be an object")
    checks = DEFAULT_CHECKS.copy()
    for name in DEFAULT_CHECKS:
        if name in checks_raw:
            value = checks_raw[name]
            if not isinstance(value, bool):
                raise HarnessValidationError(f"checks.{name} must be boolean")
            checks[name] = value

    return ValidationConfig(
        schema_version=1,
        mode="language-neutral",
        profiles=tuple(profiles),
        commands=commands,
        checks=checks,
    )


def validate_command_item(item: Any) -> HarnessCommand:
    if not isinstance(item, dict):
        raise HarnessValidationError("command entry must be an object")

    name = item.get("name")
    command = item.get("command")
    reason = item.get("reason")
    if not isinstance(name, str) or not name.strip():
        raise HarnessValidationError("command.name must be non-empty string")
    if not isinstance(reason, str) or not reason.strip():
        raise HarnessValidationError("command.reason must be non-empty string")
    if not isinstance(command, list) or not command:
        raise HarnessValidationError("command.command must be a non-empty list[str]")
    if not all(isinstance(part, str) and part for part in command):
        raise HarnessValidationError("command.command must contain only non-empty strings")

    reason_text = unsafe_command_reason(command)
    if reason_text:
        raise HarnessValidationError(f"Unsafe command {name}: {reason_text}")
    return HarnessCommand(name=name, command=tuple(command), reason=reason)


def unsafe_command_reason(command: list[str]) -> str | None:
    lowered = [part.lower() for part in command]
    lowered_base = [Path(part).name.lower() for part in command]
    token_set = set(lowered) | set(lowered_base)

    unsafe = sorted(token_set & UNSAFE_TOKENS)
    if unsafe:
        return f"forbidden token: {unsafe[0]}"

    if token_set & FORMATTER_TOKENS:
        return "formatter rewrite command is forbidden"

    if "ruff" in token_set and "--fix" in token_set:
        return "formatter rewrite command is forbidden"
    if "eslint" in token_set and "--fix" in token_set:
        return "formatter rewrite command is forbidden"
    if "prettier" in token_set and "--write" in token_set:
        return "formatter rewrite command is forbidden"

    check_only = "--check" in token_set or "--check-only" in token_set
    if ("black" in token_set or "isort" in token_set) and not check_only:
        return "formatter rewrite command is forbidden"
    if command[:2] == ["go", "fmt"] or command[:2] == ["cargo", "fmt"]:
        return "formatter rewrite command is forbidden"
    return None


def validate_project(
    *,
    root: Path,
    strict: bool,
    config_path: Path | None,
    run_commands: bool,
) -> ValidationResult:
    root = root.resolve()
    default_config_path = root / ".harness/validation.json"
    selected_config_path = config_path or (default_config_path if default_config_path.exists() else None)
    configured = strict or selected_config_path is not None
    errors: list[str] = []
    command_results: list[dict[str, Any]] = []

    try:
        config = load_validation_config(selected_config_path) if selected_config_path else DEFAULT_CONFIG
    except HarnessValidationError as exc:
        return ValidationResult(root, configured, [], [str(exc)], command_results)

    profiles = active_profiles(root, config.profiles)

    if config.checks.get("docs", True):
        errors.extend(check_docs(root, configured=configured))
    if config.checks.get("deploy", True):
        errors.extend(check_deploy(root))
    if config.checks.get("phase", True):
        errors.extend(check_phase_metadata(root))

    if run_commands and not errors:
        for command in config.commands:
            result = run_harness_command(root, command)
            command_results.append(result)
            if result["returncode"] != 0:
                errors.append(f"{command.name} failed with exit code {result['returncode']}")

    return ValidationResult(root, configured, profiles, errors, command_results)


def check_docs(root: Path, *, configured: bool) -> list[str]:
    errors: list[str] = []
    for relative in DOC_FILES:
        path = root / relative
        if not path.exists():
            errors.append(f"Missing required doc: {relative}")

    if configured:
        scan_paths = [root / relative for relative in DOC_FILES]
        agents = root / "AGENTS.md"
        if agents.exists():
            scan_paths.append(agents)
        for path in scan_paths:
            if path.exists() and PLACEHOLDER_RE.search(path.read_text(encoding="utf-8")):
                errors.append(f"Unresolved placeholder in configured project: {path.relative_to(root)}")
    return errors


def check_deploy(root: Path) -> list[str]:
    errors: list[str] = []
    ignored_roots = {".git", ".worktrees", ".harness", ".pytest_cache", "node_modules", ".next"}
    for path in root.rglob("*"):
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        if not relative.parts or relative.parts[0] in ignored_roots or relative.parts[0] == "deploy":
            continue
        if path.is_file() and path.name in DEPLOY_FILE_NAMES:
            errors.append(f"Deployment file must live under deploy/: {relative}")
        if path.is_dir() and path.name in DEPLOY_DIR_NAMES:
            errors.append(f"Deployment directory must live under deploy/: {relative}")
    return errors


def check_phase_metadata(root: Path) -> list[str]:
    index = root / "phases/index.json"
    if not index.exists():
        return []
    try:
        data = load_json(index)
    except HarnessValidationError as exc:
        return [str(exc)]
    phases = data.get("phases")
    if not isinstance(phases, list):
        return ["phases/index.json must contain phases list"]
    errors: list[str] = []
    for item in phases:
        if not isinstance(item, dict):
            errors.append("phase entry must be object")
            continue
        if not isinstance(item.get("dir"), str) or not item["dir"]:
            errors.append("phase entry dir must be non-empty string")
        if item.get("status") not in {"pending", "completed", "error", "blocked"}:
            errors.append("phase entry status is invalid")
    return errors


def run_harness_command(root: Path, command: HarnessCommand) -> dict[str, Any]:
    completed = subprocess.run(
        list(command.command),
        cwd=root,
        capture_output=True,
        text=True,
        timeout=600,
        shell=False,
    )
    return {
        "name": command.name,
        "command": list(command.command),
        "returncode": completed.returncode,
        "stdout": completed.stdout[-4000:],
        "stderr": completed.stderr[-4000:],
    }


def result_to_json(result: ValidationResult) -> dict[str, Any]:
    return {
        "root": str(result.root),
        "configured": result.configured,
        "profiles": result.profiles,
        "ok": result.ok,
        "errors": result.errors,
        "commandResults": result.command_results,
    }
