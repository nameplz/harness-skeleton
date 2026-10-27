"""Git commit gate and workspace-bound validation cache."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
import tempfile
import time
from typing import Any

try:
    from .harness_common import HarnessError
    from .harness_evidence import capture_workspace
    from .harness_risk import _git_output, _git_root, inspect_git_risk
except ImportError:
    from harness_common import HarnessError
    from harness_evidence import capture_workspace
    from harness_risk import _git_output, _git_root, inspect_git_risk


HOOKS_PATH = ".harness/githooks"
SETUP = "Define checks.quick/full in .harness/config.toml; see .agents/skills/harness/SKILL.md (Validation profile setup); run doctor --bootstrap."


def _cache_path(root: Path, profile: str) -> Path:
    if profile not in {"quick", "full"}:
        raise HarnessError("invalid cache profile")
    path = root / ".harness/state" / f"last-check-{profile}.json"
    try:
        path.resolve().relative_to(root.resolve())
    except (OSError, RuntimeError, ValueError) as exc:
        raise HarnessError("validation cache must stay inside the workspace") from exc
    return path


def save_check(root: Path, report: dict[str, Any]) -> None:
    evidence = report.get("evidence", {})
    after = report.get("evidence_after", evidence)
    if evidence.get("status") != "ok" or after.get("status") != "ok":
        return
    path = _cache_path(root, report["profile"])
    record = {
        "ok": report["ok"], "profile": report["profile"],
        "evidence": {key: evidence[key] for key in ("head", "dirty", "diff_sha256")},
        "config_sha256": evidence["config_sha256"], "finished_at": time.time(),
        "failed_checks": [item["name"] for item in report["checks"] if not item["passed"]],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent, delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(record, stream)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def evidence_matches(root: Path, profile: str) -> bool:
    if profile not in {"quick", "full"}:
        return False
    try:
        from .harness import load_config
    except ImportError:
        from harness import load_config
    try:
        config_hash = load_config(root).config_sha256
        evidence = capture_workspace(root)
        if evidence.get("status") != "ok":
            return False
        current = {key: evidence[key] for key in ("head", "dirty", "diff_sha256")}
        for candidate in (("quick", "full") if profile == "quick" else ("full",)):
            path = _cache_path(root, candidate)
            try:
                with path.open(encoding="utf-8") as stream:
                    raw = stream.read(64 * 1024 + 1)
                if len(raw) > 64 * 1024:
                    continue
                cached = json.loads(raw)
            except (OSError, UnicodeError, ValueError):
                continue
            if (isinstance(cached, dict) and cached.get("ok") is True
                    and cached.get("profile") == candidate
                    and cached.get("config_sha256") == config_hash
                    and cached.get("evidence") == current):
                return True
    except (HarnessError, OSError, RuntimeError, ValueError):
        pass
    return False


def gate(root: Path) -> tuple[bool, str]:
    try:
        from .harness import load_config, run_checks
    except ImportError:
        from harness import load_config, run_checks
    try:
        root = _git_root(root)
        config = load_config(root)
        if not config.quick or not config.full:
            return False, SETUP
        try:
            tier = inspect_git_risk(root, load_config_fn=load_config).level
        except (HarnessError, OSError, ValueError):
            tier = "unknown"
        profile = "quick" if tier in {"T0", "T1"} else "full"
        if evidence_matches(root, profile):
            return True, f"{profile} validation cache matches"
        report = run_checks(root, profile)
        if report["ok"]:
            return True, f"{profile} validation passed"
        failures = ", ".join(item["name"] for item in report.get("checks", []) if not item["passed"])
        return False, f"{profile} validation failed: {failures or report.get('error') or 'workspace changed'}. Fix failures and run check --{profile}."
    except (HarnessError, OSError, RuntimeError, ValueError) as exc:
        return False, f"Commit validation unavailable: {exc}. {SETUP}"


def install_gate(root: Path, *, force: bool = False) -> str:
    root = _git_root(root)
    values = _hooks_paths(root)
    if any(value != HOOKS_PATH for value in values) and not force:
        raise HarnessError(f"core.hooksPath is already {values}; use install-gate --force to replace it")
    _git_output(root, ["config", "--local", "core.hooksPath", HOOKS_PATH])
    return f"core.hooksPath set to {HOOKS_PATH}"


def _hooks_paths(root: Path) -> list[str]:
    # Read the effective setting without the inspection runner's hooksPath override.
    environment = {key: value for key, value in os.environ.items()
                   if key != "GIT_CONFIG_COUNT" and not key.startswith(("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"))}
    try:
        result = subprocess.run(["git", "config", "--get", "core.hooksPath"], cwd=root,
                                capture_output=True, text=True, timeout=5, check=False, env=environment)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HarnessError("could not inspect core.hooksPath") from exc
    if result.returncode not in {0, 1}:
        raise HarnessError("could not inspect core.hooksPath")
    return [result.stdout.removesuffix("\n")] if result.returncode == 0 else []


def gate_errors(root: Path) -> list[str]:
    try:
        values = _hooks_paths(root)
        hook = root / HOOKS_PATH / "pre-commit"
        if values != [HOOKS_PATH] or not hook.is_file() or not os.access(hook, os.X_OK):
            return ["commit gate unavailable: run install-gate and ensure .harness/githooks/pre-commit is executable"]
    except (HarnessError, OSError):
        return ["commit gate installation could not be inspected"]
    return []
