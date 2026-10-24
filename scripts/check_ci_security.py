#!/usr/bin/env python3
"""Validate a project's GitHub Actions CI contract and security policy."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any

_HELPER_IMPORT_ERROR: str | None = None
try:
    from .ci_action_policy import _is_checkout_action
    from .ci_action_policy import check_job_actions as _check_job_actions
    from .ci_action_policy import check_local_action_metadata as _check_local_action_metadata
    from .github_expression_scanner import extract_github_expressions
    from .harness_common import HarnessError, sanitize_log
except ImportError as exc:
    try:  # Direct script invocation from the scripts directory.
        from ci_action_policy import _is_checkout_action
        from ci_action_policy import check_job_actions as _check_job_actions
        from ci_action_policy import check_local_action_metadata as _check_local_action_metadata
        from github_expression_scanner import extract_github_expressions
        from harness_common import HarnessError, sanitize_log
    except ImportError:
        _HELPER_IMPORT_ERROR = str(exc)
        _is_checkout_action = None
        _check_job_actions = None
        _check_local_action_metadata = None
        extract_github_expressions = None

        class HarnessError(Exception):
            pass

        def sanitize_log(value: Any) -> str:
            return str(value)

FULL_PROFILE_RE = re.compile(
    r"(?:python|python3)[ \t]+-I[ \t]+scripts/harness\.py[ \t]+check[ \t]+--full\Z"
)
JOB_ID_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*\Z")
REUSABLE_WORKFLOW_JOB_KEYS = frozenset(
    {
        "name", "uses", "with", "secrets", "strategy", "needs", "if", "concurrency", "permissions", "cache-mode",
    }
)
# shortcut: labels cannot attest hosted-runner identity; enforce trusted runner groups in GitHub settings.
HOSTED_RUNNERS = frozenset({
    "ubuntu-slim", "ubuntu-latest", "ubuntu-22.04", "ubuntu-24.04", "ubuntu-26.04",
    "ubuntu-22.04-arm", "ubuntu-24.04-arm", "ubuntu-26.04-arm",
    "windows-latest", "windows-2022", "windows-2025",
    "windows-11-arm", "windows-11-vs2026-arm",
    "macos-latest", "macos-14", "macos-15", "macos-26", "macos-15-intel", "macos-26-intel",
    "xcode-27",
})
UNTRUSTED_EVENT_CONTEXT_RE = re.compile(r"\bgithub\s*\.\s*(?:head_ref|event)\b", re.IGNORECASE)
FULL_ENV_HIJACK_KEYS = frozenset({
    "path", "pythonpath", "pythonhome", "pythonuserbase", "pythonstartup", "pythoninspect",
    "pythonexecutable", "bash_env", "env", "pathext", "ld_preload", "ld_library_path", "ld_audit",
})
MAX_WORKFLOW_BYTES = 1024 * 1024
WORKFLOW_PARSE_TIMEOUT_SECONDS = 5
MAX_WORKFLOWS = 100
SAFE_RUN_SHELLS = frozenset({"bash", "sh", "pwsh", "powershell", "cmd", "cmd.exe"})


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate GitHub Actions CI workflows.")
    parser.add_argument("--root", default=".", help="project root")
    return parser.parse_args()


def workflow_files(root: Path) -> list[Path]:
    workflows = root / ".github/workflows"
    if workflows.is_symlink() or not workflows.is_dir():
        return []
    return sorted(path for path in workflows.iterdir()
                  if (path.is_file() or path.is_symlink()) and path.suffix in {".yml", ".yaml"})


def check_security_policy(*, root: Path, config_root: Path | None = None) -> dict[str, Any]:
    """Return a static CI policy result; this is not an independent trust boundary."""
    warnings = _policy_warnings()
    try:
        workspace = root.resolve(strict=True)
        if not workspace.is_dir():
            raise OSError
    except (OSError, RuntimeError):
        return _result(["project root is unavailable"], [], [], warnings, [])
    if _HELPER_IMPORT_ERROR is not None:
        return _result(["required CI policy modules are unavailable"], [], [], warnings, [], status="invalid")

    errors = _workflow_directory_errors(workspace)
    files, scan_failed, scan_errors = _scan_workflow_files(workspace)
    errors.extend(scan_errors)
    if len(files) > MAX_WORKFLOWS:
        errors.append("workflow count exceeds the limit")
        files = files[:MAX_WORKFLOWS]
    if not files:
        errors.append("CI is unconfigured: no .github/workflows/*.yml or *.yaml files exist")
    profiles_status, profile_error = _configured_profiles(workspace, config_root=config_root)
    if profiles_status != "configured":
        errors.append(profile_error)
    policy_errors, workflows, checks, required_checks, has_pull_request = _inspect_workflow_policy(workspace, files)
    errors.extend(policy_errors)
    checks.extend([
        {"name": "validation_profiles", "passed": profiles_status == "configured"},
        {"name": "pull_request_trigger", "passed": has_pull_request},
        {"name": "full_profile_job", "passed": bool(required_checks)},
    ])
    status = _policy_status(profiles_status, scan_failed, errors, files, profile_error,
                            has_pull_request, required_checks)
    return _result(list(dict.fromkeys(errors)), workflows, checks, warnings, required_checks, status=status)


def _policy_warnings() -> list[str]:
    return [
        "Static checks cannot prove test quality or replace GitHub branch protection.",
        "Runner labels cannot prove GitHub-hosted runner identity; enforce trusted runner groups in GitHub settings.",
        "External action code is not inspected; pin and trust reviewed action revisions.",
        "Pre-Full shell setup is checked for common command-file writes, not fully interpreted; review those scripts.",
        "Dockerfile RUN checks catch common package and network APIs but cannot prove arbitrary build commands are offline.",
    ]


def _workflow_directory_errors(workspace: Path) -> list[str]:
    errors: list[str] = []
    for relative in (".github", ".github/workflows"):
        path = workspace / relative
        if path.is_symlink():
            errors.append(f"{relative} cannot be a symlink")
        elif path.exists() and not path.is_dir():
            errors.append(f"{relative} must be a directory")
    return errors


def _scan_workflow_files(workspace: Path) -> tuple[list[Path], bool, list[str]]:
    try:
        return workflow_files(workspace), False, []
    except (OSError, RuntimeError):
        return [], True, ["CI workflow directory could not be inspected"]


def _inspect_workflow_policy(workspace: Path, files: list[Path]) -> tuple[
    list[str], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, str]], bool
]:
    errors, workflows, checks, required_checks, has_pull_request = _inspect_workflows(workspace, files)
    pr_action_refs = [reference for workflow in workflows for reference in workflow.get("pr_action_refs", [])]
    try:
        errors.extend(_check_local_action_metadata(
            workspace, pr_action_refs, parse_workflow_yaml=_parse_workflow_yaml,
            check_expressions=_check_expressions, max_actions=MAX_WORKFLOWS,
            max_file_bytes=MAX_WORKFLOW_BYTES,
        ))
    except (OSError, RuntimeError):
        errors.append(".github/actions metadata could not be inspected")
    job_checks = [job for workflow in workflows for job in workflow.get("job_checks", [])]
    errors.extend(_check_required_check_collisions(required_checks, job_checks))
    if not has_pull_request:
        errors.append("at least one pull_request validation workflow is required")
    if not required_checks:
        errors.append("no pull_request job runs scripts/harness.py check --full")
    return errors, workflows, checks, required_checks, has_pull_request


def _policy_status(profiles_status: str, scan_failed: bool, errors: list[str], files: list[Path],
                   profile_error: str, has_pull_request: bool,
                   required_checks: list[dict[str, str]]) -> str:
    empty_ci_errors = {
        "CI is unconfigured: no .github/workflows/*.yml or *.yaml files exist",
        "at least one pull_request validation workflow is required",
        "no pull_request job runs scripts/harness.py check --full",
    }
    incomplete_ci_errors = {
        "at least one pull_request validation workflow is required",
        "no pull_request job runs scripts/harness.py check --full",
    }
    policy_errors = [error for error in errors if error != profile_error
                     and error not in incomplete_ci_errors
                     and not error.endswith(": no job runs scripts/harness.py check --full")
                     and (files or error not in empty_ci_errors)]
    if profiles_status == "invalid" or scan_failed or policy_errors:
        return "invalid"
    if files and profiles_status == "configured" and has_pull_request and required_checks:
        return "configured"
    return "unconfigured"


def _inspect_workflows(workspace: Path, files: list[Path]) -> tuple[
    list[str], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, str]], bool
]:
    errors: list[str] = []
    workflows: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []
    required_checks: list[dict[str, str]] = []
    has_pull_request = False
    for path in files:
        try:
            relative = path.relative_to(workspace)
            if path.is_symlink():
                errors.append(f"{relative} cannot be a symlink")
                continue
            path.resolve(strict=True).relative_to(workspace)
            if path.stat().st_size > MAX_WORKFLOW_BYTES:
                errors.append(f"{relative} exceeds the workflow size limit")
                continue
            parsed = _parse_workflow_yaml(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, RuntimeError, ValueError, subprocess.SubprocessError):
            errors.append(f"{path.name}: workflow YAML or file path is invalid")
            continue
        workflow_errors, meta = _check_workflow(relative, parsed, workspace)
        errors.extend(workflow_errors)
        workflows.append(meta)
        has_pull_request = has_pull_request or "pull_request" in meta["events"]
        required_checks.extend(meta["required_checks"])
        checks.append({"name": f"workflow:{relative.as_posix()}", "passed": not workflow_errors})
    return errors, workflows, checks, required_checks, has_pull_request


def _result(errors: list[str], workflows: list[dict[str, Any]], checks: list[dict[str, Any]],
            warnings: list[str], required_checks: list[dict[str, str]], *, status: str | None = None) -> dict[str, Any]:
    ok = not errors
    return {"ok": ok, "status": status or ("configured" if ok else "invalid"),
            "workflows": workflows, "required_checks": required_checks, "checks": checks,
            "errors": errors, "warnings": warnings}


def _configured_profiles(root: Path, *, config_root: Path | None = None) -> tuple[str, str]:
    config_path = (root if config_root is None else config_root) / ".harness/config.toml"
    try:
        config_missing = not config_path.exists() and not config_path.is_symlink()
    except (OSError, RuntimeError) as exc:
        return "invalid", f".harness/config.toml is unavailable: {sanitize_log(str(exc))}"
    if config_missing:
        return "unconfigured", "unconfigured: .harness/config.toml is missing"
    try:
        try:
            from .harness import load_config
        except ImportError:  # Direct script invocation from the scripts directory.
            from harness import load_config
        config = load_config(root, config_root=config_root)
    except HarnessError as exc:
        return "invalid", f".harness/config.toml is invalid or unavailable: {sanitize_log(str(exc))}"
    if not config.quick or not config.full:
        return "unconfigured", ".harness/config.toml must define non-empty checks.quick and checks.full profiles"
    return "configured", ""


def _check_workflow(relative: Path, workflow: dict[str, Any], root: Path) -> tuple[list[str], dict[str, Any]]:
    errors: list[str] = []
    raw_triggers = workflow.get("on")
    if isinstance(raw_triggers, dict):
        triggers = raw_triggers
    elif isinstance(raw_triggers, str) and raw_triggers:
        triggers = {raw_triggers: None}
    elif isinstance(raw_triggers, list) and raw_triggers and all(
        isinstance(event, str) and event for event in raw_triggers
    ):
        triggers = dict.fromkeys(raw_triggers)
    else:
        triggers = {}
    events = list(triggers)
    is_pr = "pull_request" in events
    jobs = workflow.get("jobs")
    if not triggers:
        errors.append(f"{relative}: workflow triggers must name at least one event")
    elif is_pr:
        if set(events) - {"pull_request", "push"}:
            errors.append(f"{relative}: validation workflows may use only pull_request and push")
    if triggers:
        errors.extend(_check_triggers(relative, triggers))
    if is_pr and "cache-mode" in workflow and (
        not isinstance(workflow["cache-mode"], str) or workflow["cache-mode"] not in {"read", "none"}
    ):
        errors.append(f"{relative}: pull_request workflows may use only read or none cache access")
    if "pull_request_target" in events and _has_pr_target_execution(jobs):
        errors.append(f"{relative}: pull_request_target jobs with executable steps are unsupported")
    if not isinstance(jobs, dict) or not jobs:
        errors.append(f"{relative}: jobs must be a non-empty mapping")
        jobs = {}
    if is_pr:
        workflow_context = {key: value for key, value in workflow.items() if key != "jobs"}
        errors.extend(_check_expressions(relative, "workflow", workflow_context))
        if "permissions" not in workflow:
            errors.append(f"{relative}: workflow must declare least-privilege permissions")
        else:
            errors.extend(_check_permissions(relative, workflow["permissions"]))

    job_errors, full_jobs, job_checks, pr_action_refs = _collect_job_metadata(
        relative, workflow, jobs, root, is_pr
    )
    errors.extend(job_errors)
    if is_pr:
        errors.extend(_check_dependencies(relative, jobs))
        errors.extend(_check_full_job_dependencies(relative, jobs, full_jobs))
        if not full_jobs:
            errors.append(f"{relative}: no job runs scripts/harness.py check --full")
    meta = {"path": relative.as_posix(), "name": str(workflow.get("name") or relative.stem),
            "events": events, "jobs": [key for key in jobs if isinstance(key, str)], "job_checks": job_checks,
            "pr_action_refs": pr_action_refs,
            "required_checks": full_jobs}
    return list(dict.fromkeys(errors)), meta


def _collect_job_metadata(relative: Path, workflow: dict[str, Any], jobs: dict[str, Any],
                          root: Path, is_pr: bool) -> tuple[
    list[str], list[dict[str, str]], list[dict[str, str]], list[str]
]:
    errors: list[str] = []
    full_jobs: list[dict[str, str]] = []
    job_checks: list[dict[str, str]] = []
    pr_action_refs: list[str] = []
    for job_id, job in jobs.items():
        job_errors, full_job = _check_job(relative, job_id, job, workflow, root, is_pr)
        errors.extend(job_errors)
        if is_pr and isinstance(job_id, str) and isinstance(job, dict) and not _is_push_only_job(job):
            workflow_name = str(workflow.get("name") or relative.stem)
            job_checks.append({"workflow": workflow_name, "workflow_path": relative.as_posix(),
                               "job_id": job_id, "job_name": str(job.get("name") or job_id)})
            steps = job.get("steps")
            if isinstance(steps, list):
                pr_action_refs.extend(step["uses"] for step in steps if isinstance(step, dict)
                                      and isinstance(step.get("uses"), str)
                                      and (step["uses"] == "./.github/actions"
                                           or step["uses"].startswith("./.github/actions/")))
        if full_job:
            full_jobs.append(full_job)
    return errors, full_jobs, job_checks, pr_action_refs


def _check_job(relative: Path, job_id: Any, job: Any, workflow: dict[str, Any], root: Path,
               is_pr: bool) -> tuple[list[str], dict[str, str] | None]:
    errors: list[str] = []
    if not isinstance(job_id, str) or not JOB_ID_RE.fullmatch(job_id):
        return [f"{relative}: job identifiers must be stable strings"], None
    if not isinstance(job, dict):
        return [f"{relative}: job {job_id} must be a mapping"], None
    errors.extend(_check_job_actions(
        relative, job, root, parse_workflow_yaml=_parse_workflow_yaml,
        max_workflow_bytes=MAX_WORKFLOW_BYTES,
    ))
    if "uses" in job:
        unsupported = sorted(set(job) - REUSABLE_WORKFLOW_JOB_KEYS)
        if unsupported:
            errors.append(
                f"{relative}: reusable workflow job {job_id} has unsupported keys: {', '.join(unsupported)}"
            )
        errors.extend(_check_reusable_workflow_job_values(relative, job_id, job))
        if is_pr and not _is_push_only_job(job):
            errors.append(f"{relative}: reusable workflow jobs are not supported in pull_request validation")
            if job.get("secrets") not in (None, {}):
                errors.append(f"{relative}: reusable workflow jobs in PR validation cannot receive secrets")
        return errors, None
    if is_pr and not _is_push_only_job(job):
        errors.extend(_check_validation_job(relative, job_id, job))
        errors.extend(_check_expressions(relative, job_id, job))
    has_full, full_steps = _full_profile_steps(job)
    if not is_pr or not has_full or _is_push_only_job(job):
        return errors, None
    workflow_name = str(workflow.get("name") or relative.stem)
    full_job = {"workflow": workflow_name, "workflow_path": relative.as_posix(),
                "job_id": job_id, "job_name": str(job.get("name") or job_id)}
    if job.get("if") is not None:
        errors.append(f"{relative}: Full validation job {job_id} cannot be conditional")
    strategy = job.get("strategy")
    if isinstance(strategy, dict) and "matrix" in strategy:
        errors.append(f"{relative}: Full validation job {job_id} cannot use a matrix check name")
    for index, step in full_steps:
        if step.get("if") is not None:
            errors.append(f"{relative}: Full validation step in {job_id} cannot be conditional")
        errors.extend(_check_full_execution_context(relative, workflow, job_id, job, step, index))
    errors.extend(_check_full_job_checkout(relative, job_id, job, full_steps))
    return errors, full_job


def _check_full_job_checkout(relative: Path, job_id: str, job: dict[str, Any],
                             full_steps: list[tuple[int, dict[str, Any]]]) -> list[str]:
    steps = job.get("steps")
    checkouts = []
    if isinstance(steps, list):
        checkouts = [
            (index, step) for index, step in enumerate(steps)
            if isinstance(step, dict) and isinstance(step.get("uses"), str)
            and _is_checkout_action(step["uses"])
        ]
    if len(checkouts) != 1:
        return [f"{relative}: Full validation job {job_id} must have exactly one actions/checkout step"]
    checkout_index, checkout = checkouts[0]
    if checkout_index >= min(index for index, _step in full_steps):
        return [f"{relative}: actions/checkout must run before Full validation in {job_id}"]
    if checkout.get("if") is not None:
        return [f"{relative}: actions/checkout cannot be conditional in Full validation job {job_id}"]
    return []


def _check_reusable_workflow_job_values(relative: Path, job_id: str,
                                        job: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    field_types = {
        "name": (str,), "with": (dict,), "secrets": (dict, str), "strategy": (dict,),
        "needs": (str, list), "if": (str, bool), "concurrency": (str, dict),
        "permissions": (dict, str),
    }
    for field, expected in field_types.items():
        if field in job and not isinstance(job[field], expected):
            errors.append(f"{relative}: reusable workflow job {job_id} has invalid {field} value")
    inputs = job.get("with")
    if isinstance(inputs, dict) and any(
        not isinstance(key, str) or type(value) not in {str, int, float, bool}
        for key, value in inputs.items()
    ):
        errors.append(f"{relative}: reusable workflow job {job_id} has invalid with values")
    needs = job.get("needs")
    if isinstance(needs, list) and not all(isinstance(item, str) for item in needs):
        errors.append(f"{relative}: reusable workflow job {job_id} has invalid needs values")
    secrets = job.get("secrets")
    if isinstance(secrets, str) and secrets.casefold() != "inherit":
        errors.append(f"{relative}: reusable workflow job {job_id} has invalid secrets value")
    elif isinstance(secrets, dict) and not all(
        isinstance(key, str) and isinstance(value, str) for key, value in secrets.items()
    ):
        errors.append(f"{relative}: reusable workflow job {job_id} has invalid secrets values")
    concurrency = job.get("concurrency")
    if isinstance(concurrency, dict) and (
        set(concurrency) - {"group", "cancel-in-progress"}
        or not isinstance(concurrency.get("group"), str)
        or "cancel-in-progress" in concurrency
        and not isinstance(concurrency["cancel-in-progress"], (bool, str))
    ):
        errors.append(f"{relative}: reusable workflow job {job_id} has invalid concurrency value")
    permissions = job.get("permissions")
    if isinstance(permissions, str) and permissions.casefold() not in {"read-all", "write-all"}:
        errors.append(f"{relative}: reusable workflow job {job_id} has invalid permissions value")
    elif isinstance(permissions, dict) and not all(
        isinstance(key, str) and isinstance(value, str)
        and value.casefold() in {"read", "write", "none"}
        for key, value in permissions.items()
    ):
        errors.append(f"{relative}: reusable workflow job {job_id} has invalid permission entries")
    cache_mode = job.get("cache-mode")
    if "cache-mode" in job and (
        not isinstance(cache_mode, str) or cache_mode not in {"read", "write", "write-only", "none"}
    ):
        errors.append(f"{relative}: reusable workflow job {job_id} has invalid cache-mode value")
    return errors


def _check_full_execution_context(relative: Path, workflow: dict[str, Any], job_id: str,
                                  job: dict[str, Any], step: dict[str, Any], step_index: int) -> list[str]:
    errors: list[str] = []
    working_directory = _effective_run_option(workflow, job, step, "working-directory")
    if working_directory is not None and (
        not isinstance(working_directory, str) or working_directory.strip() not in {".", "./"}
    ):
        errors.append(f"{relative}: Full validation step in {job_id} must run from the repository root")
    shell = _effective_run_option(workflow, job, step, "shell")
    if shell is not None and (not isinstance(shell, str) or shell.casefold() not in SAFE_RUN_SHELLS):
        errors.append(f"{relative}: Full validation step in {job_id} has an unsupported shell")
    for settings in (workflow, job, step):
        environment = settings.get("env")
        if isinstance(environment, dict) and any(
            str(key).casefold() in FULL_ENV_HIJACK_KEYS
            or str(key).casefold().startswith("dyld_") for key in environment
        ):
            errors.append(f"{relative}: interpreter environment can alter Full validation in {job_id}")
            break
    steps = job.get("steps")
    if isinstance(steps, list):
        for prior_step in steps[:step_index]:
            if not isinstance(prior_step, dict):
                continue
            action_ref = prior_step.get("uses")
            if isinstance(action_ref, str) and (action_ref == "./.github/actions"
                                                or action_ref.startswith("./.github/actions/")):
                errors.append(f"{relative}: local actions cannot run before Full validation in {job_id}")
            run = prior_step.get("run")
            # shortcut: detect common shell indirection; review other script obfuscation as a blocker.
            if isinstance(run, str) and re.search(
                r"\bGITHUB_|\$\(|\$\{!|`|\beval\b", run, re.IGNORECASE
            ):
                errors.append(f"{relative}: prior steps cannot change Full validation environment in {job_id}")
                break
    return errors


def _effective_run_option(workflow: dict[str, Any], job: dict[str, Any], step: dict[str, Any],
                          option: str) -> Any:
    for settings in (step, _run_defaults(job), _run_defaults(workflow)):
        if isinstance(settings, dict) and settings.get(option) is not None:
            return settings[option]
    return None


def _run_defaults(source: dict[str, Any]) -> Any:
    defaults = source.get("defaults")
    return defaults.get("run") if isinstance(defaults, dict) else None


def _check_triggers(relative: Path, triggers: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    pr = triggers.get("pull_request")
    if pr is None:
        pr = {}
    if not isinstance(pr, dict):
        errors.append(f"{relative}: pull_request trigger must be a mapping")
    else:
        if "branches" in pr or "branches-ignore" in pr:
            errors.append(f"{relative}: pull_request branch filters can skip required validation")
        if "paths" in pr or "paths-ignore" in pr:
            errors.append(f"{relative}: path filters can skip required validation")
        types = pr.get("types")
        required_types = {"opened", "synchronize", "reopened"}
        if types is not None and (not isinstance(types, list) or not required_types.issubset(types)):
            errors.append(f"{relative}: pull_request types must include opened, synchronize, and reopened")
    push = triggers.get("push")
    if "push" in triggers:
        if not isinstance(push, dict):
            errors.append(f"{relative}: push trigger must be limited to explicit branches or finite tags")
        else:
            allowed = {"branches", "branches-ignore", "tags", "tags-ignore", "paths", "paths-ignore"}
            unsupported = sorted(set(push) - allowed)
            if unsupported:
                errors.append(f"{relative}: push trigger has unsupported filters: {', '.join(unsupported)}")
            branches = push.get("branches")
            tags = push.get("tags")
            if "branches-ignore" in push or "tags-ignore" in push:
                errors.append(f"{relative}: push ignore filters can allow unbounded refs")
            if "branches" in push and not isinstance(branches, list):
                errors.append(f"{relative}: push branches must be an explicit branch list")
            elif isinstance(branches, list) and (
                not branches
                or any(
                    not isinstance(item, str) or not item or item[0] in "*?[]!+"
                    for item in branches
                )
            ):
                errors.append(f"{relative}: push branches must be a limited positive branch list")
            if "tags" in push and not isinstance(tags, list):
                errors.append(f"{relative}: push tags must be a finite explicit tag list")
            elif isinstance(tags, list) and (
                not tags
                or any(
                    not isinstance(item, str) or not item
                    or any(char in item for char in "*?[]!+\\")
                    for item in tags
                )
            ):
                errors.append(f"{relative}: push tags must be a finite explicit tag list")
            if "branches" not in push and "tags" not in push:
                errors.append(f"{relative}: push must be limited to explicit branches or finite tags")
            if "paths" in push or "paths-ignore" in push:
                errors.append(f"{relative}: path filters can skip required validation")
    return errors


def _check_validation_job(relative: Path, job_id: str, job: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if "container" in job or "services" in job:
        errors.append(f"{relative}: job {job_id} cannot use job or service containers in pull_request validation")
    if "environment" in job:
        errors.append(f"{relative}: job {job_id} cannot request a deployment environment in pull_request validation")
    if not _hosted_runner(job.get("runs-on")):
        errors.append(f"{relative}: job {job_id} must use a GitHub-hosted runner")
    timeout = job.get("timeout-minutes")
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 1 <= timeout <= 360:
        errors.append(f"{relative}: job {job_id} must set timeout-minutes from 1 to 360")
    steps = job.get("steps")
    if not isinstance(steps, list) or not steps:
        errors.append(f"{relative}: job {job_id} must define steps")
    else:
        for step in steps:
            if not isinstance(step, dict):
                errors.append(f"{relative}: job {job_id} steps must be mappings")
            else:
                if "run" in step and (not isinstance(step["run"], str) or not step["run"].strip()):
                    errors.append(f"{relative}: job {job_id} has an empty run step")
                if "continue-on-error" in step and not _explicit_false(step["continue-on-error"]):
                    errors.append(f"{relative}: PR validation steps in {job_id} cannot ignore failures")
    if "continue-on-error" in job and not _explicit_false(job["continue-on-error"]):
        errors.append(f"{relative}: PR validation job {job_id} cannot ignore failures")
    if job.get("permissions") is not None:
        errors.extend(_check_permissions(relative, job["permissions"]))
    if "cache-mode" in job and (
        not isinstance(job["cache-mode"], str) or job["cache-mode"] not in {"read", "none"}
    ):
        errors.append(f"{relative}: PR validation job {job_id} may use only read or none cache access")
    return errors


def _hosted_runner(value: Any) -> bool:
    labels = [value] if isinstance(value, str) else value if isinstance(value, list) else []
    return len(labels) == 1 and isinstance(labels[0], str) and labels[0].casefold() in HOSTED_RUNNERS


def _check_permissions(relative: Path, value: Any) -> list[str]:
    if value == "none":
        return []
    if not isinstance(value, dict):
        return [f"{relative}: permissions must be a scoped read/none mapping"]
    errors: list[str] = []
    for scope, level in value.items():
        if not isinstance(scope, str) or not isinstance(level, str):
            errors.append(f"{relative}: permission declaration is invalid")
        elif level.casefold() == "write":
            errors.append(f"{relative}: write token permissions are forbidden in validation CI")
        elif level.casefold() not in {"read", "none"}:
            errors.append(f"{relative}: permission level must be read or none")
    return errors


def _check_expressions(relative: Path, job_id: str, job: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    def inspect(value: Any, path: tuple[str | int, ...] = ()) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                inspect(item, (*path, str(key)))
        elif isinstance(value, list):
            for index, item in enumerate(value):
                inspect(item, (*path, index))
        elif isinstance(value, str):
            expressions, malformed = extract_github_expressions(value)
            if not expressions and not malformed and path and path[-1] == "if":
                expressions, malformed = extract_github_expressions("${{ " + value + " }}")
            if malformed:
                errors.append(f"{relative}: GitHub expression is malformed")
            for _expression, code in expressions:
                if re.search(r"\bsecrets\b", code, re.IGNORECASE):
                    errors.append(f"{relative}: secrets context is forbidden in pull_request validation")
                if re.search(r"\bgithub\s*\.\s*token\b", code, re.IGNORECASE):
                    errors.append(f"{relative}: github.token is forbidden in pull_request validation")
                if re.search(r"\bgithub\s*\.\s*(?:env|path)\b", code, re.IGNORECASE):
                    errors.append(f"{relative}: GitHub command-file context is forbidden in pull_request validation")
                if re.search(r"\bgithub\s*\.\s*\*|\bgithub\s*\[|\btojson\s*\(\s*github\s*\)", code, re.IGNORECASE):
                    errors.append(f"{relative}: broad GitHub context access is forbidden")
                if UNTRUSTED_EVENT_CONTEXT_RE.search(code):
                    errors.append(
                        f"{relative}: untrusted event data cannot be interpolated into pull_request workflow values"
                    )
    inspect(job, ("jobs", job_id))
    return list(dict.fromkeys(errors))


def _is_push_only_job(job: dict[str, Any]) -> bool:
    condition = job.get("if")
    if not isinstance(condition, str):
        return False
    return re.fullmatch(r"\s*(?:\$\{\{\s*)?github\.event_name\s*==\s*['\"]push['\"]\s*(?:\}\})?\s*",
                        condition, re.IGNORECASE) is not None


def _full_profile_steps(job: Any) -> tuple[bool, list[tuple[int, dict[str, Any]]]]:
    steps = job.get("steps") if isinstance(job, dict) else None
    if not isinstance(steps, list):
        return False, []
    matches = [(index, step) for index, step in enumerate(steps)
               if isinstance(step, dict) and _is_full_profile_run(step.get("run"))]
    return bool(matches), matches


def _is_full_profile_run(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    commands = [line.strip() for line in value.splitlines()
                if line.strip() and not line.lstrip().startswith("#")]
    return len(commands) == 1 and FULL_PROFILE_RE.fullmatch(commands[0]) is not None


def _has_pr_target_execution(jobs: Any) -> bool:
    if not isinstance(jobs, dict):
        return False
    for job in jobs.values():
        if isinstance(job, dict) and isinstance(job.get("uses"), str):
            return True
        steps = job.get("steps") if isinstance(job, dict) else None
        if not isinstance(steps, list):
            continue
        for step in steps:
            if isinstance(step, dict) and ("run" in step or "uses" in step):
                return True
    return False


def _explicit_false(value: Any) -> bool:
    return value is False or isinstance(value, str) and value.strip().casefold() == "false"


def _check_dependencies(relative: Path, jobs: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    graph: dict[str, tuple[str, ...]] = {}
    for job_id, job in jobs.items():
        if not isinstance(job_id, str) or not isinstance(job, dict):
            continue
        needs = job.get("needs", [])
        if isinstance(needs, str):
            needs = [needs]
        if not isinstance(needs, list) or not all(isinstance(item, str) for item in needs):
            errors.append(f"{relative}: job {job_id} has invalid needs")
            continue
        for dependency in needs:
            if dependency not in jobs or dependency == job_id:
                errors.append(f"{relative}: job {job_id} has an invalid dependency")
        graph[job_id] = tuple(needs)
    visiting: set[str] = set()
    visited: set[str] = set()
    def visit(job_id: str) -> None:
        if job_id in visiting:
            errors.append(f"{relative}: job dependencies contain a cycle")
            return
        if job_id in visited:
            return
        visiting.add(job_id)
        for dependency in graph.get(job_id, ()):
            if dependency in graph:
                visit(dependency)
        visiting.remove(job_id)
        visited.add(job_id)
    for job_id in graph:
        visit(job_id)
    return list(dict.fromkeys(errors))


def _check_full_job_dependencies(relative: Path, jobs: dict[str, Any], full_jobs: list[dict[str, str]]) -> list[str]:
    errors: list[str] = []
    for full_job in full_jobs:
        pending = _job_dependencies(jobs.get(full_job["job_id"]))
        visited: set[str] = set()
        while pending:
            dependency_id = pending.pop()
            if dependency_id in visited:
                continue
            visited.add(dependency_id)
            dependency = jobs.get(dependency_id)
            if not isinstance(dependency, dict):
                continue
            if dependency.get("if") is not None:
                errors.append(
                    f"{relative}: Full validation job {full_job['job_id']} depends on conditional job {dependency_id}"
                )
            pending.extend(_job_dependencies(dependency))
    return list(dict.fromkeys(errors))


def _job_dependencies(job: Any) -> list[str]:
    needs = job.get("needs", []) if isinstance(job, dict) else []
    if isinstance(needs, str):
        return [needs]
    return [item for item in needs if isinstance(item, str)] if isinstance(needs, list) else []


def _check_required_check_collisions(required_checks: list[dict[str, str]],
                                    job_checks: list[dict[str, str]]) -> list[str]:
    errors: list[str] = []
    for required in required_checks:
        workflow_path = Path(required["workflow_path"])
        workflow_aliases = {required["workflow"].casefold(), workflow_path.name.casefold(),
                            workflow_path.stem.casefold()}
        job_aliases = {required["job_id"].casefold(), required["job_name"].casefold()}
        for candidate in job_checks:
            if (candidate["workflow_path"], candidate["job_id"]) == (
                required["workflow_path"], required["job_id"]
            ):
                continue
            candidate_path = Path(candidate["workflow_path"])
            candidate_workflows = {candidate["workflow"].casefold(), candidate_path.name.casefold(),
                                  candidate_path.stem.casefold()}
            candidate_jobs = {candidate["job_id"].casefold(), candidate["job_name"].casefold()}
            if workflow_aliases & candidate_workflows and job_aliases & candidate_jobs:
                errors.append(f"ambiguous required check identity: {required['workflow']} / {required['job_name']}")
    return list(dict.fromkeys(errors))


def _parse_workflow_yaml(text: str) -> dict[str, Any]:
    if len(text.encode("utf-8")) > MAX_WORKFLOW_BYTES:
        raise ValueError("workflow exceeds the size limit")
    ruby_script = r"""
source = STDIN.read
stream = Psych.parse_stream(source)
abort "workflow must have exactly one YAML document" unless stream && stream.children.length == 1
document = stream.children.first
abort "workflow root must be a mapping" unless document.root.is_a?(Psych::Nodes::Mapping)
root_keys = document.root.children.each_slice(2).map(&:first)
boolean_aliases = %w[true yes y false no n on off]
root_scalar_keys = root_keys.select { |key| key.is_a?(Psych::Nodes::Scalar) }
plain_boolean_root_keys = root_scalar_keys.select { |key| key.plain && boolean_aliases.include?(key.value.downcase) }
abort "workflow root has an ambiguous boolean key" if plain_boolean_root_keys.any? { |key| key.value.downcase != "on" }
plain_on = plain_boolean_root_keys.any? { |key| key.value.downcase == "on" }
string_on = root_scalar_keys.any? { |key| key.value.casecmp?("on") && !key.plain }
abort "workflow root has ambiguous trigger keys" if plain_on && string_on
def check_unique(node, root_mapping = false)
  case node
  when Psych::Nodes::Mapping
    keys = {}
    node.children.each_slice(2) do |key, value|
      abort "workflow mapping keys must be scalar strings" unless key.is_a?(Psych::Nodes::Scalar)
      abort "explicit YAML mapping-key tags are unsupported" if key.tag
      if key.plain
        normalized_key = key.value.downcase
        if %w[true yes y on false no n off].include?(normalized_key)
          abort "ambiguous YAML boolean mapping key" unless root_mapping && normalized_key == "on"
          identity = [:boolean, %w[true yes y on].include?(normalized_key)]
        elsif %w[null ~].include?(normalized_key) || !key.value.match?(/\A[A-Za-z_][A-Za-z0-9_.-]*\z/)
          abort "workflow mapping keys must be strings"
        else
          identity = [:scalar, key.value]
        end
      else
        identity = [:scalar, key.value]
      end
      check_unique(value)
      abort "duplicate YAML mapping key" if keys.key?(identity)
      keys[identity] = true
    end
  when Psych::Nodes::Sequence
    node.children.each { |child| check_unique(child) }
  end
end
check_unique(document.root, true)
workflow = YAML.safe_load(source, permitted_classes: [Date, Time], aliases: false)
abort "workflow root must be a mapping" unless workflow.is_a?(Hash)
if plain_on && workflow.key?(true)
  workflow["on"] = workflow.delete(true)
end
STDOUT.write(JSON.generate(workflow))
""".strip()
    completed = subprocess.run(["ruby", "-rjson", "-ryaml", "-rdate", "-e", ruby_script],
                               input=text, capture_output=True, text=True, encoding="utf-8",
                               errors="replace", timeout=WORKFLOW_PARSE_TIMEOUT_SECONDS,
                               shell=False, check=False)
    if completed.returncode != 0:
        raise ValueError("workflow YAML parser rejected the document")
    workflow = json.loads(completed.stdout)
    if not isinstance(workflow, dict):
        raise ValueError("workflow root must be a mapping")
    return workflow


def check_workflow_text(relative: Path, text: str, *, root: Path | None = None) -> list[str]:
    """Check a workflow text fixture without reading neighboring files."""
    if _HELPER_IMPORT_ERROR is not None:
        return [f"{relative}: required CI policy modules are unavailable"]
    try:
        parsed = _parse_workflow_yaml(text)
    except (OSError, ValueError, subprocess.SubprocessError):
        return [f"{relative}: workflow YAML is invalid or could not be parsed safely"]
    return _check_workflow(relative, parsed, (root or Path.cwd()).resolve())[0]


def is_sensitive_path(filename: str) -> bool:
    """Keep CI policy and Harness control files on the existing T3 risk route."""
    normalized = filename.replace(chr(92), "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    sensitive_roots = (".agents", ".github", ".harness", ".codex")
    return (normalized == "AGENTS.md"
            or normalized.endswith("/AGENTS.md")
            or normalized in sensitive_roots
            or normalized.startswith(tuple(f"{root}/" for root in sensitive_roots))
            or normalized in {"scripts/harness.py", "scripts/harness_common.py", "scripts/harness_risk.py",
                              "scripts/harness_doctor.py", "scripts/harness_evidence.py", "scripts/command_runner.py",
            "scripts/github_expression_scanner.py", "scripts/check_ci_security.py", "scripts/ci_action_policy.py",
            "scripts/verify_ci.py"}
            or normalized.startswith("scripts/check_") or normalized.startswith("scripts/validate"))


def main() -> int:
    args = parse_args()
    try:
        result = check_security_policy(root=Path(args.root))
    except (OSError, RuntimeError, ValueError) as exc:
        result = _result([f"CI policy inspection failed: {exc}"], [], [], [], [])
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
