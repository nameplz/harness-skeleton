#!/usr/bin/env python3
"""Check the Full-profile jobs associated with the current head of a GitHub PR."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Sequence

try:
    from .command_runner import run_bounded_command
    from .harness import load_config
    from .harness_common import sanitize_log
    from .harness_evidence import capture_workspace
except ImportError:  # Direct script invocation from the scripts directory.
    from command_runner import run_bounded_command
    from harness import load_config
    from harness_common import sanitize_log
    from harness_evidence import capture_workspace

GH_TIMEOUT_SECONDS = 20
MAX_GH_OUTPUT_BYTES = 1024 * 1024
REPOSITORY_RE = re.compile(r"(?:[A-Za-z0-9.-]+/)?[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
PR_FIELDS = "number,state,headRefOid,baseRefName,url"
CHECK_FIELDS = "name,state,bucket,workflow,event,link,startedAt,completedAt"
GH_PENDING_EXIT = 8
CI_CONTROL_FILES = (
    "scripts/command_runner.py",
    "scripts/harness.py",
    "scripts/harness_doctor.py",
    "scripts/harness_common.py",
    "scripts/harness_evidence.py",
    "scripts/harness_risk.py",
    "scripts/github_expression_scanner.py",
    "scripts/check_ci_security.py",
    "scripts/ci_action_policy.py",
    "scripts/verify_ci.py",
)


class VerificationError(Exception):
    """A GitHub result could not be safely verified."""


def verify_ci(root: Path, pr_number: int, *, repository: str | None = None) -> dict[str, Any]:
    workspace = root.resolve(strict=True)
    if isinstance(pr_number, bool) or not isinstance(pr_number, int) or pr_number < 1:
        return _result("blocked", "PR number must be a positive integer")
    if repository is not None and not _valid_repository(repository):
        return _result("blocked", "repository must be OWNER/REPO or HOST/OWNER/REPO")

    try:
        config, policy = _load_local_ci_policy(workspace)
    except VerificationError as exc:
        return _result("blocked", sanitize_log(str(exc)))
    except ImportError:
        return _result("blocked", "local CI control scripts are unavailable")
    except (OSError, RuntimeError, ValueError) as exc:
        return _result("blocked", f"local CI configuration could not be read: {sanitize_log(str(exc))}")
    if not config.quick or not config.full or not policy["ok"]:
        return _result("blocked", "local CI is not configured and policy-clean", errors=policy.get("errors", []))

    before = capture_workspace(workspace)
    blocked = _evidence_error(before)
    if blocked:
        return _result("blocked", blocked, errors=policy.get("errors", []), evidence=before)
    if before.get("dirty") is not False:
        return _result("blocked", "local workspace has uncommitted changes", evidence=before)

    try:
        remote = _read_verified_checks(
            workspace, pr_number, repository, before, policy["required_checks"], config.config_sha256
        )
    except (OSError, RuntimeError, ValueError, VerificationError, subprocess.SubprocessError) as exc:
        return _result("blocked", sanitize_log(str(exc)), evidence=before)

    job_results = remote["required_checks"]
    status = _overall_status([item["status"] for item in job_results])
    errors = [f"{item['job_id']}: {item['status']}" for item in job_results if item["status"] != "success"]
    pr_data = remote["pull_request"]
    return {
        "ok": status == "success",
        "status": status,
        "repository": remote["repository"],
        "pr": pr_number,
        "url": pr_data.get("url"),
        "base_branch": pr_data.get("baseRefName"),
        "head_sha": remote["head_sha"],
        "required_checks": job_results,
        "errors": errors,
        "evidence": {**before, "config_sha256": config.config_sha256},
        "warnings": policy.get("warnings", []),
    }


def _load_local_ci_policy(workspace: Path) -> tuple[Any, dict[str, Any]]:
    _require_tracked_ci_inputs(workspace)
    try:
        from .check_ci_security import check_security_policy
    except ImportError:  # Direct script invocation from the scripts directory.
        from check_ci_security import check_security_policy
    return load_config(workspace), check_security_policy(root=workspace)


def _read_verified_checks(workspace: Path, pr_number: int, repository: str | None,
                          before: dict[str, Any], required: list[dict[str, str]],
                          config_sha256: str) -> dict[str, Any]:
    repo_data = _gh_json(workspace, ["repo", "view", "--json", "nameWithOwner"], repository, accepted_codes={0})
    repo_name = repo_data.get("nameWithOwner") if isinstance(repo_data, dict) else None
    if not isinstance(repo_name, str) or not REPOSITORY_RE.fullmatch(repo_name):
        raise VerificationError("GitHub repository identity was unavailable")
    pr_data = _gh_json(workspace, ["pr", "view", str(pr_number), "--json", PR_FIELDS], repo_name, accepted_codes={0})
    if not isinstance(pr_data, dict) or pr_data.get("number") != pr_number:
        raise VerificationError("GitHub did not return the requested pull request")
    if str(pr_data.get("state", "")).casefold() != "open":
        raise VerificationError("pull request is not open")
    head_sha = pr_data.get("headRefOid")
    if not isinstance(head_sha, str) or before.get("head") != head_sha:
        raise VerificationError("local HEAD does not match the current pull request head")

    checks_data = _gh_json(workspace, ["pr", "checks", str(pr_number), "--json", CHECK_FIELDS], repo_name,
                           accepted_codes={0, 1, GH_PENDING_EXIT})
    if not isinstance(checks_data, list):
        raise VerificationError("GitHub check results were not a JSON list")
    job_results = _match_required_checks(required, checks_data)
    latest = _gh_json(workspace, ["pr", "view", str(pr_number), "--json", PR_FIELDS], repo_name, accepted_codes={0})
    if not isinstance(latest, dict) or latest.get("headRefOid") != head_sha:
        raise VerificationError("pull request head changed while checks were being read")
    after = capture_workspace(workspace)
    blocked = _evidence_error(after)
    if blocked:
        raise VerificationError(blocked)
    if _identity(before) != _identity(after) or after.get("dirty") is not False:
        raise VerificationError("local source or CI configuration changed during verification")
    _require_tracked_ci_inputs(workspace)
    if load_config(workspace).config_sha256 != config_sha256:
        raise VerificationError("local validation configuration changed during verification")
    return {"repository": repo_name, "pull_request": pr_data, "head_sha": head_sha,
            "required_checks": job_results}


def _require_tracked_ci_inputs(workspace: Path) -> None:
    try:
        from .check_ci_security import workflow_files
    except ImportError:  # Direct script invocation from the scripts directory.
        from check_ci_security import workflow_files
    required = {".harness/config.toml", *CI_CONTROL_FILES,
                *(path.relative_to(workspace).as_posix() for path in workflow_files(workspace))}
    actions_root = workspace / ".github/actions"
    if actions_root.is_dir() and not actions_root.is_symlink():
        required.update(
            path.relative_to(workspace).as_posix()
            for path in actions_root.rglob("*")
            if path.is_file() or path.is_symlink()
        )
    result = run_bounded_command(
        ["git", "ls-files", "-v", "-z", "--", ".harness/config.toml", ".github/workflows",
         ".github/actions", *CI_CONTROL_FILES],
        cwd=workspace,
        timeout_seconds=GH_TIMEOUT_SECONDS,
        max_output_bytes=MAX_GH_OUTPUT_BYTES,
    )
    if result.timed_out or result.output_limited or result.returncode != 0:
        raise VerificationError("Git could not confirm committed CI inputs")
    tracked: set[str] = set()
    for entry in filter(None, result.output.split("\0")):
        if len(entry) < 3 or entry[1] != " ":
            raise VerificationError("Git returned invalid CI input tracking data")
        if entry[0] != "H":
            raise VerificationError("Git index flags can hide local CI input changes")
        tracked.add(entry[2:])
    if not required.issubset(tracked):
        raise VerificationError("all CI inputs must be committed at the PR head")
    for relative in required:
        path = workspace / relative
        try:
            if path.is_symlink() or not path.is_file():
                raise ValueError
            resolved = path.resolve(strict=True)
            resolved.relative_to(workspace)
            parent = path.parent
            while parent != workspace:
                if parent.is_symlink():
                    raise ValueError
                parent = parent.parent
        except (OSError, RuntimeError, ValueError):
            raise VerificationError("CI inputs must be regular files inside the repository") from None


def _result(status: str, message: str, *, errors: Sequence[str] = (),
            evidence: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"ok": False, "status": status, "repository": None, "pr": None, "url": None,
            "base_branch": None, "head_sha": None, "required_checks": [],
            "errors": [message, *errors], "evidence": evidence, "warnings": []}


def _evidence_error(evidence: dict[str, Any]) -> str | None:
    if evidence.get("status") != "ok" or not evidence.get("head"):
        return "local Git revision evidence is unavailable"
    if evidence.get("diff_sha256") is None:
        return "local dirty-diff evidence is unavailable"
    return None


def _identity(evidence: dict[str, Any]) -> tuple[Any, ...]:
    return evidence.get("status"), evidence.get("head"), evidence.get("dirty"), evidence.get("diff_sha256")


def _gh_json(root: Path, arguments: Sequence[str], repository: str | None, *, accepted_codes: set[int]) -> Any:
    command = ["gh", *arguments]
    if repository:
        command.extend(["--repo", repository])
    try:
        completed = run_bounded_command(
            command,
            cwd=root,
            timeout_seconds=GH_TIMEOUT_SECONDS,
            max_output_bytes=MAX_GH_OUTPUT_BYTES,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise VerificationError(f"GitHub CLI could not run: {sanitize_log(str(exc))}") from exc
    if completed.timed_out:
        raise VerificationError("GitHub request timed out")
    if completed.output_limited:
        raise VerificationError("GitHub response exceeded the output limit")
    if completed.returncode not in accepted_codes:
        detail = sanitize_log(completed.output.strip())
        lowered = detail.casefold()
        if any(term in lowered for term in ("disabled", "resource not accessible", "permission", "auth", "forbidden")):
            raise VerificationError("GitHub Actions or API access is blocked")
        raise VerificationError("GitHub API request failed" + (f": {detail}" if detail else ""))
    try:
        return json.loads(completed.output)
    except json.JSONDecodeError as exc:
        raise VerificationError("GitHub CLI returned invalid JSON") from exc


def _match_required_checks(expected: list[dict[str, str]], checks: list[Any]) -> list[dict[str, Any]]:
    matches_by_required: list[list[tuple[int, dict[str, Any]]]] = []
    owners: dict[int, list[int]] = {}
    for required_index, required in enumerate(expected):
        matches = [(index, check) for index, check in enumerate(checks)
                   if _matches_check(required, check)]
        matches_by_required.append(matches)
        for index, _check in matches:
            owners.setdefault(index, []).append(required_index)

    ambiguous = {index for index, required_indices in owners.items() if len(required_indices) > 1}
    results: list[dict[str, Any]] = []
    for required, matches in zip(expected, matches_by_required):
        if any(index in ambiguous for index, _check in matches):
            status = "blocked"
            latest_runs = [check for _index, check in matches]
        else:
            status, latest_runs = _summarize_check_runs([check for _index, check in matches])
        results.append({**required, "status": status,
                        "runs": [{"name": check.get("name"), "state": check.get("state"),
                                  "bucket": check.get("bucket"), "link": check.get("link")}
                                 for check in latest_runs]})
    return results


def _summarize_check_runs(matches: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    by_name: dict[str, list[dict[str, Any]]] = {}
    for check in matches:
        by_name.setdefault(str(check.get("name") or ""), []).append(check)
    latest_runs: list[dict[str, Any]] = []
    states: list[str] = []
    for runs in by_name.values():
        dated = [check for check in runs if _check_timestamp(check)]
        undated = [check for check in runs if not _check_timestamp(check)]
        if dated:
            latest = max(dated, key=_check_timestamp)
            latest_runs.append(latest)
            states.append(_check_status(latest))
        for check in undated:
            latest_runs.append(check)
            state = _check_status(check)
            states.append(state if state != "success" else "blocked")
    return (_overall_status(states) if states else "missing"), latest_runs


def _check_timestamp(check: dict[str, Any]) -> str:
    for field in ("startedAt", "completedAt"):
        value = check.get(field)
        if isinstance(value, str) and value:
            return value
    return ""


def _matches_check(required: dict[str, str], check: Any) -> bool:
    if not isinstance(check, dict):
        return False
    workflow = check.get("workflow")
    expected_workflow = Path(required["workflow_path"])
    allowed_workflows = {
        required["workflow"].casefold(), expected_workflow.name.casefold(), expected_workflow.stem.casefold()
    }
    if not isinstance(workflow, str) or workflow.casefold() not in allowed_workflows:
        return False
    if str(check.get("event") or "").casefold() != "pull_request":
        return False
    name = check.get("name")
    if not isinstance(name, str):
        return False
    job_name = name
    for workflow_name in sorted(allowed_workflows, key=len, reverse=True):
        prefix = f"{workflow_name} / "
        if name.casefold().startswith(prefix.casefold()):
            job_name = name[len(prefix):]
            break
    return job_name.casefold() == required["job_name"].casefold()


def _check_status(check: dict[str, Any]) -> str:
    bucket = str(check.get("bucket") or "").casefold()
    bucket_status = {"pass": "success", "fail": "failure", "pending": "pending",
                     "cancel": "cancelled", "skipping": "skipped"}.get(bucket)
    state = str(check.get("state") or "").casefold().replace(" ", "_")
    if state in {"success", "succeeded", "completed_successfully"}:
        state_status = "success"
    elif state in {"failure", "failed", "error", "startup_failure", "action_required"}:
        state_status = "failure"
    elif state in {"pending", "queued", "in_progress", "requested", "waiting", "expected"}:
        state_status = "pending"
    elif state in {"cancelled", "canceled"}:
        state_status = "cancelled"
    elif state in {"skipped", "neutral", "stale"}:
        state_status = "skipped"
    else:
        state_status = None
    if state_status not in {None, "success"}:
        return state_status
    if not bucket or bucket_status is None:
        return "blocked"
    if bucket_status not in {None, "success"}:
        return bucket_status
    return "success" if state_status == "success" and bucket_status in {None, "success"} else "blocked"


def _valid_repository(repository: str) -> bool:
    if not isinstance(repository, str) or not REPOSITORY_RE.fullmatch(repository):
        return False
    return all(component not in {".", ".."} for component in repository.split("/"))


def _overall_status(states: Sequence[str]) -> str:
    for status in ("failure", "cancelled", "skipped", "pending", "missing", "blocked"):
        if status in states:
            return status
    return "success" if states and all(status == "success" for status in states) else "missing"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify required GitHub Actions checks for a pull request.")
    parser.add_argument("--pr", type=int, required=True, help="pull request number")
    parser.add_argument("--repo", help="OWNER/REPO or HOST/OWNER/REPO; defaults to the current repository")
    parser.add_argument("--root", default=".", help="local repository root at the PR head revision")
    args = parser.parse_args(argv)
    try:
        result = verify_ci(Path(args.root), args.pr, repository=args.repo)
    except (OSError, RuntimeError, ValueError) as exc:
        result = _result("blocked", sanitize_log(str(exc)))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
