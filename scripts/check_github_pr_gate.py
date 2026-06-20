#!/usr/bin/env python3
"""Check GitHub PR gate before enabling Harness auto-merge."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from typing import Any


REQUIRED_CHECKS = ("security-policy", "pr-contract", "harness-core", "project-validation")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    return parser.parse_args()


def run_json(command: list[str]) -> dict[str, Any]:
    completed = subprocess.run(command, capture_output=True, text=True, timeout=60, shell=False)
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip() or "gh command failed")
    return json.loads(completed.stdout or "{}")


def check_repo_gate(repo: str) -> list[str]:
    errors: list[str] = []
    repo_data = run_json(["gh", "api", f"repos/{repo}"])
    if repo_data.get("allow_auto_merge") is not True:
        errors.append("GitHub auto-merge is not enabled")

    try:
        protection = run_json(["gh", "api", f"repos/{repo}/branches/main/protection"])
    except RuntimeError as exc:
        errors.append(f"main branch protection is missing or unreadable: {exc}")
        protection = {}

    contexts = required_contexts(protection)
    missing_contexts = [name for name in REQUIRED_CHECKS if name not in contexts]
    if missing_contexts:
        errors.append("Missing required branch checks: " + ", ".join(missing_contexts))

    try:
        pr_data = run_json(["gh", "pr", "view", "--repo", repo, "--json", "statusCheckRollup"])
    except RuntimeError as exc:
        errors.append(f"Current branch PR is missing or unreadable: {exc}")
        return errors

    check_status = status_check_map(pr_data.get("statusCheckRollup", []))
    incomplete = [name for name in REQUIRED_CHECKS if check_status.get(name) != "SUCCESS"]
    if incomplete:
        errors.append("Required PR checks are not successful: " + ", ".join(incomplete))
    return errors


def required_contexts(protection: dict[str, Any]) -> set[str]:
    status_checks = protection.get("required_status_checks")
    if not isinstance(status_checks, dict):
        return set()
    contexts = status_checks.get("contexts")
    if isinstance(contexts, list):
        return {item for item in contexts if isinstance(item, str)}
    checks = status_checks.get("checks")
    if isinstance(checks, list):
        return {item["context"] for item in checks if isinstance(item, dict) and isinstance(item.get("context"), str)}
    return set()


def status_check_map(rollup: Any) -> dict[str, str]:
    if not isinstance(rollup, list):
        return {}
    results: dict[str, str] = {}
    for item in rollup:
        if not isinstance(item, dict):
            continue
        name = item.get("name") or item.get("context")
        conclusion = item.get("conclusion") or item.get("state") or item.get("status")
        if isinstance(name, str) and isinstance(conclusion, str):
            results[name] = conclusion.upper()
    return results


def main() -> int:
    args = parse_args()
    try:
        errors = check_repo_gate(args.repo)
    except (RuntimeError, json.JSONDecodeError) as exc:
        print(f"GitHub PR gate failed: {exc}", file=sys.stderr)
        return 1
    if not errors:
        print("GitHub PR gate passed")
        return 0
    print("GitHub PR gate failed:")
    for error in errors:
        print(f"- {error}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
