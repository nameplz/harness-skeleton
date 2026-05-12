#!/usr/bin/env python3
"""Run available project validation commands when a Codex turn stops."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


SCRIPT_COMMANDS = (
    ("lint", ["npm", "run", "lint"]),
    ("build", ["npm", "run", "build"]),
    ("test", ["npm", "run", "test"]),
)


def _read_payload() -> dict:
    try:
        return json.load(sys.stdin)
    except json.JSONDecodeError:
        return {}


def _load_package_scripts(cwd: Path) -> set[str]:
    package_json = cwd / "package.json"
    if not package_json.exists():
        return set()
    try:
        data = json.loads(package_json.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return set()
    scripts = data.get("scripts", {})
    return set(scripts) if isinstance(scripts, dict) else set()


def _run_command(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=90,
    )


def main() -> int:
    payload = _read_payload()
    cwd = Path(payload.get("cwd") or ".").resolve()
    if payload.get("stop_hook_active"):
        print(json.dumps({"continue": True}))
        return 0

    scripts = _load_package_scripts(cwd)
    commands = [(name, command) for name, command in SCRIPT_COMMANDS if name in scripts]
    if not commands:
        print(json.dumps({"continue": True}))
        return 0

    failures: list[str] = []
    for name, command in commands:
        result = _run_command(command, cwd)
        if result.returncode != 0:
            output = "\n".join(part for part in (result.stdout, result.stderr) if part).strip()
            failures.append(f"`{' '.join(command)}` failed with exit code {result.returncode}.\n{output[-3000:]}")

    if not failures:
        print(json.dumps({"continue": True}))
        return 0

    print(
        json.dumps(
            {
                "decision": "block",
                "reason": "Project validation failed. Fix the following before finishing:\n\n"
                + "\n\n".join(failures),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
