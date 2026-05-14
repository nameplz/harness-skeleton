import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def load_hook(name: str):
    path = ROOT / ".codex" / "hooks" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_command_policy_allows_safe_command():
    command_policy = load_hook("command_policy")

    assert command_policy.evaluate_command("pytest -q") is None


def test_command_policy_blocks_destructive_command():
    command_policy = load_hook("command_policy")

    reason = command_policy.evaluate_command("git reset --hard")

    assert reason is not None
    assert "git reset --hard" in reason


def test_pre_tool_use_denial_shape():
    command_policy = load_hook("command_policy")

    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "rm -rf ."},
    }
    result = command_policy.evaluate_payload(payload)

    assert result["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_permission_request_denial_shape():
    command_policy = load_hook("command_policy")

    payload = {
        "hook_event_name": "PermissionRequest",
        "tool_name": "Bash",
        "tool_input": {"command": "git push --force origin main"},
    }
    result = command_policy.evaluate_payload(payload)

    decision = result["hookSpecificOutput"]["decision"]
    assert result["hookSpecificOutput"]["hookEventName"] == "PermissionRequest"
    assert decision["behavior"] == "deny"


def test_stop_validation_skips_when_no_project_commands(tmp_path):
    stop_validation = load_hook("stop_validation")

    commands = stop_validation.select_validation_commands(tmp_path)

    assert commands == []


def test_stop_validation_selects_package_json_scripts(tmp_path):
    stop_validation = load_hook("stop_validation")
    package_json = {
        "scripts": {
            "lint": "eslint .",
            "build": "next build",
            "test": "vitest",
            "dev": "next dev",
        }
    }
    (tmp_path / "package.json").write_text(json.dumps(package_json))

    commands = stop_validation.select_validation_commands(tmp_path)

    assert commands == [
        ["npm", "run", "lint"],
        ["npm", "run", "build"],
        ["npm", "run", "test"],
    ]


def test_pre_commit_validation_detects_git_commit():
    pre_commit_validation = load_hook("pre_commit_validation")

    assert pre_commit_validation.is_git_commit_command("git commit -m test")
    assert pre_commit_validation.is_git_commit_command("rtk git commit -m test")
    assert pre_commit_validation.is_git_commit_command("rtk proxy git commit -m test")


def test_pre_commit_validation_ignores_non_commit():
    pre_commit_validation = load_hook("pre_commit_validation")

    payload = {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "git status"},
    }

    assert pre_commit_validation.evaluate_payload(payload) is None


def test_pre_commit_validation_blocks_failed_validation(tmp_path, monkeypatch):
    pre_commit_validation = load_hook("pre_commit_validation")
    monkeypatch.setattr(
        pre_commit_validation.project_validation,
        "validation_failure",
        lambda cwd: "`npm run test` failed.",
    )
    payload = {
        "cwd": str(tmp_path),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "git commit -m test"},
    }

    result = pre_commit_validation.evaluate_payload(payload)

    assert result["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert result["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "npm run test" in result["hookSpecificOutput"]["permissionDecisionReason"]


def test_pre_commit_validation_allows_passed_validation(tmp_path, monkeypatch):
    pre_commit_validation = load_hook("pre_commit_validation")
    monkeypatch.setattr(
        pre_commit_validation.project_validation,
        "validation_failure",
        lambda cwd: None,
    )
    payload = {
        "cwd": str(tmp_path),
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "git commit -m test"},
    }

    assert pre_commit_validation.evaluate_payload(payload) is None
