import importlib.util
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


def load_hook(name: str):
    path = ROOT / ".codex" / "hooks" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def load_script(name: str):
    path = ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
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


def test_select_validation_commands_detects_node_package_manager_and_typecheck(tmp_path):
    harness_validation = load_script("harness_validation")
    package_json = {
        "scripts": {
            "lint": "eslint .",
            "typecheck": "tsc --noEmit",
            "build": "next build",
            "test": "vitest",
        },
        "devDependencies": {"typescript": "^5.0.0"},
        "dependencies": {"next": "^15.0.0"},
    }
    (tmp_path / "package.json").write_text(json.dumps(package_json))
    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: '9.0'")

    commands = harness_validation.select_validation_commands(tmp_path)

    assert commands == [
        ["pnpm", "run", "lint"],
        ["pnpm", "run", "typecheck"],
        ["pnpm", "run", "build"],
        ["pnpm", "run", "test"],
    ]


def test_select_validation_commands_detects_python_project_commands(tmp_path):
    harness_validation = load_script("harness_validation")
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_example.py").write_text("def test_example():\n    assert True\n")

    commands = harness_validation.select_validation_commands(tmp_path)

    assert commands == [
        [
            "python3",
            "-m",
            "compileall",
            "-q",
            "-x",
            harness_validation.PYTHON_COMPILEALL_EXCLUDE_PATTERN,
            ".",
        ],
        ["python3", "-m", "pytest", "-q"],
    ]


def test_build_validation_config_detects_python_tools(tmp_path):
    harness_validation = load_script("harness_validation")
    pyproject = """
[project]
dependencies = ["pytest", "ruff", "mypy"]

[tool.ruff]
line-length = 100

[tool.mypy]
python_version = "3.12"
"""
    (tmp_path / "pyproject.toml").write_text(pyproject)

    config = harness_validation.build_validation_config(tmp_path)

    assert config["language"] == "python"
    assert config["stack"] == "python"
    assert config["commands"] == [
        {
            "name": "syntax",
            "command": [
                "python3",
                "-m",
                "compileall",
                "-q",
                "-x",
                harness_validation.PYTHON_COMPILEALL_EXCLUDE_PATTERN,
                ".",
            ],
            "reason": "Check Python syntax",
        },
        {
            "name": "lint",
            "command": ["python3", "-m", "ruff", "check", "."],
            "reason": "Run configured Python lint rules",
        },
        {
            "name": "typecheck",
            "command": ["python3", "-m", "mypy", "."],
            "reason": "Run configured Python type checks",
        },
        {
            "name": "test",
            "command": ["python3", "-m", "pytest", "-q"],
            "reason": "Run Python tests",
        },
    ]


def test_build_validation_config_detects_node_stack(tmp_path):
    harness_validation = load_script("harness_validation")
    package_json = {
        "scripts": {
            "lint": "eslint .",
            "typecheck": "tsc",
            "build": "vite build",
            "test": "vitest",
        },
        "dependencies": {"vite": "^6.0.0"},
        "devDependencies": {"typescript": "^5.0.0"},
    }
    (tmp_path / "package.json").write_text(json.dumps(package_json))
    (tmp_path / "bun.lock").write_text("")

    config = harness_validation.build_validation_config(tmp_path)

    assert config["language"] == "typescript"
    assert config["stack"] == "vite"
    assert config["package_manager"] == "bun"
    assert [item["command"] for item in config["commands"]] == [
        ["bun", "run", "lint"],
        ["bun", "run", "typecheck"],
        ["bun", "run", "build"],
        ["bun", "run", "test"],
    ]


def test_find_unresolved_placeholders_reports_spec_files(tmp_path):
    harness_validation = load_script("harness_validation")
    docs = tmp_path / "docs"
    docs.mkdir()
    (tmp_path / "AGENTS.md").write_text("# 프로젝트: {프로젝트명}\n")
    (docs / "PRD.md").write_text("# PRD\n## 목표\n{목표}\n")

    placeholders = harness_validation.find_unresolved_placeholders(tmp_path)

    assert [item.relative_path for item in placeholders] == ["AGENTS.md", "docs/PRD.md"]


def test_configure_harness_blocks_unresolved_placeholders(tmp_path):
    (tmp_path / "AGENTS.md").write_text("# 프로젝트: {프로젝트명}\n")
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_example.py").write_text("def test_example():\n    assert True\n")

    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "configure_harness.py"),
            "--root",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "Unresolved Harness placeholders" in result.stderr
    assert not (tmp_path / ".harness" / "validation.json").exists()


def test_configure_harness_writes_validation_config(tmp_path):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_example.py").write_text("def test_example():\n    assert True\n")

    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "configure_harness.py"),
            "--root",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    config_path = tmp_path / ".harness" / "validation.json"
    assert config_path.exists()
    config = json.loads(config_path.read_text())
    assert config["language"] == "python"
    assert [item["name"] for item in config["commands"]] == ["syntax", "test"]


def test_validate_project_returns_zero_without_commands(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "validate_project.py"),
            "--root",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert "No validation commands configured." in result.stdout


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
