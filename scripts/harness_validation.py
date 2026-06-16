"""Project stack detection and validation helpers for Harness projects."""

from __future__ import annotations

import json
import re
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


HARNESS_VALIDATION_FILE = Path(".harness") / "validation.json"
VALIDATION_TIMEOUT_SECONDS = 300
VALIDATION_SCRIPT_ORDER = ("lint", "typecheck", "build", "test")
PYTHON_COMPILEALL_EXCLUDE_PATTERN = (
    r"(^|/)(\.git|\.hg|\.svn|\.codex|\.agents|\.harness|\.venv|venv|env|node_modules|__pycache__|"
    r"\.pytest_cache|\.mypy_cache|\.ruff_cache|build|dist)(/|$)"
)
PLACEHOLDER_FILES = (
    "AGENTS.md",
    "docs/PRD.md",
    "docs/ARCHITECTURE.md",
    "docs/ADR.md",
    "docs/UI_GUIDE.md",
)
PLACEHOLDER_PATTERN = re.compile(r"\{[^{}\n]+\}")
IGNORED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".codex",
    ".agents",
    ".harness",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "build",
    "dist",
}


@dataclass(frozen=True)
class PlaceholderOccurrence:
    """An unresolved template placeholder in a project specification file."""

    relative_path: str
    line: int
    text: str


class ValidationConfigError(ValueError):
    """Raised when .harness/validation.json cannot be used safely."""


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _read_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as file:
            data = tomllib.load(file)
    except (OSError, tomllib.TOMLDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _iter_files(root: Path):
    for path in root.rglob("*"):
        if any(part in IGNORED_DIRS for part in path.relative_to(root).parts):
            continue
        if path.is_file():
            yield path


def _has_file(root: Path, *names: str) -> bool:
    return any((root / name).exists() for name in names)


def _safe_lower_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").lower()
    except OSError:
        return ""


def _dependency_names(package_data: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        value = package_data.get(key)
        if isinstance(value, dict):
            names.update(str(name).lower() for name in value)
    return names


def _node_package_manager(root: Path) -> str:
    if (root / "pnpm-lock.yaml").exists():
        return "pnpm"
    if (root / "bun.lock").exists() or (root / "bun.lockb").exists():
        return "bun"
    if (root / "yarn.lock").exists():
        return "yarn"
    return "npm"


def _node_run_command(package_manager: str, script_name: str) -> list[str]:
    return [package_manager, "run", script_name]


def _has_source_file(root: Path, suffixes: tuple[str, ...]) -> bool:
    return any(path.suffix in suffixes for path in _iter_files(root))


def _node_language(root: Path, package_data: dict[str, Any]) -> str:
    dependencies = _dependency_names(package_data)
    if (
        (root / "tsconfig.json").exists()
        or "typescript" in dependencies
        or _has_source_file(root, (".ts", ".tsx"))
    ):
        return "typescript"
    return "javascript"


def _node_stack(root: Path, package_data: dict[str, Any]) -> str:
    dependencies = _dependency_names(package_data)
    config_names = {path.name for path in root.glob("*config.*")}
    if "next" in dependencies or any(name.startswith("next.config.") for name in config_names):
        return "nextjs"
    if "vite" in dependencies or any(name.startswith("vite.config.") for name in config_names):
        return "vite"
    if "react" in dependencies:
        return "react"
    if "express" in dependencies:
        return "express"
    return "node"


def _node_commands(package_data: dict[str, Any], package_manager: str) -> list[dict[str, Any]]:
    scripts = package_data.get("scripts")
    if not isinstance(scripts, dict):
        return []

    reasons = {
        "lint": "Run project lint rules",
        "typecheck": "Run project type checks",
        "build": "Verify project build",
        "test": "Run project tests",
    }
    return [
        {
            "name": script_name,
            "command": _node_run_command(package_manager, script_name),
            "reason": reasons[script_name],
        }
        for script_name in VALIDATION_SCRIPT_ORDER
        if script_name in scripts
    ]


def _detect_node_config(root: Path) -> dict[str, Any] | None:
    package_json = root / "package.json"
    if not package_json.exists():
        return None

    package_data = _read_json(package_json)
    if package_data is None:
        return None

    package_manager = _node_package_manager(root)
    return {
        "language": _node_language(root, package_data),
        "stack": _node_stack(root, package_data),
        "package_manager": package_manager,
        "commands": _node_commands(package_data, package_manager),
    }


def _pyproject_dependencies(pyproject: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    project = pyproject.get("project")
    if isinstance(project, dict):
        dependencies = project.get("dependencies")
        if isinstance(dependencies, list):
            names.update(_dependency_name(item) for item in dependencies if isinstance(item, str))
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for values in optional.values():
                if isinstance(values, list):
                    names.update(_dependency_name(item) for item in values if isinstance(item, str))

    tool = pyproject.get("tool")
    if isinstance(tool, dict) and isinstance(tool.get("poetry"), dict):
        poetry_deps = tool["poetry"].get("dependencies")
        poetry_groups = tool["poetry"].get("group")
        if isinstance(poetry_deps, dict):
            names.update(str(name).lower() for name in poetry_deps if name.lower() != "python")
        if isinstance(poetry_groups, dict):
            for group in poetry_groups.values():
                if isinstance(group, dict) and isinstance(group.get("dependencies"), dict):
                    names.update(str(name).lower() for name in group["dependencies"])
    return {name for name in names if name}


def _dependency_name(value: str) -> str:
    match = re.match(r"\s*([A-Za-z0-9_.-]+)", value)
    return match.group(1).lower().replace("_", "-") if match else ""


def _requirements_dependencies(root: Path) -> set[str]:
    names: set[str] = set()
    for path in root.glob("requirements*.txt"):
        for line in _safe_lower_text(path).splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "-")):
                continue
            names.add(_dependency_name(stripped))
    return names


def _python_package_manager(root: Path, pyproject: dict[str, Any]) -> str:
    tool = pyproject.get("tool")
    if (root / "uv.lock").exists() or (isinstance(tool, dict) and "uv" in tool):
        return "uv"
    if (root / "poetry.lock").exists() or (
        isinstance(tool, dict) and isinstance(tool.get("poetry"), dict)
    ):
        return "poetry"
    if (root / "Pipfile").exists():
        return "pipenv"
    return "python"


def _python_tool_command(package_manager: str, tool: str, args: list[str]) -> list[str]:
    if package_manager == "uv":
        return ["uv", "run", tool, *args]
    if package_manager == "poetry":
        return ["poetry", "run", tool, *args]
    if package_manager == "pipenv":
        return ["pipenv", "run", tool, *args]
    if tool == "pyright":
        return ["pyright", *args]
    return ["python3", "-m", tool, *args]


def _has_pytest_tests(root: Path) -> bool:
    for path in _iter_files(root):
        if path.suffix != ".py":
            continue
        if path.name.startswith("test_") or path.name.endswith("_test.py"):
            return True
        if "tests" in path.relative_to(root).parts:
            return True
    return False


def _has_python_files(root: Path) -> bool:
    return any(path.suffix == ".py" for path in _iter_files(root))


def _pyproject_tool(pyproject: dict[str, Any], name: str) -> bool:
    tool = pyproject.get("tool")
    return isinstance(tool, dict) and name in tool


def _setup_cfg_has(root: Path, section: str) -> bool:
    setup_cfg = root / "setup.cfg"
    return setup_cfg.exists() and f"[{section.lower()}]" in _safe_lower_text(setup_cfg)


def _python_has_project_evidence(root: Path) -> bool:
    return (
        _has_file(
            root,
            "pyproject.toml",
            "setup.py",
            "setup.cfg",
            "pytest.ini",
            "tox.ini",
            "uv.lock",
            "poetry.lock",
            "Pipfile",
        )
        or any(root.glob("requirements*.txt"))
        or _has_python_files(root)
    )


def _python_commands(
    root: Path,
    package_manager: str,
    pyproject: dict[str, Any],
) -> list[dict[str, Any]]:
    dependencies = _pyproject_dependencies(pyproject) | _requirements_dependencies(root)
    commands: list[dict[str, Any]] = [
        {
            "name": "syntax",
            "command": [
                "python3",
                "-m",
                "compileall",
                "-q",
                "-x",
                PYTHON_COMPILEALL_EXCLUDE_PATTERN,
                ".",
            ],
            "reason": "Check Python syntax",
        }
    ]

    has_ruff = (
        _pyproject_tool(pyproject, "ruff")
        or _has_file(root, "ruff.toml", ".ruff.toml")
        or "ruff" in dependencies
    )
    if has_ruff:
        commands.append(
            {
                "name": "lint",
                "command": _python_tool_command(package_manager, "ruff", ["check", "."]),
                "reason": "Run configured Python lint rules",
            }
        )

    has_mypy = (
        _pyproject_tool(pyproject, "mypy")
        or _has_file(root, "mypy.ini")
        or _setup_cfg_has(root, "mypy")
        or "mypy" in dependencies
    )
    has_pyright = (
        _pyproject_tool(pyproject, "pyright")
        or _has_file(root, "pyrightconfig.json")
        or "pyright" in dependencies
    )
    if has_mypy:
        commands.append(
            {
                "name": "typecheck",
                "command": _python_tool_command(package_manager, "mypy", ["."]),
                "reason": "Run configured Python type checks",
            }
        )
    elif has_pyright:
        commands.append(
            {
                "name": "typecheck",
                "command": _python_tool_command(package_manager, "pyright", []),
                "reason": "Run configured Python type checks",
            }
        )

    has_pytest = (
        _pyproject_tool(pyproject, "pytest")
        or _has_file(root, "pytest.ini")
        or _setup_cfg_has(root, "tool:pytest")
        or _has_pytest_tests(root)
        or "pytest" in dependencies
    )
    if has_pytest:
        commands.append(
            {
                "name": "test",
                "command": _python_tool_command(package_manager, "pytest", ["-q"]),
                "reason": "Run Python tests",
            }
        )
    return commands


def _detect_python_config(root: Path) -> dict[str, Any] | None:
    if not _python_has_project_evidence(root):
        return None

    pyproject = _read_toml(root / "pyproject.toml")
    package_manager = _python_package_manager(root, pyproject)
    return {
        "language": "python",
        "stack": "python",
        "package_manager": package_manager,
        "commands": _python_commands(root, package_manager, pyproject),
    }


def _prefix_commands(prefix: str, commands: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            **item,
            "name": f"{prefix}-{item['name']}",
        }
        for item in commands
    ]


def build_validation_config(root: Path) -> dict[str, Any]:
    """Detect project stack and return a .harness/validation.json payload."""
    root = root.resolve()
    configs = [item for item in (_detect_node_config(root), _detect_python_config(root)) if item]
    configs = [item for item in configs if item["commands"]]

    if not configs:
        return {
            "language": "unknown",
            "stack": "unknown",
            "package_manager": "unknown",
            "commands": [],
        }

    if len(configs) == 1:
        return configs[0]

    commands: list[dict[str, Any]] = []
    for config in configs:
        commands.extend(_prefix_commands(config["language"], config["commands"]))
    return {
        "language": "mixed",
        "stack": "+".join(config["stack"] for config in configs),
        "package_manager": "+".join(config["package_manager"] for config in configs),
        "commands": commands,
    }


def read_harness_validation_commands(path: Path) -> list[list[str]]:
    """Read and validate command arrays from .harness/validation.json."""
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValidationConfigError(f"invalid JSON: {exc.msg}") from exc

    if not isinstance(config, dict):
        raise ValidationConfigError("top-level value must be an object")

    commands = config.get("commands")
    if not isinstance(commands, list):
        raise ValidationConfigError("commands must be a list")

    selected = []
    for index, item in enumerate(commands):
        if not isinstance(item, dict):
            raise ValidationConfigError(f"commands[{index}] must be an object")

        command = item.get("command")
        if not isinstance(command, list):
            raise ValidationConfigError(f"commands[{index}].command must be a list[str]")
        if not command:
            raise ValidationConfigError(f"commands[{index}].command must be non-empty")
        if not all(isinstance(arg, str) and arg for arg in command):
            raise ValidationConfigError(f"commands[{index}].command must be a list[str]")

        selected.append(command)

    return selected


def select_validation_commands(cwd: Path) -> list[list[str]]:
    """Select validation commands from explicit config or safe stack detection."""
    cwd = cwd.resolve()
    harness_validation = cwd / HARNESS_VALIDATION_FILE
    if harness_validation.exists():
        return read_harness_validation_commands(harness_validation)

    config = build_validation_config(cwd)
    return [item["command"] for item in config["commands"]]


def run_validation(commands: list[list[str]], cwd: Path) -> tuple[bool, str]:
    """Run validation commands in order and return the first failure."""
    for command in commands:
        command_text = " ".join(command)
        try:
            result = subprocess.run(
                command,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=VALIDATION_TIMEOUT_SECONDS,
            )
        except FileNotFoundError:
            return False, f"`{command_text}` failed: command not found."
        except subprocess.TimeoutExpired:
            return False, (
                f"`{command_text}` timed out after "
                f"{VALIDATION_TIMEOUT_SECONDS} seconds."
            )

        if result.returncode != 0:
            output = (result.stdout + "\n" + result.stderr).strip()
            if len(output) > 2000:
                output = output[-2000:]
            return False, f"`{command_text}` failed.\n\n{output}"
    return True, ""


def validation_failure(cwd: Path) -> str | None:
    """Return a failure reason when configured validation does not pass."""
    try:
        commands = select_validation_commands(cwd)
    except ValidationConfigError as exc:
        return f"Invalid .harness/validation.json: {exc}"

    if not commands:
        return None

    passed, reason = run_validation(commands, cwd)
    return None if passed else reason


def find_unresolved_placeholders(root: Path) -> list[PlaceholderOccurrence]:
    """Find template placeholders that should be filled before configuring Harness."""
    occurrences: list[PlaceholderOccurrence] = []
    for relative_path in PLACEHOLDER_FILES:
        path = root / relative_path
        if not path.exists():
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for line_number, line in enumerate(lines, start=1):
            if PLACEHOLDER_PATTERN.search(line):
                occurrences.append(
                    PlaceholderOccurrence(
                        relative_path=relative_path,
                        line=line_number,
                        text=line.strip(),
                    )
                )
    return occurrences


def write_validation_config(root: Path, config: dict[str, Any]) -> Path:
    """Write .harness/validation.json and return its path."""
    path = root / HARNESS_VALIDATION_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(config, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path
