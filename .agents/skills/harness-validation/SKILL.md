---
name: harness-validation
description: Generate or update .harness/validation.json for a project by reading filled project docs and configuration files. Use when setting up Harness validation commands for Codex hooks, pre-commit checks, phase execution verification, or when adapting the language-neutral Harness skeleton to Node or Python projects.
---

# Harness Validation

## Overview

Create or update `.harness/validation.json` so project validation is explicit, repeatable, and safe for hooks and phase steps to run.

Harness is language-neutral. Do not assume npm, Node, Python, pytest, or any other stack unless the project docs or repository files establish it. The preferred workflow is to fill project placeholders first, then run the configuration CLI.

This skill configures validation commands only. It does not install dependencies, run dev servers, deploy, migrate data, or rewrite project files through formatters.

## Workflow

1. Read project intent and constraints first:
   - `AGENTS.md`
   - `docs/PRD.md`
   - `docs/ARCHITECTURE.md`
   - `docs/ADR.md`
   - `docs/UI_GUIDE.md` when UI exists
2. Confirm that unresolved `{...}` placeholders have been filled. If placeholders remain, stop and ask the user to complete the project spec unless they explicitly want an early validation draft.
3. Inspect actual project configuration before choosing commands:
   - Node/JavaScript/TypeScript: `package.json`, lockfiles, framework configs, `tsconfig.json`
   - Python: `pyproject.toml`, `pytest.ini`, `setup.cfg`, `requirements*.txt`, lockfiles, test files
   - Other stacks: language-specific manifests and test config
4. Prefer the CLI:
   - Preview: `python3 scripts/configure_harness.py --dry-run`
   - Write config: `python3 scripts/configure_harness.py`
   - Overwrite existing config: `python3 scripts/configure_harness.py --force`
   - Early setup with template placeholders: `python3 scripts/configure_harness.py --allow-placeholders`
5. Verify configured validation:
   - `python3 scripts/validate_project.py`
6. If validation tools are declared but unavailable in the current environment, tell the user which dependency setup command to run manually. Do not run dependency installation.
7. Summarize configured validation commands and any manual setup needed.

## Validation JSON Format

Use this shape:

```json
{
  "language": "typescript",
  "stack": "vite",
  "package_manager": "pnpm",
  "commands": [
    {
      "name": "lint",
      "command": ["pnpm", "run", "lint"],
      "reason": "Run project lint rules"
    }
  ]
}
```

Rules:

- `commands` must be a list.
- Each command item must include `name`, `command`, and `reason`.
- `command` must be a non-empty `list[str]`.
- Do not use a shell string such as `"npm run lint"`.
- Prefer commands already declared by the project over invented commands.
- Prefer `python3 scripts/configure_harness.py` for generation instead of hand-writing JSON.

## Safe Command Policy

Allowed validation commands are repeatable checks, such as:

- syntax checks
- lint checks without `--fix`
- type checks
- build checks
- test commands
- coverage reporting when the project already supports it

Do not include commands that:

- install dependencies: `npm install`, `pnpm install`, `pip install`, `uv sync`, `poetry install`
- rewrite files: `ruff --fix`, `black .`, `isort .`, formatter commands without check mode
- start long-running processes: dev servers, watch mode, background workers
- deploy, publish, migrate, seed, or reset data
- require credentials, API keys, browser login, or paid external services

## Node Detection Defaults

When `package.json` exists:

- Detect package manager from lockfiles:
  - `pnpm-lock.yaml` -> `pnpm`
  - `bun.lock` or `bun.lockb` -> `bun`
  - `yarn.lock` -> `yarn`
  - fallback -> `npm`
- Detect TypeScript from `tsconfig.json`, TypeScript dependencies, or `.ts`/`.tsx` files.
- Detect common stacks from dependencies/configs: `nextjs`, `vite`, `react`, `express`, otherwise `node`.
- Include only existing safe scripts in this order:
  - `lint`
  - `typecheck`
  - `build`
  - `test`

Example:

```json
{
  "language": "typescript",
  "stack": "nextjs",
  "package_manager": "pnpm",
  "commands": [
    {
      "name": "lint",
      "command": ["pnpm", "run", "lint"],
      "reason": "Run project lint rules"
    },
    {
      "name": "typecheck",
      "command": ["pnpm", "run", "typecheck"],
      "reason": "Run project type checks"
    },
    {
      "name": "build",
      "command": ["pnpm", "run", "build"],
      "reason": "Verify project build"
    },
    {
      "name": "test",
      "command": ["pnpm", "run", "test"],
      "reason": "Run project tests"
    }
  ]
}
```

## Python Detection Defaults

When Python project evidence exists:

- Detect from `pyproject.toml`, `setup.py`, `setup.cfg`, `pytest.ini`, `tox.ini`, `requirements*.txt`, `uv.lock`, `poetry.lock`, `Pipfile`, or `.py` files.
- Detect package runner:
  - `uv.lock` or `[tool.uv]` -> `uv run`
  - `poetry.lock` or `[tool.poetry]` -> `poetry run`
  - `Pipfile` -> `pipenv run`
  - fallback -> `python3 -m`
- Always include a syntax check using `compileall`.
- Exclude Harness/control/cache directories from Python syntax walks: `.git`, `.codex`, `.agents`, `.harness`, virtualenvs, `node_modules`, cache dirs, `build`, and `dist`.
- Include `ruff` only when configured or declared.
- Include `mypy` or `pyright` only when configured or declared.
- Include `pytest` when configured, declared, or test files exist.

Example:

```json
{
  "language": "python",
  "stack": "python",
  "package_manager": "uv",
  "commands": [
    {
      "name": "syntax",
      "command": [
        "python3",
        "-m",
        "compileall",
        "-q",
        "-x",
        "(^|/)(\\.git|\\.hg|\\.svn|\\.codex|\\.agents|\\.harness|\\.venv|venv|env|node_modules|__pycache__|\\.pytest_cache|\\.mypy_cache|\\.ruff_cache|build|dist)(/|$)",
        "."
      ],
      "reason": "Check Python syntax"
    },
    {
      "name": "lint",
      "command": ["uv", "run", "ruff", "check", "."],
      "reason": "Run configured Python lint rules"
    },
    {
      "name": "test",
      "command": ["uv", "run", "pytest", "-q"],
      "reason": "Run Python tests"
    }
  ]
}
```

## Mixed Projects

If both Node and Python are detected, include both sets of safe commands and prefix command names by language, such as `typescript-lint` and `python-test`. Keep command execution deterministic and avoid duplicate names.

## Dependency Setup Guidance

Do not run dependency installation. If tools are configured but missing, output a manual setup note.

Example:

```text
Created .harness/validation.json

Configured validation:
- syntax: python3 -m compileall -q -x <exclude-pattern> .
- lint: uv run ruff check .
- test: uv run pytest -q

Dependency setup needed:
- uv sync

I did not run dependency installation. Run it manually before relying on lint/test validation.
```
