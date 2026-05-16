---
name: harness-validation
description: Generate or update .harness/validation.json for a project by reading project docs and configuration files. Use when setting up harness validation commands for Codex hooks, pre-commit checks, or phase execution verification.
---

# Harness Validation

## Overview

Create or update `.harness/validation.json` so project validation is explicit, repeatable, and safe for hooks to run.

The skill configures validation commands only. It does not install dependencies, run dev servers, deploy, migrate data, or rewrite project files through formatters.

## Workflow

1. Read project intent and constraints first:
   - `AGENTS.md`
   - `docs/PRD.md`
   - `docs/ARCHITECTURE.md`
   - `docs/ADR.md`
   - `docs/UI_GUIDE.md`
2. Inspect actual project configuration before choosing commands:
   - JavaScript/TypeScript: `package.json`, lockfiles, framework configs
   - Python: `pyproject.toml`, `pytest.ini`, `setup.cfg`, `requirements*.txt`, lockfiles
   - Other stacks: language-specific manifests and test config
3. Create or update `.harness/validation.json` with only commands that are safe to repeat in hooks.
4. If validation tools are declared but unavailable in the current environment, tell the user which dependency setup command to run manually. Do not run dependency installation.
5. Summarize configured validation commands and any manual setup needed.

## Validation JSON Format

Use this shape:

```json
{
  "language": "typescript",
  "stack": "nextjs",
  "package_manager": "npm",
  "commands": [
    {
      "name": "lint",
      "command": ["npm", "run", "lint"],
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

## Safe Command Policy

Allowed validation commands are read-only checks, such as:

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

## Dependency Setup Guidance

Do not run dependency installation. If tools are configured but missing, output a manual setup note.

Example:

```text
Created .harness/validation.json

Configured validation:
- syntax: python3 -m compileall -q .
- lint: uv run ruff check .
- test: uv run pytest -q

Dependency setup needed:
- uv sync

I did not run dependency installation. Run it manually before relying on lint/test validation.
```

## Stack Examples

Python with `uv`:

```json
{
  "language": "python",
  "stack": "python",
  "package_manager": "uv",
  "commands": [
    {
      "name": "syntax",
      "command": ["python3", "-m", "compileall", "-q", "."],
      "reason": "Check Python syntax"
    },
    {
      "name": "lint",
      "command": ["uv", "run", "ruff", "check", "."],
      "reason": "Run configured lint rules"
    },
    {
      "name": "test",
      "command": ["uv", "run", "pytest", "-q"],
      "reason": "Run project tests"
    }
  ]
}
```

Node with npm:

```json
{
  "language": "typescript",
  "stack": "nextjs",
  "package_manager": "npm",
  "commands": [
    {
      "name": "lint",
      "command": ["npm", "run", "lint"],
      "reason": "Run project lint rules"
    },
    {
      "name": "build",
      "command": ["npm", "run", "build"],
      "reason": "Verify production build"
    },
    {
      "name": "test",
      "command": ["npm", "run", "test"],
      "reason": "Run project tests"
    }
  ]
}
```
