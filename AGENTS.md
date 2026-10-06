# Harness Skeleton Agent Guide

## Read when relevant

- Runtime boundaries and validation: `docs/ARCHITECTURE.md`
- Durable design decisions: `docs/ADR.md`
- Task routing, planning, and review: `.agents/skills/harness/SKILL.md`
- GitHub PR publication and CI completion: `.agents/skills/pr-workflow/SKILL.md`
- Project validation and risk settings: `.harness/config.toml`
- Product scope: `docs/PRD.md`; visual work: `docs/UI_GUIDE.md`

## Core invariants

- Codex owns planning, context, tool use, delegation, and implementation. Harness scripts provide deterministic validation, risk signals, and setup checks.
- Project validation commands are explicit argv arrays. Never infer a language tool or invoke a command through a shell.
- Invalid configuration, unsafe paths, and failed required checks stop the operation. Bound captured output and redact known credential-shaped values and email addresses.
- Keep one implementation writer. Use subagents only for independent read-only investigation or review.
- Commit each completed task after configured checks and required reviews pass. Keep incomplete, failed, unrelated, and pre-existing user changes out of the commit; honor explicit no-commit requests. Push or merge only when asked.

## Development

- Add or update tests for behavior changes. Run `python scripts/harness.py check --quick` for focused work and `--full` before completion when configured.
- Run `python scripts/harness.py risk` after code changes and follow its review signals. CI remains the trusted merge gate.
