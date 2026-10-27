---
name: harness
description: Local deterministic validation, risk routing, and completion evidence.
---

# Harness workflow

## Risk and procedure

Run `python scripts/harness.py risk` on the final diff. It gives a minimum tier; never lower hard T2/T3 signals. Hints do not force review; escalate for material risks missed by the diff.

- **T0:** documentation or typos; run quick when configured, no reviewer.
- **T1:** ordinary local changes; update behavior tests, run quick, self-review, and report acceptance evidence.
- **T2:** public APIs, dependencies, cross-module contracts, `.harness/config.toml`, or `test_weakening`; run full and obtain one independent read-only `reviewer` review.
- **T3:** hooks, runner/risk scripts, auth/secrets/subprocess/SQL/migrations, or user-added `.github/workflows/**`; run full and obtain independent read-only `reviewer` and `security_reviewer` reviews.

Keep one implementation writer. Reviewers do not replace deterministic tests; no separate test-review role is needed. Reviewer findings cover only requirement gaps, incorrect behavior, regressions, missing tests, and justified or unjustified test_weakening signals. Security review is limited to changed trust boundaries. Exclude style, preferences, and hypothetical cases.

## Review request

Provide scope, acceptance criteria, final HEAD, dirty diff fingerprint, config identity, and validation evidence. Request `status`, `summary`, `findings`, `evidence`, and `recommendation`. Each finding needs `path:line` and a concrete failure scenario; require an explicit no-findings result when passing. Reviewers must not edit, commit, send messages, or perform external writes. Revalidate and review affected changes after edits; stale evidence cannot cover a new diff.

## Validation profile setup

Choose Python 3.11+: try `python3`, `python`, then `py -3`. Use the working command consistently locally and in adapter hooks (`.codex/config.toml`, `.claude/settings.json`). `doctor` checks hook interpreters and suggests replacements in `next_action`; it never rewrites configuration.

Adapter compatibility: Codex hooks use Git-root-based paths because sessions may start in subdirectories. Their `$(git rev-parse --show-toplevel)` requires POSIX shell (Windows: Git Bash), not cmd.exe/PowerShell. Claude uses `${CLAUDE_PROJECT_DIR}`. Codex reference: https://developers.openai.com/codex/hooks/.

Use this section when `doctor` reports `unconfigured` or the project's test, lint, or build setup changes. Start with `python scripts/harness.py doctor --bootstrap`. Inspect multiple files for languages, runtime versions, package manager, lockfiles, workspace layout, real test files and runners, and lint/type/build configuration. Cross-check package scripts against the lockfile; a manifest alone is insufficient. Identify required non-secret test settings and services without forwarding credentials.

Write `checks.quick` for useful fast development checks and `checks.full` for actual tests plus configured lint/type/build checks in `.harness/config.toml`. Use argv arrays; execution uses `shell=False`. Keep dependency installation commands and credentials out of profiles. Do not put long-running resident processes (for example, `npm run watch`) in check profiles; checks must terminate. Never invent tools, tests, or versions. If no meaningful validation exists, leave the project unconfigured and report why; an empty profile is not a pass.

Run `python scripts/harness.py check --quick`, `python scripts/harness.py check --full`, and `python scripts/harness.py doctor`. Configuration changes require T2 review at minimum.

## Completion and task commits

Define 2–5 acceptance criteria before work when none exist. For T1+, report a table of criterion → command, exit code, and 1–3 key output lines; mark unsupported items unverified. Check `evidence`, `evidence_after`, and `evidence_unchanged`; source/config changes during validation invalidate success. Null identity is unavailable evidence.

Install the commit gate during setup with `python scripts/harness.py install-gate`. Run `python scripts/harness.py check --full` before committing to catch failures early; `python scripts/harness.py gate` requires quick for T0/T1 and full for T2/T3 or failed risk classification, bound to the current HEAD, diff, and config. Commit each completed task separately after configured checks and required reviews pass. Keep dependent changes together, exclude unrelated changes and pre-existing user edits, and leave unfinished or failed work uncommitted. Honor explicit no-commit instructions.

Remote work only when requested by the user.

## Session start

Run `python scripts/harness.py status`, then read ongoing `.harness/tasks/*.md` notes. Without a passing record matching current evidence, run `python scripts/harness.py check --quick` before new work. Unconfigured profiles need setup first. SessionStart hooks are optional.

For multi-session work, use `.harness/task-template.md` for acceptance evidence, constraints, decisions, state, and next action. Skip routine notes; never store credentials or conversations.
