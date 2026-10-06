---
name: harness
description: Route Harness tasks through Codex-native planning and risk-based validation, review, and security escalation.
---

# Harness workflow

Codex is the execution environment. Use its normal planning, tools, context handling, and subagent support. Harness does not run implementation workers or retry loops.

## Classify the task

Use `python scripts/harness.py risk` for a deterministic minimum tier. Hard T2/T3 signals must not be lowered. `hints` are non-binding context signals, not automatic review triggers; use task meaning and trust-boundary context to escalate when needed. File count alone does not force T2.

- **T0, trivial:** wording, typo, or a small documentation-only change. Edit, run the quick check when configured, and finish without a reviewer.
- **T1, normal:** a focused bug fix or single-module change. Add or update behavior tests, run deterministic checks, and self-review. Do not launch reviewers by default.
- **T2, complex:** public API, dependency, explicit subsystem, or cross-module contract change. Plan the change, run full deterministic checks, then delegate one independent read-only review to `reviewer`. It checks requirements, contracts, architecture, maintainability, regression risk, and test adequacy.
- **T3, high risk:** hard security-sensitive paths or high-confidence security behavior, including authentication, authorization, credentials, secrets, shell/subprocess boundaries, SQL or migrations, deployment, `.github/`, `.harness/`, or `.codex/`. Plan the change and run full deterministic checks, then delegate independent read-only reviews to `reviewer` and `security_reviewer`; the two reviews may run in parallel.

Main Codex is the implementation writer. T2/T3 do not imply an implementation subagent. There is no separate test-review worker. Test commands and their exit status are deterministic; reviewers may assess test adequacy but must not re-judge test results.

Keep reviewers read-only. Ask each reviewer to return `status`, `summary`, `findings`, `evidence`, and `recommendation`; findings include a cause, a repository `path:line` citation, and a concrete fix. An explicit no-findings result is required when the review passes.

## State and artifacts

- Use `/goal` for a long-running objective that spans phases or needs durable completion tracking.
- For a complex task that must survive a new session, keep one concise `.harness/tasks/<slug>.md` file with Goal, Acceptance, Constraints, Decisions, Current state, and Next. Validate the slug as a relative path under `.harness/tasks/`.
- Do not create a task file for routine T0/T1 changes. Git records code state; CI records validation state.

## Task units and commits

- For multi-step requests, plan cohesive, independently verifiable task units; keep dependent changes together.
- Finish one unit end-to-end before starting the next: implement it, run its configured checks, and complete any required read-only reviews.
- Commit each completed task separately after checks and reviews pass. Stage only that task's changes or hunks. Never stage unrelated changes or pre-existing user changes.
- Leave failed or unfinished work uncommitted. Honor explicit no-commit requests. Push or merge only when asked.

## Delegation and worktrees

- Keep one implementation writer in a mutable workspace.
- Use subagents only for independent parallel investigation or a read-only review after implementation. Never use parallel writers for dependent changes.
- Use a worktree when work must be isolated, run concurrently, or could disturb the current branch. Ordinary interactive work can stay in the current worktree.

## Validation and finish

- Read the project-specific command lists in `.harness/config.toml`; do not guess test, lint, typecheck, or build tools from the language.
- Run `python scripts/harness.py check --quick` for T0/T1 and `--full` for T2/T3. Resolve failed checks before finishing.
- Run the risk command on the final diff. When it reports `code_review`, obtain a read-only code review; when it reports `security_review`, obtain a read-only security review.
- Hooks provide fast feedback only. Codex sandbox and permissions, trusted CI, and repository branch protection define enforcement boundaries.
- Report changes, commands, results, and any review findings. Do not create phase indexes, heartbeat files, or worker output JSON.
