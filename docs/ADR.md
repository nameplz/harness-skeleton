# Architecture Decision Records

## Project decisions

Add durable choices for the concrete project here. Record the decision, the reason, and the trade-off.

## Harness v2 decisions

### ADR-010: Codex owns orchestration
**Decision:** Use Codex's native session, planning, context, tools, and selective subagents as the execution path. Keep Harness focused on project knowledge, task contracts, deterministic validation, risk signals, and CI boundaries.
**Reason:** The v1 Python `StepPipeline` had no Codex adapter and duplicated lifecycle behavior without running a real Codex worker.
**Trade-off:** Progress lives in `/goal`, Git, or one optional task artifact rather than a centrally managed runtime state machine. The harness has no Python worker pipeline, heartbeat, or stuck-state runtime.

### ADR-011: Risk-based review routing
**Decision:** T0/T1 tasks use deterministic checks and self-review. T2 tasks add one independent code review. T3 tasks add an independent security review. No separate test-review worker runs.
**Reason:** Test status is deterministic, while independent reasoning is most useful for complex changes and trust boundaries.
**Trade-off:** The diff detector is an escalation signal, not a complete understanding of task intent; ambiguous or unshown risks are escalated by the skill.

### ADR-012: Project-defined validation commands
**Decision:** Keep project commands in `.harness/config.toml` as argv arrays selected by quick/full profile. Run with `shell=False`, a 10-minute per-command limit, a 2-minute quick and 15-minute full-profile ceiling, a 1 MiB output cap, and sanitized output; terminate timed-out POSIX process groups. Run `unittest` and `compileall` through isolated Python module loading, and resolve the built-in doctor command to the trusted Harness script. The unittest output summary is only a sanity heuristic: test code can print a fake completion summary, so trusted CI obtains its validation config from the protected checkout, executes candidate code without repository secrets. Confine path arguments, option values, and path-like assignment values to the workspace. Reject environment-replacement launchers, Git subcommands outside a local read-only allowlist, Git helper configuration, and external transport options. Drop inherited `GIT_*` environment overrides, inject fixed safe Git settings, and ignore global/system Git config. Permit an absolute executable only when it resolves to the running Python interpreter.
**Reason:** The harness must not guess toolchains or turn project configuration into arbitrary shell text.
**Trade-off:** A new project must provide its own checks; the core does not invent tests, lint, typecheck, or build commands. Logs redact known credential forms, including URL userinfo, JWTs, PEM keys, email addresses, and unquoted multiline credential records through the next blank line, but cannot infer arbitrary secret values with no recognizable format.

### ADR-013: Trusted maintenance for sensitive files
**Decision:** Pull request checks use `pull_request_target`, which loads workflow definitions from the trusted base branch; ordinary `pull_request` and manual dispatch are disabled. Trusted base-branch validators inspect candidate files. The `security-policy` job receives `contents: read` and `pull-requests: read`; the `project-ci` `source-package` job receives only `contents: read`. Both jobs inspect or package candidate files without executing them. The explicit `github.token` expression is limited to the exact policy step; candidate tests run only in artifact-consuming jobs with `permissions: {}` and no repository secrets. One-day artifact payloads are tar archives that retain hidden files and executable modes while omitting Git metadata. Normal pull requests cannot alter security-sensitive paths, including local actions under `.github/actions/`. Trusted source comes from the PR base or protected `main`. Private cross-repository PR sources are explicitly rejected before checkout because the base token cannot reliably access them; same-repository private branches and public forks remain supported. The `harness-trusted-maintenance` label allows sensitive-path changes only on the event that applies it, after the trusted checker confirms that event actor has admin or maintain permission through GitHub's repository-permission API. Later push or PR events require a fresh label action; structural workflow checks always run. The checker requires fixed hosted runner labels, non-persisted checkout credentials, exact approved trigger mappings without path filters, and bounded authenticated Git changed-path collection.
**Reason:** A candidate change must not replace the validator that judges that same candidate, while the harness still needs a reviewed way to evolve.
**Trade-off:** The initial migration of the trusted gate needs one privileged bootstrap because the old base-branch validator cannot authorize its replacement. Subsequent sensitive changes need a trusted maintainer to reapply the label after each update; the label does not bypass workflow-content checks.

### ADR-014: Hooks are feedback, CI is enforcement
**Decision:** Keep local hooks small and focused on command policy and project-defined validation. Treat Codex sandbox/permissions and trusted CI as enforcement boundaries.
**Reason:** A regex hook is not a complete sandbox and must not be presented as one.
**Trade-off:** Local checks improve feedback but do not replace repository protection or CI.
