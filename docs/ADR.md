# Architecture Decision Records

## Project decisions

Add durable choices for the concrete project here. Record the decision, the reason, and the trade-off.

## Harness v2 decisions

### ADR-010: Codex owns orchestration

**Decision:** Use Codex's native session, planning, context, tools, and selective subagents as the execution path. Keep Harness focused on project knowledge, task contracts, deterministic validation, risk signals, and CI boundaries.

**Reason:** The v1 Python StepPipeline had no Codex adapter and duplicated lifecycle behavior without running a real Codex worker.

**Trade-off:** Progress lives in /goal, Git, or one optional task artifact rather than a centrally managed runtime state machine. The harness has no Python worker pipeline, heartbeat, or stuck-state runtime.

### ADR-011: Risk-based review routing

**Decision:** Risk output is a deterministic minimum tier. Hard paths, high-confidence security behavior, and explicit complexity signals set T3/T2; hard signals cannot be lowered. Broad keywords and implementation-file count are hints, so two source files alone do not force review. T0/T1 use deterministic checks and self-review; T2 adds one independent read-only reviewer; T3 adds an independent read-only reviewer and security reviewer after full validation.

**Reason:** Deterministic signals catch clear trust-boundary and complexity changes without forcing review for ordinary multi-file fixes or documentation vocabulary. Test status is deterministic; independent reasoning is most useful for complex changes and trust boundaries.

**Trade-off:** Diff detection gives a minimum tier, not full task understanding; Codex uses hints and task context to escalate ambiguous or unseen risks. Project config enables reviewer roles and hooks but leaves concurrency and reviewer model selection to user/runtime defaults.

### ADR-012: Project-defined validation commands

**Decision:** Keep project checks in .harness/config.toml as quick/full argv arrays. The starter profiles are empty and mean unconfigured. Run configured commands with shell=False, a 10-minute per-command limit, a 2-minute quick and 15-minute full-profile ceiling, a 1 MiB output cap, and sanitized output; terminate timed-out POSIX process groups. Python unittest and compileall module commands use isolated interpreter loading. Confine path arguments, option values, and path-like assignment values to the workspace. Reject environment-replacement launchers, Git subcommands outside a local read-only allowlist, Git helper configuration, and external transport options. Drop inherited GIT_* environment overrides, inject safe Git settings, and ignore global/system Git config. Permit an absolute executable only when it resolves to the running Python interpreter.

**Reason:** Harness must not guess a toolchain or turn project configuration into arbitrary shell text. Empty checks must never become a passing result.

**Trade-off:** A new project must provide its own checks; the core does not invent tests, lint, typecheck, or build commands. Logs redact known credential forms but cannot infer arbitrary unlabelled secret values. The unittest summary check is a sanity heuristic, not proof that tests completed honestly.

### ADR-013: Codex creates project-specific CI

**Decision:** The starter contains no GitHub Actions workflows. Codex analyzes the actual project and configures .harness/config.toml plus a PR workflow that runs the Full profile. The local CI policy checker validates YAML structure and common security rules, but it lives in the same repository and is not an independent trust boundary. Existing deploy/release/publish jobs are preserved. pull_request_target is not used to execute PR validation.

**Reason:** Skeleton consumers have different languages, runtimes, tests, and platforms. A fixed Python workflow or language template would give false assurance and duplicate project behavior.

**Trade-off:** A malicious PR can change both workflow and local checker. GitHub required checks and branch protection must be configured separately. Static checks cannot prove test quality.

### ADR-014: Hooks provide feedback, not isolation

**Decision:** Keep local hooks small and focused on command policy and configured quick validation. Permit bootstrap work while profiles are unconfigured without reporting a pass. Treat Codex host permissions and GitHub branch protection as enforcement boundaries.

**Reason:** Regex hooks and same-repository CI do not form a complete security sandbox.

**Trade-off:** Local checks improve feedback but cannot confine arbitrary test code, network access, or filesystem access.

### ADR-015: Protect control-plane changes with risk routing and bound evidence

**Decision:** Route .github/**, .harness/**, CI policy validators, Harness skills, and related configuration to T3 review. Bind local checks to HEAD, dirty-content, and applied-config fingerprints; expose execution-limit metadata and invalidate results when source or config changes during validation.

**Reason:** CI and Harness policy affect what the project validates. Results cannot be safely reused for a different revision or configuration.

**Trade-off:** Fingerprints are bounded, non-atomic change evidence rather than execution attestations. Local policy does not replace GitHub enforcement.

### ADR-016: Derive initialization state from files and checks

**Decision:** doctor --bootstrap validates base Harness structure without requiring project profiles or CI. Normal doctor reports configured only when quick/full profiles, a pull_request Full-profile job, and static policy checks are valid. check returns unconfigured for missing/empty profiles. Do not write a persistent verified flag.

**Reason:** The initial skeleton has no project stack to validate, and absent commands must not be confused with successful validation.

**Trade-off:** doctor does not query GitHub. Configured means ready to run, not that a PR CI has succeeded.

### ADR-017: Verify GitHub results against the current PR revision

**Decision:** scripts/verify_ci.py uses gh to read the PR and its associated check results, derives expected job identities from the local policy-clean Full-profile workflows, and checks PR head plus local workspace evidence before and after the query. It does not compare a Check Run SHA to the PR head by string equality or modify remote settings.

**Reason:** GitHub may attach a PR check to a synthetic merge revision, while old results or skipped/missing jobs must not imply success for the current head.

**Trade-off:** Authentication, disabled Actions, missing checks, pending runs, and API errors remain incomplete. The result is a time-scoped report; branch protection still needs the generated required checks configured.
