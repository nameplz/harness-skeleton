# Architecture Decision Records

## Project decisions

Add durable choices for the concrete project here. Record the decision, the reason, and the trade-off.

## Harness v2 decisions

### ADR-010: Codex owns orchestration

**Decision:** Use Codex's native session, planning, context, tools, and selective subagents as the execution path. Keep Harness focused on project knowledge, task contracts, deterministic validation, risk signals, and local validation boundaries.

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

**Superseded by ADR-018.** CI generation is optional project policy, not a Harness requirement.

### ADR-014: Hooks provide feedback, not isolation

**Decision:** Keep local hooks small and focused on command policy and tier-based quick/full validation. Permit bootstrap work while profiles are unconfigured without reporting a pass. Treat Codex host permissions as enforcement boundaries; remote enforcement is a project choice.

**Reason:** Regex hooks and same-repository validators do not form a complete security sandbox.

**Trade-off:** Local checks improve feedback but cannot confine arbitrary test code, network access, or filesystem access.

### ADR-015: Protect control-plane changes with risk routing and bound evidence

**Decision:** Route hooks, runner/risk scripts, control configuration, and user-added .github/workflows/** to T3; .harness/config.toml alone and test_weakening are at least T2. Bind local checks to HEAD, dirty-content, and applied-config fingerprints; expose execution-limit metadata and invalidate results when source or config changes during validation.

**Reason:** Harness policy affects what the project validates. Results cannot be safely reused for a different revision or configuration.

**Trade-off:** Fingerprints are bounded, non-atomic change evidence rather than execution attestations. Local policy does not replace host confinement or optional remote enforcement.

### ADR-016: Derive initialization state from files and checks

**Superseded by ADR-018.** Local profiles and structure determine configured state; no CI requirement or persistent verified flag remains.

### ADR-017: Verify GitHub results against the current PR revision

**Superseded by ADR-018.** PR result verification belongs to user-selected remote integration.

### ADR-018: Local validation is the complete default

**Decision:** Remove mandatory issues, PR delivery, and CI from the skeleton. Users choose remote integration; local validation needs no remote credentials or services. Retain optional integration as one architecture sentence, without shipped generators or remote verifiers.

**Source and reason:** Reference design §2.1, principles 7–8: “The threat model is agent mistakes” and “Delivery procedures (issue/PR/CI) are the project's choice.” Same-repository policy cannot create independent remote enforcement. Keeping local gates explicit reduces always-loaded instructions and false assurance.

**Validation ladder:** T0 documentation uses configured quick checks; T1 adds acceptance evidence. T2 public API/dependency/contract/configuration changes or test-weakening signals require full checks and one read-only correctness reviewer. T3 trust-boundary or runner/hook/risk changes add a security reviewer. Hard T2/T3 cannot be lowered. Stop uses quick; commit uses quick for T0/T1 and full for T2/T3 or unknown risk, covering the whole working tree since HEAD (N3).

**N1:** Deleted tests, net assertion loss, and added skip/xfail/only markers create non-lowerable T2 signals. Review judges their justification; tests must not be weakened merely to pass.

**N2:** Define 2–5 acceptance criteria before work when absent. T1+ final reports map each criterion to command, exit code, and 1–3 key output lines. Missing evidence is unverified; source/config changes invalidate old evidence.

**Excluded** (reference design §2.1 principles 6–8 and §4.5): mandatory issue gates, PR workflows, CI generation, CI policy checks, remote-result verification, publication templates and contract checks; planner/generator/evaluator sprints, exhaustive feature JSON, ledger/stall replanning, background documentation gardening, flaky reruns, coverage filters, and generated architecture linters.

**Trade-off:** Local gates target mistakes, not adversarial control of validators. Host confinement remains necessary. Remote enforcement and delivery remain user-owned; no verified state is inferred from configured profiles. Empty profiles stay unconfigured and never pass.
