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

**Decision:** Keep quick/full checks as project-defined argv arrays in `.harness/config.toml`; empty profiles mean unconfigured.
Run with `shell=False`, a 10-minute command limit, 2-minute quick and 15-minute full ceilings, a 1 MiB output cap, and sanitized output; terminate timed-out POSIX process groups.
Reject forbidden operations by executable/subcommand position, including supported runners, rather than banning words in ordinary arguments.
Allow `npm run watch`; a nonterminating command fails through runtime limits.
Allow only direct Git invocations with `status`, `diff`, `log`, `show`, `ls-files`, `rev-parse`, `grep`, `describe`, or `cat-file`; reject global Git configuration overrides and wrapped Git.
Run Git with inherited GIT_* overrides removed, safe settings injected, global/system configuration ignored, and external transports disabled.
Reject inline shell/code and confine paths, option values, and path-like assignments to the workspace.
Absolute executables must resolve inside the workspace, except the running Python interpreter.
Isolated unittest/compileall commands preserve explicitly pathed Python interpreters and resolve bare Python names to the running interpreter.
Trusted doctor checks use the running Harness interpreter and script.

**Reason:** Harness must not guess toolchains or turn configuration into arbitrary shell text. Empty checks must never become a passing result.

**Trade-off:** Projects supply their own tests, lint, typecheck, and build checks. Redaction covers known credential forms, not arbitrary unlabelled secrets. The unittest summary is a sanity heuristic, not proof of honest completion.

### ADR-013: Codex creates project-specific CI

**Superseded by ADR-018.** CI generation is optional project policy, not a Harness requirement.

### ADR-014: Hooks provide feedback, not isolation

**Decision:** Keep agent hooks focused on command feedback and Stop quick validation. Commit enforcement moved to the Git pre-commit gate and bound evidence cache described in ADR-019. Permit bootstrap work while profiles are unconfigured without reporting a pass. Treat host permissions as enforcement boundaries; remote enforcement is a project choice.

**Reason:** Agent hooks fail open, and same-repository validators do not form a complete security sandbox.

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

### ADR-019: Minimal verification with an agent-neutral core

**Gate and contract.** DEC-01 puts commit enforcement in Git pre-commit with workspace-bound evidence caching; DEC-02 applies the default that empty profiles block commits. MV-1 through MV-6 in [Minimum verification](ARCHITECTURE.md#minimum-verification) define the guaranteed behavior. **Reason:** agent hooks fail open and stale checks cannot authorize changed work. **Trade-off:** deliberate bypasses, forged caches, and non-commit completion remain outside enforcement.

**Command policy.** DEC-03 applies the default local read-only Git allowlist. DEC-04 applies the default allowing resident commands, with guidance against them and runtime limits. ADR-012 records argv semantics and preserved path interpreters. **Reason:** ordinary arguments must not trigger operation bans. **Trade-off:** supported runner parsing is limited, and nonterminating checks consume their time budget.

**Core and adapters.** DEC-05, DEC-06, and DEC-11 apply defaults: ship optional Codex/Claude adapters, locate shared feedback at `scripts/hooks/agent_hook.py`, and omit duplicate PermissionRequest registration. **Reason:** Git enforcement and neutral core files preserve the minimum contract without agent-specific hooks. **Trade-off:** optional feedback depends on each host's event support.

**Risk vocabulary.** DEC-12 applies the default moving secret, credential, authentication, and authorization words from hard signals to hints. Projects may restore hard `security_keywords`. **Reason:** documentation vocabulary caused false T3 escalation. **Trade-off:** contextual risk still needs agent judgment; control-file and test-weakening hard signals remain.

**Small defaults.** DEC-07 excludes model/reasoning settings, leaving runtime/user choices. DEC-08 excludes extra E2E entrypoints. DEC-09 and DEC-10 apply defaults: optional project document templates and English core guidance. **Reason:** avoid unsupported assumptions and unnecessary instructions. **Trade-off:** projects configure their own models, validation tools, and domain documents.
