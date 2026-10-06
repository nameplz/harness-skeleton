# Harness Skeleton Architecture

## Runtime boundary

Codex owns the agent loop: it plans, manages context, uses tools, delegates selectively, implements, and repairs failures. Harness provides the project knowledge map, deterministic checks, a diff-based risk signal, setup diagnostics, and trusted CI policy. It does not launch implementation workers or maintain a parallel task state machine.

```text
AGENTS.md → .agents/skills/harness/SKILL.md → Codex session
                                      │
                   scripts/harness.py check / risk / doctor
                                      │
                             Git + trusted CI
```

## Knowledge and task state

- `AGENTS.md` is a short index. Load architecture and decisions only when they matter to the task.
- `.agents/skills/harness/SKILL.md` defines T0–T3 routing, delegation, task artifacts, and finish criteria.
- `.harness/config.toml` is the project-specific source for local validation commands and additional hard-risk and hint patterns. Trusted CI supplies this file from its trusted checkout with `--config-root`, so a candidate change cannot redefine the commands used to validate itself.
- Use `/goal` for the active long-running objective. Keep one `.harness/tasks/<slug>.md` artifact only when a complex task must continue in a later session.
- Git is the source for code state; deterministic command results and CI are the source for validation state.

## Deterministic CLI

`scripts/harness.py` is the single user-facing entrypoint. `scripts/harness_risk.py` owns Git path/diff inspection and risk routing, while `scripts/harness_common.py` centralizes errors and output redaction:

- `check` validates configuration and runs the selected project-defined argv commands with `shell=False`; the internal `scripts/command_runner.py` bounds captured output to 1 MiB per command, limits quick checks to 2 minutes and full profiles to 15 minutes, and terminates timed-out POSIX process groups. Python `unittest` and `compileall` module checks run with isolated interpreter mode, and the built-in doctor command resolves to the trusted Harness script. The non-empty unittest summary check catches silent early exits; it is a sanity heuristic, not proof that arbitrary test code completed, because tests can print their own summary before exiting. Trusted CI uses no repository secrets for candidate execution.
- `risk` reads changes only under the requested project root, loads that root's `.harness/config.toml`, and reports the deterministic minimum tier, reviewer routes, reasons, non-binding hints, and changed paths.
- `doctor` checks the skeleton's required files, configuration, and Git state.

The core does not infer pytest, npm, Go, or other tools from files. Configuration and path-like command arguments fail closed when invalid, including embedded assignment values, existing extensionless files, option values, and Windows absolute paths. It rejects environment-replacement launchers, Git commands outside a local read-only allowlist, and Git helper configuration or transport options. Validation subprocesses drop inherited `GIT_*` overrides, inject fixed safe Git settings, and ignore system/global Git configuration. An absolute executable is accepted only when it resolves to the running Python interpreter; other executable paths must stay inside the workspace. Captured output is memory-bounded and sanitized before display, including credential labels, URL userinfo, JWTs, PEM private keys, email addresses, and unquoted multiline credential records through the next blank line. Each command has a 10-minute ceiling; quick validation has a 2-minute aggregate ceiling and the full profile has a 15-minute ceiling. Timeout cleanup terminates the original process group; a descendant that starts a new session may outlive a local command timeout. Candidate CI runs without token permissions on an ephemeral job with a 15-minute limit.

One `harness_hook.py` handles `PreToolUse`, `PermissionRequest`, and `Stop`. It blocks a small set of destructive shell patterns and runs the configured quick checks before a Git commit or turn completion. Hooks are convenience guardrails, not a sandbox.

## Risk routing

The risk level is a deterministic minimum tier. No changes return T0; hard security-sensitive paths return T3 before documentation checks; ordinary documentation-only changes return T0; high-confidence security behavior returns T3; explicit complexity signals such as dependency declarations, public API areas, or subsystem/cross-module markers return T2; other focused changes return T1. Hard T2/T3 signals are never lowered. Broad security terms and implementation-file count appear as `hints`; two implementation files alone do not force T2. Hints help Codex assess task meaning and do not trigger review by themselves. Tasks can be escalated when context shows risk not visible in the diff. A reviewer cannot replace a configured test, lint, typecheck, build, or CI command.

T0/T1 use no reviewer by default. T2 uses one independent read-only code reviewer. T3 uses separate independent read-only code and security reviewers after implementation and full deterministic validation; those reviews may run in parallel. Reviewers may assess test adequacy but do not re-judge deterministic test results. Main Codex remains the implementation writer.

Project-local `.codex/config.toml` keeps multi-agent tools, agent roles, and hooks enabled because Harness relies on configured reviewers and lifecycle hooks even when user defaults disable them. It does not pin concurrency or reviewer models; model selection inherits user/runtime defaults.

## Security and CI boundaries

Validation commands are explicit argv arrays, run without a shell, checked against a small set of destructive or mutating patterns, and bounded by per-command and aggregate time limits. Path-like command arguments and paths from Git/config are normalized and confined to the workspace. Logs redact common credential-shaped values and email addresses; arbitrary unlabelled secrets cannot be inferred from output.

Pull request checks use `pull_request_target`, so GitHub loads the workflow definition from the trusted base branch; ordinary `pull_request` and manual dispatch are disabled. The trusted `security-policy` job checks the candidate using base-branch scripts and has `contents: read` plus `pull-requests: read`. The `project-ci` `source-package` job has only `contents: read` so it can package trusted Harness and candidate source. Both source jobs inspect or package candidate files without executing them. The only explicit `github.token` reference is in the exact trusted policy step, where it authenticates the base diff fetch and the label-actor permission check. Jobs that execute candidate tests or validation declare `permissions: {}` and receive no repository secrets. Each trusted source job creates a one-day tar archive containing dotfiles and executable modes but excluding Git metadata, then uploads it as an artifact; permissionless jobs extract it, initialize candidate Git metadata, and run validation with both the trusted Harness script and trusted `.harness/config.toml` against the candidate checkout. See [GitHub's `pull_request_target` guidance](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target) and [artifact upload documentation](https://github.com/actions/upload-artifact).

Trusted checkouts use the PR base or protected `main`. Private cross-repository PR sources are rejected before checkout because the base repository token cannot reliably read them; same-repository private branches and public forks remain supported. The changed-path inventory is NUL-delimited, collected by the trusted helper with a 60-second timeout and 1 MiB output cap, and stored under the runner's temporary directory outside the candidate checkout. The base fetch uses the policy job's read token through a temporary Git HTTP header; checkout credentials are not persisted. Git external diff and text conversion are disabled. Unsafe paths and candidate workflow symlinks are rejected. Jobs require the fixed `ubuntu-24.04` hosted runner label; every `actions/checkout` step disables credential persistence and cannot supply custom checkout credentials. Workflow expressions cannot access the secrets context or serialize the GitHub context. Candidate changes to workflows, local actions, Harness config, Codex config/hooks, or trusted validators require the `harness-trusted-maintenance` label. The trusted checker accepts it only on the event that applies the label and verifies that event's actor through GitHub's repository-permission API; pushes and other later PR events require a fresh label action. It bypasses only sensitive-path denial, while workflow-content checks still run. Workflow triggers require exact approved branch/type mappings with no path filters. Workflow YAML is safely parsed with Ruby Psych on the pinned Ubuntu 24.04 runner; multiple documents, ambiguous YAML 1.1 boolean keys, duplicate keys, and invalid YAML fail closed. Local actions must resolve within `.github/actions/`; symlink escapes are rejected. The initial migration of this gate requires one privileged bootstrap because the current base-branch checker cannot yet recognize the label. Project hooks provide quick feedback, not a sandbox. Codex permissions, writable roots, network boundaries, branch protection, and trusted CI enforce the actual limits.

`harness-ci.yml` validates the Harness repository itself by running the trusted base-branch `harness.py` and `.harness/config.toml` against the candidate source. The configured Python module checks use isolated imports, and the doctor command resolves to the trusted script. `project-ci.yml` uses the same trusted entrypoint for a candidate project's configured checks on an ephemeral GitHub-hosted runner; it does not hard-code the Harness internal test suite. Candidate checks run in jobs with empty workflow token permissions and no repository secrets; checkout credentials are not persisted. A copied project should edit `.harness/config.toml` to define its own test, lint, typecheck, build, and integration commands.

## Isolation

Use the current worktree for ordinary interactive tasks. Use a separate Git worktree for concurrent independent work, risky experiments, or migrations that need isolation. Codex remains the orchestrator in both cases.
