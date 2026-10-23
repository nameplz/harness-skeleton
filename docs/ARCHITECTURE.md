# Harness Skeleton Architecture

## Runtime boundary

Codex owns planning, context, tools, delegation, implementation, CI creation, and failure repair. Harness provides project instructions, deterministic configuration checks, command execution, risk routing, evidence, setup diagnostics, and static CI policy checks. GitHub Actions runs the project validation that Codex configured. There is no worker framework, retry engine, or separate orchestration runtime.

    AGENTS.md → Harness / CI Setup / PR Workflow skills → Codex session
                                      │
                    scripts/harness.py check / risk / doctor
                                      │
                           project GitHub Actions CI

## Knowledge and task state

- AGENTS.md is a short index. Load architecture and decisions when they matter.
- .agents/skills/harness/SKILL.md defines issue-first delivery and T0–T3 routing. ci-setup/SKILL.md analyzes a project and defines its validation and CI; pr-workflow/SKILL.md handles PR publication and GitHub result verification.
- .harness/config.toml is the project source of truth for local quick/full argv checks and extra risk patterns. The starter file has empty profiles; a copied project must define actual commands. Harness never guesses a tool from language or manifest files.
- Git is the source of code state. Local check output and GitHub check runs are separate evidence; neither can be reused after their associated source/config revision changes.
- Use /goal for a long-running objective. Keep one .harness/tasks/<slug>.md note only when a complex task must continue in another session.

## CI initialization state

The starter contains no GitHub Actions workflow and no default test commands. Run python scripts/harness.py doctor --bootstrap to validate the Harness layout and Git state before project CI exists. The normal doctor reports unconfigured until both non-empty quick/full profiles and a policy-clean pull_request workflow are present.

Unconfigured allows bootstrap diagnostics, Git status checks, project analysis, risk classification, and CI setup. It does not allow empty checks to pass or describe the project as release-ready. Configured means the profiles are valid, a PR workflow runs scripts/harness.py check --full, and the static policy passes. Verified is only a current GitHub execution result; it is not stored in a Boolean setting.

## Deterministic CLI

scripts/harness.py is the user-facing entry point. scripts/harness_risk.py owns bounded Git path/diff inspection and routing. scripts/harness_common.py centralizes errors and output redaction.

- check validates .harness/config.toml and runs each explicit argv command with shell=False. Missing or empty profiles return a non-zero unconfigured result. The runner caps output at 1 MiB per command, each command at 10 minutes, quick at 2 minutes total, and full at 15 minutes total; timed-out POSIX process groups are terminated.
- Python unittest and compileall module commands use isolated interpreter mode. The non-empty unittest summary check catches silent early exits but is only a heuristic; test code could print a fake summary. It is not an execution attestation.
- risk works before check profiles exist and reports the deterministic minimum tier, review routes, reasons, hints, and changed paths.
- doctor --bootstrap permits absent CI and absent profiles while checking the Harness structure. Normal doctor validates profiles, CI workflow presence, and the static CI policy. Neither doctor mode queries GitHub or reports verified.

Command path arguments and configuration fail closed when invalid, including embedded assignment values, existing extensionless files, option values, Windows absolute paths, environment replacement launchers, unsafe shell forms, mutating formatters, and Git commands outside a read-only allowlist. Git helper configuration, callbacks, and transport options are blocked. Subprocesses drop inherited GIT_* overrides, set safe Git defaults, and ignore system/global Git config. Before Git status/diff, the runner checks effective local/include/worktree configuration for filter callbacks and fails closed if preflight is inconclusive. It disables external diff/text conversion, turns off fsmonitor, ignores dirty submodule contents, and sets GIT_OPTIONAL_LOCKS=0. This preflight is not atomic against concurrent Git config changes.

An absolute executable is accepted only if it resolves to the running Python interpreter; other executable paths must stay inside the workspace. Output is bounded and sanitized for known credential labels, URL userinfo, JWTs, PEM keys, emails, and unquoted multiline credential records. Arbitrary unlabelled secret values cannot be inferred. A descendant that starts a new session may outlive local timeout cleanup. Arbitrary test code can spawn its own processes or access the network/filesystem; the host must enforce those boundaries.

## Risk routing and review

Risk is a deterministic minimum tier. No changes are T0; hard security-sensitive paths and high-confidence security behavior are T3; ordinary documentation-only changes are T0; dependency/public API/cross-module complexity signals are T2; other focused changes are T1. Hard T2/T3 signals cannot be lowered. Broad security words and implementation-file count are hints only. Task context can escalate a route when the diff misses relevant risk.

T0/T1 use no reviewer by default. T2 adds one independent read-only code reviewer. T3 adds independent read-only code and security reviewers after full local validation; reviews may run in parallel. Reviewers assess requirements, contracts, architecture, regressions, and test adequacy; they do not replace configured tests. Main Codex remains the only implementation writer.

The risk classifier keeps .github/**, .harness/**, policy validators, and Harness/CI skills at T3. CI policy and Harness control-plane changes require the corresponding reviews. Project-local .codex/config.toml enables reviewer roles and lifecycle hooks without pinning concurrency or models.

## Project-specific CI and static policy

Codex analyzes language/framework, lockfiles and package manager, actual runtimes, build/test/lint/type-check setup, monorepo layout, environment/service dependencies, existing workflows, default branch, and platform restrictions. It defines quick/full argv profiles and creates or adapts workflow YAML. Python, Node.js/TypeScript, Go, Rust, and common monorepos are supported by Codex analysis; there is no language template generator.

The responsibilities stay separate:

- CI Setup skill decides what to create and how to verify it.
- .harness/config.toml lists the actual project validation commands.
- .github/workflows defines the GitHub runtime, setup, and Full-profile job.
- scripts/check_ci_security.py checks workflow structure and common CI security hazards.
- GitHub Actions executes the workflow; scripts/verify_ci.py reads the PR-associated result.

The policy checker supports .yml/.yaml, safe single-document YAML, duplicate-key detection, workflow size and symlink/path-escape checks, pull_request on every target branch with limited push branches, stable job IDs, job dependencies, supported GitHub-hosted runner labels, explicit timeouts, scoped read-only PR permissions, full-SHA external Action pins in all workflows, non-persistent checkout credentials, and a standalone `python -I` Full-profile command that cannot be skipped or ignored. It rejects Python and shell environment overrides on the Full job, untrusted event interpolation into PR workflow values and local composite actions, unpinned Docker images, inappropriate secrets/token context in PR workflows, conditional Full-job dependencies, ambiguous required-check names, self-hosted or custom PR runner labels, all PR branch/path filters, writable PR token scopes, unsafe local action paths, and missing Full jobs. Preserve existing deployment/release/publish jobs; if an executable pull_request_target workflow blocks a configured result, report it without removing the workflow. Split validation into its own workflow when privileged jobs cannot safely share one.

The checker is a static local policy tool in the same repository as the workflow. It cannot prevent a malicious change from weakening itself, prove test quality, or act as a trusted merge boundary. Do not confuse its result with repository branch protection. Configure GitHub required checks separately and require the generated Full-profile job.

## GitHub result verification

After opening a PR, run python scripts/verify_ci.py --pr <number> from a clean local checkout at that PR head. It checks the jobs derived from the current policy-clean workflows, uses gh PR-associated checks rather than assuming a check's SHA string equals the PR head, and reads the PR head again after querying results. A synthetic merge revision may be used for a PR check.

The result is success, failure, pending, missing, cancelled, skipped, or blocked. Only success means the required jobs are currently successful for that PR revision. The verifier also requires matching local HEAD and unchanged source/config evidence before and after the query. It does not change repository settings, push, or wait indefinitely. Authentication, disabled Actions, permission, and API failures remain blocked; no check run is never a pass.

## Hooks and execution boundaries

One harness_hook.py handles PreToolUse, PermissionRequest, and Stop. It blocks a small set of destructive shell patterns and runs quick checks before a direct Git commit or turn completion. An unconfigured profile does not block bootstrap work, but Harness check still returns unconfigured. Hooks are feedback, not a sandbox; host permissions and GitHub branch protection define enforcement boundaries.

## Validation evidence

Check reports preserve per-command duration_ms, started, timed_out, output_limited, and failure_reason. A profile aggregate timeout records commands not started. Results include evidence and evidence_after with status, HEAD, dirty state, diff_sha256, and the SHA-256 of the exact applied config bytes. --config-root hashes the supplied config root when a trusted caller explicitly needs that mode.

The dirty fingerprint covers Git status, tracked binary diffs, and bounded non-ignored untracked content, including symlink targets. Each capture uses a shared five-second budget for Git calls and untracked reads, with 1 MiB per file and 8 MiB total. Identity fields are null when unavailable or erroneous. A standalone non-Git project may run checks with unavailable evidence; evidence errors in a known Git repository fail closed. Final capture errors invalidate a completed result. Ignored build artifacts and dirty submodule contents are excluded; gitlink changes remain visible. This bounded fingerprint is not an atomic filesystem snapshot, a proof about ignored files, or a host-level boundary. A malicious command could change and restore a file between snapshots.

Bind T2/T3 review evidence to the final HEAD, dirty diff, and configuration. Rerun affected checks and reviews after any change. Do not use HEAD alone for dirty workspaces or use a clean-tree risk result as a branch-wide assessment.

## Effective execution policy

| Control | Owner | What must be checked |
|---|---|---|
| Configuration/argv/path validation, output/time limits | Harness | Explicit checks, errors, size bounds, sanitized reports |
| Filesystem and network confinement | Codex/host | Effective writable roots, outbound policy, subprocess/tool permissions |
| Credentials and privileged identities | Host/organization | Keep credentials outside candidate reach; do not forward secrets to PR validation |
| External writes and approvals | Runtime/user | Confirm target and scope; preserve standing authorization |
| Remote review/merge requirements | GitHub operator | Required generated checks, branch protection, and repository Actions policy |

The runner forwards only safe runtime/path/locale/temp/certificate/color settings and injects safe Git settings. Project-specific TEST_MODE/DATABASE_URL and arbitrary credentials are not forwarded. Add a trusted explicit allowlist only for required non-secret test settings; never forward the whole environment or allow project config to request CI secrets.

Doctor checks Harness files, reviewer configs, hook command/type/matcher structure, Git state, validation profiles, and static CI readiness. It does not prove runtime hook delivery, effective native permissions, test coverage, or product readiness. Commit feedback recognizes direct Git commands and simple command lists; shell functions, substitutions, wrappers, and malformed shell input are outside the recognizer. Codex may continue after a hook error, so hook exit status is not a hard permission boundary.
