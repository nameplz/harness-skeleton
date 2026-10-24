# Project CI setup

The Harness skeleton starts with no GitHub Actions workflows and empty quick/full validation profiles. It does not assume a language, test framework, or build system. Codex analyzes the checked-out project and creates a project-specific CI.

## States

| State | Evidence | What it means |
|---|---|---|
| Unconfigured | Missing or empty quick/full profiles, or no valid PR workflow | Bootstrap and project analysis are allowed. No test or CI pass is implied. |
| Configured | Valid non-empty profiles, a PR workflow running the Full profile, and passing static policy checks | Local validation and PR CI are ready to run. |
| Verified | GitHub reports all expected Full-profile jobs successful for the current PR head, and local source/config evidence stays unchanged during the query | Verified describes that revision only. It is not saved as a permanent setting. |

Run the bootstrap check while setting up a copied skeleton:

    python scripts/harness.py doctor --bootstrap

After CI is created, use the regular doctor and explicit profile commands:

    python scripts/harness.py doctor
    python scripts/harness.py check --quick
    python -I scripts/harness.py check --full
    python scripts/check_ci_security.py --root .

A check with a missing or empty profile returns an unconfigured error and a non-zero exit. Risk classification remains usable before CI is configured. The local hook allows bootstrap work while profiles are unconfigured; it never reports that skipped validation passed.

## Analyze the project

Use .agents/skills/ci-setup/SKILL.md. Inspect more than one file before selecting a stack or command:

- Language, framework, build system, actual runtime version, and platform constraints.
- Package manager, lockfile, workspace/monorepo layout, and real install commands.
- Existing test files and test runner, lint/type-check config, and build steps.
- Required environment variables and external test services.
- Existing PR, release, deployment, and publishing workflows.

The Skill can configure Python, Node.js/TypeScript, Go, Rust, and typical monorepos. It does not generate language-specific templates. Commands must exist in the project; when test or lint setup is absent, add it only when the task calls for it or leave the project unconfigured and say why.

## Configure validation commands

Set quick and full as argv arrays in .harness/config.toml. Harness runs each command with shell=False, bounds time and output, validates path-like arguments, and sanitizes captured output. CI prepares the required runtime and dependencies before calling the Harness Full profile.

Quick should be useful during active work. Full should include the project's required tests, lint, type checks, and build. Do not put secrets in command arguments or ask Harness to guess a tool from a manifest.

## Configure GitHub Actions

Create a focused workflow under .github/workflows/ or adapt an existing PR validation workflow. It must run:

    python -I scripts/harness.py check --full

Use pull_request for PR validation without branch or path filters; the required check must run for every target branch. An optional push trigger must name a limited branch list or a finite list of literal release tags. Set the actual runtime, reproducible dependency installation, a hosted runner where practical, and a bounded timeout. Give tokens only read permissions needed for checkout. Do not expose repository secrets to PR validation.

The Full job runs `python -I scripts/harness.py check --full`; isolated mode ignores Python import environment overrides. It must contain exactly one SHA-pinned `actions/checkout` before Full, with `persist-credentials: false`, workspace cleaning enabled, and default repository, revision, and root path. Do not override `repository`, `ref`, `path`, sparse checkout, or checkout server. Do not set interpreter, loader, shell, or PATH environment overrides on the Full job. PR validation jobs cannot use `continue-on-error`; path filters and conditions cannot bypass required validation. PR jobs cannot use job/service containers or deployment environments. Earlier steps cannot write GitHub command files or run local actions before Full; avoid shell command substitution, indirect variable expansion, backticks, and `eval` in setup scripts. The Full job must have one exact check name, so it cannot use a matrix.

The policy checker accepts .yml and .yaml files and standard mapping, scalar, or list trigger forms. It checks safe YAML parsing, duplicate mapping keys, single-document input, file and path boundaries, supported triggers, the standalone isolated Full-profile command, permissions, runner labels, action SHA pins in every workflow, exactly one current-repository checkout before Full, checkout credentials, untrusted event interpolation, job dependencies, timeouts, and common test-skip patterns. It checks PR-used local composite actions for untrusted event data, environment-file writes, and ignored step failures, and requires Docker action images, Dockerfile base images, and external `COPY --from` images to use SHA-256 digests. It rejects executable `pull_request_target` jobs, write-capable cache access in PR workflows or validation jobs, malformed reusable-workflow jobs and values, invalid local reusable-workflow targets, reusable-workflow calls in PR validation, self-hosted or custom PR runner labels, push triggers without limited branches or literal tags, push ignore/path filters, any PR branch/path filter, writable PR token permissions, unpinned external Actions, ambiguous Full check names, conditional Full-job dependencies, and ignored PR validation failures.

Static checks cannot prove a runner label is backed by GitHub-hosted infrastructure; configure trusted runner groups in GitHub settings. External Action code and arbitrary Dockerfile `RUN` behavior are not inspected, so only use reviewed pinned Actions and review Dockerfile changes for network access.

Existing deployment, release, and package-publishing jobs must be preserved. Prefer a separate PR validation workflow when privileged jobs cannot safely share one. Do not replace the whole workflow or duplicate existing tests without a reason. Review the actual effect on each existing trigger and job before editing.

The static policy scans every workflow and rejects executable `pull_request_target` jobs. Preserve existing privileged automation during setup; if it prevents a configured result, report the limitation and leave its migration decision to the project owner.

## Verify a PR on GitHub

After the workflow is committed to a PR branch, run this from a clean checkout at that PR head:

    python scripts/verify_ci.py --pr 42

The read-only verifier uses gh to identify the repository and PR, derives required job IDs/names from workflows that run Full, reads the checks associated with that PR, and confirms the PR head and local workspace evidence remain unchanged. It does not require the Check Run SHA to equal the PR head string; GitHub may associate a PR check with a synthetic merge revision.

Results are success, failure, pending, missing, cancelled, skipped, or blocked. Only success is verified. Missing expected jobs, stale PR heads, local changes, failed jobs, and skipped required checks are not success. GitHub authentication or Actions policy errors are reported as blocked. No script changes repository settings or waits indefinitely.

Configure GitHub branch protection or repository rules separately to require the generated job checks before merge. The local validator and generated workflow live in the same repository, so they are not independent security boundaries. Static checks cannot prove test quality, prevent a malicious change from weakening the checker, or replace GitHub's required-check enforcement.

## Existing CI migration and recovery

For an existing project, first record current workflow triggers, runtimes, checks, and privileged jobs. Reuse jobs that already cover the Full profile. Keep deploy/release steps unchanged; split only when PR validation would otherwise expose secrets or writable permissions. Run the policy checker and local Full profile before opening or updating a PR, then use verify_ci.py against the new PR revision.

If a check is missing, inspect whether the workflow was triggered, whether the required Full job was skipped, and whether GitHub Actions is enabled. If a check fails, read its run log, fix the project or runtime setup, run local Full again, and push a new revision. If access or repository policy prevents a run, leave the state configured, report blocked, and describe the required administrator action. Do not claim verified until GitHub reports success for the current revision.
