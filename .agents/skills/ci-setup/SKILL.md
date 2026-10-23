---
name: ci-setup
description: Analyze a project and create or update its project-specific GitHub Actions CI and Harness validation profiles.
---

# Project CI setup

Use this skill when python scripts/harness.py doctor reports unconfigured, or when CI or .harness/config.toml needs to be added or changed. Codex decides what the project needs; Harness scripts validate the resulting config and workflow. Do not add an AI orchestration engine or language template generator.

## 1. Inspect before editing

Run python scripts/harness.py doctor --bootstrap, then inspect the repository and GitHub remote. Confirm the default branch from repository state instead of assuming main. Review every existing workflow before writing.

Identify the actual project setup from multiple sources:

- Languages, frameworks, and runtime versions from source files and project configuration.
- Package managers and lockfiles, including workspace or monorepo declarations.
- Build systems, real test files, test frameworks, lint and type-check configuration.
- Environment variables and external services tests need.
- Existing CI jobs, deployment/release/publish workflows, required operating systems, and platform restrictions.

The workflow can support Python, Node.js/TypeScript, Go, Rust, and monorepos when those are the actual project stacks. This is a Codex analysis capability, not a set of prebuilt language templates.

A manifest alone is not proof that a tool or command is used. For example, inspect package scripts and the matching lockfile before choosing Node commands. Do not invent missing tests, tools, or runtime versions.

## 2. Define local validation

Update .harness/config.toml with explicit argv arrays for checks.quick and checks.full. These are commands, not shell strings; Harness executes each with shell=False and validates paths and arguments.

- Quick contains the useful fast checks for development.
- Full includes the real tests and configured lint, type, and build checks required before a PR is ready.
- Keep required dependency installation in the CI workflow. Do not put credentials in command arguments.
- If the project has no meaningful validation yet, leave it unconfigured and report that limitation. An empty profile is never a passing check.

## 3. Create or adapt GitHub Actions

Create the smallest project-specific workflow under .github/workflows/ or adapt the existing PR validation workflow. It must run python -I scripts/harness.py check --full on pull_request. A limited push trigger for relevant branches is optional. Configure the runtime and reproducible dependency installation from the files actually present.

For validation jobs:

- Prefer GitHub-hosted runners and set a bounded timeout-minutes.
- Give the workflow and jobs only the read permissions they need; validation must not receive repository secrets or use github.token.
- Pin every external Action to its full commit SHA. Set actions/checkout persist-credentials: false and do not provide custom checkout credentials.
- Pin Docker action images and Dockerfile base images to a SHA-256 digest.
- Pin external Dockerfile `COPY --from` images to a digest; do not use remote `ADD` or common network-fetch/install commands in `RUN`.
- Keep the Full command unconditional and fail on its exit code. Do not use path filters, continue-on-error, or skip conditions to bypass required validation.
- Do not add branch filters to `pull_request`; the policy requires the PR workflow to run for every target branch. Limit branches only on the optional `push` trigger.
- Do not set interpreter, loader, shell, or PATH environment overrides on the Full validation job.
- Keep the Full job non-matrix with one exact check name. Do not use job/service containers or deployment environments on PR validation jobs.
- Keep checkout on the current PR repository, revision, and root path. Do not let earlier steps write GitHub command files or run local actions before Full.
- Avoid shell command substitution, indirect variable expansion, backticks, or `eval` in setup scripts before Full.
- Runner labels do not prove hosted-runner identity; use trusted runner groups in GitHub settings.
- Do not use pull_request_target to run project validation or execute pull request code.
- The policy checker rejects executable pull_request_target jobs anywhere in the repository. Preserve an existing privileged workflow and report it as a blocker; do not silently remove or rewrite it to make the checker pass.

If an existing workflow has deployment, release, or package-publishing jobs, preserve them. Avoid replacing the workflow or duplicating jobs; when CI and privileged jobs cannot safely share a workflow, add a separate validation workflow and leave the privileged workflow intact. Record the reason and the preserved behavior in the change summary.

## 4. Verify locally and on GitHub

Run these checks after creating or changing the profiles and workflow:

    python scripts/harness.py check --quick
    python -I scripts/harness.py check --full
    python scripts/check_ci_security.py --root .
    python scripts/harness.py doctor

Fix failures in the project or workflow; do not suppress them. Run python scripts/harness.py risk and follow its T3 review route for CI, Harness config, policy-validator, and Skill changes.

After the PR is open, use python scripts/verify_ci.py --pr <number>. It checks the jobs derived from workflows that run the Full profile against the PR's current associated checks, and confirms the PR head and local evidence did not change while reading them. Do not compare a check run SHA to the PR head by plain string equality; GitHub can associate PR checks with a synthetic merge revision.

Only success means the current PR revision is verified. failure, pending, missing, cancelled, skipped, and blocked are incomplete. Do not save a permanent verified flag. If GitHub access, Actions, or permissions prevent checking, report the exact status and stop at configured.

## Repeat runs and limits

Re-read the current profiles and workflows before each run. Reuse correct configuration and make only the needed edits; do not append another job or workflow when an existing one already runs Full. The policy validator checks structure and common security hazards, but it cannot prove test quality or enforce itself against a malicious change in the same repository. Configure GitHub branch protection and required checks separately.
