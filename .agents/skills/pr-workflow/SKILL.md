---
name: pr-workflow
description: Publish a completed task linked to an existing GitHub issue; push its branch, open or update a PR, and follow CI until required checks pass.
---

# GitHub pull request workflow

This project uses one existing GitHub issue, task-scoped commits, one pull request, and green CI for each completed task. Issue creation is handled by the currently configured issue workflow. When the user has requested this workflow, publish the task branch without asking for the same authorization again. Never merge the pull request.

## Prepare the branch

- Use the existing GitHub issue for the task. Do not create a duplicate issue or invent an issue number. If no issue exists, stop and hand off to the currently configured issue workflow; resume when its GitHub issue link is available.
- Confirm the repository, issue, current branch, remote, and base branch. This repository's CI runs pull request workflows against `main`; follow an explicit user-selected base or the repository's current default if it has changed.
- Ensure the current branch contains only this issue's completed task commits and has no uncommitted or unrelated changes. Do not push the base branch. If task commits are mixed with other work or only exist on the base branch, stop and separate them safely before publishing; never rewrite shared history to make a PR fit.
- Each task commit must already have passed risk classification and any required reviews while its diff was present, following the Harness workflow. Do not treat `harness risk` on a clean committed tree as the branch risk result: it only inspects changes since `HEAD`.
- Before publishing, run `python scripts/harness.py check --full` against the complete branch and confirm each issue commit's validation and required-review results. If PR preparation creates a new uncommitted fix, classify and review that diff before committing it.

## Publish or update the PR

- Check for an existing open PR from this branch. Update that PR instead of creating a duplicate.
- Push the task branch to `origin`. Use the connected GitHub integration for PR operations when available; otherwise use `gh`.
- Create a PR against the confirmed base. Use a concise title and a body with `Summary`, `Validation`, and a link to the task issue. Use `Closes #<number>` only when this PR completes that issue; otherwise use `Refs #<number>`.
- Do not change workflow permissions, skip required checks, force-push, or merge.

## Wait for CI

- Wait until every required check reports success. In this repository, expect `security-policy`, `harness-core`, `source-package`, and `project-validation`; inspect the actual PR checks because workflow configuration can change.
- For a failed check, inspect its run log. Fix failures caused by this task, rerun local full validation, commit the fix on the same issue branch, push, and wait for the new checks. Do not suppress or bypass a failure.
- If a check is pending, missing, blocked by permissions, or failing for an external reason that cannot be fixed in the branch, report the PR URL and exact status as blocked. Do not claim CI passed.
- Finish with the issue and PR links, commits, local validation result, and CI status.
