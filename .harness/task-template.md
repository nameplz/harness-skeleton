# Goal
State the requested outcome and published issue link, or the explicit local-only request.

## Acceptance
List independently verifiable completion criteria.

## Constraints
Record scope, user changes to preserve, effective permissions, and granted write authorization.

## Decisions
Record decisions needed by the next session; link existing architecture/ADR sources.

## Current state
- Repository, issue, branch, remote, base, and HEAD:
- Last completed task unit:
- Validation command/result and HEAD/diff/config identity:
- Independent review result and reviewed identity:
- Pending approval, external write, PR, or CI state:

## Next
State the next action and completion conditions. Recheck actual Git/remote state on resume;
never reuse stale evidence or repeat an external write without querying its outcome.

Do not store credentials, raw prompts, or entire conversations. Routine T0/T1 tasks do not need this file.
