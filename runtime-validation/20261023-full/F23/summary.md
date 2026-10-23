# F23 — T12 role-based authorization

F23 followed the frozen v2-then-v1 order. Both conditions preserved owner access, added optional comma-separated role IDs, applied the configured-guild policy before all listed Orca/Codex entry points, and passed the independent frozen host grader.

v2 passed the installed-wheel project suite (77 tests; two pytest temporary-directory cleanup warnings), the host suite (77 tests plus all 11 semantics), and independent code/security reviews. v1 passed the installed-wheel project suite (80 tests; the same two cleanup warnings), the host suite (80 tests plus all 11 semantics), and independent code/test/security reviews. The main TUI conversation was reused; v1 explicitly acknowledged the prior v2 solution before launching its separate implementation worker, so some workflow-level carryover is possible. Candidate files were reset. Later pairs start fresh Codex conversations per condition.

v1 used all three workflow attempts: reviewers first found oversized role IDs escaping as `ValueError`, then an environment-dependent test, both fixed before the final pass.

Harness risk/full checks were unavailable because the pinned checkout lacks its validation profile and scripts. The candidate feature branch was blocked by filesystem permissions; no candidate commit or remote CI was used. No network, live services, push, publication, or merge occurred.

See [frozen task](task.md), [acceptance](acceptance.json), [freeze record](freeze.json), [baseline grade](baseline-grade.json), [positive control](positive-control-grade.json), [v2 run](v2-run.json) / [patch](v2-final.patch) / [grade](v2-grade.json), [v1 run](v1-run.json) / [patch](v1-final.patch) / [grade](v1-grade.json), and [pair results](results.json).
