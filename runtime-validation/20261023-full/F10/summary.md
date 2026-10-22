# F10 — T10 stale doctor binding

F10 ran v1 then v2 from the same pinned snapshot. Both final patches are limited to bot.py and test_harness_compatibility.py. The independent host build/install, full suite (59 passed), focused doctor regression (1 passed), and exact-scope checks passed for both. v1 also completed code, test, and security reviews; security review found and fixed arbitrary agent-state disclosure. v2 completed in 2m09s and ran a source-based suite (58 passed, one installed-wheel provenance test deselected), but did not run pip or build a wheel in the candidate.

Both frozen raw host grades are marked fail because the frozen semantic test double supplied validate_codex_binding and inspected only direct response.send_message. Both valid implementations use the existing resolve_binding API and defer an ephemeral interaction before sending a private followup. A separate, post-run diagnostic adapted only those two fake interfaces; all identity, authorization, stale/missing guidance, privacy, state, and validation-error checks passed for both patches. The frozen grader and acceptance inputs were not changed after the conditions. See supplemental-semantic.py and the per-condition diagnostic records.

The candidate TUI ran on the host; harness-eval applied to tool children only. No live services, network, publication, push, merge, or hosted CI were used. Candidate commits were not made. Token usage and model-turn counts were not captured.

See the [frozen task](task.md), [acceptance](acceptance.json), [freeze/calibration](freeze.json), [v1 run and patch](v1-run.json) / [v1.patch](v1.patch), [v2 run and patch](v2-run.json) / [v2.patch](v2.patch), and [raw host grades](host-grade-v1.json) / [host-grade-v2.json].
