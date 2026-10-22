# F19 — T01 alternate invalid JSON state

F19 followed the frozen v1-then-v2 order. Both final patches pass the unchanged host grader: offline wheel build/install, the full and focused suites, six non-object JSON roots, five malformed byte forms, unchanged invalid-file bytes, missing/valid state, and connect/disconnect behavior. v1 passed with 68 tests; v2 passed with 72.

v1 passed independent code, test, and security reviews. v2 followed the configured T1 self-review route. Both patches stay within `state.py` and `test_harness_compatibility.py`; neither condition made a local candidate commit because Git metadata writes were sandbox-blocked. The task, prompt, semantic checks, and grader remained frozen.

Candidate test runs reported two pytest temporary-directory cleanup warnings, but assertions passed; the independent host runs completed cleanly. The pinned snapshot lacks `scripts/harness.py` and `.harness/config.toml`, so Harness risk/quick checks were unavailable. The TUI parent was a host process, with harness-eval applied only to tool children. No network, live service, hosted CI, publication, push, or merge occurred; token usage is unknown.

See [the frozen task](task.md), [acceptance](acceptance.json), [freeze hashes and calibration](freeze.json), [v1 run](v1-run.json), [v1 patch](v1-final.patch), [v1 host grade](v1-grade.json), [v2 run](v2-run.json), [v2 patch](v2-final.patch), [v2 host grade](v2-grade.json), and [pair results](results.json).
