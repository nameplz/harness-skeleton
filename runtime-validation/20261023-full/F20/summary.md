# F20 — T09 preserve slash-command behavior

F20 used the frozen v2-then-v1 order. Both final patches pass the unchanged host grader: offline wheel build/install, full 59-test suite, six command/prompt semantic cases, and allowed scope. v2 added focused behavioral assertions; v1 also hardened filtering of box-drawing screen decoration.

v1 passed independent code, test, and security reviews. v2 followed the configured T1 self-review path. The task, prompt, semantic check, and grader stayed frozen. Candidate commits were blocked by sandbox restrictions on Git metadata; no bypass was attempted.

Candidate pytest runs reported two temporary-directory cleanup warnings, but all assertions passed; host runs completed cleanly. Harness risk/quick checks were unavailable because `scripts/harness.py` and `.harness/config.toml` are absent. No network, live services, hosted CI, push, publication, or merge occurred; token usage is unknown.

See [frozen task](task.md), [acceptance](acceptance.json), [freeze record](freeze.json), [v2 run](v2-run.json) / [patch](v2-final.patch) / [grade](v2-grade.json), [v1 run](v1-run.json) / [patch](v1-final.patch) / [grade](v1-grade.json), and [pair results](results.json).
