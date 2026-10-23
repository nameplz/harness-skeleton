# F22 — T05 tilde/local-link output

F22 used the frozen v2-then-v1 order. v2 passed candidate checks (66 tests, two temporary-directory cleanup warnings) and the frozen host grader (19 tests plus all 16 semantic checks).

v1 passed its candidate suite (63 tests, two cleanup warnings) and the frozen host grader (18 tests plus all frozen semantics), but it was not accepted. After three implementation attempts, independent code review still found that an outside absolute path containing parentheses can leak through partial Markdown-destination matching. The three-attempt Harness workflow limit was reached; the independent security review was not run. The frozen grader did not include this case, which the review exposed.

The v1 SessionStart hook exited 125; it was not bypassed, and protected hook/delivery hashes remained unchanged. The candidate diff stayed within the two allowed product files. Harness quick/risk checks were unavailable because `scripts/harness.py` is absent. No network, live services, hosted CI, push, publication, or merge occurred.

See [frozen task](task.md), [acceptance](acceptance.json), [freeze record](freeze.json), [v2 setup](v2-setup.json), [v2 run](v2-run.json) / [patch](v2-final.patch) / [grade](v2-grade.json), [v1 setup](v1-setup.json), [v1 run](v1-run.json) / [patch](v1-final.patch) / [grade](v1-grade.json), and [pair results](results.json).
