# F02 — T11 multiple input channels

The reused T11 task/prompt and corrected host grader were frozen before either condition. A fresh pinned-snapshot baseline rebuilt and installed offline, passed all 58 existing tests, and failed only the additional-channel forwarding and invalid-ID rejection checks. The grader permits exactly the three files named by the task.

Both v2 and v1 passed frozen host acceptance, including all five semantic checks, exact scope, and fresh offline build/install. v2 passed 62 tests; v1 passed 63. Final code and security reviews passed in v2; final code, test, and security reviews passed in v1. v1 corrected an initial regression in configuration error precedence before final acceptance.

TUI-reported durations were 3m 52s for v2 and 5m 35s for v1, excluding host grading. See [frozen acceptance](acceptance.json), [v2 record](v2-run.json), [v1 record](v1-run.json), [v2 host grade](host-grade-v2.json), and [v1 host grade](host-grade-v1.json); retained patches are [v2.patch](v2.patch) and [v1.patch](v1.patch).

Limitations: token usage and shell-command counts were not captured. The snapshot lacks `scripts/harness.py` and `.harness/config.toml`, so the candidate-side Harness checks could not run; hosted CI was not dispatched. The TUI parent remained on the host and tool children alone used the harness-eval profile.
