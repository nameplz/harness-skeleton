# F01 — T14 cancellation versus timeout

Frozen acceptance was applied unchanged to both conditions. v1 and v2 each passed a fresh offline wheel build/install, the full project test suite, all five semantic checks, and the exact two-file scope check. v1 passed with 61 tests; v2 passed with 60 tests, including repeated cancellation and a SIGTERM-resistant child. Final required independent reviews passed for both conditions.

v1 took 12m 49s and v2 took 6m 33s (TUI-reported; host grading excluded). v1's initial security review finding about repeated cancellation interrupting child cleanup was fixed before final acceptance. v2's reviewers drove bounded terminate-to-kill cleanup, safe fake-child test cleanup, and an explicit repeated-cancellation test; its final code and security reviews found no remaining issues.

See [frozen task](task.md), [prompt](task-prompt.txt), [acceptance](acceptance.json), [v1 record](v1-run.json), [v2 record](v2-run.json), [v1 host grade](host-grade-v1.json), and [v2 host grade](host-grade-v2.json). Candidate patches are retained as [v1.patch](v1.patch) and [v2.patch](v2.patch).

Limitations: token usage and shell-command counts were not captured. The candidate snapshot lacks `scripts/harness.py` and `.harness/config.toml`, so its Harness-specific risk/full checks could not run. The hosted GitHub workflow was not dispatched. The TUI parent ran on the host; only tool children had the harness-eval profile.
