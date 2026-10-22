# F03 — T06 long and interrupted replies

Frozen acceptance was applied unchanged to both conditions. v1 and v2 each passed a fresh offline wheel build/install, the full project test suite, all four semantic checks, and the exact two-file scope check. v1 passed with 59 tests and v2 with 60. v1 final code, test, and security reviews passed. The T1 v2 route did not launch independent review agents; its candidate self-review and host-owned acceptance passed.

v1 took 7m 58s and v2 took 2m 47s (TUI-reported; host grading excluded). The final output preserves lossless chunk concatenation, the 1,900-character limit, the interruption marker, and the documented empty-output fallback.

See [frozen task](task.md), [prompt](task-prompt.txt), [acceptance](acceptance.json), [v1 record](v1-run.json), [v2 record](v2-run.json), [v1 host grade](host-grade-v1.json), and [v2 host grade](host-grade-v2.json). Candidate patches are retained as [v1.patch](v1.patch) and [v2.patch](v2.patch).

Limitations: token usage and shell-command counts were not captured. The candidate snapshot lacks `scripts/harness.py` and `.harness/config.toml`, so its Harness-specific checks could not run. Hosted CI was not dispatched. The TUI parent ran on the host; only tool children had the harness-eval profile.
