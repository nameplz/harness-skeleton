# F04 — T04 worktree and pane isolation tests

The plan required v2 then v1. Both runs changed only `tests/test_orca_parsing.py` and `tests/test_harness_compatibility.py`; candidate builds, offline installs, full suites (58 passed each), and the independent focused regression tests (4 passed each) succeeded. v1's implementation, code, test, and security reviews passed.

The frozen host grader returned **fail** for both conditions before its focused semantic command because its static check required an identifier named `expected_messages`. Both patches instead assert the exact expected selected-pane output inline. The grader was not changed after either run. Supplemental focused tests against the host-graded trees passed in both conditions, but the formal raw host grades remain failures.

TUI-reported durations were 2m 10s for v2 and 6m 46s for v1 (host grading excluded). v1's candidate workflow also retained a stale T01 `state-load` phase step that conflicted with the frozen T04 scope; the candidate preserved task scope and recorded that phase as blocked. Sandbox restrictions also denied candidate Git staging/branch creation. See the [frozen task](task.md), [acceptance](acceptance.json), [v2 record](v2-run.json), [v1 record](v1-run.json), raw [v2 host grade](host-grade-v2.json), raw [v1 host grade](host-grade-v1.json), and [full-batch progress](../progress.json).

Limitations: token and shell-command counts were not captured. Candidate Harness checks and hosted CI were unavailable; the TUI parent ran on the host while tool children alone used the harness-eval profile.
