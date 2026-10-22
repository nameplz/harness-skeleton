# F05 — T20 shared authorization policy

The planned order was v1 then v2. Both conditions passed the frozen host grader: fresh offline wheel build/install, exact two-file scope, full project suite (60 tests for v1 and 59 for v2), shared `_auth_error` use in message routing, and denied-message/command Orca call-spy checks. v1 implementation, code, test, and security reviews passed with no findings. v2 followed its T1 self-review route.

TUI-reported durations were 4m 33s for v1 and 2m 51s for v2 (host grading excluded). The v1 candidate could not create its feature branch and v2 could not write the local Git index; both final patches and all host grades are retained.

See the [frozen task](task.md), [acceptance](acceptance.json), [v1 record](v1-run.json), [v2 record](v2-run.json), and [host grades](host-grade-v1.json) / [host-grade-v2.json]. Candidate patches are [v1.patch](v1.patch) and [v2.patch](v2.patch).

Limitations: token usage and shell-command counts were not captured. Candidate Harness checks and hosted CI were unavailable; the TUI parent ran on the host while tool children alone used the harness-eval profile.
