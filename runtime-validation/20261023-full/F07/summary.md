# F07 — T18 standard macOS launcher

The frozen order was v1 then v2. Both candidates changed only `start.command` and `tests/test_harness_compatibility.py`; both launchers were executable. Each candidate passed offline wheel build/install and the full 59-test suite. Both frozen host grades passed the focused behavior checks for first-install startup, repeat reuse without system Python or reinstall, paths with spaces, missing-Python guidance, and token redaction. v1’s implementation, code, test, and security reviews passed; v2 followed the T1 self-review route.

TUI-reported durations were 7m 16s for v1 and 2m 58s for v2. Candidate branch/commit writes were denied by sandbox Git restrictions, so both patches are retained without candidate commits. No network, external services, project hooks, push, publish, merge, or hosted CI was used. The pinned checkout lacks the Harness risk/check files.

See the [frozen task](task.md), [acceptance](acceptance.json), [v1 run and patch](v1-run.json) / [v1.patch](v1.patch), [v2 run and patch](v2-run.json) / [v2.patch](v2.patch), and [v1 host grade](host-grade-v1.json) / [v2 host grade](host-grade-v2.json).
