# F06 — T18 missing-Python launcher bootstrap

The frozen order was v2 then v1. Both candidates added the executable `start.command` and a temporary-fake regression test, stayed within the exact two-file product scope, and passed offline wheel build/install plus the full 59-test suite. The focused launcher regression passed in both host rechecks. v1’s implementation, final code/test reviews, and security review passed; review added an assertion for the source launcher’s executable mode and aligned repeat launches with the README by skipping reinstall.

Both raw frozen host grades are retained as failures. Their only failing semantic assertion requires `pip install` on a reused venv; both candidates instead install when creating the venv and start directly on later runs, matching the README. The frozen grader was not changed, and the focused tests do not replace the raw grades.

v2 took 4m 8s. v1 took about 10 minutes; exact completion duration was not captured. The candidate could not create a Git branch or commit because sandbox Git writes were denied. No external service, network, push, publish, merge, or hosted CI was used. The pinned checkout lacks the Harness risk/check files.

See the [frozen task](task.md), [acceptance](acceptance.json), [v2 run and patch](v2-run.json) / [v2.patch](v2.patch), [v1 run and patch](v1-run.json) / [v1.patch](v1.patch), [v2 raw host grade](host-grade-v2.json) / [v1 raw host grade](host-grade-v1.json), and [v2 supplemental check](supplemental-v2.json) / [v1 supplemental check](supplemental-v1.json).
