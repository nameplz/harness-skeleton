# F17 — T02 atomic private state persistence

v1 passed the frozen host grader: offline wheel build/install, 60-test suite, all seven filesystem semantics, exact scope, and final code/test/security reviews. Its TUI test run reported two temporary-directory cleanup warnings (Errno 66 Directory not empty); the independent host suite completed without warnings. Security review noted a pre-existing low-severity `_load()` failure on valid non-object JSON, outside this task.

v2 passed offline wheel build/install, the 59-test suite, mode/parent/cleanup/reload semantics, and final read-only review. Its frozen raw host grade fails two atomic-replacement checks because the grader monkeypatches `os.replace`, while v2 imported that function as `atomic_replace`. A separate diagnostic intercepting the actual imported alias passed all seven checks. The frozen grader was not changed, so the matched-pair decision remains **fail**.

Both candidate local commits were sandbox-blocked; neither condition pushed or published anything. The candidate lacks `scripts/harness.py`, so its Harness risk/quick checks were unavailable. No hosted CI, network, Discord/Orca service, push, publish, or merge occurred.

See the frozen task/calibration, setup/run records, patches, raw host grades, supplemental diagnostic, and pair result in this directory.
