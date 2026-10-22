# F14 — T09 status versus compact

Both conditions passed the frozen host grader. Each rebuilt and installed the wheel offline, passed the 59-test project suite, passed all six focused slash-command cases, changed only the allowed Orca client and compatibility test, and passed diff checks.

v1 passed independent code, test, and security reviews. The test reviewer requested that the test assert the send targets the bound terminal; the candidate added that assertion, reran acceptance, and then all final reviews passed. v2 passed final read-only code and security reviews after fixing an ASCII screen-border filtering case; the final reviewers assessed the updated diff. No separate v2 test-review result was captured.

The TUI could not create v1's requested local workflow branch because the sandbox denied writing its Git ref lock; no bypass or candidate commit was attempted. The candidate checkout lacks scripts/harness.py, so its Harness quick/risk wrapper did not run. Both conditions used the pinned snapshot and offline commands only. No network, live services, hosted CI, publication, push, or merge occurred. Token counts and exact model-turn counts are unknown.

See the frozen task, freeze/calibration, v1 and v2 run records, patches, host grades, and pair results in this directory.
