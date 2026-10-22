# T14 matched pilot pair

Task: make subprocess timeout and cancellation cleanup robust. The frozen task, prompt, acceptance criteria, and baseline calibration are in this directory. Both conditions started from the same pinned snapshot and ran in the order v1 then v2.

| Condition | Candidate workflow | Independent host grade |
|---|---|---|
| v1 | 60 candidate tests passed. Code and security reviews passed. Required test review failed after three attempts because the tests did not deterministically prove that reaping completed before timeout/cancellation propagated. No candidate commit. | Pass: offline wheel build/install, 60 tests, all five semantic checks; only `orca.py` and `test_harness_compatibility.py` changed. |
| v2 | A code review found an inherited-pipe cleanup edge case. The implementation and fake-CLI test were updated; 61 candidate tests and final code/security reviews passed. Candidate commit was blocked when Git could not create `.git/index.lock`. | Pass: offline wheel build/install, 61 tests, all five semantic checks; same two-file scope. |

Both host graders independently rebuilt from the pinned snapshot and retained patch. The baseline had 58 passing tests and failed only the frozen cancellation-cleanup semantic check. T14 is counted as pilot pair 10 of 12 (20/24 model runs); the condition-order balance is now 5 v1→v2 and 5 v2→v1. The next pilot pair is T13, v2 then v1; T17, v1 then v2, follows.

The TUI parent ran on the host; harness-eval applied only to tool children. `scripts/harness.py` was absent, so candidate Harness risk/full checks were unavailable. Tokens, CI, and OS-level action audit were not measured. No remote push, publication, or merge occurred.
