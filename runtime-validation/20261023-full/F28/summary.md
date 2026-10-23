# F28 matched full-evaluation pair

Task: make Orca subprocess timeout and cancellation cleanup robust. Order: v2 then v1.

| Condition | Candidate checks | Frozen host grade | Reviews |
|---|---|---|---|
| v2 | Offline wheel/install and full 60-test suite passed; two temporary-directory cleanup warnings. | Pass: all five semantic checks, 60-test suite, and exact two-file scope. | Final code and security reviews passed. Earlier review findings on repeated cancellation and inherited pipes were fixed and re-reviewed. |
| v1 | Offline wheel/install and full 60-test suite passed; focused final review run 8 passed, 41 deselected; two temporary-directory cleanup warnings. | Pass: all five semantic checks, 60-test suite, and exact two-file scope. | Final code, test, and security reviews passed. Test review recorded a low-severity note on separately asserting redaction across every exception-chain field. |

Both patches change only `orca.py` and `tests/test_harness_compatibility.py`. They preserve argv execution and visible error categories, terminate and reap children on timeout/cancellation, and redact subprocess arguments, output, and executable paths from surfaced failures.

F28 completes pair 28/36 (56/72 model runs). The cumulative order allocation is 14 v1→v2 and 14 v2→v1. See the frozen task, run records, host grades, and patches for evidence.
