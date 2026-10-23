# F29 matched full-evaluation pair

Task: treat valid non-object JSON state as an empty disconnected state. Order: v2 then v1.

| Condition | Candidate checks | Frozen host grade | Reviews |
|---|---|---|---|
| v2 | Offline wheel/install; full suite 65 passed; focused module 54 passed; two cleanup warnings. | Pass: seven non-object roots, preserved state behavior, both suites, exact two-file scope. | T1 self-review passed. |
| v1 | Offline wheel/install; full suite 65 passed; focused module 54 passed; two cleanup warnings. | Pass: seven non-object roots, preserved state behavior, both suites, exact two-file scope. | Code, test, and security reviews passed with no findings. |

Both patches change only `state.py` and `tests/test_harness_compatibility.py`. Candidate Harness CLI/config and Git metadata were unavailable; the independent host grader verified patch application and scope.

F29 completes pair 29/36 (58/72 model runs). The cumulative order allocation is 14 v1→v2 and 15 v2→v1. See the frozen task, calibration artifacts, run records, host grades, and patches for evidence.
