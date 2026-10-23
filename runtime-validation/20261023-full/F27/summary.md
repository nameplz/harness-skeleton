# F27 matched full-evaluation pair

Task: revalidate saved Orca terminal bindings before forwarding when pane/worktree identity changes. Order: v2 then v1.

| Condition | Candidate checks | Frozen host grade | Reviews |
|---|---|---|---|
| v2 | Offline wheel/install and 59-test suite passed; initial fake setup error was fixed; two cleanup warnings. | Pass: focused regression, pane/worktree semantics, scope, and 59-test suite. | Code and security passed. |
| v1 | Offline wheel/install, 59-test suite, focused regression, and diff check passed; two cleanup warnings. | Pass: focused regression, pane/worktree semantics, scope, and 59-test suite. | Code, test, and security passed. |

Both patches change only bot.py and tests/test_harness_compatibility.py. Both verify validation before persisting/exchanging a changed binding, skip validation when unchanged, and preserve state when validation fails.

F27 completes pair 27/36 (54/72 model runs). The cumulative order allocation is 14 v1→v2 and 13 v2→v1. See the frozen task, run records, grades, and patches for evidence.
