# F26 matched full-evaluation pair

Task: add a minimal GitHub Actions workflow with matching push/pull-request path filters. Order: v1 then v2.

| Condition | Candidate checks | Frozen host grade | Reviews |
|---|---|---|---|
| v1 | Offline wheel/install passed; 58 tests passed (two cleanup warnings). | Pass: exact workflow semantics, scope, offline build/install, and 58-test suite. | Code, test, and security passed. |
| v2 | Offline wheel/install passed; 58 tests passed (two cleanup warnings); git diff --check passed. | Pass: exact workflow semantics, scope, offline build/install, and 58-test suite. | Code and security passed. |

Both patches add only .github/workflows/ci.yml. The workflow uses the five frozen paths for both push and pull request, Python 3.11–3.13, least-privilege permissions, pinned checkout/setup-python actions, and the requested install/test commands. No workflow was dispatched.

F26 completes pair 26/36 (52/72 model runs). The cumulative order allocation is 14 v1→v2 and 12 v2→v1. See v1-run.json, v2-run.json, frozen grades, and patches for evidence.
