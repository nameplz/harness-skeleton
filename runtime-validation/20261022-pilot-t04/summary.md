# T04 pilot: prevent output crossing worktree and pane boundaries

Both conditions added test-only isolation coverage and passed independent host grading. The pinned implementation already selected the exact worktree and pane; no product code changed. The new fixtures put a same-pane foreign-worktree row and a wrong-pane row before the exact row, and the compatibility test checks that foreign assistant text, prompt/tool details, and screen reads do not enter ordinary structured output.

Both candidate and independent host suites passed all 58 tests. Fresh offline wheel builds/installations and host semantic checks passed. v2 used its risk-based T3 route and its code/security reviews passed. v1’s implementation, code, test, and security reviews passed. The v1 workflow nevertheless records a blocked phase because the sandbox denied creating its feature branch; v2 could not stage a local commit for the same `.git` write restriction. Those failures were not bypassed.

Condition order was v2 then v1, repeating T09 instead of alternating. Exact thread/turn IDs and token usage were unavailable from the terminal adapter and remain unknown. The TUI parent was a host process; only tool children used `harness-eval`. See `results.json` for the deviations and preserved evidence.
