# Formal pilot pair T01 — non-object JSON state

Completed 2026-10-22 from the pinned Orca Discord Bridge snapshot `d64e447c9ede7be9687d9077859b5b7ba91213cf`. Both conditions used the same frozen task, prompt and host acceptance, `gpt-6-luna` at `max`, the same candidate-only child-tool profile, and a 30-minute cap. Order was v1 then v2.

| Condition | Host acceptance | Wall time | Total model tokens | Shell commands | Workflow |
|---|---:|---:|---:|---:|---|
| v1 | pass | 6m 30s | 1,987,414 | 38 (3 failed) | 4 subagents; code, test and security reviews passed |
| v2 | pass | 2m 06s | 369,088 | 28 (5 failed) | main-session implementation and self-review |

Both conditions changed only `state.py` and the installed-wheel compatibility tests. Each candidate suite reported 63 passing tests. Independent host copies rebuilt and installed both wheels offline; all 63 tests and separate checks for missing, malformed, object, connect/disconnect, and null/array/string/number/true/false values passed.

The v1 branch-creation command failed because the `eval-base` tag and branch name were ambiguous; work continued in the supplied checkout. v2 could not run the absent `scripts/harness.py` helper commands. Both candidate wheel builds emitted an SSL-unavailable warning for the configured package index; no packages were fetched, and v2 reran with index access disabled. No live Discord/Orca calls or publication occurred. The TUI parent was a host process; `harness-eval` applied to tool children, not a VM.

For this one pair, v1 used about 5.4× the tokens, 3.1× the wall time, and 1.4× the shell commands of v2. These are descriptive measurements, not a general quality or efficiency conclusion.

The formal pilot now has 4 of 24 model runs (2 of 12 pairs). The separate full evaluation remains 0 of 72 runs.

See [`results.json`](results.json), [`acceptance.json`](acceptance.json), [`task-prompt.txt`](task-prompt.txt), and the final condition patches [`v1.patch`](v1.patch) and [`v2.patch`](v2.patch).
