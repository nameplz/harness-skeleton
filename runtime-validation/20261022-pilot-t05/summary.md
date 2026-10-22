# Formal pilot pair T05 — output filtering

Completed 2026-10-22 from the pinned Orca Discord Bridge snapshot `d64e447c9ede7be9687d9077859b5b7ba91213cf`. Both conditions used the same frozen task, prompt, host acceptance, `gpt-6-luna` at `max`, the same candidate-only child-tool profile, and a 30-minute cap. Order was v2 then v1.

| Condition | Functional host acceptance | Final workflow gates | Wall time | Total model tokens | Shell commands |
|---|---:|---:|---:|---:|---:|
| v2 | pass; 61 tests | pass; self-review | 3m 10s | 543,833 | 29 (5 failed) |
| v1 | pass; 68 tests | fail; code and security reviews | 19m 37s | 7,421,509 | 142 (0 failed) |

Both candidates changed only `src/orca_discord_bridge/orca.py` and `tests/test_orca_parsing.py`. Independent host copies rebuilt and installed both wheels offline; the full suite and the frozen semantic acceptance passed for both. The v1 workflow exhausted its three implementation attempts: the final code review found that standalone diff-like prose after a hunk can be dropped, and the security review found unsupported Markdown URI schemes such as `vscode://` can pass through as clickable Discord links. These findings remain unresolved; the phase result is `error`, despite functional host acceptance passing. The semantic host fixture did not exercise either edge case.

The v2 run could not execute the repository harness risk/check commands because `scripts/harness.py` and `.harness/config.toml` are absent. The v1 run stayed on the supplied `eval-base` checkout after branch creation was denied. Neither condition committed a candidate change. No live Discord/Orca calls, successful network access, publication, push, merge, or CI run occurred. The Orca TUI parent was a host process; `harness-eval` applied only to tool children.

The pilot now has 6 of 24 model runs (3 of 12 pairs); the separate full evaluation remains at 0 of 72 runs. This pair is mixed and is not evidence of comparative superiority.

See [`task.md`](task.md), [`results.json`](results.json), [`acceptance.json`](acceptance.json), [`task-prompt.txt`](task-prompt.txt), and the final condition patches [`v1.patch`](v1.patch) and [`v2.patch`](v2.patch).
