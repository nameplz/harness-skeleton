# Formal pilot pair T06 — long and interrupted replies

Completed 2026-10-22 from the pinned Orca Discord Bridge snapshot `d64e447c9ede7be9687d9077859b5b7ba91213cf`. Both conditions used the same frozen task, prompt, host grader, `gpt-6-luna` at `max`, the same candidate-only child-tool profile, and a 30-minute cap. Order was v1 then v2.

| Condition | Host acceptance | Workflow reviews | Wall time | Total model tokens | Shell commands |
|---|---:|---|---:|---:|---:|
| v1 | pass; 60 tests | code, test, and security passed | 8m 18s | 2,919,542 | 62 (4 failed) |
| v2 | pass; 63 tests | no independent reviewers in the T1 route | 3m 39s | 450,298 | 22 (4 failed) |

Both patches changed only `formatting.py` and the compatibility tests. Independent host copies rebuilt and installed both wheels offline; the full project suites and the frozen semantic checks passed. Those checks covered the 1,900-character limit, exact reassembly of cleaned long text with spaces and newlines, the interruption marker, and the documented empty-output fallback. The pinned baseline failed the lossless-reassembly check, confirming the task exercised existing behavior.

The v1 run could not create its requested branch because sandbox policy denied the Git ref write; it completed on `eval-base` without a candidate commit. In v2, the optional harness risk and quick-check commands were unavailable because `scripts/harness.py` and `.harness/config.toml` are absent; TUI Git status was also blocked by system-config access. Host-side grading verified the final scope independently. No project hooks or live services ran, and no network call, push, publication, merge, or CI run occurred. The TUI parent was a host process; `harness-eval` applied only to tool children.

The pilot now has 8 of 24 model runs (4 of 12 pairs); the separate full evaluation remains at 0 of 72 runs. This pair passed both conditions but does not establish comparative superiority.

See [`task.md`](task.md), [`results.json`](results.json), [`acceptance.json`](acceptance.json), [`task-prompt.txt`](task-prompt.txt), and the final condition patches [`v1.patch`](v1.patch) and [`v2.patch`](v2.patch).
