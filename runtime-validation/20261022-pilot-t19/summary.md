# Formal pilot pair T19 — operational documentation

Completed 2026-10-22 using the pinned Orca Discord Bridge snapshot `d64e447c9ede7be9687d9077859b5b7ba91213cf` and baseline `36797d68457b9c806268050d62b7b085a8429bd6`. Both conditions received the same frozen prompt and host-owned source-to-README acceptance rubric, `gpt-6-luna` at `max`, the same candidate-only child-tool profile, and a 30-minute cap. Condition order was v2 then v1.

| Condition | Host acceptance | Wall time | Total model tokens | Shell commands | Agents/reviews |
|---|---:|---:|---:|---:|---|
| v2 | 7/7 pass | 4m 12s | 661,535 | 32 (4 failed) | no subagents; main-session self-review |
| v1 | 7/7 pass | 10m 54s | 7,442,177 | 190 (2 failed searches) | 4 subagent threads, 12 child turns; code, behavior, and security reviews passed after two correction rounds |

Both final README patches passed the independent host rubric. The v1 first draft had precision findings from reviewers and was corrected before all three final reviews passed. The v2 turn tried two unavailable `scripts/harness.py` checks; the representative project has no such script. Neither condition ran project tests because this was documentation-only; the prepared baseline suite had 58 passing tests, which is setup evidence, not a trial result. Both conditions ran `git diff --check` successfully; Git emitted sandbox warnings for the inaccessible system gitattributes file. No live Discord/Orca calls, network access, publication, or candidate commits occurred.

For this single pair, v1 used about 11.3× the tokens, 2.6× the wall time, and 5.9× the shell commands of v2. These are descriptive observations, not a general performance or quality conclusion. The TUI parent ran on the host; the `harness-eval` boundary applied to its tool children and protected hook runner, not a VM.

The formal pilot now has 2 of 24 model runs (1 of 12 pairs) complete. The separate full evaluation remains 0 of 72 runs.

See [`results.json`](results.json), [`acceptance.json`](acceptance.json), and the saved final outputs [`v1-README.md`](v1-README.md) and [`v2-README.md`](v2-README.md); these can be compared with the pinned snapshot to reconstruct each product diff.
