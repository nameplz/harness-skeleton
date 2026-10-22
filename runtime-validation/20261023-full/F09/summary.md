# F09 — T05 standard Discord output filtering

F09 ran v2 then v1. Both final patches stayed within `orca.py` and `test_orca_parsing.py`. Each final patch passed the frozen host grader: offline wheel build/install, 60-test full suite, both named boundary/link tests, host semantic checks, and exact allowed scope. The patches address EOF diff omission; v1 also covers Git rename, deletion, binary-patch metadata and exact 2,400/2,401-character and 45/46-line boundaries. Candidate `git diff --check` passed for v1.

v2 completed its T1 self-review in 2m 28s. v1’s first review cycle found implementation and test-coverage changes, which were applied. The v1 TUI later returned an incomplete response at `max_output_tokens`; three concise continuation/security-review prompts were accepted but each stream disconnected before returning a result. The final v1 patch passed the independent host grader, but its final code/test review results and required security-review outcome were not captured. Retain this as a workflow-completion failure rather than changing the host-grade outcome.

No network, live services, publication, push, or merge was used. The pinned snapshot lacks the Harness risk/check files. Candidate Git writes were sandbox-blocked; no workaround was attempted. Token usage and model-turn counts remain unknown.

See the [frozen task](task.md), [acceptance](acceptance.json), [freeze/calibration](freeze.json), [v2 run and patch](v2-run.json) / [v2.patch](v2.patch), [v1 run and patch](v1-run.json) / [v1.patch](v1.patch), and [host v2](host-grade-v2.json) / [host v1](host-grade-v1.json) grades.
