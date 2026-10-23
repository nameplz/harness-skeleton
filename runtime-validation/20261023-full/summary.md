# 2026-10-23 v1/v2 evaluation summary

The exploratory `20261022-matched-task-01` pair is excluded because its 30-minute budget was not declared before the runs. Each formal condition used the same 1,800-second wall-clock cap from task submission through the candidate's final response; host grading was outside that cap. Formal pilot and full batches are complete: 12 pilot pairs / 24 model runs and 36 full pairs / 72 model runs. Across both batches, the task IDs cover T01–T20. Pilot order was balanced 6/6; `progress.json` records the full batch order as 18/18.

## Frozen host-grade outcomes

| Batch | v1 pass | v2 pass | Both pass | One pass | Neither pass |
|---|---:|---:|---:|---:|---:|
| Pilot (12 pairs) | 11/12 | 12/12 | 11/12 | 1/12 | 0/12 |
| Full (36 pairs) | 25/36 | 24/36 | 22/36 | 5/36 | 9/36 |

These are frozen functional host-grade results, not a statistical claim that either harness is generally better. The pilot's one mixed pair (T05) passed functional acceptance on v1 but failed its final code/security review gate. T14 also records a v1 test-review gate failure despite passing its frozen host grade. Full-batch F13 v1 was blocked before editing and is counted as a non-pass in the denominator. Review/security findings and grader limitations remain part of the pair records; a host-grade pass alone does not resolve them. For example, F21/F22 retain review-level blockers, and F35's v2 frozen semantic check did not recognize the explicit `guild_id=None` fixture. Frozen task inputs and graders were not changed after runs to improve scores.

## Metric coverage and limits

- Pilot wall time is recorded for all 24 conditions (numeric milliseconds for 12); token usage is available for 8/24 conditions.
- Full wall time is recorded for 24/36 conditions per harness (numeric values for 16 v1 and 18 v2 conditions). Token usage and model turns were not captured for the full batch. Tool-call counts are not consistently available, and subagent-launch metadata covers only a small subset; no overall reduction claim is supported.
- The outer harness repository's `python scripts/harness.py check --full` passed before this documentation update: 766 unit tests, 36 risk fixtures, and dry-run 12 tasks / 36 trials. Dry-run trials are not model runs.
- Candidate project patches were independently graded and retained. Candidate Git writes were denied in the evaluated project snapshots, so those candidates were not committed there. The Orca TUI parent was a host process; `harness-eval` applied to tool children only. This does not establish complete TUI, MCP, OS-audit, or descendant-cleanup confinement.
- GitHub Actions was not dispatched. Draft PR #2 targets `harness-v2`, while the trusted base workflows select pull requests targeting `main`; the PR currently has zero checks. The Python CI matrix therefore remains unverified.

The formal run quotas are complete. The remaining delivery limitation is trusted CI for the explicitly selected `harness-v2` base; the PR remains draft and unmerged pending a separately authorized trusted-base path.
