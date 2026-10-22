# Agent evaluation: lightweight v1/v2 comparison

Updated 2026-10-22. The handoff asks whether a lightweight Codex-native workflow preserves task quality while reducing orchestration, context and maintenance cost. This document defines that comparison. Unit tests, risk fixtures, fixed provider responses and protocol qualification are implementation evidence, not model-task results. No actual v1/v2 task comparison has been recorded yet.

## 2026-10-22 isolation and exploratory pilot

An existing Lima VM (`audit-vz`) is retained under `v4/.lima-vm01` and is currently stopped. It has no host mounts, but its qualification manifest records zero evaluation model calls, `runtime_readiness: unknown`, and incomplete production action-audit and process-cleanup verification. Its supervised native preflight explicitly made no auth or model-turn requests. It is therefore not qualified to run model-driven v1/v2 trials. Running the pinned Codex CLI inside that guest would also violate v1's explicit ban on an external headless runner; the VM does not resolve v1's missing executable adapter.

The repository already provides a candidate-only Codex permission profile, so the exploratory pilot used that existing path instead of adding another sandbox layer. With the project Python runtime, a preflight under `harness-eval` allowed candidate writes and denied opens of the host Codex config and an external synthetic grader sentinel, writes outside the candidate, and a loopback network bind (`EPERM` for each denied operation). The probe opened no file bytes. The Codex CLI parent remains trusted and uses the host account; these checks cover model-generated tool processes, not a hostile parent or the whole machine.

An earlier bare `codex sandbox` probe could open `~/.codex/config.toml` without reading it. That default sandbox is insufficient; the pilot used the explicit repository profile and verified its boundary as above. OpenAI's [sandbox security guidance](https://developers.openai.com/api/docs/guides/agents-api/environments/security) likewise says agent-generated code can access files and credentials available to its environment and recommends isolated compute and credential separation.

One exploratory documentation-task pair used the existing `baseline`/`harness` fixture conditions. It is an ablation, not v1 versus v2. Both runs used `gpt-6-luna`, Codex CLI `0.163.0`, the current runner's `high` reasoning setting, one completed model turn and five command calls. Both candidate transcripts show `python -m unittest discover -v` exiting 0; the same test was rerun by the host in a read-only sandbox and passed. The host functional grader passed both README fixes. Its `validation_ok` and `scope_ok` remain unknown because this direct CLI path does not produce the evaluator's required hook-based validation observation or a complete action audit.

| Condition | Wall time | Input / output tokens | Functional check | Independent test |
|---|---:|---:|---|---|
| baseline | 22.39 s | 144,789 / 1,215 | pass | 1 test passed |
| harness | 21.83 s | 128,083 / 1,098 | pass | 1 test passed |

These are two exploratory runs, not evidence of a general quality, time or token advantage. The harness treatment's Git seed also contains its additional guidance files. The preserved v1 commit (`134c98a2f8be326e3e3688f411a6b348bd463f7f`) has no executable Codex adapter for `StepPipeline`, and its workflow explicitly forbids an external headless runner. The installed CLI is `0.163.0`; the separate native evaluator remains pinned to `0.162.1` and does not accept v1/v2 conditions. Therefore the v1/v2 comparison is still unrun. The pilot evidence is in [`comparison.json`](/Users/yuhyeon/Documents/proj/harness/codex_work/v4/runtime-validation/20261022-baseline-harness-smoke-01/comparison.json) (SHA-256 `ff56a2a847e610538a792ee97152eb36c41de92a531c4fdbda1b35822ae5f86a`); its source snapshot was target HEAD `53b4de7fec57bea2980b5c225136b18aef9895b8`.

## Minimal execution

1. Preserve the legacy-v1 revision and the actual v2 revision, instructions and project validation config. Define how each workflow runs in Codex; do not assume a Python Protocol is an executable adapter. The existing fixture conditions `baseline`/`harness` remove/add guidance and config; they are an ablation, not legacy-v1 versus v2. Do not relabel their records as v1/v2.
2. Resolve the handoff's GPT-6 Luna Max target against the earlier gpt-6.1-sol/high manifest. Use the same actual model, reasoning, runtime, starting product state, permissions, budget and independent functional checks for both conditions. Preserve the workflow/instruction differences being measured. If v1 cannot be reproduced, state the limitation instead of inventing a baseline.
3. Start with one small documentation or bug-fix task per condition using existing Codex execution and logs. Reset the starting state between runs; retain failures and timeouts. Workflow reviewers may add calls: two task runs do not necessarily mean two model calls.
4. Have the operator inspect final changes and run the same acceptance checks outside candidate control. Keep answers and grading records protected. A candidate's completion message is not proof of success. Fix only observed blockers, then extend to representative tasks.

The handoff recommends20–30 real-use tasks. Grow toward that coverage through ordinary edits, bugs, regressions, API/module changes, dependencies, CI and security-sensitive changes; do not wait for every fixture before the first measurement. Add repeats when variability or an important regression warrants them. There is no mandatory24-trial pilot,72-trial full run, three repeats per case, or separate smoke-to-formal promotion gate.

## Metrics and interpretation

| Metric | Evidence |
|---|---|
| Task success and first-pass success | Common functional acceptance, preserved tests and final diff; distinguish repair from the first attempt |
| Model turns, subagent and tool calls | Existing logs and explicit operator records; distinguish workflow review from external grading |
| Validation/CI failures, useful review findings, manual interventions | Actual events and adjudicated findings; unrun CI is unmeasured |
| Wall-clock time and available token/usage | Include workflow review and report external grading separately; unknown cost stays unknown |
| Source, static context and maintenance size | Same deployed scope for v1/v2; evaluator development code counted separately |

Keep a small comparison table with task/revision, actual conditions, outcomes, metrics and log references. Do not create a new worker engine or telemetry platform to collect these fields. Unknown or missing observations stay unknown; failed runs remain in the report. One pair of runs does not establish statistical superiority or non-inferiority.

The handoff targets task success at least as good as v1, subagent calls reduced by50% or more, static context by40–60%, agent turns by30% or more, and harness source by50% or more. These are improvement targets, not measured results or automatic reasons to add infrastructure. Explain misses and restore a necessary guardrail when evidence warrants it. Ordinary T0/T1 work must not acquire extra mandatory reviewers; T2/T3 retain risk-based independent review.

## Existing safety boundaries

Use the configured sandbox, writable roots, network/tool permissions, bounded execution and existing cleanup mechanisms. Separate actual service authentication from candidate tools; never copy host credentials into the guest. Use synthetic data and no production services or unauthorized external writes. If the chosen environment cannot protect credentials, grading or the host, do not launch; report the specific blocker and smallest safe alternative.

Functional task observations and security claims are separate. Passing task checks does not prove that no forbidden syscall occurred. Record observed scope violations or denied attempts and any limits of the observation. Complete OS action-audit coverage, universal descendant-cleanup proof, BPF/LSM observers and additional protected receipt infrastructure are outside this handoff comparison. Their absence must not be converted into a true capability flag or an empty forbidden-action list.

An optional backend retains all its own safety and replay guards. Do not bypass them to obtain a passing result. Use an appropriate existing Codex execution path for the task instead of making that backend's unfinished qualification a prerequisite for every comparison. Production audit/whole-tree capability flags remain false and readiness unknown where currently unverified.

## Existing experimental tools

```bash
python scripts/eval_harness.py
python scripts/check_agent_eval.py
python scripts/check_agent_eval.py --results /path/outside-candidate/results.json
```

`eval_harness.py` checks deterministic risk fixtures. The default result checker only prints a12-scenario, three-trial plan and never launches a model. Supplied-result validation is advisory: it checks its strict schema and consistency, not grader authenticity. It supports `baseline`/`harness`, not newly implemented v1/v2 workflows. Its schema2 suites distinguish handling outcomes from actual successful validation.

These tools and their12 synthetic fixtures are optional existing implementations, not required benchmark coverage or a fixed96-run completion criterion. All12 materialization paths exist; the two remote cases require a fresh protected context. Reuse a fixture only where it matches a real task being compared. Do not add arbitrary fields to the checker or present an independently written comparison table as a checker-accepted result.

The experimental native grader still rejects the supervised profile, native collector cleanup flags stayfalse, and complete-audit scope acceptance remainsunknown. Those implementation contracts are unchanged; a checker report may remain incomplete. Completing that adversarial evaluator is no longer a prerequisite or required follow-up for the handoff's functional/productivity comparison.

## Preserved qualification records

Existing native/VM/audit experiments and failed runs remain valid only for their recorded source and finite scope. They are not model quality results. Optional pinned BPF contracts remain in [NATIVE_BPF.md](NATIVE_BPF.md). The longer historical infrastructure protocol is preserved in Git at `475b9e64b2782a043f31c94e985c330aa78f745e:docs/AGENT_EVALUATION.md`; it is not the active work plan. Do not rewrite old source identities or reinterpret their missing audit/cleanup evidence as a pass.
