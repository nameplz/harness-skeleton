# Agent evaluation: lightweight v1/v2 comparison

Updated 2026-10-22. The handoff asks whether a lightweight Codex-native workflow preserves task quality while reducing orchestration, context and maintenance cost. This document defines that comparison. Unit tests, risk fixtures, fixed provider responses and protocol qualification are implementation evidence, not model-task results. No actual v1/v2 task comparison has been recorded yet.

## 2026-10-22 isolation and exploratory pilot

An existing Lima VM (`audit-vz`) is retained under `v4/.lima-vm01` and is currently stopped. It has no host mounts, but its qualification manifest records zero evaluation model calls, `runtime_readiness: unknown`, and incomplete production action-audit and process-cleanup verification. Its supervised native preflight explicitly made no auth or model-turn requests. It is therefore not qualified to run model-driven v1/v2 trials. Reusing its previous `codex exec` path would violate v1's explicit ban on an external headless runner; a native interactive TUI path in a qualified guest has not been implemented or tested.

The repository provides a candidate-only Codex permission profile. Run `python scripts/check_eval_sandbox.py` before a local trial to qualify its effective boundary; it creates and removes a disposable candidate, launches no model, and never reads host config, auth, or sentinel bytes. Run it from a host process that can apply the OS sandbox; an `EPERM` sandbox-application failure is a failed preflight, not a pass. The preflight requires present host config/auth files, verifies the CLI and its Node runtime against a root-controlled installation, and checks candidate writes, host config/auth and external sentinel opens, outside-candidate writes, loopback bind, and inheritance of file restrictions by a Python descendant. It also runs a synthetic project hook through `scripts/isolated_hook_runner.py`. The Codex CLI parent remains trusted and outside this tool-child sandbox; TUI hook event delivery, MCP behavior, and universal descendant cleanup are not established by this preflight.

On 2026-10-22 the preflight passed with Codex CLI `0.163.0`: trusted host controls could open config/auth and the synthetic sentinel without reading bytes, write outside the candidate, and bind loopback; the sandboxed candidate could write only inside its root, while config/auth/sentinel opens, outside writes, loopback bind, and both descendant boundary probes were denied. Codex and Node binary SHA-256 values were `61b0194f3bb6534439c8d26a3ed57d0805f84b884588b761795323eeb92fcf70` and `4992b78b24d763b45f0d61917ed883312e9f48f6f9041f6735a866dcf81934fa`; policy, command, and environment SHA-256 values were `8f3a98d783453ccadef5ffa051ec0f6e8ef06a7ca29aa19bdcb6a1c66a18c2c6`, `f884ceb8e6b2835a953704ece426378a464a6ef9d9cf0fa46a9846ace1a82c3a`, and `e2cd9279b69b158e617970b1b3fd108f7d23dc18a78bf05d200458ed22345add`, respectively. No model call was made. This is an OS sandbox for tool child processes, not a separate VM or a claim that the trusted Codex parent is isolated.

An earlier bare `codex sandbox` probe could open `~/.codex/config.toml` without reading it. That default sandbox is insufficient; the pilot used the explicit repository profile and verified its boundary as above. OpenAI's [sandbox security guidance](https://developers.openai.com/api/docs/guides/agents-api/environments/security) likewise says agent-generated code can access files and credentials available to its environment and recommends isolated compute and credential separation.

## 2026-10-22 isolated hook launcher probe

`scripts/isolated_hook_runner.py` accepts only a bounded JSON hook event and sends those bytes as stdin; it never inherits the host terminal or hook process stdin. It requires the workspace and its `.harness` scratch directory to be owned by the operator and private (no group/other permissions), with the workspace strictly below a private operator scratch root and on the same filesystem. It rejects escaping symlinks, hardlinks, special files, different-device directories and reported mountpoints, and caps the tree at 100,000 entries. Same-device bind mounts are not detected. Callers must stage a fresh, credential-free disposable copy; the runner cannot determine whether ordinary files inside a candidate contain secrets. The runner snapshots a regular hook source (at most 1 MiB) to a private read-only directory outside the candidate before execution. The candidate hook runs under the `harness-eval` OS sandbox with a 180-second maximum, 1 MiB captured output, only `PATH`, temporary `HOME`/`TMPDIR`, and `PYTHONDONTWRITEBYTECODE`, and Codex/Node binaries checked before and after the run. The candidate workspace is the only writable root; the profile disables network, and `CODEX_HOME` and host credentials are omitted. Invoke this runner from the protected source checkout for disposable candidate copies. The runner is opt-in: the repository's normal `.codex/config.toml` still points its local development hooks directly at `harness_hook.py`, so this preflight does not claim to sandbox those hooks automatically.

The updated `python scripts/check_eval_sandbox.py` preflight passed on 2026-10-22 with Codex CLI `0.163.0`. Its synthetic hook parsed the bounded `SessionStart` JSON received on stdin. The candidate `.codex/config.toml` attempted to grant root/tmp access and enable network; the effective sandbox still allowed candidate writes while denying host config/auth and external sentinel opens, outside writes, loopback bind, and Python-descendant boundary attempts. The trusted preflight opened host config/auth paths without reading bytes. The adversarial project-config SHA-256 is `03bd0f4451925b2ed8f3418fd9a3bc2f4fe800d8f01d6b1a95dc11cf12038230`; hook payload/runner SHA-256 values are `42b59eba24e4a1a47a1c6df810294647e69b10c383382bfa83b540b8269397c5` / `8ff82766b66ceacf5e690306a606492f7b8c033876cfc280233b30a82e9286fc`. Codex, Node and policy SHA-256 values remain `61b0194f3bb6534439c8d26a3ed57d0805f84b884588b761795323eeb92fcf70`, `4992b78b24d763b45f0d61917ed883312e9f48f6f9041f6735a866dcf81934fa`, and `8f3a98d783453ccadef5ffa051ec0f6e8ef06a7ca29aa19bdcb6a1c66a18c2c6`; this run's direct probe command/environment SHA-256 values are `f2afe35f9e86556e15ef4ac166f42f8761c08e34abdc6e1f2b6f2bc4a3379fd8` / `43c938d3042aa40bb3666aa5e9e9bfa21227a194993e6a47d496f8473b961ee7`. The profile disables direct network and loopback bind was denied; outbound, DNS and Unix-socket probes were not measured. Model task started: no.

The configured `python scripts/harness.py check --full` passed with 765 unit tests, 36 risk fixtures, and a dry-run plan for 12 tasks/36 trials; the captured working-tree evidence was unchanged. Three subprocess `ResourceWarning`s were emitted by the existing test suite.

The disposable TUI project was reviewed through Codex's normal hook review screen. Its one `SessionStart` command pointed to the protected source runner and the synthetic candidate hook; the operator trusted that hook individually, and the UI reported it active. The TUI then reached an empty prompt, but no `SessionStart` delivery record appeared. A local-session attempt was interrupted without an evaluation task or model-generated response. Therefore actual TUI hook delivery remains unknown; no trust bypass was used. The temporary TUI project and `CODEX_HOME` are disposable and are removed after this check. MCP behavior and universal cleanup of detached descendants remain unmeasured.

One exploratory documentation-task pair used the existing `baseline`/`harness` fixture conditions. It is an ablation, not v1 versus v2. Both runs used `gpt-6-luna`, Codex CLI `0.163.0`, the current runner's `high` reasoning setting, one completed model turn and five command calls. Both candidate transcripts show `python -m unittest discover -v` exiting 0; the same test was rerun by the host in a read-only sandbox and passed. The host functional grader passed both README fixes. Its `validation_ok` and `scope_ok` remain unknown because this direct CLI path does not produce the evaluator's required hook-based validation observation or a complete action audit.

| Condition | Wall time | Input / output tokens | Functional check | Independent test |
|---|---:|---:|---|---|
| baseline | 22.39 s | 144,789 / 1,215 | pass | 1 test passed |
| harness | 21.83 s | 128,083 / 1,098 | pass | 1 test passed |

These are two exploratory runs, not evidence of a general quality, time or token advantage. The harness treatment's Git seed also contains its additional guidance files. The preserved v1 commit (`134c98a2f8be326e3e3688f411a6b348bd463f7f`) has no executable Codex adapter for `StepPipeline`, and its workflow explicitly forbids an external headless runner. The installed CLI is `0.163.0`; the separate native evaluator remains pinned to `0.162.1` and does not accept v1/v2 conditions. Therefore the v1/v2 comparison is still unrun. The pilot evidence is in [`comparison.json`](/Users/yuhyeon/Documents/proj/harness/codex_work/v4/runtime-validation/20261022-baseline-harness-smoke-01/comparison.json) (SHA-256 `ff56a2a847e610538a792ee97152eb36c41de92a531c4fdbda1b35822ae5f86a`); its source snapshot was target HEAD `53b4de7fec57bea2980b5c225136b18aef9895b8`.

## 2026-10-22 interactive TUI hook preflight (no model task)

The installed Codex CLI `0.163.0` was started through its interactive TUI with `--no-alt-screen`, a temporary `CODEX_HOME`, the `harness-eval` permission overrides, model selection `gpt-6-luna`, and reasoning effort `max`. The temporary home linked the existing auth file; it did not copy credentials. A temporary candidate Git root was used so Codex would not resolve the parent repository's `AGENTS.md` from outside the candidate boundary. The TUI reached its prompt without a task prompt being sent. Its status bar showed `GPT-6-Luna max`; this is only the selected UI label, not a model inference result.

The TUI required review of the synthetic project `SessionStart` hook and displayed: “Hooks can run outside the sandbox after you trust them.” Automatic review rejected trusting that hook because the trust action could execute candidate-controlled hook code outside the sandbox. The hook was left untrusted, so it did not run. No model prompt or inference call was made, and no hook event was observed. The first launch also failed to start because Codex resolved the parent repository as the workspace and could not read its `AGENTS.md` through the candidate sandbox; a nested temporary Git root fixed that separate setup error. Codex's [hook documentation](https://developers.openai.com/codex/hooks) describes the same trust boundary: project hooks require a trusted project and non-managed hooks require reviewing and trusting their current definition.

This does not qualify direct host-run project hooks. A hook script inside a writable candidate can change during a task, so evaluation must invoke it through the protected launcher described below. The effective TUI tool sandbox, actual hook delivery, and model-task behavior remain unknown; the v1/v2 pair is still unrun.

## 2026-10-22 representative project recheck

The recorded Orca Discord Bridge snapshot still matches its pinned commit (`d64e447c9ede7be9687d9077859b5b7ba91213cf`), remains clean, and contains exactly the ten allowlisted source files plus the previously recorded owned compatibility test. The compatibility test helper's SHA-256 still matches its evidence record. An ephemeral copy ran the installed package and compatibility tests with Python `3.13.12`: `python -I -B -m pytest -q -p no:cacheprovider tests` completed with 58 passing tests in 3.78 seconds. All Orca and Discord interactions in this suite are fake or mocked; no live service calls were made, and the temporary copy was removed.

This rechecks the existing macOS/Python 3.13 project evidence. It is not a v1/v2 model task, a fix for the project's recorded defects, or a new Python/platform matrix; those defects remain recorded as open.

## Minimal execution

1. Preserve the legacy-v1 revision and the actual v2 revision, instructions and project validation config. Define how each workflow runs in Codex; do not assume a Python Protocol is an executable adapter. The existing fixture conditions `baseline`/`harness` remove/add guidance and config; they are an ablation, not legacy-v1 versus v2. Do not relabel their records as v1/v2.
2. Resolve the handoff's GPT-6 Luna Max target against the earlier gpt-6.1-sol/high manifest. Use the same actual model, reasoning, runtime, starting product state, permissions, budget and independent functional checks for both conditions. Preserve the workflow/instruction differences being measured. If v1 cannot be reproduced, state the limitation instead of inventing a baseline.
3. Start with one small documentation or bug-fix task per condition using existing Codex execution and logs. Reset the starting state between runs; retain failures and timeouts. Workflow reviewers may add calls: two task runs do not necessarily mean two model calls.
4. Have the operator inspect final changes and run the same acceptance checks outside candidate control. Keep answers and grading records protected. A candidate's completion message is not proof of success. Fix only observed blockers, then extend to representative tasks.

The handoff recommends 20–30 real-use tasks across ordinary edits, bugs, regressions, API/module changes, dependencies, CI and security-sensitive changes. The current user-approved execution plan starts with one matched task per condition and expands based on observed blockers; it explicitly removes a fixed 24-trial pilot, separate 72-trial full evaluation, and mandatory three repetitions. Retain failures and unknowns, and do not substitute the earlier `baseline`/`harness` ablation or the synthetic fixture count for v1/v2 task results.

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

These tools and their 12 synthetic fixtures are not real matched tasks and do not count toward the handoff's 20–30 real-use task recommendation. All 12 materialization paths exist; the two remote cases require a fresh protected context. Reuse a fixture only where it matches a real task being compared. Do not add arbitrary fields to the checker or present an independently written comparison table as a checker-accepted result.

The experimental native grader still rejects the supervised profile, native collector cleanup flags stayfalse, and complete-audit scope acceptance remainsunknown. Those implementation contracts are unchanged; a checker report may remain incomplete. Completing that adversarial evaluator is no longer a prerequisite or required follow-up for the handoff's functional/productivity comparison.

## Preserved qualification records

Existing native/VM/audit experiments and failed runs remain valid only for their recorded source and finite scope. They are not model quality results. Optional pinned BPF contracts remain in [NATIVE_BPF.md](NATIVE_BPF.md). The longer historical infrastructure protocol is preserved in Git at `475b9e64b2782a043f31c94e985c330aa78f745e:docs/AGENT_EVALUATION.md`; it is not the active work plan. Do not rewrite old source identities or reinterpret their missing audit/cleanup evidence as a pass.
