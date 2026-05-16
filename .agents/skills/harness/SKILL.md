---
name: harness
description: Harness framework workflow for planning phased implementation, generating phases/index.json, task index files, and stepN.md files, and executing them through scripts/execute.py with Codex headless sessions. Use when the user asks to use the harness, create or run implementation phases, split work into steps, or manage phase/step status.
---

# Harness

## Overview

Use this workflow to turn a larger implementation request into self-contained phase files that can be executed by `scripts/execute.py`.

## Workflow

1. Read `docs/PRD.md`, `docs/ARCHITECTURE.md`, `docs/ADR.md`, and other relevant docs before proposing steps.
2. Discuss unresolved product or technical decisions with the user before writing phase files.
3. When the user approves implementation planning, split the work into small steps. Keep each step focused on one layer or module.
4. Create or update the phase files under `phases/`.
5. Run phases with `python3 scripts/execute.py <task-name>` or `python3 scripts/execute.py <task-name> --push` when requested.

## Step Design Rules

- Make every `stepN.md` self-contained. Do not rely on prior chat context.
- List required files to read, including docs and files created by previous steps.
- Give interfaces, file paths, class/function names, and invariants; leave implementation details to the executing Codex session unless they are safety-critical.
- Write executable acceptance criteria, such as `npm run build && npm test`.
- State prohibitions concretely as "Do not do X. Reason: Y."
- Use kebab-case step names that describe the core module or action, such as `project-setup`, `api-layer`, or `auth-flow`.

## Phase Files

Create `phases/index.json` if missing. Add the task to the top-level `phases` list:

```json
{
  "phases": [
    {
      "dir": "0-mvp",
      "status": "pending"
    }
  ]
}
```

Create `phases/<task-name>/index.json`:

```json
{
  "project": "<project-name>",
  "phase": "<task-name>",
  "steps": [
    { "step": 0, "name": "project-setup", "status": "pending" },
    { "step": 1, "name": "core-types", "status": "pending" },
    { "step": 2, "name": "api-layer", "status": "pending" }
  ]
}
```

Do not add timestamps during file creation. `scripts/execute.py` records `created_at`, `started_at`, `completed_at`, `failed_at`, and `blocked_at`.

## Step Template

````markdown
# Step {N}: {name}

## 읽어야 할 파일

먼저 아래 파일들을 읽고 프로젝트의 아키텍처와 설계 의도를 파악하라:

- `/docs/ARCHITECTURE.md`
- `/docs/ADR.md`
- {previously created or modified file paths}

## 작업

{specific implementation instructions}

## Acceptance Criteria

```bash
npm run build
npm test
```

## 검증 절차

1. 위 AC 커맨드를 실행한다.
2. ARCHITECTURE.md, ADR, AGENTS.md 규칙 위반 여부를 확인한다.
3. `phases/{task-name}/index.json`의 해당 step 상태를 업데이트한다.

## 금지사항

- {Do not do X. Reason: Y.}
- 기존 테스트를 깨뜨리지 마라.
````

## Execution Semantics

`scripts/execute.py` runs each step in order and invokes Codex headlessly with:

```bash
codex exec -c approval_policy=never -s workspace-write --json "작업 내용"
```

The executor injects `AGENTS.md` and `docs/*.md`, accumulates completed step summaries, retries failed steps up to three times, and separates feature commits from phase metadata commits.

Headless Codex sessions should modify the required files, run the step acceptance criteria, and update only the current step's `status`, `summary`, `error_message`, or `blocked_reason` in `phases/<task-name>/index.json`. They must not run `git commit`; `scripts/execute.py` owns all feature and housekeeping commits.

If a step fails, reset that step from `error` to `pending` and remove `error_message` before rerunning. If a step is blocked, resolve `blocked_reason`, reset it to `pending`, and rerun.
