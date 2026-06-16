---
name: harness-workflow
description: Use this skill when planning or executing Harness framework phases and steps, creating `phases/index.json`, `phases/{task}/index.json`, `stepN.md` files, or orchestrating phase execution with Codex worker subagents.
origin: harness_framework
---

# Harness Workflow

이 프로젝트는 Harness 프레임워크를 사용한다. 작업을 phase와 step으로 나누어 설계하고, 승인된 step 파일은 Codex 메인 세션이 worker 서브 에이전트로 순차 실행한다.

Harness skeleton은 언어 중립이다. 프로젝트 문서나 실제 repo 파일이 확립하기 전에는 Node, Python, frontend, backend, 특정 프레임워크를 가정하지 않는다.

## Workflow

1. `AGENTS.md`, `docs/PRD.md`, `docs/ARCHITECTURE.md`, `docs/ADR.md`, 필요한 추가 문서를 읽는다.
2. `AGENTS.md`와 `docs/*.md`에 unresolved `{...}` placeholder가 남아 있으면 phase 계획 전에 사용자에게 프로젝트 spec 작성을 요청한다. 사용자가 명시적으로 early draft를 원한 경우에만 예외로 둔다.
3. 프로젝트 spec이 채워진 뒤 validation을 설정한다.
   - Preview: `python3 scripts/configure_harness.py --dry-run`
   - Write: `python3 scripts/configure_harness.py`
   - Existing config overwrite: `python3 scripts/configure_harness.py --force`
   - Placeholder가 남은 상태의 의도적 초기 설정: `python3 scripts/configure_harness.py --allow-placeholders`
4. 구현에 필요한 제품/기술 결정을 사용자와 논의한다.
5. 작업을 작고 자기완결적인 step으로 나눈다.
6. `phases/` 아래 phase 파일을 생성하거나 갱신한다.
7. 사용자가 phase 실행을 요청하면 메인 세션이 `references/subagent-execution.md` 프로토콜로 worker 서브 에이전트를 순차 실행한다.

## Step Design Rules

- 하나의 step은 하나의 레이어, 모듈, 계약에 집중한다.
- 모든 `stepN.md`는 외부 대화 없이 수행 가능해야 한다.
- 읽어야 할 파일에 docs와 이전 step 산출물 파일을 명시한다.
- 구현 안전에 필요한 파일 경로, 함수/클래스 시그니처, command, schema, invariant는 구체적으로 적는다.
- 구현 세부는 worker 재량에 맡기되, 멱등성, 보안, 데이터 무결성 같은 핵심 규칙은 명확히 적는다.
- Acceptance Criteria는 실행 가능한 command여야 한다.
- `.harness/validation.json`이 있으면 `python3 scripts/validate_project.py`를 기본 AC로 사용한다.
- validation이 아직 설정되지 않았다면 `AGENTS.md`, docs, manifest에 명시된 프로젝트별 command만 사용한다. Node/npm command를 기본값으로 만들지 않는다.
- 금지사항은 "X를 하지 마라. Reason: Y." 형식으로 작성한다.
- step name은 `project-setup`, `validation-config`, `api-layer`처럼 kebab-case slug를 사용한다.

## Files To Create

### `phases/index.json`

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

- `dir`: task 디렉토리명.
- `status`: `"pending"` | `"completed"` | `"error"` | `"blocked"`.
- 타임스탬프는 실행 오케스트레이터가 상태 변경 시 기록한다. 생성 시 넣지 않는다.

### `phases/{task-name}/index.json`

```json
{
  "project": "<프로젝트명>",
  "phase": "<task-name>",
  "steps": [
    { "step": 0, "name": "project-setup", "status": "pending" },
    { "step": 1, "name": "core-contracts", "status": "pending" },
    { "step": 2, "name": "feature-flow", "status": "pending" }
  ]
}
```

- `project`: 프로젝트명.
- `phase`: task 이름. 디렉토리명과 일치시킨다.
- `steps[].step`: 0부터 시작하는 순번.
- `steps[].name`: kebab-case slug.
- `steps[].status`: 초기값은 모두 `"pending"`.

상태 전이:

| 전이 | 기록되는 필드 | 기록 주체 |
|------|-------------|----------|
| → `running` | `started_at`, `attempt` | 메인 세션 |
| → `completed` | `completed_at`, `summary` | worker 응답 기반 메인 세션 |
| → `error` | `failed_at`, `error_message` | worker 응답 기반 메인 세션 |
| → `blocked` | `blocked_at`, `blocked_reason` | worker 응답 기반 메인 세션 |

`summary`는 다음 step 프롬프트에 컨텍스트로 누적 전달되므로, 생성된 파일과 핵심 결정을 한 줄로 담는다.

### `phases/{task-name}/step{N}.md`

````markdown
# Step {N}: {name}

## 읽어야 할 파일

먼저 아래 파일들을 읽고 프로젝트의 아키텍처와 설계 의도를 파악하라:

- `/AGENTS.md`
- `/docs/PRD.md`
- `/docs/ARCHITECTURE.md`
- `/docs/ADR.md`
- {이전 step에서 생성/수정된 파일 경로}

## 작업

{구체적인 구현 지시}

## Acceptance Criteria

```bash
python3 scripts/validate_project.py
```

## 검증 절차

1. 위 AC 커맨드를 실행한다.
2. `AGENTS.md`, `docs/ARCHITECTURE.md`, `docs/ADR.md` 규칙 위반 여부를 확인한다.
3. 최종 응답에 결과를 보고한다:
   - 성공 → `status: completed`, `summary: "산출물 한 줄 요약"`
   - 실패 → `status: error`, `error_message: "구체적 에러 내용"`
   - 사용자 개입 필요 → `status: blocked`, `blocked_reason: "구체적 사유"`

## 금지사항

- {Do not do X. Reason: Y.}
- 기존 테스트를 깨뜨리지 마라.
- phase metadata와 git commit은 메인 세션이 담당하므로 worker가 직접 수정하지 마라.
- `.harness/validation.json`이 없다는 이유만으로 Node/npm 명령을 임의로 추가하지 마라. Reason: Harness는 언어 중립이다.
````

If `python3 scripts/validate_project.py` is not available or no validation commands are configured, replace the Acceptance Criteria block with the exact project-specific validation commands established in `AGENTS.md`, docs, manifests, or `.harness/validation.json`.

## Execute

사용자가 phase 실행을 요청하면 메인 세션이 오케스트레이터가 된다. 외부 headless CLI runner, sandbox 우회 옵션, 별도 executor script는 사용하지 않는다.

상세 실행 프로토콜은 `references/subagent-execution.md`를 읽고 따른다.
