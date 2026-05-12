---
name: harness-workflow
description: Use this skill when planning or executing Harness framework phases and steps, creating `phases/index.json`, `phases/{task}/index.json`, `stepN.md` files, or orchestrating phase execution with Codex worker subagents.
origin: harness_framework
---

# Harness Workflow

이 프로젝트는 Harness 프레임워크를 사용한다. 작업을 phase와 step으로 나누어 설계하고, 승인된 step 파일은 Codex 메인 세션이 worker 서브 에이전트로 순차 실행한다.

## Workflow

### A. 탐색

`/docs/` 하위 문서(PRD, ARCHITECTURE, ADR 등)를 읽고 프로젝트의 기획, 아키텍처, 설계 의도를 파악한다. 필요시 독립적인 탐색 작업을 병렬화한다.

### B. 논의

구현을 위해 구체화하거나 기술적으로 결정해야 할 사항이 있으면 사용자에게 제시하고 논의한다.

### C. Step 설계

사용자가 구현 계획 작성을 지시하면 여러 step으로 나뉜 초안을 작성해 피드백을 요청한다.

설계 원칙:

1. **Scope 최소화**: 하나의 step에서 하나의 레이어 또는 모듈만 다룬다. 여러 모듈을 동시에 수정해야 하면 step을 쪼갠다.
2. **자기완결성**: 각 step 파일은 독립된 worker 서브 에이전트가 수행한다. 외부 대화 참조 없이 필요한 정보를 전부 파일 안에 적는다.
3. **사전 준비 강제**: 관련 문서 경로와 이전 step에서 생성/수정된 파일 경로를 명시한다.
4. **시그니처 수준 지시**: 함수/클래스의 인터페이스만 제시하고 내부 구현은 에이전트 재량에 맡긴다. 단, 멱등성, 보안, 데이터 무결성 같은 핵심 규칙은 명시한다.
5. **AC는 실행 가능한 커맨드**: `npm run build && npm test`처럼 실제 검증 커맨드를 포함한다.
6. **주의사항은 구체적으로**: "X를 하지 마라. 이유: Y" 형식으로 적는다.
7. **네이밍**: step name은 kebab-case slug로, 핵심 모듈/작업을 한두 단어로 표현한다.

## Files To Create

### `phases/index.json`

여러 task를 관리하는 top-level 인덱스. 이미 존재하면 `phases` 배열에 새 항목을 추가한다.

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
- 타임스탬프(`completed_at`, `failed_at`, `blocked_at`)는 실행 오케스트레이터가 상태 변경 시 기록한다. 생성 시 넣지 않는다.

### `phases/{task-name}/index.json`

```json
{
  "project": "<프로젝트명>",
  "phase": "<task-name>",
  "steps": [
    { "step": 0, "name": "project-setup", "status": "pending" },
    { "step": 1, "name": "core-types", "status": "pending" },
    { "step": 2, "name": "api-layer", "status": "pending" }
  ]
}
```

- `project`: 프로젝트명 (`AGENTS.md` 참조).
- `phase`: task 이름. 디렉토리명과 일치시킨다.
- `steps[].step`: 0부터 시작하는 순번.
- `steps[].name`: kebab-case slug.
- `steps[].status`: 초기값은 모두 `"pending"`.

상태 전이:

| 전이 | 기록되는 필드 | 기록 주체 |
|------|-------------|----------|
| → `completed` | `completed_at`, `summary` | worker (summary), 메인 세션 (metadata) |
| → `error` | `failed_at`, `error_message` | worker (message), 메인 세션 (metadata) |
| → `blocked` | `blocked_at`, `blocked_reason` | worker (reason), 메인 세션 (metadata) |

`summary`는 다음 step 프롬프트에 컨텍스트로 누적 전달되므로, 생성된 파일과 핵심 결정을 한 줄로 담는다.

### `phases/{task-name}/step{N}.md`

```markdown
# Step {N}: {이름}

## 읽어야 할 파일

먼저 아래 파일들을 읽고 프로젝트의 아키텍처와 설계 의도를 파악하라:

- `/docs/ARCHITECTURE.md`
- `/docs/ADR.md`
- {이전 step에서 생성/수정된 파일 경로}

## 작업

{구체적인 구현 지시. 파일 경로, 클래스/함수 시그니처, 로직 설명을 포함.
코드 스니펫은 인터페이스/시그니처 수준만 제시하고, 구현체는 에이전트에게 맡겨라.
단, 설계 의도에서 벗어나면 안 되는 핵심 규칙은 명확히 박아넣어라.}

## Acceptance Criteria

```bash
npm run build
npm test
```

## 검증 절차

1. 위 AC 커맨드를 실행한다.
2. 아키텍처 체크리스트를 확인한다:
   - ARCHITECTURE.md 디렉토리 구조를 따르는가?
   - ADR 기술 스택을 벗어나지 않았는가?
   - AGENTS.md CRITICAL 규칙을 위반하지 않았는가?
3. 최종 응답에 결과를 보고한다:
   - 성공 → `status: completed`, `summary: "산출물 한 줄 요약"`
   - 실패 → `status: error`, `error_message: "구체적 에러 내용"`
   - 사용자 개입 필요 → `status: blocked`, `blocked_reason: "구체적 사유"`

## 금지사항

- {이 step에서 하지 말아야 할 것. "X를 하지 마라. 이유: Y" 형식}
- 기존 테스트를 깨뜨리지 마라
- phase metadata와 git commit은 메인 세션이 담당하므로 worker가 직접 수정하지 마라
```

## Execute

사용자가 phase 실행을 요청하면 메인 세션이 오케스트레이터가 된다. 외부 headless CLI runner나 sandbox 우회 방식은 사용하지 않는다.

상세 실행 프로토콜은 `references/subagent-execution.md`를 읽고 따른다.

메인 세션이 자동으로 처리하는 것:

- `feat-{task-name}` 브랜치 생성/checkout
- 각 pending step을 worker 서브 에이전트에 하나씩 위임
- `AGENTS.md` + `docs/*.md` 경로와 완료된 step `summary`를 worker 프롬프트에 전달
- 실패 시 최대 3회 재시도
- 코드 변경(`feat`)과 메타데이터(`chore`)를 분리 커밋
- `started_at`, `completed_at`, `failed_at`, `blocked_at` 기록
- 사용자가 명시한 경우에만 `git push -u origin feat-{task-name}` 실행

worker가 담당하는 것:

- step 파일과 관련 문서를 직접 읽고 구현한다
- AC 커맨드를 실행한다
- 최종 응답으로 `status`, `summary`, `changed_files`, `validation`, 필요 시 `error_message` 또는 `blocked_reason`을 보고한다
- git commit, push, phase metadata 수정은 하지 않는다

에러 복구:

- `error`: 해당 step의 `status`를 `"pending"`으로 바꾸고 `error_message`를 삭제한 뒤 재실행한다.
- `blocked`: `blocked_reason`을 해결한 뒤 `status`를 `"pending"`으로 바꾸고 `blocked_reason`을 삭제한 뒤 재실행한다.
