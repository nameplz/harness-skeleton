# Subagent Execution Protocol

이 문서는 Harness phase를 Codex 메인 세션과 worker 서브 에이전트로 실행하는 절차다. 메인 세션은 오케스트레이터이고, worker는 한 번에 하나의 step만 구현한다.

## Trigger

사용자가 phase 실행을 요청하면 이 프로토콜을 따른다. 예:

- "`0-mvp` phase 실행해줘"
- "`0-mvp`를 harness-workflow 방식으로 실행하고 push까지 해줘"

외부 headless CLI runner, sandbox 우회 옵션, 별도 executor script는 사용하지 않는다.

## Main Session Responsibilities

1. `phases/index.json`과 `phases/{phase}/index.json`을 읽는다.
2. 이전 실행에서 남은 `running` step이 있으면 `pending`으로 복구하고 `attempt`를 제거한다.
3. 기존 `error` 또는 `blocked` step이 있으면 실행하지 않고 사용자에게 복구 방법을 보고한다.
4. `feat-{phase}` 브랜치를 checkout하거나 생성한다.
5. phase `created_at`이 없으면 기록한다.
6. 첫 번째 `pending` step부터 순차 실행한다.
7. 각 step의 `started_at`, `completed_at`, `failed_at`, `blocked_at`, `attempt`를 기록한다.
8. worker 결과를 `phases/{phase}/step{N}-output.json`에 저장한다.
9. 코드 변경과 metadata/output 변경을 분리 커밋한다.
10. 모든 step 완료 후 phase와 top-level index를 `completed`로 갱신한다.
11. 사용자가 push를 명시한 경우에만 `git push -u origin feat-{phase}`를 실행한다.

메인 세션은 구현 세부 작업을 직접 수행하지 않는다. 단, worker 결과 검토, metadata 갱신, 커밋, 재시도 판단은 메인 세션이 담당한다.

## Worker Launch

각 pending step마다 worker 하나만 실행한다.

- `agent_type`: `worker`
- `fork_context`: `false`
- 동시 실행 금지. 이전 step이 완료된 뒤 다음 step을 실행한다.
- worker는 같은 코드베이스에서 혼자 작업하지 않는다는 전제를 반드시 받는다.

메인 세션은 worker 시작 직전에 해당 step을 `running`으로 바꾸고 `attempt`, `started_at`을 기록한다. worker는 phase metadata 파일을 수정하지 않는다.

## Worker Prompt Template

아래 템플릿을 step별 값으로 채워 worker에게 전달한다.

```markdown
You are implementing one Harness step in this repository.

You are not alone in the codebase. Do not revert edits made by others. Adjust your implementation to accommodate existing changes.

## Scope

- Phase: `{phase}`
- Step: `{step_number}` / `{step_name}`
- Step file: `phases/{phase}/step{step_number}.md`
- Phase index: `phases/{phase}/index.json`

## Required Reading

Read these files before editing:

- `AGENTS.md`
- `docs/PRD.md`
- `docs/ARCHITECTURE.md`
- `docs/ADR.md`
- `docs/UI_GUIDE.md` if present
- `phases/{phase}/step{step_number}.md`

Previous completed step summaries:

{completed_step_summaries}

## Rules

- Implement only this step.
- Do not implement future steps.
- Do not modify phase metadata files.
- Do not commit or push.
- Run the Acceptance Criteria commands from the step file.
- Prefer `python3 scripts/validate_project.py` when the step file uses Harness validation.
- If a required secret, account, network permission, external service, or manual setup is missing, stop and return `blocked`.

## Final Response Contract

Return:

- `status`: `completed` | `error` | `blocked`
- `summary`: one-line summary when completed
- `changed_files`: list of changed paths
- `validation`: commands run and results
- `error_message`: required when status is `error`
- `blocked_reason`: required when status is `blocked`
```

On retry, append:

```markdown
## Previous Attempt Failure

{previous_error_message}

Fix the cause above. Do not repeat the failed approach.
```

## Result Handling

### Completed

When worker returns `completed`:

1. Review changed files enough to confirm scope.
2. Update the step entry:
   - `status`: `completed`
   - `summary`: worker summary
   - `completed_at`: current timestamp
   - remove `attempt`
3. Save `step{N}-output.json`.
4. Commit code changes first:
   - `feat({phase}): step {N} - {step-name}`
5. Commit metadata/output changes:
   - `chore({phase}): step {N} output`
6. Continue to the next pending step.

### Blocked

When worker returns `blocked`:

1. Update the step entry:
   - `status`: `blocked`
   - `blocked_reason`: worker reason
   - `blocked_at`: current timestamp
   - remove `attempt`
2. Update `phases/index.json` phase status to `blocked`.
3. Save `step{N}-output.json`.
4. Commit metadata/output changes if possible.
5. Stop execution and report the reason.

### Error

When worker returns `error`, violates the response contract, or leaves the step incomplete:

1. Retry up to 3 total attempts.
2. Include the previous error in the next worker prompt.
3. If all attempts fail, update the step entry:
   - `status`: `error`
   - `error_message`: final error with attempt count
   - `failed_at`: current timestamp
   - remove `attempt`
4. Update `phases/index.json` phase status to `error`.
5. Save `step{N}-output.json`.
6. Commit metadata/output changes if possible.
7. Stop execution and report the error.

## Output JSON

Save each attempt result to `phases/{phase}/step{N}-output.json` with this shape:

```json
{
  "schemaVersion": 2,
  "phase": "0-mvp",
  "step": 0,
  "name": "step-name",
  "attempt": 1,
  "worker": {
    "type": "subagent"
  },
  "stepStatus": {
    "status": "completed",
    "summary": "one-line summary",
    "errorMessage": null,
    "blockedReason": null
  },
  "changedFiles": ["path/to/file"],
  "validation": ["command: result"],
  "timestamps": {
    "startedAt": "YYYY-MM-DDTHH:MM:SS+0900",
    "finishedAt": "YYYY-MM-DDTHH:MM:SS+0900",
    "recordedAt": "YYYY-MM-DDTHH:MM:SS+0900"
  }
}
```

## Recovery

- To retry an `error` step, set its `status` to `pending` and remove `error_message`, `failed_at`, and `attempt`.
- To retry a `blocked` step, resolve the blocker, set `status` to `pending`, and remove `blocked_reason`, `blocked_at`, and `attempt`.
- To recover a stale `running` step, set it to `pending` and remove `attempt`.
- Preserve completed step summaries; they are the context bridge for later workers.
