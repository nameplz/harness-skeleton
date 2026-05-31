# 프로젝트: {프로젝트명}

## 기술 스택
- {프레임워크/런타임}
- {언어 및 버전}
- {패키지 매니저/빌드 도구}
- {테스트/검증 도구}
- {UI가 있다면 스타일링/컴포넌트 전략, 없으면 N/A}

## 아키텍처 규칙
- CRITICAL: {절대 지켜야 할 규칙 1}
- CRITICAL: {절대 지켜야 할 규칙 2}
- {일반 규칙}

## 개발 프로세스
- CRITICAL: 새 기능 구현 시 반드시 테스트를 먼저 작성하고, 테스트가 통과하는 구현을 작성할 것 (TDD)
- 커밋 메시지는 conventional commits 형식을 따를 것 (feat:, fix:, docs:, refactor:)
- Codex headless 호출은 `codex exec -c approval_policy=never -s workspace-write --json "작업 내용"` 형식을 사용할 것
- `AGENTS.md`와 `docs/*.md`의 placeholder를 실제 프로젝트 spec으로 채운 뒤 `python3 scripts/configure_harness.py`를 실행해 검증 설정을 생성할 것

## 프로젝트 로컬 스킬
- `.agents/skills/harness`: phase/step 설계와 `scripts/execute.py` 실행 워크플로우
- `.agents/skills/harness-review`: 변경사항 리뷰와 프로젝트 규칙 검증 워크플로우
- `.agents/skills/harness-validation`: 프로젝트 기술 스택 감지와 `.harness/validation.json` 생성 워크플로우

## Codex Hooks
- `.codex/config.toml`의 `[features] hooks = true`를 사용한다.
- `PreToolUse`/`PermissionRequest` hook은 위험한 Bash 명령을 차단한다.
- `PreToolUse` hook은 Codex가 `git commit` Bash 명령을 실행하기 전에 프로젝트 검증을 수행한다.
- `Stop`/pre-commit 검증은 `.harness/validation.json`이 있으면 이를 우선 사용한다.
- `.harness/validation.json`은 `python3 scripts/configure_harness.py`로 생성한다.
- 일반 Git hook이 필요하면 repo에서 `git config core.hooksPath .githooks`를 설정한다.

## 명령어
python3 scripts/configure_harness.py   # 프로젝트 스택 감지 및 검증 설정 생성
python3 scripts/validate_project.py    # .harness/validation.json 기반 검증 실행
python3 scripts/execute.py <phase-dir> # phase step 순차 실행
