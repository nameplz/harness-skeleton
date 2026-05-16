# 프로젝트: {프로젝트명}

## 기술 스택
- {프레임워크 (예: Next.js 15)}
- {언어 (예: TypeScript strict mode)}
- {스타일링 (예: Tailwind CSS)}

## 아키텍처 규칙
- CRITICAL: {절대 지켜야 할 규칙 1 (예: 모든 API 로직은 app/api/ 라우트 핸들러에서만 처리)}
- CRITICAL: {절대 지켜야 할 규칙 2 (예: 클라이언트 컴포넌트에서 직접 외부 API를 호출하지 말 것)}
- {일반 규칙 (예: 컴포넌트는 components/ 폴더에, 타입은 types/ 폴더에 분리)}

## 개발 프로세스
- CRITICAL: 새 기능 구현 시 반드시 테스트를 먼저 작성하고, 테스트가 통과하는 구현을 작성할 것 (TDD)
- 커밋 메시지는 conventional commits 형식을 따를 것 (feat:, fix:, docs:, refactor:)
- Codex headless 호출은 `codex exec -c approval_policy=never -s workspace-write --json "작업 내용"` 형식을 사용할 것

## 프로젝트 로컬 스킬
- `.agents/skills/harness`: phase/step 설계와 `scripts/execute.py` 실행 워크플로우
- `.agents/skills/harness-review`: 변경사항 리뷰와 프로젝트 규칙 검증 워크플로우

## Codex Hooks
- `.codex/config.toml`의 `[features] hooks = true`를 사용한다.
- `PreToolUse`/`PermissionRequest` hook은 위험한 Bash 명령을 차단한다.
- `PreToolUse` hook은 Codex가 `git commit` Bash 명령을 실행하기 전에 `lint`, `build`, `test`를 순서대로 검증한다.
- `Stop`/pre-commit 검증은 `.harness/validation.json`이 있으면 이를 우선 사용하고, 없으면 `package.json`의 `lint`, `build`, `test` 스크립트를 fallback으로 감지한다.
- 일반 Git hook이 필요하면 repo에서 `git config core.hooksPath .githooks`를 설정한다.

## 명령어
npm run dev      # 개발 서버
npm run build    # 프로덕션 빌드
npm run lint     # ESLint
npm run test     # 테스트
