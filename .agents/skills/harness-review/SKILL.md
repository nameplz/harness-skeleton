---
name: harness-review
description: Use this skill when reviewing changes in this Harness framework project for architecture compliance, ADR alignment, test coverage, AGENTS.md critical rules, and buildability.
origin: harness_framework
---

# Harness Review

이 프로젝트의 변경 사항을 리뷰할 때 사용한다. 리뷰는 버그, 위험, 회귀, 누락된 테스트를 우선한다.

## Required Reading

먼저 다음 문서들을 읽는다:

- `/AGENTS.md`
- `/docs/ARCHITECTURE.md`
- `/docs/ADR.md`

그런 다음 변경된 파일을 확인하고 체크리스트로 검증한다.

## Checklist

1. **아키텍처 준수**: `ARCHITECTURE.md`에 정의된 디렉토리 구조를 따르는가?
2. **기술 스택 준수**: `ADR.md`에 정의된 기술 선택을 벗어나지 않았는가?
3. **테스트 존재**: 새로운 기능 또는 변경된 동작에 대한 테스트가 작성되어 있는가?
4. **CRITICAL 규칙**: `AGENTS.md`의 CRITICAL 규칙을 위반하지 않았는가?
5. **빌드 가능**: 빌드/테스트 명령어가 에러 없이 통과하는가?

## Output Format

```markdown
| 항목 | 결과 | 비고 |
|------|------|------|
| 아키텍처 준수 | ✅/❌ | {상세} |
| 기술 스택 준수 | ✅/❌ | {상세} |
| 테스트 존재 | ✅/❌ | {상세} |
| CRITICAL 규칙 | ✅/❌ | {상세} |
| 빌드 가능 | ✅/❌ | {상세} |
```

위반 사항이 있으면 파일/라인 근거와 수정 방안을 구체적으로 제시한다. 심각한 문제를 먼저 나열하고, 요약은 뒤에 짧게 둔다.

