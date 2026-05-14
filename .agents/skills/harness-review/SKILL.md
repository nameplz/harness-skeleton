---
name: harness-review
description: Review workflow for Harness framework projects. Use when the user asks to review current changes, verify implementation quality, check phase outputs, or compare modified files against AGENTS.md, docs/ARCHITECTURE.md, docs/ADR.md, tests, and build expectations.
---

# Harness Review

## Overview

Use this review workflow to evaluate changed files in a Harness project. Lead with concrete findings, ordered by severity, and include file references when possible.

## Review Procedure

1. Read `/AGENTS.md`, `/docs/ARCHITECTURE.md`, and `/docs/ADR.md`.
2. Inspect changed files and generated phase outputs.
3. Verify the change against the checklist below.
4. Run relevant build, lint, and test commands when available and appropriate.
5. Report findings first. Keep summary and test notes secondary.

## Checklist

| 항목 | 기준 |
|------|------|
| 아키텍처 준수 | `docs/ARCHITECTURE.md`의 디렉토리 구조와 경계를 따르는가? |
| 기술 스택 준수 | `docs/ADR.md`의 기술 선택을 벗어나지 않았는가? |
| 테스트 존재 | 새 동작이나 변경된 동작에 대한 테스트가 있는가? |
| CRITICAL 규칙 | `AGENTS.md`의 CRITICAL 규칙을 위반하지 않았는가? |
| 빌드 가능 | 빌드/테스트 명령이 통과하는가? |

## Output Format

If issues exist, respond with findings first:

```markdown
**Findings**
- High: [file.py:12] 구체적 문제와 영향.
- Medium: [file.py:34] 구체적 문제와 영향.

**Open Questions**
- 확인이 필요한 사항.

**Tests**
- `command` 통과/실패/미실행 사유.
```

If there are no issues, say that clearly and still mention test coverage or residual risk:

```markdown
문제는 발견하지 못했습니다.

**Tests**
- `command` 통과.

**Residual Risk**
- {남은 위험 또는 없음}
```

## Review Standards

- Treat missing tests as a finding when behavior changed and no equivalent coverage exists.
- Flag phase metadata errors if statuses, summaries, timestamps, or output files contradict `scripts/execute.py` semantics.
- Flag broad or cross-module edits when a step claims a narrow scope.
- Do not rewrite code during a review unless the user explicitly asks for fixes.
