---
name: harness-review
description: Review workflow for Harness framework projects. Use when the user asks to review current changes, verify implementation quality, check phase outputs, or compare modified files against AGENTS.md, docs/ARCHITECTURE.md, docs/ADR.md, tests, and build expectations.
origin: harness_framework
---

# Harness Review

## Overview

Use this review workflow to evaluate changed files in a Harness project. Lead with concrete findings, ordered by severity, and include file references when possible.

`python3 scripts/validate_project.py` is the primary validation command for Harness projects. It reads `.harness/validation.json` when present and otherwise uses the shared Harness validation detection in `scripts/harness_validation.py`. Prefer it over ad hoc stack-specific commands during review.

## Review Procedure

1. Read `/AGENTS.md`, `/docs/ARCHITECTURE.md`, and `/docs/ADR.md`.
2. Inspect changed files and generated phase outputs.
3. Run `python3 scripts/validate_project.py` from the project root when `scripts/validate_project.py` exists.
4. If `validate_project.py` is unavailable or reports no configured commands, use only validation commands explicitly established in `AGENTS.md`, docs, manifests, or `.harness/validation.json`.
5. Verify the change against the checklist below.
6. Report findings first. Keep summary and test notes secondary.

Do not invent Node/npm commands as a fallback. Harness is language-neutral, and validation should flow through `scripts/validate_project.py` whenever available.

## Checklist

| 항목 | 기준 |
|------|------|
| 아키텍처 준수 | `docs/ARCHITECTURE.md`의 디렉토리 구조와 경계를 따르는가? |
| 기술 스택 준수 | `docs/ADR.md`의 기술 선택을 벗어나지 않았는가? |
| 테스트 존재 | 새 동작이나 변경된 동작에 대한 테스트가 있는가? |
| CRITICAL 규칙 | `AGENTS.md`의 CRITICAL 규칙을 위반하지 않았는가? |
| 프로젝트 검증 | `python3 scripts/validate_project.py`가 통과하는가? |
| Phase 산출물 | step 상태, summaries, timestamps, `stepN-output.json` 구조가 `harness-workflow/references/subagent-execution.md` semantics와 일치하는가? |

## Output Format

If issues exist, respond with findings first:

```markdown
**Findings**
- High: [file.py:12] 구체적 문제와 영향.
- Medium: [file.py:34] 구체적 문제와 영향.

**Open Questions**
- 확인이 필요한 사항.

**Tests**
- `python3 scripts/validate_project.py` 통과/실패/미실행 사유.
```

If there are no issues, say that clearly and still mention test coverage or residual risk:

```markdown
문제는 발견하지 못했습니다.

**Tests**
- `python3 scripts/validate_project.py` 통과.

**Residual Risk**
- {남은 위험 또는 없음}
```

## Review Standards

- Treat missing tests as a finding when behavior changed and no equivalent coverage exists.
- Treat `python3 scripts/validate_project.py` failure as a finding unless the failure is unrelated pre-existing project state and clearly documented.
- Flag phase metadata errors if statuses, summaries, timestamps, or output files contradict the subagent execution protocol.
- Flag broad or cross-module edits when a step claims a narrow scope.
- Do not rewrite code during a review unless the user explicitly asks for fixes.
