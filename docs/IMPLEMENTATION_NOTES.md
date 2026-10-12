# v4 implementation notes

이 복사본은 `nameplz/harness-skeleton`의 `harness-v2` 브랜치, 커밋 `6656c50cf36324b13093a3b5f6a535f2c45d3da2`에서 시작했다. 로컬 브랜치는 `v4-hardening`이다. 변경은 [35개 공식 자료를 분석한 보고서](research/harness-v2-agent-harness-review-2026-10-12.md)에 근거한다. 보고서는 수정 전 분석이며, 아래 표가 현재 구현 상태다.

## 분석 결과와 수정 대응

| 제안 | 반영 내용 | 확인 방법 / 남은 범위 |
|---|---|---|
| R1 제어 지침·검증기 보호 | 루트/중첩 AGENTS, `.agents/`, expression scanner, command runner, evidence helper를 CI 보호 및 T3 분류에 포함 | 보호된 검증기의 로컬 import closure, 경로 테스트와 위험 fixture |
| R2 PR 계약 | 여섯 한국어 섹션, 실제 내용, 이슈 참조를 skill/템플릿/검사기에 통일 | 빈 템플릿·주석·fenced/indented/inline code 위장 실패; URL은 구문 검사이며 발행 시 이슈 존재·대상 검증 필요 |
| R3 제한된 읽기 | 미추적 파일을 1 MiB+1까지만 읽고 초과 오류 | 경계 크기, 실제 요청 길이, symlink 테스트 |
| R4 훅 피드백 | Git 전역 옵션·인용·단순 명령 목록의 commit 인식; 잘못된 JSON 진단; doctor 명령/type/matcher 확인 | 순수 recognizer와 hook CLI 테스트; 실제 Codex hook 전달은 별도 smoke test 필요 |
| R5 실행 경계 | 파일/네트워크/자격 증명/MCP 권한의 주체를 명시 | native/host 정책이 필요; argv 검사를 OS sandbox라고 주장하지 않음 |
| R6 검증 증거 | HEAD·dirty content·적용 config SHA-256, 전후 비교, duration/start/timeout/output/failure 필드 | 변경 시 결과 무효; 알려진 Git 저장소의 증거 오류는 검사 시작 전 실패; 독립 비Git 프로젝트는 unavailable 명시 |
| R7 재개 | 기존 task note용 템플릿에 실제 Git·리뷰·검증·외부 pending 상태 포함 | 단순 작업에 새 상태 파일 강제하지 않음 |
| R8 리뷰·발행 | 리뷰 대상 identity, standing authorization, 응답 유실 후 remote 조회·중복 방지 지침 | 지침 계약이며 별도 외부 자동 재시도 엔진 없음 |
| R9 평가 분리 | 12 시나리오×3회 계획, 엄격한 외부 결과 contract, 독립 grader 및 A/B protocol | 기본 CI는 dry run; live model 평가/성능 개선 수치는 없음; 결과 검사는 advisory |
| R10 테스트 환경 | 기존 safe environment 유지, 필요 시 비밀 없는 설정만 trusted allowlist에 추가하도록 문서화 | 이 skeleton에서 요구가 없는 환경 변수/API credential 전달 기능은 추가하지 않음 |
| R11 지식 지도 | PR skill/template, task template, evidence helper, 평가 문서의 필수 파일 검사 | doctor 통과와 제품/PRD/UI/실효 권한 준비를 구분 |
| R12 GitHub 정책 | 2026-11-02 관련 운영 확인 항목 및 공식 출처 기록 | 원격 저장소/조직 정책과 branch protection은 변경·실측하지 않음 |

## 독립 리뷰에서 추가한 보완

Git `status`와 working-tree `diff`는 읽기 전용 명령이어도 local `filter.clean/process`를 실행할 수 있었다. 공통 runner는 effective Git config를 includes/worktree scope까지 조회하고 callback 정의나 preflight 오류가 있으면 실제 검사 명령을 시작하지 않는다. global/system config와 inherited Git 환경은 기존 정책대로 제외한다. 부모 검사 중 dirty submodule이 별도 callback을 실행하지 않도록 `--ignore-submodules=dirty`를 적용한다. gitlink 커밋 변경은 보지만 하위 작업 트리 내용은 fingerprint에 포함하지 않으므로, 그 내부 변경은 별도 격리된 검사 대상으로 삼아야 한다.

local/included/worktree callback, malformed config, nested submodule에 marker 기반 회귀 테스트를 추가했다. 이 preflight는 동시 local config 변조에 대한 원자적 보장이 아니며 host sandbox를 대체하지 않는다. 원래 `.gitignore`의 `.env`, 빌드 산출물, 임시 worktree 제외를 보존하고 coverage 제외만 더했다.

후속 리뷰에서는 `git.exe`/대소문자 인식을 공통화하고 visible wrapped Git argv를 거부했다. runner의 status/diff에서 CLI override보다 뒤에 fsmonitor 비활성화 및 external diff/textconv 금지를 적용하고, `GIT_OPTIONAL_LOCKS=0`으로 일반/linked worktree의 index 갱신을 막았다. PR 내용에서는 heading-only 줄을 제외하고, 숨은 코드·주석을 지운 자리에 줄별 sentinel을 유지하여 새 제목이 만들어지는 우회를 막았다. 증거 status의 양방향 전환도 결과를 무효화한다.

정상 용도의 Git LFS 같은 filter도 이 보수적 정책에서는 차단된다. 그런 저장소는 callback이 없는 신뢰된 검사 checkout이나 별도로 검토한 실행 정책이 필요하며, 자동 예외를 제공하지 않는다.

검증 fingerprint는 ignored 파일을 제외하는 비원자적 전후 관측이다. Git 오류/큰 파일/제한 초과를 성공으로 꾸미지 않지만, 검사 도중 변경 후 원복된 내용이나 독립 grader의 진위를 증명하지 않는다. native 격리·trusted CI·독립 grader가 각각의 보장을 제공해야 한다.

## 재현할 검증

Python 3.13에서 216개 테스트가 통과했고, `scripts`와 `.codex/hooks`를 대상으로 측정한 전체 statement coverage는 84%였다. 위험 분류 fixture 36개가 통과했고 doctor는 필수 파일·설정 검사를 통과했다. 커버리지는 파일별 최저값이 아닌 전체 합계다. 실제 에이전트 계획의 36회는 실행한 모델 trial 수가 아니다.

```bash
python -m unittest discover -s tests -t .
python scripts/harness.py check --full --root .
python scripts/harness.py risk --root .
git diff --check
```

Python 3.11 이상이 필요하다. coverage 도구가 있으면 `coverage run --source=scripts,.codex/hooks -m unittest discover -s tests -t .` 및 `coverage report --fail-under=80`으로 측정한다. coverage는 개발 검증용이며 runtime dependency로 추가하지 않았다. CLI E2E는 hook, doctor/check/risk, PR/event 및 평가 결과 입출력 경계를 대상으로 한다. 웹 UI가 없는 프로젝트여서 브라우저 E2E는 해당하지 않는다.

실제 모델 호출, 원격 issue/PR 생성, push, merge, GitHub CI 실행 및 조직 정책 변경은 수행 범위에 포함하지 않았다. v4는 리뷰 가능한 로컬 변경이며 게시된 릴리스가 아니다.
