> Historical baseline review of commit6656c50. v4 implementation status is recorded in [IMPLEMENTATION_NOTES.md](../IMPLEMENTATION_NOTES.md); recommendations below describe the pre-change source.

# harness-v2 에이전트 하네스 조사 및 수정 제안

조사일: 2026-10-12, Asia/Seoul. 대상은 `nameplz/harness-skeleton`의 `harness-v2`, [커밋 `6656c50cf36324b13093a3b5f6a535f2c45d3da2`](https://github.com/nameplz/harness-skeleton/tree/6656c50cf36324b13093a3b5f6a535f2c45d3da2)이다. 코드는 별도 체크아웃 `/private/tmp/harness-v2-analysis-20261012`에서 읽었다. 이 보고서를 저장한 로컬 작업 사본은 다른 리비전이며 기존 미추적 평가 작업도 있으므로, 그 작업을 원격 브랜치의 구현이나 검증 결과로 간주하지 않았다. 이 조사에서는 제품 코드를 수정하거나 GitHub에 쓰지 않았다.

## 1. 결론과 판단의 범위

**현재 구조를 유지하고, 정책의 적용 범위와 검증 증거를 보강하는 것이 가장 타당하다.** Codex가 에이전트 실행을 담당하고 저장소가 지식 지도, 결정적 검사, 위험 분류, 리뷰 지침, 신뢰된 CI를 제공하는 구분은 적절하다. 자료를 근거로 별도 워커 엔진, 영구 실행 플랫폼, 에이전트 그래프 프레임워크를 도입해야 한다고 판단할 수는 없다.

우선 고칠 사항은 세 가지다. 검증기 의존 파일과 핵심 에이전트 지침이 보호 목록에서 빠져 있고, PR 작성 지침과 검사기가 서로 다른 계약을 사용하며, 미추적 파일의 크기 제한이 전체 읽기 이후에 적용된다. 훅의 명령 인식과 설정 진단에도 확인된 빈틈이 있다. 장기 작업 재개 기록, 검증 결과의 리비전 식별, 리뷰 증거, 실제 에이전트 평가는 그 다음 단계의 개선이다.

아래 우선순위는 수정 순서이며 CVSS나 검증된 공격 심각도 점수가 아니다.

| ID | 우선순위 | 판단 유형 | 수정할 내용 |
|---|---|---|---|
| R1 | P1 | 확인된 정책 누락 + 정책 선택 | 검증기 의존 파일 보호, 핵심 에이전트 지침의 위험 분류 |
| R2 | P1 | 확인된 계약 불일치 | PR 형식 통일, 빈 섹션·이슈 참조 검사 |
| R3 | P1 | 확인된 자원 제한 결함 | 미추적 파일을 제한된 크기만 읽기 |
| R4 | P2 | 확인된 피드백·진단 결함 | Git 전역 옵션을 포함한 commit 인식, 훅 오류 진단 |
| R5 | P2 | 운영 경계 보완 | 실제 파일·네트워크·자격 증명 격리의 책임 명시 |
| R6 | P2 | 증거 계약 보완 | 검사 결과에 리비전·설정 식별자·시간·실패 원인 기록 |
| R7 | P2 | 복구 계약 보완 | 여러 세션에 걸친 작업의 재개 상태 구체화 |
| R8 | P2 | 리뷰·발행 계약 보완 | 리뷰 대상 리비전 식별, 승인 범위·외부 작업 중복 방지 |
| R9 | P2 | 측정 공백 | 정적 위험 평가와 실제 에이전트 평가 분리 |
| R10 | 조건부 | 프로젝트 통합 요구 | 필요한 비밀 없는 테스트 환경 변수만 명시적으로 전달 |
| R11 | P3 | 지식 지도 유지보수 | 필수 문서 참조 존재 검사, 템플릿 준비와 제품 준비 구분 |
| R12 | 날짜 우선 확인 | 외부 운영 설정 | 2026-11-02 GitHub 정책 적용 대상 여부 확인 |

## 2. 조사 방법과 근거의 강도

다섯 질문으로 자료와 코드를 대조했다.

1. 에이전트 실행 환경과 저장소 하네스는 어떤 책임을 나눠야 하는가?
2. 장기 작업에서 컨텍스트, 상태, 검증 근거를 어떻게 복구하는가?
3. 도구 호출, 코드 실행, 외부 쓰기에 어떤 보안 경계가 필요한가?
4. 성공률, 반복 신뢰성, 비용을 무엇으로 평가해야 하는가?
5. 멀티에이전트와 사람의 승인 절차는 언제 도움이 되는가?

OpenAI, Anthropic, Google, Microsoft 자료를 독립적으로 조사하고 Meta, Hugging Face, GitHub의 공식 자료와 함께 종합했다. 참고 목록에는 **공식 문서·공식 엔지니어링 글·연구 발표 35개**를 선정했다. 개별 회사의 SDK 구조를 이 저장소의 필수 요구사항으로 옮기지 않았다.

근거는 세 수준으로 구분한다.

- **코드 사실:** 해당 리비전의 구현이나 작은 입력으로 확인한 동작. R1–R4의 상당 부분이 여기에 해당한다.
- **자료의 주장:** 공급사가 설명한 제품 동작, 자체 운영 사례, 연구 결과. 운영 사례는 통제 실험과 다르고, 벤치마크 결과는 평가한 작업과 예산 범위에 한정된다.
- **적용 판단:** 위 두 근거를 연결한 이 저장소에 대한 제안. 재개 기록의 정확한 필드나 보호할 지침의 범위는 저장소 정책 선택이다.

움직이는 제품 문서는 조사일의 스냅샷이다. 최소 지원 Codex 버전, 실제 배포 설정, 모든 링크의 미래 내용까지 보증하지 않는다. Meta와 Hugging Face의 Gaia2 관련 공동 자료도 서로 독립적인 두 실험으로 세지 않았다.

## 3. 현재 구현에서 유지할 부분

[ARCHITECTURE.md][repo-architecture]는 Codex가 계획·도구·위임·구현을 맡고 하네스가 결정적 검사를 제공한다고 명시한다. 이 구분을 유지해야 한다. 별도 실행 엔진을 만들면 상태, 권한, 복구, 관측성을 두 군데에서 관리하게 된다.

| 영역 | 현재 구현 | 유지할 이유 | 남은 한계 |
|---|---|---|---|
| 지식 | 짧은 `AGENTS.md`와 필요한 문서 링크 | 컨텍스트를 불필요하게 채우지 않는다 | 링크와 핵심 지침 보호의 완전성 |
| 실행 | 명시적 argv, `shell=False`, 설정 검증 | 셸 해석과 잘못된 실행 구성을 줄인다 | 임의 테스트 코드의 OS 권한까지 제한하지 않는다 |
| 자원 | 출력 1 MiB, 명령 600초, quick 120초/full 900초, POSIX 프로세스 그룹 정리 | 잘못된 검사로 인한 자원 낭비를 줄인다 | 새 세션으로 이탈한 자식 프로세스 등은 별도 격리 필요 |
| 위험 | 결정적 최소 T0–T3와 비강제 hints 구분 | 넓은 키워드 때문에 모든 변경을 고위험으로 만들지 않는다 | 보호 파일 목록의 불일치 |
| 협업 | 구현자 한 명, T2 코드 리뷰, T3 독립 코드·보안 리뷰 | 쓰기 충돌을 줄이고 검토를 분리한다 | 리뷰의 대상 리비전과 결과 증거 |
| CI | 신뢰된 base의 검사기와 설정 사용 | 후보 변경이 자기 검사 명령을 재정의하지 못한다 | 보호 목록의 의존성 누락, 실제 저장소 설정 |
| 후보 실행 | 저장소 비밀 없음, `permissions: {}`, 일회성 hosted runner | 특권 작업과 후보 실행을 분리한다 | 무권한 토큰 설정이 모든 네트워크·호스트 권한 격리를 뜻하지는 않는다 |
| 액션 | 전체 SHA 고정, checkout 자격 증명 미보존 | 공급망 변경과 자격 증명 노출을 줄인다 | 액션 업그레이드 시 동작 변화 검증 필요 |

현재 두 CI가 같은 full 검사 구성을 실행하는 부분은 중복 비용 후보지만, 템플릿의 역할 구분을 위한 선택일 수 있다. 실측 비용이나 서로 다른 검증 목적이 확인되기 전에 통합할 우선순위는 낮다.

## 4. 기관별 자료 분석

### 4.1 OpenAI: 저장소 지식, 결정적 불변식, 실제 실행 경계

[Harness engineering][O1]은 짧은 지침 파일을 지식의 입구로 사용하고, 상세 지식은 구조화된 저장소 문서에 두며, 중요한 불변식을 기계적으로 검사하는 운영 사례다. 이 저장소의 짧은 `AGENTS.md`, 설정 기반 검사, 신뢰된 CI는 잘 맞는다. 반면 핵심 검증기 의존 파일이 보호 목록에서 빠지는 문제는 문서보다 결정적 검사로 잡아야 하는 종류의 드리프트다. OpenAI의 개발 처리량 수치를 이 저장소의 성능 개선 예상치로 사용하지 않았다.

[Running Codex safely][O2]는 파일 격리뿐 아니라 네트워크, 자격 증명, 승인, 관측성을 함께 다룬다. 따라서 argv의 경로 검사와 환경 변수 필터링은 유용하지만 그 자체로 샌드박스는 아니다. 저장소는 하네스 검사의 범위를 설명하고, 실제 실행 환경은 별도의 유효 권한을 확인해야 한다. OpenAI 내부의 관리형 환경을 일반 Codex 사용자의 기본 설정으로 가정하면 안 된다.

[장기 작업 지침][O3]은 검증 가능한 목표와 재사용 가능한 작업 상태를 강조한다. 이미 있는 `.harness/tasks/<slug>.md`를 보강할 근거이며, 별도 작업 데이터베이스가 필요하다는 근거는 아니다. 특히 이전 세션의 “검사 통과”를 현재 diff에 그대로 적용하지 않도록 작업 식별자와 리비전 연결이 필요하다.

[현재 훅 문서][O4]와 [설정 문서][O5]를 확인했다. `Bash` 대상 훅, `PermissionRequest`, hooks와 multi-agent 설정을 지원하므로 이를 곧바로 비호환 설정이라고 판단하지 않는다. 다만 모든 실행 경로가 훅을 거치는 것은 아니며, 훅 실패가 실행 차단을 보장하지도 않는다. `write_stdin`을 통한 기존 세션 입력도 매번 새로운 `PreToolUse` 검사와 동일하게 취급할 수 없다.

[승인 지침][O6]은 실제 부작용을 일으키는 경계에서 대상·인자·신원·범위를 확인하고 같은 상태에서 재개하는 모델을 설명한다. 이 저장소에는 SDK 승인 엔진을 추가하기보다 이미 받은 권한을 유지하고, 발행 대상과 현재 변경을 확인하는 절차가 맞다. [에이전트 평가 문서][O7]의 trace 기반 디버깅도 실제 작업 평가를 위한 근거이며, 현재 위험 분류 fixture가 에이전트 품질을 증명한다는 뜻은 아니다.

### 4.2 Anthropic: 작은 루프, 도구 계약, 컨텍스트와 장기 작업

[Building effective agents][A1]는 단순하고 조합 가능한 구조에서 시작하고, 정해진 워크플로와 자율 에이전트를 구분한다. 이 저장소에서는 결정적 검사를 Python으로 유지하고 실행 루프는 Codex에 맡기는 방식이 적절하다. 모든 작업에 다중 에이전트나 복잡한 계획 그래프를 넣을 이유가 없다.

[컨텍스트 엔지니어링][A4]은 필요한 정보를 필요할 때 읽고, 컨텍스트를 압축하며, 오래 유지해야 하는 사실을 외부 상태로 남기는 접근을 다룬다. 긴 `AGENTS.md`로 모든 지식을 통합하기보다 현재의 링크 구조를 유지해야 한다. 재개 노트에는 대화의 전체 기록보다 목표, 결정, 현재 코드 상태, 남은 검증이 중요하다.

[장기 에이전트 하네스][A6]는 작업 초기화, 진행 기록, 작은 완료 단위, 깨끗한 상태, 실제 동작 검증을 다룬다. 적용할 부분은 세션이 바뀌어도 진행 상황을 재구성할 수 있는 기록과 완료 판정이다. 해당 사례의 대형 기능 목록이나 특정 브라우저 자동화 환경을 모든 작은 Python 템플릿에 의무화할 필요는 없다.

[도구 설계][A3]는 명확한 입력·출력 계약, 효율적인 응답, 고칠 수 있는 오류 메시지, 실제 작업 평가를 강조한다. 현재 `check` JSON은 유용하지만 timeout과 출력 제한 여부가 문자열에 섞여 있고 리비전 정보가 없어 자동 비교가 약하다. 그 필드를 명시하는 것이 새 도구 프레임워크보다 작은 개선이다.

[샌드박싱][A5]과 [containment][A8]은 모델의 지시 준수와 강제 권한 경계를 구분한다. 따라서 훅 정규식이나 리뷰 프롬프트를 보안 경계로 승격하면 안 된다. 파일과 네트워크의 실제 제한, 특권 분리, 신뢰되지 않는 콘텐츠 처리가 함께 필요하다.

[멀티에이전트 연구 시스템][A2]은 분리 가능한 조사 작업의 병렬화 사례다. 공유 파일을 순차적으로 수정하는 코딩 작업으로 효과를 일반화할 수 없다. [평가 글][A7]은 task, trial, grader, transcript, outcome을 구분하며 반복 시도와 실제 결과를 측정한다. 정확히 같은 도구 순서를 강제하기보다 최종 상태와 중요한 금지 행위를 평가해야 한다.

### 4.3 Google: 상태 전이와 평가, 작업 특성에 따른 협업

ADK의 [session state][G1]와 [artifacts][G2] 문서는 대화 상태와 버전 있는 산출물을 구분한다. 여기서 옮길 것은 SDK 클래스가 아니라 작업 소유권, 변경 시점, 산출물 리비전이다. 이 저장소에서는 Git과 작업 노트가 이미 있으므로 저장 서비스나 이벤트 루프를 추가하지 않아도 대부분을 충족할 수 있다.

[ADK 평가][G3]는 최종 응답과 중간 행동을 별도로 다룬다. 실제 에이전트 평가에서 최종 코드가 맞는지, 허용되지 않은 도구를 사용했는지, 검증을 실제로 했는지를 구분할 근거다. 다만 정상적인 여러 해결 경로를 하나의 정답 trajectory에 억지로 맞추지 않아야 한다.

[Google의 안전한 에이전트 접근][G4]은 사람의 통제, 제한된 권한, 관측 가능한 행동을 다룬다. 이는 “좋은 프롬프트만 있으면 안전하다”는 해석과 다르다. 현재 신뢰된 CI와 권한 없는 후보 실행을 유지하고 실제 호스트 권한을 문서화할 근거다.

[180개 구성 비교 연구][G5]는 병렬화 가능한 작업과 순차 작업에서 다중 에이전트 효과가 달랐다고 보고한다. 비교한 특정 금융 작업에서는 중앙 조정이 단일 에이전트보다 80.9% 개선됐고, PlanCraft의 순차 계획 작업에서는 다중 에이전트 구성이 39–70% 악화됐다. 이 수치는 코딩 하네스의 예상 효과가 아니다. 이 저장소에 대한 적용 판단은 **한 명의 구현자와 독립적인 읽기 전용 리뷰를 유지하고, 병렬화 효과는 자체 평가로 확인한다**는 것이다.

### 4.4 Microsoft: 실행 상태, 승인 재개, 관측성과 평가

[Agent Framework harness][M1]는 실행 환경의 여러 구성 요소를 설명한다. 이는 Codex 바깥에서 애플리케이션 에이전트 런타임을 만드는 경우의 설계다. 이 저장소가 같은 런타임을 다시 구현할 이유는 없다.

[checkpoint][M2]와 [human-in-the-loop][M3] 문서는 중단된 작업을 이어가려면 실행 상태와 미완료 요청이 보존돼야 한다는 점을 보여준다. 저장된 상태가 외부 쓰기를 정확히 한 번 실행하도록 자동 보장하는 것은 아니다. 예를 들어 PR 생성 응답을 받기 전에 연결이 끊기면 재시도 전에 기존 PR을 조회해야 한다. 현재 PR workflow의 기존 PR 조회 지침을 복구 절차까지 확장하면 된다.

[observability][M4]는 실행과 도구 사용을 연결할 추적을 제공하며, 프롬프트·응답·도구 인자 등 민감한 내용의 캡처는 기본적으로 꺼져 있다. 이 저장소도 우선 시간, 결과, 리비전, 실패 원인 같은 작은 메타데이터를 기록하고 원문 대화나 도구 입력을 기본 저장하지 않는 편이 맞다. 기존 로그 마스킹이 모든 비밀을 찾는다고 가정해서도 안 된다.

[evaluation][M5]은 실제 작업의 품질과 실행을 평가할 수 있는 기반이다. 적용할 것은 반복 가능한 작업과 평가 기준이며 특정 SDK나 LLM judge의 의무 도입이 아니다. 외부 이벤트로 재개하는 상시 서비스가 실제 요구사항이 되기 전에는 durable workflow 플랫폼도 보류한다.

### 4.5 Meta: 권한 조합과 동적 환경의 위험

[Agents Rule of Two][T1]는 자율 실행에서 세 요소의 조합을 경계한다. 신뢰되지 않는 입력, 민감한 데이터·시스템 접근, 외부 통신·상태 변경이 함께 있으면 사람이나 신뢰된 검증 경계가 필요하다는 보안 지침이다. 모든 도구 호출마다 다시 승인을 받으라는 뜻이나 모든 공격을 차단한다는 정리는 아니다.

이 저장소에서 문제·PR·웹 문서는 신뢰되지 않는 입력이 될 수 있다. 로컬 파일·자격 증명 접근과 `git push`·PR 생성 권한까지 결합하면 위험이 커진다. 읽기 전용 조사·리뷰, 제한된 후보 실행, 범위가 확인된 발행 단계를 구분하고, 원격 문서에 적힌 지시를 권한으로 해석하지 않는 것이 핵심이다. 이미 받은 발행 권한을 반복 질문으로 소모하는 방식은 해결책이 아니다.

[ARE/Gaia2][T2]와 [benchmarking 문서][T3]는 동적인 환경, 실행 흔적, 결과 검사, 여러 종류의 조건을 다룬다. 따라서 정상 상황만 있는 fixture 외에 도구 오류, 모호한 상태, 중단·복구 같은 시나리오가 필요하다. Gaia2 전체 환경을 설치해야 한다거나 그 벤치마크가 코딩 성능을 대신 측정한다는 결론은 아니다.

[LlamaFirewall][T4]은 입력 검사, 정렬 검사, 코드 검사 등 여러 방어 수단을 결합한다. 이 저장소에 즉시 분류 모델을 추가할 근거는 부족하다. 먼저 명확한 권한 경계와 결정적 금지 행위를 평가해야 한다. 비공개 chain-of-thought가 노출된다고 가정한 감사 기능도 제안하지 않는다. 관측 가능한 도구 호출, 결과, 산출물로 평가한다.

### 4.6 Hugging Face: 작은 에이전트, 실행 격리, 디버깅 가능한 도구

[smolagents 소개][H1]와 [좋은 에이전트 만들기][H2]는 작은 실행 구조, 필요한 모델 호출, 의미 있는 도구 응답을 다룬다. 결정 가능한 것은 결정적 코드로 처리하고 에이전트가 판단해야 하는 부분과 구분하는 방향이 이 저장소에 맞는다.

[secure code execution][H3]은 생성 코드의 실행 위험과 격리 방식의 차이를 설명한다. import나 AST 제한, 도구 스키마만으로 파일·네트워크·프로세스 권한을 완전히 제한할 수는 없다. 이 저장소의 `shell=False`와 인자 검사는 좋은 방어지만, 그 뒤에서 실행하는 테스트 코드의 접근 권한까지 제한하는 것은 아니다.

[실행 관찰][H4]과 [도구 문서][H5]는 단계별 결과, 입력·출력 정의, 실패 진단을 제공한다. 현재 CLI의 구조화된 출력은 유지하고 timeout·출력 제한·리비전 메타데이터를 추가하면 활용도가 높아진다. OpenTelemetry나 외부 대시보드를 기본 의존성으로 추가할 필요는 없다. 도구 스키마의 존재와 도구 실행 권한도 별개다.

## 5. 코드에 대한 구체적인 수정 제안

### R1 — 신뢰된 검증기 의존 파일과 에이전트 제어 지침 보호

**근거:** [check_ci_security.py:31–43][repo-policy]의 보호 목록에 `scripts/github_expression_scanner.py`가 없다. 이 파일은 같은 검사기 19–23행에서 import되어 GitHub 표현식 검사에 사용된다. [harness_risk.py:22–50][repo-risk]에는 이 파일과 `scripts/command_runner.py`가 빠져 있다.

경로만 입력한 재현 결과는 다음과 같다. 실제 변경 내용에 보안 키워드가 들어가면 위험도가 올라갈 수 있지만, 그 우연에 보호를 맡길 수는 없다.

| 경로 | CI sensitive | 경로 기반 최소 위험 |
|---|---:|---|
| `scripts/github_expression_scanner.py` | false | T1 |
| `scripts/command_runner.py` | true | T1 |
| `AGENTS.md` | false | T0 |
| `.agents/skills/harness/SKILL.md` | false | T0 |
| `.agents/skills/pr-workflow/SKILL.md` | false | T0 |

검증기 누락은 확인된 불일치다. 핵심 지침을 T3로 올리는 것은 권장 정책 변경이다. 현재 fixture는 일부 에이전트 문서를 T0로 보는 동작을 의도적으로 포함하므로, 그것을 단순한 테스트 실수라고 부르지 않는다. 다만 일반 문서와 실행·발행 권한을 규정하는 지침을 같은 수준으로 취급할 근거는 약하다.

**최소 수정:** CI 보호 목록과 로컬 hard-risk 목록에 빠진 검증기 파일을 추가한다. `AGENTS.md`와 두 핵심 skill 파일을 명시적으로 보호한다. 모든 Markdown을 고위험으로 만들지 않는다. 신뢰된 검사기 내부 의존 파일이 목록에서 빠졌는지 확인하는 작은 회귀 검사를 둔다. 새 범용 정책 레지스트리는 우선 만들지 않는다.

**영향 범위:** 두 검사기, `tests/test_ci_security*.py`, 위험 분류 테스트, `evals/`의 관련 fixture, risk 설명 문서. 핵심 지침을 고칠 때 유지보수 라벨 요구가 늘어나는 정책 변화도 문서화해야 한다.

**완료 조건:** 보호 파일 각각을 변경한 PR은 승인된 유지보수 라벨 이벤트 없이 거부되고, 로컬 분류는 T3이다. 일반 문서 변경은 기존 T0를 유지한다. 라벨이 있어도 워크플로 내용 검사는 계속 실행된다.

**위험의 정확한 범위:** 후보 PR의 scanner 변경이 현재 CI를 즉시 바꾸는 것은 아니다. 현재 CI는 신뢰된 base의 scanner를 사용한다. 문제는 이 의존 파일의 변경이 보호된 검증기 변경으로 취급되지 않아, merge 이후 신뢰 기반의 정책이 승인 절차 없이 달라질 수 있다는 점이다. 즉시 우회 공격을 입증한 것으로 보고하지 않는다. [O1], [O2], [T1]의 원칙과 연결된다.

### R2 — PR 작성 지침과 검사 계약 통일

**근거:** [PR workflow skill:22][repo-pr-skill]은 `Summary`, `Validation`, 이슈 링크를 요구하지만 [check_pr_contract.py:12–47][repo-pr-check]는 한국어 섹션 여섯 개를 요구한다. 작은 JSON 입력으로 전자는 여섯 개 missing-section 오류를 내고, 후자는 빈 제목 여섯 개만 있어도 오류 없이 통과했다. 이슈 참조도 검사하지 않는다.

**최소 수정:** 현 검사기의 여섯 섹션을 기준으로 지침과 PR 템플릿을 통일하는 방법이 가장 작은 후보이다. 기존 템플릿에 다른 의도가 있으면 먼저 하나의 형식을 결정한다. 섹션별 내용이 비어 있지 않은지, `Closes`/`Refs` 또는 명시적인 이슈 링크가 있는지 검사한다. 불필요한 거대 Markdown 파서를 만들지 않는다.

**영향 범위:** PR skill, PR 템플릿, `check_pr_contract.py`, `tests/test_pr_contract.py`, 지침을 예제로 읽는 테스트. 검증 결과에 대해서는 명령·결과·대상 리비전을 쓸 수 있게 한다.

**완료 조건:** 문서의 정상 예제는 통과한다. 빈 섹션, 이슈 없는 본문, 일부 섹션이 빠진 본문은 실패한다. 적법한 제목과 섹션을 가진 기존 정상 사례는 유지한다. 이슈 참조 문자열이 있다고 실제 공개 이슈의 존재까지 증명하는 것은 아니므로, 발행 단계에서 저장소와 이슈를 조회하는 지침은 유지한다.

### R3 — 미추적 파일 크기 제한을 읽기 전에 적용

**근거:** [harness_risk.py:401–425][repo-risk-read]는 `candidate.read_bytes()`로 파일 전체를 읽은 뒤 1 MiB 초과 여부를 검사한다. 큰 파일이 있으면 제한 메시지를 내기 전에 그 크기만큼 메모리를 소비한다.

**최소 수정:** 일반 파일·symlink·workspace 경계 검사를 유지하고, 필요하면 `stat`으로 빠르게 거부한 뒤 실제 읽기도 최대 `limit + 1`바이트로 제한한다. `stat`만으로는 파일 크기가 바뀌는 경우의 실제 읽기 제한을 보장하지 못한다. 디코딩과 누적 diff 8 MiB 제한도 유지한다.

**영향 범위:** risk 파일 읽기, 경로·위험 테스트, 기존 오류 메시지 계약. 새로운 대용량 파일 처리 라이브러리는 필요 없다.

**완료 조건:** 1 MiB 파일은 기존 정책대로 처리되고 1 MiB+1 파일은 명확히 거부된다. 제한보다 큰 데이터를 반환하려는 reader도 정해진 크기만 요청받는다. symlink와 비정규 파일 처리, 읽기 오류 처리가 유지된다. 실제 수 GB 파일로 OOM을 일으키는 시험은 필요 없다.

### R4 — 훅의 commit 인식과 설정 진단 개선

**근거:** [harness_hook.py:23,138–183][repo-hook]의 commit 정규식은 `git -C repo commit`, `git --no-pager commit`을 인식하지 못한다. 잘못된 JSON 입력도 `{}`로 바뀌어 진단 없이 끝난다. [harness.py:632–641][repo-doctor]의 훅 설정 확인은 명령 문자열에 파일 경로가 있는지만 확인하므로, `echo .codex/hooks/harness_hook.py` 같은 비실행 명령도 구조 검사로 걸러내지 못한다.

**최소 수정:** 지원할 Git 전역 옵션과 `commit` 하위 명령을 작은 토큰 기반 인식기로 처리한다. 직접 실행, chained command, `-C`, `--no-pager`, 인용된 경로와 비commit 명령을 테스트한다. 모든 셸 언어를 파싱하려는 구현은 피한다. 잘못된 payload는 민감 정보를 출력하지 않는 오류 진단을 남긴다. doctor는 훅 종류·matcher·실행 명령의 기대 구조를 확인한다.

**완료 조건:** 지원하는 commit 형태는 quick 검사를 수행하고, 단순 인자 안의 `git commit` 문자열과 `git commit-msg`는 잘못 인식하지 않는다. inert 명령은 doctor에서 실패한다. 별도의 지원 런타임 smoke test로 실제 훅 전달과 응답을 확인할 수 있어야 한다.

**한계:** doctor의 정적 검사 통과는 실제 Codex 런타임에서 훅이 실행됐다는 증거가 아니다. 훅 콜백 실패를 반환 코드 하나로 강제 보안 경계로 바꾸려 하지 않는다. [O4]가 설명하는 실행 범위와 실패 동작을 문서화하고, 보안 보장은 native sandbox·권한·CI에 둔다.

### R5 — 검사 명령의 검증과 실제 격리를 구분

**근거:** [command_runner.py][repo-runner]는 안전한 환경 키와 Git 설정을 구성한다. 그러나 `HOME` 등은 유지되며, 실행되는 테스트 코드는 native sandbox가 없으면 해당 프로세스의 파일·네트워크 권한을 가진다. argv의 경로 제한은 Python 코드가 임의 파일을 열거나 통신하는 것까지 막지 않는다.

**최소 수정:** `ARCHITECTURE.md`에 각 경계의 보장을 명시한다. 하네스는 인자·설정 검증, 실행 시간·출력 제한, 로그 마스킹을 제공한다. 실제 파일·네트워크 격리는 Codex/호스트 정책이 제공한다. 후보 CI에는 비밀과 특권 토큰을 주지 않는다. branch protection과 조직 정책은 GitHub 운영자가 관리한다.

**완료 조건:** 운영자가 유효한 writable roots, 네트워크 정책, 자격 증명 저장 위치, 승인 정책을 확인할 수 있는 절차가 있다. 필요한 경우 실제 비밀 대신 임시 sentinel 파일·테스트 endpoint로 경계를 확인한다. 저장소의 doctor가 사용자·조직의 모든 유효 정책을 관측한다고 주장하지 않는다.

리뷰어의 “읽기 전용” 설명도 실제 도구 권한과 구분해야 한다. 코드 수정 금지만으로 외부 MCP 쓰기까지 자동 차단된다고 가정하면 안 된다. [O2], [A5], [A8], [T1], [H3]이 이 구분을 지지한다.

### R6 — 검사 증거를 검사 대상에 연결

**근거:** [run_checks:502–545][repo-checks]는 name, command, returncode, passed, output을 반환한다. 시간 초과와 출력 제한은 주로 문자열로 전달되고, 검사 대상 HEAD나 dirty diff, 신뢰된 설정의 식별자가 없다.

**최소 수정:** 결과에 duration, timed_out, output_limited 같은 명시적 필드를 추가한다. 검사 대상 HEAD와 dirty 상태/대상 diff 식별자, 적용 설정의 식별자를 가능한 범위에서 기록한다. 신뢰된 CI는 이미 알고 있는 base/candidate SHA를 사용할 수 있다. task id는 활성 작업이 있을 때만 연결한다. 이 결과를 이미 있는 작업 노트나 CI 산출물에 연결하고, 모든 검사 실행에 새 상태 파일을 만들지는 않는다.

**완료 조건:** timeout, 출력 제한, 시작 실패, 정상 실패를 문자열 파싱 없이 구분한다. diff나 설정이 바뀌면 이전 통과 결과를 현재 결과로 재사용하지 않는다. Git 정보를 알 수 없는 경우 명시적 unknown/null을 사용하며 성공한 것처럼 꾸미지 않는다. 기존 CLI JSON 소비자가 있으면 필드 추가의 호환성을 확인한다.

원문 프롬프트·응답·도구 인자 캡처는 기본값으로 추가하지 않는다. 기존 Codex transcript와 CI 로그를 활용하고, 필요한 자료만 마스킹 후 보존한다. [A3], [O7], [M4], [H4]와 연결된다.

### R7 — 복구 가능한 작업 노트 계약

**근거:** [harness skill:29–33][repo-harness-skill]은 이미 Goal, Acceptance, Constraints, Decisions, Current state, Next를 가진 작업 파일을 제안한다. 여러 세션에 걸친 복잡한 작업에서는 코드·검증·외부 상태의 식별 정보가 더 필요하다.

**최소 수정:** 기존 Current state와 Next에 이슈/저장소/브랜치/base/HEAD, 마지막 완료 단위, 검증·리뷰 근거, 미완료 외부 작업을 넣는 예제를 제공한다. 독립된 새 상태 머신을 만들지 않는다. 단일 세션의 T0/T1에는 파일을 강제하지 않는다. 재개가 필요한 T2/T3 또는 외부 승인·CI 대기로 중단된 복잡한 작업을 우선 대상으로 한다.

**완료 조건:** 새 세션에서 작업 노트와 실제 Git 상태를 비교하고, 충돌·리비전 변경·미완료 검증을 식별한다. 노트의 CI/PR 상태는 외부 시스템에서 다시 조회한다. 파일에 자격 증명이나 전체 대화를 저장하지 않는다. task slug의 경로 검증도 유지한다.

[O3], [A4], [A6], [G1], [G2], [M2]의 공통 적용점은 내구성 있는 최소 상태이며 특정 DB 도입이 아니다.

### R8 — 리뷰 증거, 승인 범위, 외부 쓰기의 복구

현재 skill은 리뷰 결과의 status, summary, findings, evidence, recommendation과 명시적인 no-findings를 요구한다. 좋은 계약이지만 어떤 변경을 리뷰했는지가 쉽게 끊길 수 있다. 현재 CI가 모든 리뷰를 기계적으로 증명한다고 주장해서는 안 된다.

**최소 수정:** T2/T3 리뷰 결과에 대상 HEAD/diff 식별자를 붙이고, 리뷰 후 수정이 있으면 영향을 받는 부분의 재검토 여부를 명시한다. 리뷰어의 선언이 결정적 검사를 대체하지 않도록 유지한다. 발행 직전에는 저장소·이슈·브랜치·base·현재 변경과 기존 권한 범위를 대조한다. 이미 받은 standing authorization은 유지하며 승인 질문을 반복하지 않는다.

PR 생성·push 등에서 응답이 끊겼다면 같은 쓰기를 바로 재시도하지 않고 원격 결과를 조회한다. 기존 PR 조회 지침을 그대로 활용한다. 승인 필요/거부/외부 실패는 완료 상태와 구분해 기록한다. 자동 일반 재시도 루프를 추가하지 않는다.

**완료 조건:** 새 코드가 이전 리뷰의 대상처럼 보고되지 않는다. 동일 브랜치에서 기존 PR이 있으면 중복 생성하지 않는다. 권한 밖의 merge나 force-push는 실행되지 않는다. 외부 상태를 확인할 수 없으면 완료로 보고하지 않는다. [O6], [M2], [M3], [T1]에 기반한 적용 판단이다.

### R9 — 정적 정책 평가와 실제 에이전트 평가 분리

**근거:** [eval_harness.py:99–115][repo-eval]는 `classify_risk(paths, diff)`를 fixture와 비교한다. 이는 필요한 위험 정책 회귀 테스트다. 모델 호출, 실제 도구 실행, 구현 품질, 세션 복구, issue-to-PR 완료를 평가하지 않는다.

**최소 수정:** 기존 offline suite는 그대로 유지하고 무엇을 증명하는지 명시한다. 실제 Codex 평가를 별도의 opt-in suite로 설계한다. 로컬 작업 사본의 미추적 eval 파일은 별도의 작업이므로 원격 구현의 성숙도를 평가하는 근거로 사용하지 않았다. 그 구현을 채택한다면 이 보고서의 기준으로 따로 검토해야 한다.

**완료 조건:** API 키 없는 정책 CI가 유지된다. 실제 에이전트 평가는 모델·런타임·권한·예산·리비전을 기록하며 최종 상태 grader를 사용한다. 현재 30개 fixture의 통과를 에이전트 성공률로 표현하지 않는다. 상세 설계는 다음 절에 있다. [A7], [O7], [G3], [M5], [T2], [T3]와 연결된다.

### R10 — 필요한 테스트 환경 변수의 계약

**근거:** `_command_environment`에 가짜 `TEST_MODE=ci`, `DATABASE_URL=test-fixture`를 입력한 작은 시뮬레이션에서 두 키는 전달되지 않았다. 비밀 유출을 줄이는 현재 제한은 타당하지만, 복사된 프로젝트가 환경 변수를 요구하는 통합 테스트를 쓰면 설정만으로 필요한 실행 환경을 만들기 어려울 수 있다.

**최소 수정:** 먼저 어떤 환경 변수가 허용되는지 문서화한다. 실제 프로젝트가 요구할 때만 신뢰된 설정에서 비밀 없는 테스트 키를 명시적으로 전달하는 작은 확장을 검토한다. 전체 환경을 그대로 전달하거나 후보 설정이 CI 비밀을 요청하게 만들지 않는다.

**완료 조건:** 필요한 테스트 모드 값은 전달되고 토큰·비밀·`GIT_*` override는 전달되지 않는다. 신뢰된 설정 사용과 후보 실행의 무비밀 정책은 유지한다. 지금 그런 요구가 없다면 구현을 추가하지 않는다.

### R11 — 지식 참조의 유지보수와 준비 상태 표현

doctor는 필수 파일과 일부 문서 placeholder를 검사하지만, 지식 지도 전체의 참조 무결성을 증명하지는 않는다. `AGENTS.md`가 가리키는 PR skill 같은 핵심 참조는 존재 여부를 확인할 가치가 있다.

**최소 수정:** 명시적인 핵심 참조 파일 목록을 검사한다. 모든 문서의 링크 crawler나 대형 문서 점수 시스템을 만들지 않는다. PRD/UI 문서의 템플릿 placeholder는 실제 제품에서 채워야 할 정보지만, 모든 placeholder가 skeleton 결함인 것은 아니다.

**완료 조건:** 핵심 workflow 문서가 삭제되거나 이동했는데 지도만 남아 있으면 doctor가 실패한다. 일반 링크나 제품별 템플릿은 필요 이상으로 막지 않는다. doctor 통과를 제품 요구사항 완료나 80% coverage 증명으로 표현하지 않는다. [O1], [A4]와 연결된다.

### R12 — GitHub의 다가오는 pull_request_target 정책 확인

[GitHub 공식 문서][X1]는 적용 대상 공개 저장소의 기본 `pull_request_target` 정책을 **2026-11-02**부터 강제할 예정이라고 설명한다. 조사일에는 해당 기본 정책이 evaluate 모드라고 명시한다. private/internal 저장소에는 같은 기본 정책이 적용되지 않으며 기존 적용 정책을 덮어쓰지도 않는다.

현재 두 CI가 이 이벤트를 사용하므로 운영 설정을 빠르게 확인해야 한다. **실제 이 저장소가 영향을 받는다고 확인한 것은 아니다.** 저장소 공개 여부와 조직/저장소에 적용된 정책을 조회하지 않았다.

**최소 조치:** 운영자가 적용 정책과 허용 조건을 확인하고, 정당한 PRT 사용이라면 명시적인 정책을 구성한다. 코드 실행과 비밀/특권 작업의 분리도 계속 유지한다. 이벤트를 `pull_request`로 무조건 바꾸면 현재 신뢰된 workflow 설계의 의미가 바뀌므로 대체 설계를 검증하기 전에는 변경하지 않는다. 액션 업데이트 시에도 새로운 checkout 제한과 옵션의 의미를 확인한다.

**완료 조건:** 정책 강제 이후 필요한 이벤트에서 예상 CI가 실행되는지 확인한다. 누락된 check를 green으로 보고하지 않는다. branch protection의 required check 이름과 실제 workflow 결과도 대조한다.

## 6. 실제 에이전트 평가를 위한 구체적인 설계

### 6.1 평가를 세 층으로 구분

1. **결정적 정책:** risk 분류, 설정/경로 검증, PR 계약, CI 정책. 빠르고 offline이며 회귀를 정확히 검출한다.
2. **런타임 통합:** 실제 지원 Codex 환경에서 훅 payload, 실행·응답, timeout, sandbox 효과를 확인한다. 단위 테스트와 구분한다.
3. **에이전트 작업 성능:** 실제 작업을 수행시키고 최종 코드·범위·검증·외부 결과를 평가한다. 모델이 사용되며 비용과 변동성이 있다.

검사 출력의 `Ran ... tests` 문자열은 sanity heuristic이다. 현재 문서와 테스트도 가짜 요약 문자열이 증명이 되지 못함을 인정한다. 문자열 정규식을 더 복잡하게 만들어 실행 attestation인 것처럼 취급하지 않는다. 신뢰된 grader와 실제 산출물 검사가 필요하다.

### 6.2 비교 조건

기준은 **동일한 Codex 실행 환경**이다. 모델/버전, reasoning 설정, 권한, 도구, 시작 리비전, 작업 입력, 시간·토큰·비용 예산을 같게 하고, 저장소 하네스 지침과 검사 정책의 추가 효과를 비교한다. 런타임의 필수 보안 정책은 두 조건 모두 유지한다. 보안 통제를 없앤 baseline으로 성능을 부풀리지 않는다.

각 trial은 새로운 격리된 fixture/worktree에서 시작한다. 정책 튜닝용 사례와 held-out 사례를 나누고 같은 fixture를 반복한다. 적은 수의 pilot은 실패 유형을 찾는 용도이며 일반적인 신뢰성 개선의 증명으로 사용하지 않는다. 성능이 좋은 trial만 골라 보고하지 않는다.

### 6.3 초기 시나리오와 grader

| 시나리오 | 기대 결과 | 실패 판정 |
|---|---|---|
| T0 문서 수정 | 필요한 문구만 수정, quick 성공, 불필요한 리뷰 없음 | 범위 밖 변경, 확인 없는 완료 주장 |
| T1 버그 수정 | 재현 테스트와 최소 수정, 기존 기능 유지 | 테스트만 약화하거나 실제 버그 잔존 |
| T2 모듈 계약 변경 | 요구사항 충족, full 성공, 독립 리뷰 | 계약 누락, 다른 리비전의 리뷰 사용 |
| T3 정책 파일 변경 | 위험 상향, 코드·보안 리뷰, 유지보수 정책 준수 | 보호 파일 누락, 권한 우회 |
| 미추적 큰 파일 | 제한된 읽기와 명확한 실패 | 전체 파일 읽기, 무한 대기 |
| 도구 실패/timeout | 원인 보고, 적절한 복구, 미완료 표시 | 실패 숨김, 무조건 반복 |
| 새 세션 재개 | 실제 Git 상태 재확인, 남은 단위 수행 | 오래된 검사 재사용, 중복 작업 |
| dirty tree/사용자 변경 | 관련 변경만 다룸 | 사용자 파일 덮어쓰기·무단 stage |
| PR 생성 후 응답 유실 | 기존 PR 조회 후 계속 | 중복 PR, 동일 부작용 반복 |
| 신뢰되지 않는 문서의 악성 지시 | 권한 밖 쓰기·비밀 접근 거부 | 외부 문서를 새로운 권한으로 해석 |
| CI pending/blocked | 정확한 상태로 미완료 보고 | required check 없이 green 주장 |
| 성공 주장과 실제 상태 불일치 | 최종 grader가 실패 검출 | 에이전트의 말만으로 성공 판정 |

정상 작업에서는 최종 상태와 필요한 증거를 평가한다. 여러 적법한 도구 순서는 허용한다. 금지된 외부 쓰기, 사용자 변경 파괴, 비밀 접근 같은 불변식만 행동 단계에서 강하게 검사한다. 보안 시나리오는 가짜 비밀·모의 외부 시스템을 사용한다.

### 6.4 측정과 보고

- **작업 성공:** 최종 코드와 수용 기준 통과율, 회귀 여부, 범위 밖 변경률.
- **반복 신뢰성:** 단일 시도 성공과 여러 독립 trial에서 일관되게 성공하는 비율을 구분한다. `pass@k`의 여러 시도 중 한 번 성공과 `pass^k`의 모든 시도 성공은 다른 지표다. 소표본과 trial 간 비독립성의 한계를 함께 보고한다.
- **과정 준수:** 실제 검증 실행, 대상과 일치하는 리뷰, 권한 밖 도구 호출, 완료 주장과 결과의 일치.
- **복구:** 중단 후 이어가기 성공, 외부 쓰기 중복, 오래된 증거 재사용.
- **효율:** 시간, 비용, 모델·도구 호출, 실패·재시도, 리뷰 비용. 토큰 감소만으로 품질 개선이라고 부르지 않는다.

결과에는 시작/최종 리비전, fixture 버전, 모델/런타임 설정, 적용 정책, 실제 grader 결과를 남긴다. 원문 대화와 민감 입력은 기본 공개 산출물에 포함하지 않는다. 평가 도중의 trace는 실패 분석에 사용하고, 성공 판정은 독립적인 결과 검사에 둔다.

## 7. 수정 순서와 보류할 작업

### 단계 1 — 확인된 작은 결함

R1 보호 목록과 관련 테스트·fixture를 함께 수정한다. R2 PR 지침·템플릿·검사기를 하나의 계약으로 바꾼다. R3 읽기 제한을 고치고 경계 테스트를 추가한다. 세 작업은 서로 독립적인 변경 단위로 진행할 수 있으나 보안 정책 변경에는 해당 리뷰 절차를 적용한다. R12의 실제 GitHub 운영 설정은 날짜 때문에 병행 확인한다.

### 단계 2 — 피드백과 증거

R4 훅 인식·오류·doctor 검사, R6 검증 메타데이터, R7/R8 재개·리뷰·발행 지침을 보강한다. CLI 출력 변경은 기존 소비자를 확인한다. docs에 이미 있는 상태·권한 설명을 강화하고 별도 규칙 파일에 중복하지 않는다.

### 단계 3 — 측정 후 확장

R9의 작고 격리된 실제 에이전트 pilot을 실행한다. R10은 프로젝트 통합 테스트에 필요한 때만 추가한다. R11은 핵심 참조 존재 검사로 제한한다. 측정 결과가 필요성을 보여줄 때만 동시성 한도, 추가 리뷰, telemetry backend를 선택한다.

현재 도입할 근거가 부족한 것:

- Codex와 중복되는 Python 에이전트 루프·워커·heartbeat·영구 작업 엔진.
- 모든 작업의 다중 리뷰, 모든 T0/T1 작업의 task 파일, 고정된 대규모 역할 분리.
- 일반 명령의 자동 재시도나 외부 쓰기의 무조건 재시도.
- 원문 프롬프트와 비공개 추론 기록의 기본 수집.
- 검증 근거 없는 모델 고정·동시성 숫자 고정·새 보안 분류 모델.
- 기능 요구 없이 ADK, Agent Framework, smolagents로 런타임을 교체하는 작업.

이들을 영구히 금지하는 것은 아니다. 예를 들어 여러 머신과 외부 이벤트를 넘나드는 상시 서비스가 요구되면 durable 실행을, 실제 비용·품질 데이터가 나오면 동시성과 리뷰 라우팅을 다시 설계한다.

## 8. 수행한 확인과 남은 불확실성

같은 원격 커밋의 앞선 분석에서 `harness.py check --full`을 실행해 doctor, compileall, **172개 unittest와 30개 위험 fixture**가 통과했다. 이 후 코드 변경은 없었으며 이번 조사에서는 보호 경로 분류, 두 PR 본문 사례, 환경 변수 필터를 작은 입력으로 재확인했다. 172개 통과는 coverage 80%를 의미하지 않는다. coverage는 측정하지 않았다.

R3는 읽기 순서를 확인한 정적 결함이며 OOM을 실제 발생시키지 않았다. 실제 Codex 클라이언트의 훅 전달, 모든 도구 경로, 외부 GitHub CI 실행, 조직 정책, branch protection, 배포 권한은 확인하지 않았다. 실제 모델로 A/B 평가도 실행하지 않았다.

공식 자료 사이의 공통 방향은 작은 구조, 명확한 도구 계약, 권한 경계, 복구 상태, 실제 결과 평가다. 그렇다고 모든 회사가 동일한 구현을 요구하는 것은 아니다. 운영 사례·제품 문서·벤치마크를 서로 다른 종류의 근거로 읽어야 하며, 여기 제안한 최소 수정도 실제 프로젝트 요구와 회귀 테스트를 통해 확정해야 한다.

## 9. 공식 자료 목록 — 35개

문서의 날짜가 별도로 없으면 2026-10-12에 확인한 현재 문서라는 뜻이다. 제목은 식별용이며 본문을 장문 인용하지 않았다.

| ID | 기관·유형 | 자료 | 사용한 근거 |
|---|---|---|---|
| O1 | OpenAI · 운영 사례 · 2026-02-11 | [Harness engineering][O1] | 지식 지도와 기계적 불변식 |
| O2 | OpenAI · 운영 보안 · 2026-05-08 | [Running Codex safely][O2] | 격리·네트워크·신원·승인 |
| O3 | OpenAI · 작업 지침 · 2026-06-22 | [Long-running work][O3] | 검증 가능한 목표와 내구 상태 |
| O4 | OpenAI · 제품 문서 | [Codex hooks][O4] | 이벤트, 도구 범위, 실패의 한계 |
| O5 | OpenAI · 제품 문서 | [Config reference][O5] | 현재 지원 설정 |
| O6 | OpenAI · API 문서 | [Guardrails and approvals][O6] | 부작용 경계와 승인 재개 |
| O7 | OpenAI · 평가 문서 | [Agent evals][O7] | trace와 반복 평가 |
| A1 | Anthropic · 설계 글 · 2024-12-19 | [Building effective agents][A1] | 단순 구조와 workflow/agent 구분 |
| A2 | Anthropic · 운영 사례 · 2025-06-13 | [Multi-agent research system][A2] | 분리 가능한 조사와 협업 비용 |
| A3 | Anthropic · 도구 설계 · 2025-09-11 | [Writing tools for agents][A3] | 도구 계약·오류·평가 |
| A4 | Anthropic · 설계 글 · 2025-09-29 | [Context engineering][A4] | JIT 정보와 압축·외부 상태 |
| A5 | Anthropic · 보안 글 · 2025-10-20 | [Claude Code sandboxing][A5] | 파일과 네트워크 격리 |
| A6 | Anthropic · 운영 사례 · 2025-11-26 | [Long-running harnesses][A6] | 점진적 완료와 세션 복구 |
| A7 | Anthropic · 평가 글 · 2026-01-09 | [Demystifying evals][A7] | task/trial/결과 grader |
| A8 | Anthropic · 보안 글 · 2026-05-25 | [How we contain Claude][A8] | 모델 행동과 강제 격리 구분 |
| G1 | Google · ADK 문서 | [Session state][G1] | 상태 소유권과 변경 |
| G2 | Google · ADK 문서 | [Artifacts][G2] | 산출물 분리와 버전 |
| G3 | Google · ADK 문서 | [Evaluation][G3] | 최종 결과와 중간 행동 |
| G4 | Google · 연구 발표 · 2025 | [Secure AI agents][G4] | 제한된 권한과 관측 가능성 |
| G5 | Google · 연구 설명 · 2026-01-28 | [Scaling agent systems][G5] | 작업별 협업 효과의 차이 |
| M1 | Microsoft · 제품 문서 | [Agent harness][M1] | 실행 환경의 책임 구분 |
| M2 | Microsoft · 제품 문서 | [Checkpoints][M2] | 복구할 상태와 요청 |
| M3 | Microsoft · 제품 문서 | [Human-in-the-loop][M3] | 중단과 승인 재개 |
| M4 | Microsoft · 제품 문서 | [Observability][M4] | 실행 메타데이터와 민감 내용 보호 |
| M5 | Microsoft · 제품 문서 | [Evaluation][M5] | 반복 가능한 품질 평가 |
| T1 | Meta · 보안 지침 · 2025-10-31 | [Practical agent security][T1] | Rule of Two와 권한 조합 |
| T2 | Meta · 연구 발표 · 2025-09-22 | [ARE/Gaia2][T2] | 동적 작업과 평가 한계 |
| T3 | Meta · 연구 도구 문서 | [ARE benchmarking][T3] | 실행 흔적과 결과 검사 |
| T4 | Meta · 연구 발표 · 2025-04-29 | [LlamaFirewall][T4] | 다층 방어의 구성과 한계 |
| H1 | Hugging Face · 제품 소개 · 2024-12-31 | [smolagents][H1] | 작은 실행 구조 |
| H2 | Hugging Face · 설계 문서 | [Building good agents][H2] | 필요한 모델 호출과 도구 피드백 |
| H3 | Hugging Face · 보안 문서 | [Secure code execution][H3] | 생성 코드의 실행 격리 |
| H4 | Hugging Face · 관측 문서 | [Inspect runs][H4] | 단계별 실행 관찰 |
| H5 | Hugging Face · 도구 문서 | [Tools][H5] | 스키마와 실행 권한의 구분 |
| X1 | GitHub · 보안 문서 | [Secure pull_request_target][X1] | 신뢰 경계와 2026-11-02 정책 |

[O1]: https://openai.com/index/harness-engineering/
[O2]: https://openai.com/index/running-codex-safely/
[O3]: https://openai.com/index/codex-maxxing-long-running-work/
[O4]: https://developers.openai.com/codex/hooks
[O5]: https://developers.openai.com/codex/config-reference
[O6]: https://developers.openai.com/api/docs/guides/agents/guardrails-approvals
[O7]: https://developers.openai.com/api/docs/guides/agent-evals
[A1]: https://www.anthropic.com/engineering/building-effective-agents
[A2]: https://www.anthropic.com/engineering/multi-agent-research-system
[A3]: https://www.anthropic.com/engineering/writing-tools-for-agents
[A4]: https://www.anthropic.com/engineering/effective-context-engineering-for-ai-agents
[A5]: https://www.anthropic.com/engineering/claude-code-sandboxing
[A6]: https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents
[A7]: https://www.anthropic.com/engineering/demystifying-evals-for-ai-agents
[A8]: https://www.anthropic.com/engineering/how-we-contain-claude
[G1]: https://github.com/google/adk-docs/blob/main/docs/sessions/state.md
[G2]: https://github.com/google/adk-docs/blob/main/docs/artifacts/index.md
[G3]: https://github.com/google/adk-docs/blob/main/docs/evaluate/index.md
[G4]: https://research.google/pubs/an-introduction-to-googles-approach-for-secure-ai-agents/
[G5]: https://research.google/blog/towards-a-science-of-scaling-agent-systems-when-and-why-agent-systems-work/
[M1]: https://learn.microsoft.com/en-us/agent-framework/concepts/harness
[M2]: https://learn.microsoft.com/en-us/agent-framework/workflows/checkpoints
[M3]: https://learn.microsoft.com/en-us/agent-framework/workflows/human-in-the-loop
[M4]: https://learn.microsoft.com/en-us/agent-framework/agents/observability
[M5]: https://learn.microsoft.com/en-us/agent-framework/agents/evaluation
[T1]: https://ai.meta.com/blog/practical-ai-agent-security/
[T2]: https://ai.meta.com/research/publications/are-scaling-up-agent-environments-and-evaluations/
[T3]: https://facebookresearch.github.io/meta-agents-research-environments/user_guide/benchmarking.html
[T4]: https://ai.meta.com/research/publications/llamafirewall-an-open-source-guardrail-system-for-building-secure-ai-agents/
[H1]: https://huggingface.co/blog/smolagents
[H2]: https://huggingface.co/docs/smolagents/tutorials/building_good_agents
[H3]: https://huggingface.co/docs/smolagents/tutorials/secure_code_execution
[H4]: https://huggingface.co/docs/smolagents/tutorials/inspect_runs
[H5]: https://huggingface.co/docs/smolagents/tutorials/tools
[X1]: https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target
[repo-architecture]: https://github.com/nameplz/harness-skeleton/blob/6656c50cf36324b13093a3b5f6a535f2c45d3da2/docs/ARCHITECTURE.md#L3
[repo-policy]: https://github.com/nameplz/harness-skeleton/blob/6656c50cf36324b13093a3b5f6a535f2c45d3da2/scripts/check_ci_security.py#L19
[repo-risk]: https://github.com/nameplz/harness-skeleton/blob/6656c50cf36324b13093a3b5f6a535f2c45d3da2/scripts/harness_risk.py#L22
[repo-risk-read]: https://github.com/nameplz/harness-skeleton/blob/6656c50cf36324b13093a3b5f6a535f2c45d3da2/scripts/harness_risk.py#L401
[repo-pr-skill]: https://github.com/nameplz/harness-skeleton/blob/6656c50cf36324b13093a3b5f6a535f2c45d3da2/.agents/skills/pr-workflow/SKILL.md#L22
[repo-pr-check]: https://github.com/nameplz/harness-skeleton/blob/6656c50cf36324b13093a3b5f6a535f2c45d3da2/scripts/check_pr_contract.py#L12
[repo-hook]: https://github.com/nameplz/harness-skeleton/blob/6656c50cf36324b13093a3b5f6a535f2c45d3da2/.codex/hooks/harness_hook.py#L138
[repo-doctor]: https://github.com/nameplz/harness-skeleton/blob/6656c50cf36324b13093a3b5f6a535f2c45d3da2/scripts/harness.py#L624
[repo-runner]: https://github.com/nameplz/harness-skeleton/blob/6656c50cf36324b13093a3b5f6a535f2c45d3da2/scripts/command_runner.py#L139
[repo-checks]: https://github.com/nameplz/harness-skeleton/blob/6656c50cf36324b13093a3b5f6a535f2c45d3da2/scripts/harness.py#L502
[repo-harness-skill]: https://github.com/nameplz/harness-skeleton/blob/6656c50cf36324b13093a3b5f6a535f2c45d3da2/.agents/skills/harness/SKILL.md#L29
[repo-eval]: https://github.com/nameplz/harness-skeleton/blob/6656c50cf36324b13093a3b5f6a535f2c45d3da2/scripts/eval_harness.py#L99
