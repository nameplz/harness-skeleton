# Orca Discord Bridge v0.2

개인 Discord 서버에서 Orca가 관리하는 기존 Codex terminal과 텍스트로 대화하기 위한 브리지입니다. Codex API를 별도로 호출하지 않습니다.

v0.2 일반 대화의 응답은 Codex TUI 화면을 읽어 추측하지 않고, Orca가 `worktree ps`로 제공하는 일치된 agent row의 `lastAssistantMessage`에서 가져옵니다.

```text
입력
Discord #codex → orca terminal send → 기존 Orca Codex terminal

출력
orca terminal show → worktreeId, tabId, leafId
orca worktree ps --limit 500 --json
  └─ 같은 worktreeId + paneKey(tabId:leafId)의 agent row
       ├─ state와 row 변경 정보 → turn 추적
       ├─ lastAssistantMessage → Discord 응답
       └─ toolName/toolInput → 응답 본문으로 사용하지 않음
```

일반 대화는 `terminal read`, `terminal read --screen`, TUI 화면 텍스트나 `Working (...)` 같은 상태 문구를 읽지 않습니다. Orca row의 structured `state` 필드는 turn 추적에 사용합니다. `/status` Codex slash command만 제한적으로 화면을 읽습니다.

## 지원 기능

- 지정한 서버·사용자·`CODEX_CHANNEL_ID`의 일반 메시지 → 연결된 Orca/Codex terminal
- 일치된 agent row의 `lastAssistantMessage` → Discord
- row의 `toolName`/`toolInput`을 응답 본문으로 전달하지 않음
- 일반 코드 예시와 shell 명령은 보존하고 unified diff/patch와 긴 비-shell 코드 블록은 축약
- `/orca terminals`, `/orca connect`, `/orca status`, `/orca disconnect`
- `//clear`, `//compact`, `//new` → Codex로 전달 후 전달 확인 표시
- `//status` → Codex `/status` 실행 후 제한된 TUI 상태 화면 표시
- Discord 메시지 우클릭 → **Apps → Send to Codex**로 수동 전달
- `#codex` 메시지에 답글을 달면 인용 메시지의 텍스트/embed도 함께 전달

이 브리지는 GitHub API를 호출하거나 GitHub Webhook 수신 서버를 제공하지 않습니다. Discord webhook 메시지도 자동으로 Codex에 전달하지 않습니다.

의도적으로 지원하지 않는 기능:

- 파일·이미지 첨부 전달
- Discord 입력을 브리지의 shell 명령으로 직접 실행
- Codex TUI 전체 복제 또는 대화형 slash-command picker 조작
- tool call 세부 정보나 unified diff 전문을 Discord에 출력

## 요구 조건

- macOS와 Python 3.11 이상
- Orca CLI 실행 파일: 기본값 `orca`를 쓰면 PATH에 있어야 함. 다른 위치라면 `ORCA_BINARY`로 지정
- Orca terminal에서 Codex가 실행 중이고, Orca `worktree ps`가 그 pane의 agent row를 제공해야 함
- Discord Bot의 Message Content Intent 활성화

Mac Terminal에서 Orca CLI와 agent row를 확인합니다.

```bash
command -v orca
orca status --json
orca terminal list --json
orca worktree ps --limit 500 --json
```

연결할 terminal의 `orca terminal show` 결과에는 `worktreeId`, `tabId`, `leafId`가 있어야 합니다. 브리지는 `paneKey = tabId:leafId`를 만들고, `worktree ps` 결과에서 같은 worktree와 pane key의 row만 찾습니다. row가 없으면 연결을 거부합니다. `agentType` 값이 있으면 `codex`인지 확인하지만, 필드가 없거나 빈 값인 row는 거부하지 않습니다.

## Discord 설정

프로젝트 루트의 `.env` 파일에 값을 지정합니다.

```dotenv
DISCORD_TOKEN=...
DISCORD_GUILD_ID=...
DISCORD_USER_ID=...
CODEX_CHANNEL_ID=...
ORCA_BINARY=orca
ORCA_WAIT_TIMEOUT_MS=300000
STATE_PATH=.state.json
```

필수 값은 `DISCORD_TOKEN`, `DISCORD_GUILD_ID`, `DISCORD_USER_ID`, `CODEX_CHANNEL_ID`입니다. ID 값은 정수여야 합니다. 선택 값의 기본값은 `ORCA_BINARY=orca`, `ORCA_WAIT_TIMEOUT_MS=300000`(밀리초), `STATE_PATH=.state.json`입니다. 제한 시간은 1,000ms 이상이어야 합니다. `STATE_PATH`의 `~`는 홈 디렉터리로 확장되고, 상대 경로는 실행 당시 작업 디렉터리를 기준으로 합니다.

Discord Developer Portal에서 Message Content Intent를 켜야 일반 메시지 내용을 받을 수 있습니다.

## 설치 및 실행

현재 snapshot에는 Finder에서 실행하는 `start.command`가 포함되어 있지 않습니다. 프로젝트 루트에서 가상 환경을 만들고 패키지를 설치한 뒤 실행합니다.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
orca-discord-bridge
```

`pyproject.toml`의 콘솔 명령 `orca-discord-bridge`가 봇을 시작합니다. 프로젝트 루트에서 실행하면 루트의 `.env`와 기본 `.state.json`을 사용합니다. 종료는 `Ctrl+C`입니다.

## 처음 연결

Orca에서 Codex를 실행한 뒤 허용된 사용자가 Discord에서 다음을 실행합니다.

```text
/orca terminals
/orca connect
```

`/orca connect`의 `terminal` 항목에서 autocomplete 목록을 고릅니다. 연결 시 브리지는 해당 terminal의 identity와 일치하는 structured agent row를 찾아 저장합니다. `agentType`이 명시되어 있고 `codex`가 아니면 연결을 거부합니다.

연결 상태는 `/orca status`로 확인하고, 연결을 지우려면 `/orca disconnect`를 사용합니다. 상태 파일에는 `terminal_handle`, `worktree_id`, `pane_key`만 저장합니다. 현재 agent state나 대화 기록은 저장하지 않습니다. 봇 재시작 시 저장된 terminal을 다시 검증하고, stale 상태면 `/orca connect`를 다시 실행해야 합니다.

## 일반 대화

지정된 `CODEX_CHANNEL_ID`에서 메시지를 보냅니다.

```text
현재 구현을 검토하고 문제를 찾아줘.
```

Codex가 이미 `working`, `waiting`, `blocked`이면 새 prompt를 보내지 않고 오류를 반환합니다. 새 대화는 기존 row의 revision과 assistant 메시지를 기준으로 시작을 확인하고, 바뀐 `lastAssistantMessage`를 수집합니다. 매우 짧은 turn은 `working` 상태를 관찰하지 않고 곧바로 새 `done` row와 메시지로 나타나도 시작으로 인정합니다. 응답을 반환하기 전에는 같은 revision의 `done` 상태를 연속 두 번 확인합니다.

브리지는 `ORCA_WAIT_TIMEOUT_MS`까지 상태를 기다립니다. 시작 상태를 관찰하지 못하거나 제한 시간에 완료되지 않으면 오류를 반환합니다. `waiting` 상태가 계속되면 Orca에서 필요한 사용자 입력이나 승인을 처리한 뒤 다시 확인해야 합니다. 일반 대화 경로는 TUI 화면을 fallback으로 읽지 않습니다.

## Discord에 표시되는 내용

응답 원문은 일치된 row에서 수집한 `lastAssistantMessage`입니다. `toolName`과 `toolInput`은 turn 변경 감지용 revision에 포함되지만, 별도 응답 텍스트로 출력하지 않습니다. 브리지는 tool result를 별도 수집하지 않습니다. 따라서 assistant 메시지 자체에 포함된 내용까지 제거한다고 보장하지는 않습니다.

표시 필터는 다음과 같이 동작합니다.

- 짧은 fenced code 예시와 shell 명령은 유지
- unified diff/patch 본문은 축약
- 2,400자 초과 또는 45줄 초과인 fenced non-shell 코드 블록은 축약
- 로컬 파일 Markdown 링크는 label과 경로 텍스트로 정규화하고, 일반 HTTP(S) 링크는 유지
- Discord 메시지 길이에 맞춰 최대 1,900자 조각으로 나눠 전송

필터링 후 표시할 assistant 내용이 없으면 완료되었지만 대화형 출력이 없다는 안내를 보냅니다. 응답 시점과 내용은 Orca가 해당 row에 제공한 상태 및 `lastAssistantMessage` 갱신에 의존합니다. TUI의 모든 진행 표시나 중간 상태를 스트리밍하지 않습니다.

## Codex slash command

Discord 메시지로 Codex slash command를 보낼 때는 앞에 `/`를 하나 더 붙입니다.

```text
//clear    → /clear
//compact  → /compact
//new      → /new
//status   → /status
```

`/clear`, `/compact`, `/new`는 terminal에 전달한 뒤 전달 확인만 표시합니다. `/status`만 전달 후 짧게 기다렸다가 `terminal read --screen` 결과를 읽고 일부 prompt/UI 줄을 제외해 표시합니다. 그 밖의 Codex slash command도 terminal에 전달되지만, 일반적으로 실제 명령 결과는 읽지 않고 전달 안내를 표시합니다. 대화형 picker는 Discord에서 조작할 수 없습니다.

## GitHub Webhook 메시지 전달

GitHub → Discord Webhook 설정은 별도로 유지합니다. 브리지는 webhook 메시지를 자동 처리하지 않습니다. 허용된 사용자가 메시지를 우클릭(모바일에서는 길게 누름)한 뒤 직접 선택합니다.

```text
Apps → Send to Codex
```

선택된 Discord 메시지의 본문과 embed의 author/title/description/fields/URL/footer 텍스트를 참고 데이터로 전달합니다. 내용은 최대 12,000자이며, 선택 입력은 최대 1,000자입니다. 첨부 파일이나 이미지 자체는 전달하지 않습니다. 메시지 안의 지시를 참고 데이터로 취급하라는 안내를 Codex prompt에 넣지만, 이는 브리지에서 강제하는 보안 경계가 아닙니다.

## 문제 해결

### `/orca connect`가 structured agent 상태를 찾지 못함

Mac에서 선택한 handle의 terminal identity와 agent row를 확인합니다.

```bash
orca terminal show --terminal <handle> --json
orca worktree ps --limit 500 --json
```

`terminal show`의 `worktreeId`, `tabId`, `leafId`로 `paneKey = tabId:leafId`를 계산하고, `worktree ps`에서 같은 `worktreeId`와 `paneKey`의 row가 있는지 확인합니다. `agentType`이 존재한다면 값이 `codex`인지 확인합니다.

### 메시지는 Codex로 들어가지만 응답 상태가 갱신되지 않음

이 버전은 일반 대화에서 TUI 화면을 fallback으로 읽지 않습니다. Orca `worktree ps`의 같은 row에서 revision/state와 `lastAssistantMessage`가 갱신되는지 확인합니다. Orca가 값을 제공하지 않으면 브리지에서 응답을 만들 수 없습니다.

### Orca를 재시작함

Terminal handle은 runtime-scoped일 수 있습니다. `/orca status`에서 연결 상태를 확인하고 stale이면 `/orca connect`를 다시 실행하세요.

## 보안 범위

- `/orca` 명령과 `Send to Codex` context menu는 설정한 guild에만 등록되고, 설정한 guild ID와 user ID를 검사합니다.
- 일반 메시지 전달은 설정한 guild ID, user ID, `CODEX_CHANNEL_ID`가 모두 일치할 때만 처리합니다. 다른 사용자, bot author, webhook 메시지는 일반 메시지 경로에서 무시합니다.
- slash command와 context menu는 `CODEX_CHANNEL_ID`로 제한되지 않습니다. 허용된 사용자는 해당 guild의 다른 채널에서도 사용할 수 있습니다. Codex 응답은 `CODEX_CHANNEL_ID`로 보냅니다.
- 브리지는 Discord 내용을 로컬 shell command로 실행하지 않고 Orca CLI를 인자 분리된 subprocess로 호출합니다. 하지만 일반 prompt와 Codex slash command는 연결된 Codex terminal로 전달되며, 그 세션에서 Codex가 가진 도구와 권한은 별도로 제한하지 않습니다.
- 봇의 발신 메시지에는 Discord mention 해석을 비활성화합니다.
- 이 snapshot에는 프로젝트 `.gitignore`가 없어 `.env`와 `.state.json`을 제외하는 repo 규칙이 없습니다. 토큰을 담은 `.env`와 연결 정보를 담은 state 파일을 저장소에 추가하지 마세요.
