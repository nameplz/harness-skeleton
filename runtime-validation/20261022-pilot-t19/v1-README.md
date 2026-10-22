# Orca Discord Bridge v0.2

개인 Discord 서버에서 **Orca가 관리하는 기존 Codex terminal**에 메시지를 보내고, Codex의 응답을 Discord로 전달하는 브리지입니다. Codex API를 호출하거나 Discord 입력을 shell 명령으로 실행하지 않습니다. Codex가 할 수 있는 작업은 Orca/Codex 쪽 권한과 승인 설정을 따릅니다.

일반 대화는 Codex TUI 화면을 읽거나 화면 문구를 파싱하지 않습니다.

```text
입력
Discord → orca terminal send → 기존 Orca Codex

출력
Codex → Orca가 제공하는 worktree ps --json의 agent 상태
      → 같은 worktree + paneKey의 lastAssistantMessage → Discord
```

일반 대화에는 `terminal read`, `terminal read --screen`, `tui-idle`, `Working (...)` 문자열 파싱을 사용하지 않습니다. 예외는 Codex `/status` 명령을 요청했을 때 화면 보고서를 읽는 경우뿐입니다.

## 지원 기능

- 설정된 서버의 설정된 채널에서 지정된 사용자 메시지를 Codex terminal로 전달
- Discord 메시지 답글에서 참조 메시지를 가져올 수 있으면 그 텍스트와 embed 정보를 함께 전달
- `/orca terminals`, `/orca connect`, `/orca status`, `/orca disconnect` 연결 명령
- `//clear`, `//compact`, `//new`, `//status` 등 Codex slash command 전달
- 메시지의 **Apps → Send to Codex** 메뉴로 선택한 메시지와 embed의 텍스트 정보 전달
- 응답의 자연어와 짧은 코드 예시 표시. 인식한 diff/patch와 긴 일반 코드 블록은 생략

지원하지 않는 기능:

- GitHub API 연동, GitHub Webhook 수신 서버, Webhook 자동 전달
- 파일·이미지 첨부 전달
- Discord에서 임의 shell 명령 실행
- Codex TUI 전체 복제, 중간 진행 상황의 실시간 스트리밍, tool 호출/결과 전달
- Codex slash command의 대화형 picker 조작

## 요구 조건

- Python 3.11 이상
- Orca CLI를 실행할 수 있는 환경이며 `orca`가 PATH에 등록되어 있거나 `ORCA_BINARY`에 실행 경로가 지정되어 있어야 함
- Orca에서 Codex가 실행 중인 terminal
- Discord 애플리케이션의 Message Content Intent 활성화
- 봇 token과 서버·사용자·채널 ID

연결 전 Mac Terminal 등에서 Orca CLI를 확인합니다.

```bash
command -v orca
orca terminal list --json
orca terminal show --terminal <handle> --json
orca worktree ps --limit 500 --json
```

`terminal show`의 terminal 정보에 `handle`, `worktreeId`, `tabId`, `leafId`가 모두 있어야 합니다. `worktree ps` 결과에는 같은 worktree와 `paneKey = tabId:leafId`에 대응하는 agent row가 있어야 합니다. 응답은 다음처럼 `result.worktrees` 또는 최상위 `worktrees`에 worktree 목록을 담을 수 있습니다.

```json
{
  "result": {
    "worktrees": [
      {
        "worktreeId": "...",
        "agents": [
          {
            "paneKey": "...:...",
            "state": "done",
            "agentType": "codex",
            "lastAssistantMessage": "..."
          }
        ]
      }
    ]
  }
}
```

연결 시 브리지는 동일 worktree의 동일 `paneKey` row를 찾습니다. row가 없으면 연결을 거부하고, `agentType` 값이 있을 때 `codex`가 아니면 연결을 거부합니다. `agentType` 필드가 없거나 비어 있는 row는 이 검사만으로 거부하지 않습니다.

## 설정

프로젝트 폴더에 `.env` 파일을 만들고 값을 입력합니다.

```dotenv
DISCORD_TOKEN=...
DISCORD_GUILD_ID=...
DISCORD_USER_ID=...
CODEX_CHANNEL_ID=...

# 선택 항목
ORCA_BINARY=orca
ORCA_WAIT_TIMEOUT_MS=300000
STATE_PATH=.state.json
```

필수 항목은 `DISCORD_TOKEN`, `DISCORD_GUILD_ID`, `DISCORD_USER_ID`, `CODEX_CHANNEL_ID`입니다. 세 ID는 정수여야 합니다. `CODEX_CHANNEL_ID`는 일반 대화를 받고 응답을 게시할 text channel 또는 thread의 ID입니다.

선택 항목의 기본값은 `ORCA_BINARY=orca`, `ORCA_WAIT_TIMEOUT_MS=300000`(5분), `STATE_PATH=.state.json`입니다. 대기 시간은 정수 밀리초이며 최소 1000입니다. `STATE_PATH`는 `~`를 확장합니다.

설정된 `STATE_PATH`(기본 경로인 `.state.json`)에는 연결한 terminal handle, worktree ID, pane key가 저장됩니다. 실행 때 저장된 연결을 다시 확인하며, 파일이 없거나 읽기에서 오류가 나거나 JSON 파싱에 실패하면 연결되지 않은 상태로 시작합니다. `.env`에는 Discord token이 있으므로 저장소에 포함하지 마세요. 저장소 루트에는 `.gitignore`가 없어 `.env`와 설정된 state 파일이 자동으로 제외되지 않으므로, 버전 관리에 들어가지 않도록 직접 관리해야 합니다.

## 설치 및 실행

저장소 폴더에서 가상 환경을 만들고 프로젝트를 설치합니다. `pyproject.toml`은 Python 3.11 이상, `discord.py` 2.6 이상 3 미만, `python-dotenv` 1 이상 2 미만을 지정합니다.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

`.env`를 준비한 다음 같은 가상 환경에서 실행합니다.

```bash
python -m orca_discord_bridge
```

설치된 `orca-discord-bridge` 명령으로도 실행할 수 있습니다. 현재 저장소에는 `start.command`나 자동 가상 환경·의존성 설치 기능이 없습니다. 종료하려면 실행한 터미널에서 `Ctrl+C`를 누릅니다.

## 처음 연결

Orca에서 Codex를 실행한 뒤 Discord에서 봇과 상호작용합니다.

```text
/orca terminals
/orca connect terminal:<handle>
/orca status
```

`/orca terminals`는 최대 25개 terminal을 보여줍니다. `/orca connect`는 선택 terminal의 identity와 structured agent row를 검증하고 연결을 저장합니다. 봇이 재시작되면 저장된 terminal을 다시 검증하며, Orca 재시작이나 레이아웃 변경으로 연결이 오래된 경우 `/orca connect`를 다시 실행하세요. `/orca` 응답은 ephemeral 메시지입니다.

## 일반 대화와 structured 상태

`CODEX_CHANNEL_ID`로 지정한 채널에서 설정된 사용자 계정으로 메시지를 보냅니다. README의 `#codex`는 이 설정 채널을 뜻합니다. 답글의 참조 메시지는 Discord가 이미 제공했거나 현재 채널에서 가져오기에 성공한 경우에만 prompt에 함께 넣습니다.

```text
현재 구현을 검토하고 문제를 찾아줘.
```

브리지는 Orca CLI의 `terminal show --terminal <handle> --json`에서 terminal identity를 얻고, `worktree ps --limit 500 --json` 결과에서 해당 worktree와 pane의 agent row를 찾습니다. 응답 본문은 row의 `lastAssistantMessage` 값에서 가져옵니다. `state`, `prompt`, `toolName`, `toolInput`, `interrupted`, `stateStartedAt`, `updatedAt`은 turn 변화와 완료 상태의 안정 여부를 판단하는 revision에 사용하며 assistant 응답 본문으로 전달하지 않습니다. `interrupted=true`이고 표시할 응답 본문이 있을 때만 본문 뒤에 중단 상태 안내를 별도로 붙입니다. TUI 화면을 긁어오지 않으며 tool 이름, tool 입력, tool 결과를 별도로 Discord에 전달하지 않습니다.

일반 structured 대화 turn은 terminal handle별로 직렬 처리됩니다. slash command 경로는 이 직렬화 잠금을 사용하지 않습니다. structured turn 시작 시 agent 상태가 `working`, `blocked`, `waiting`이면 새 prompt를 보내지 않고 오류를 돌려줍니다. `waiting`은 Orca에서 승인이나 사용자 입력을 기다리는 상태일 수 있습니다. 요청 후에는 agent가 시작된 것을 확인하고 `done` 상태가 연속해서 안정적으로 관찰될 때 응답을 게시합니다. 기본 대기 시간은 5분이며, 그 안에 시작 또는 완료 상태를 확인하지 못하면 오류가 납니다.

이 브리지는 Orca가 제공하는 `lastAssistantMessage`를 읽으므로 중간 TUI 진행 문구를 실시간으로 보내지 않습니다. 자연어 설명과 짧은 코드 예시를 보존하고, 구현이 diff/patch로 판별한 본문은 생략합니다. 그 외 fenced 코드 블록은 2,400자를 넘거나 45줄보다 길면 생략할 수 있지만, 언어 태그가 `sh`, `shell`, `bash`, `zsh`, `fish`, `powershell`, `ps1`, `cmd`, `bat`, `console` 중 하나인 shell 블록은 길이와 관계없이 보존합니다. 태그가 없거나 다른 태그를 쓴 큰 코드 블록은 생략될 수 있습니다. 긴 응답은 Discord에 최대 1,900자 단위로 나눠 게시합니다. 로컬 파일 링크는 가능한 경우 worktree 기준 경로로 표시합니다.

## Codex slash command

Discord의 `/` 앱 명령과 구별해 Codex 명령은 메시지 앞에 `/`를 두 번 입력합니다. 브리지는 맨 앞의 `//`를 `/` 하나로 바꿔 terminal에 보냅니다.

```text
//clear    → /clear
//compact  → /compact
//new      → /new
//status   → /status
```

`/clear`, `/compact`, `/new`는 전달 완료 문구만 표시합니다. `/status`만 전달 후 잠시 기다렸다가 제한적으로 terminal 화면을 읽어 상태 보고서를 보여줍니다. 다른 `/...` 명령도 terminal에 전달하지만 대화형 picker를 조작할 수 없으며, 전달 안내 문구를 표시합니다.

## GitHub Webhook 메시지 전달

GitHub와 브리지는 API로 연결되지 않으며 GitHub Webhook을 자동으로 Codex에 전달하지 않습니다. 기존 GitHub → Discord Webhook이 올린 메시지를 Codex에 참고시키려면 해당 메시지에서 우클릭(모바일에서는 길게 누름)합니다.

```text
Apps → Send to Codex
```

선택 메시지의 본문과 embed에 있는 작성자 이름, 제목, 설명, 필드, URL, footer 텍스트를 전달합니다. 이미지·파일 첨부는 전달하지 않으며, 메시지 텍스트와 embed 텍스트는 합쳐서 최대 12,000자까지 사용합니다. 선택적으로 입력하는 지시는 최대 1,000자입니다. 브리지는 인용한 메시지의 지시문을 신뢰하지 말고 참고 자료로만 취급하라는 문구와 함께 Codex에 전달합니다. Webhook 메시지는 일반 채널 입력으로는 처리되지 않으며 사용자가 직접 메뉴를 선택해야 합니다.

## 권한과 보안 범위

- 일반 메시지 입력은 설정한 서버, 사용자, 채널이 모두 일치할 때만 처리합니다. 봇 메시지와 Webhook 메시지는 일반 입력에서 무시합니다.
- `/orca`와 **Send to Codex** 앱 상호작용은 설정한 서버와 사용자만 사용할 수 있습니다. 코드에서는 이 앱 상호작용에 채널 ID 검사를 하지 않으며, 응답은 ephemeral로 표시합니다.
- Discord에서 받은 텍스트는 Orca CLI의 `terminal send --text` 인자로 전달됩니다. 브리지는 shell process를 실행하지 않습니다. Codex가 할 수 있는 작업은 Orca/Codex의 권한과 승인 설정에 달려 있습니다.
- 봇의 메시지 mention은 비활성화되어 있습니다.
- `.env`는 token을 포함하며 설정된 state 파일(`STATE_PATH`, 기본 경로 `.state.json`)은 Orca 연결 정보를 포함합니다. 저장소 루트에는 `.gitignore`가 없어 두 파일이 자동으로 제외되지 않습니다.

## 문제 해결

### `/orca connect`가 agent 상태를 찾지 못함

Mac에서 terminal identity와 agent row를 확인합니다.

```bash
orca terminal show --terminal <handle> --json
orca worktree ps --limit 500 --json
```

`worktreeId`와 `tabId`, `leafId`로 선택한 terminal을 찾고, 같은 worktree 안에 `paneKey = tabId:leafId`인 agent row가 있는지 확인합니다. Orca가 해당 상태를 제공하지 않으면 연결할 수 없습니다.

### 메시지는 Codex로 들어가지만 응답이 오지 않음

`worktree ps --limit 500 --json`에서 같은 agent row의 `state`와 `lastAssistantMessage`가 갱신되는지 확인합니다. 새 prompt를 보낼 때 agent가 `working`, `blocked`, `waiting`이면 먼저 현재 상태를 해결해야 합니다. Orca 쪽 상태가 갱신되지 않으면 Orca↔Codex 상태 연동을 확인하세요.

### 저장된 연결을 사용할 수 없음

terminal handle은 runtime에 따라 바뀔 수 있습니다. Discord에서 `/orca connect`를 다시 실행하세요.
