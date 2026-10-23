from __future__ import annotations

import re
from pathlib import Path

root = Path.cwd()
readme = (root / 'README.md').read_text(encoding='utf-8')
text = re.sub(r'\s+', ' ', readme).casefold()
config = (root / 'src/orca_discord_bridge/config.py').read_text(encoding='utf-8')
bot = (root / 'src/orca_discord_bridge/bot.py').read_text(encoding='utf-8')
orca = (root / 'src/orca_discord_bridge/orca.py').read_text(encoding='utf-8')
pyproject = (root / 'pyproject.toml').read_text(encoding='utf-8')

checks = {}
def record(name: str, value: bool) -> None:
    checks[name] = bool(value)

record('supported_setup', ('python -m venv .venv' in text or 'python3 -m venv .venv' in text) and
    all(token.casefold() in text for token in (
    'source .venv/bin/activate', 'python -m pip install -e .',
    'orca-discord-bridge', 'python 3.11', 'macos')) and
    'orca-discord-bridge' in pyproject and
    'start.command' in text and '포함되어 있지 않습니다' in text and
    not re.search(r'(?m)^\s*(?:\./)?start\.command\b', readme))

required_env = ('DISCORD_TOKEN', 'DISCORD_GUILD_ID', 'DISCORD_USER_ID', 'CODEX_CHANNEL_ID')
record('environment_and_defaults', all(name in readme for name in required_env) and
    'ORCA_BINARY=orca' in readme and 'ORCA_WAIT_TIMEOUT_MS=300000' in readme and
    'STATE_PATH=.state.json' in readme and ('1000ms' in text or '1,000ms' in text) and
    ('~' in readme or '홈 디렉터리' in readme) and '.env' in readme and
    'load_dotenv' in config and '300000' in config and 'expanduser' in config)

record('structured_agent_state', all(token.casefold() in text for token in (
    'worktreeid', 'tabid', 'leafid', 'panekey', 'lastassistantmessage', 'toolname', 'toolinput', 'worktree ps')) and
    ('같은 worktree' in text or '동일 worktree' in text) and
    'state' in text and 'tui 화면' in text and ('fallback' in text or '읽지 않습니다' in text) and
    'assistant' in text and ('tool result' in text or 'tool result' in orca.casefold()))

record('authorization_scope_and_limits', all(name in readme for name in required_env[1:]) and
    'CODEX_CHANNEL_ID' in readme and ('제한되지 않습니다' in text or 'not restricted' in text) and
    bool(re.search(r'(?i)(?:\bos\b|\bvm\b).{0,24}(?:sandbox|격리)|(?:sandbox|격리).{0,24}(?:\bos\b|\bvm\b)', readme)) is False and
    'guild_id' in bot and 'user_id' in bot)

record('github_boundary', 'github api' in text and '수신 서버' in text and 'webhook' in text and
    '자동' in text and ('직접 선택' in text or 'manual' in text))

record('slash_semantics', all(command in readme for command in ('//clear', '//compact', '//new', '//status')) and
    'terminal read --screen' in text and '/status' in readme and
    ('유일한' in text or 'only' in text or '/status`만' in text) and 'screen' in text and
    ('일반 대화' in text or 'normal prompts' in text) and
    ('slash' in bot.casefold() or 'status' in bot.casefold()))

failed = [name for name, passed in checks.items() if not passed]
print({'checks': checks, 'failed': failed})
raise SystemExit(bool(failed))
