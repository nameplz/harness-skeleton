import asyncio
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock
from orca_discord_bridge import bot as bot_module, config, formatting, orca

FALLBACK='Codex 작업은 완료됐지만 Discord에 표시할 대화형 출력은 없습니다. (tool call·코드/diff 상세는 생략됩니다.)'
MARKER='_(Codex turn이 중단된 상태로 종료되었습니다.)_'
source=('첫 문단 with spaces, punctuation, and Unicode.\n'
        '  들여쓴 두 번째 줄과 빈 줄도 그대로 유지해야 합니다.\n\n')*160
clean=formatting.clean_terminal_output(source)
chunks=formatting.split_for_discord(clean)
assert len(chunks)>1
assert all(len(chunk)<=1900 for chunk in chunks)
assert ''.join(chunks)==clean, 'chunk boundaries changed cleaned prose'

async def forward(text, interrupted):
    class Channel(bot_module.discord.TextChannel):
        def __init__(self): self.sent=[]
        async def send(self,value): self.sent.append(value)
    with TemporaryDirectory() as tmp:
        settings=config.Settings('synthetic-token',1,2,3,'fake-orca',1000,Path(tmp)/'state.json')
        bot=bot_module.BridgeBot(settings)
        bot.store.connect('term','wt','tab:leaf')
        binding=orca.TerminalBinding('term','wt','tab','leaf')
        bot.orca=NS(resolve_binding=AsyncMock(return_value=binding),exchange=AsyncMock(return_value=orca.ExchangeResult(text,'done',interrupted)))
        channel=Channel();bot.get_channel=lambda _:channel
        await bot.forward_to_codex('synthetic prompt',origin='host grader')
        assert channel.sent and all(len(chunk)<=1900 for chunk in channel.sent)
        assert bot.orca.exchange.await_count==1
        await bot.close()
        return channel.sent

async def main():
    long_output=('paragraph words and punctuation survive every Discord boundary.\n')*120
    normal=await forward(long_output,False)
    assert ''.join(normal)==formatting.clean_terminal_output(long_output)
    interrupted=await forward(long_output,True)
    expected=formatting.clean_terminal_output(long_output)+'\n\n'+MARKER
    assert ''.join(interrupted)==expected
    assert MARKER in interrupted[-1]
    empty=await forward('',False)
    assert empty==[FALLBACK]

asyncio.run(main())
print('host semantic checks passed: <=1900 chars, lossless concatenation, interruption marker, empty fallback')
