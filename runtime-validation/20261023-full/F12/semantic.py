import asyncio
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock
import discord
from orca_discord_bridge import bot as bot_module, config, orca

class Channel(bot_module.discord.TextChannel):
    def __init__(self): self.sent=[]
    async def send(self, value): self.sent.append(value)

def make_bot(tmp, initial):
    settings=config.Settings('synthetic-token',1,2,3,'fake-orca',1000,Path(tmp)/'state.json')
    bot=bot_module.BridgeBot(settings)
    bot.store.connect(initial.handle,initial.worktree_id,initial.pane_key)
    return bot

async def changed_case(field):
    with TemporaryDirectory() as tmp:
        initial=orca.TerminalBinding('saved-handle','old-worktree','old-tab','old-leaf')
        observed=orca.TerminalBinding('saved-handle',
            'new-worktree' if field=='worktree' else initial.worktree_id,
            'new-tab' if field=='pane' else initial.tab_id,
            'new-leaf' if field=='pane' else initial.leaf_id)
        validated=orca.TerminalBinding('saved-handle','validated-worktree','validated-tab','validated-leaf')
        bot=make_bot(tmp,initial)
        bot.orca=NS(
            resolve_binding=AsyncMock(return_value=observed),
            validate_codex_binding=AsyncMock(return_value=validated),
            exchange=AsyncMock(return_value=orca.ExchangeResult('forwarded output','done',False)))
        channel=Channel();bot.get_channel=lambda _:channel
        await bot.forward_to_codex('synthetic prompt',origin='host grader')
        bot.orca.resolve_binding.assert_awaited_once_with(initial.handle)
        bot.orca.validate_codex_binding.assert_awaited_once_with(initial.handle)
        bot.orca.exchange.assert_awaited_once_with(validated,'synthetic prompt')
        assert (bot.store.state.terminal_handle,bot.store.state.worktree_id,bot.store.state.pane_key)==(validated.handle,validated.worktree_id,validated.pane_key)
        assert channel.sent==['forwarded output']
        await bot.close()

async def unchanged_case():
    with TemporaryDirectory() as tmp:
        initial=orca.TerminalBinding('saved-handle','old-worktree','old-tab','old-leaf')
        bot=make_bot(tmp,initial)
        bot.orca=NS(
            resolve_binding=AsyncMock(return_value=initial),
            validate_codex_binding=AsyncMock(),
            exchange=AsyncMock(return_value=orca.ExchangeResult('forwarded output','done',False)))
        channel=Channel();bot.get_channel=lambda _:channel
        await bot.forward_to_codex('synthetic prompt',origin='host grader')
        bot.orca.resolve_binding.assert_awaited_once_with(initial.handle)
        bot.orca.validate_codex_binding.assert_not_awaited()
        bot.orca.exchange.assert_awaited_once_with(initial,'synthetic prompt')
        assert bot.store.state.pane_key==initial.pane_key and channel.sent==['forwarded output']
        await bot.close()

async def failed_case():
    with TemporaryDirectory() as tmp:
        initial=orca.TerminalBinding('saved-handle','old-worktree','old-tab','old-leaf')
        observed=orca.TerminalBinding('saved-handle','old-worktree','new-tab','new-leaf')
        bot=make_bot(tmp,initial)
        bot.orca=NS(
            resolve_binding=AsyncMock(return_value=observed),
            validate_codex_binding=AsyncMock(side_effect=orca.OrcaError('synthetic validation failure')),
            exchange=AsyncMock())
        channel=Channel();bot.get_channel=lambda _:channel
        try:
            await bot.forward_to_codex('synthetic prompt',origin='host grader')
        except orca.OrcaError:
            pass
        else:
            raise AssertionError('failed stale-binding validation must stop forwarding')
        bot.orca.validate_codex_binding.assert_awaited_once_with(initial.handle)
        bot.orca.exchange.assert_not_awaited()
        assert (bot.store.state.terminal_handle,bot.store.state.worktree_id,bot.store.state.pane_key)==(initial.handle,initial.worktree_id,initial.pane_key)
        assert channel.sent==[]
        await bot.close()

async def main():
    await changed_case('pane')
    await changed_case('worktree')
    await unchanged_case()
    await failed_case()

asyncio.run(main())
print('host semantic checks passed: pane/worktree drift revalidation, validated binding persistence/use, unchanged path, and fail-closed behavior')
