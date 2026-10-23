import asyncio
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock

from orca_discord_bridge import bot as bot_module
from orca_discord_bridge import config

checks = {}

def record(name, value):
    checks[name] = bool(value)

class Typing:
    async def __aenter__(self):
        return None
    async def __aexit__(self, *args):
        return False

def interaction(bot, *, guild=1, user=7, roles=()):
    return NS(
        client=bot,
        guild_id=guild,
        user=NS(id=user, roles=[NS(id=value) for value in roles]),
        response=NS(send_message=AsyncMock(), defer=AsyncMock(), send_modal=AsyncMock()),
        followup=NS(send=AsyncMock()),
    )

def message(*, guild=1, user=7, roles=()):
    return NS(
        author=NS(id=user, bot=False, roles=[NS(id=value) for value in roles]),
        webhook_id=None,
        guild=None if guild is None else NS(id=guild),
        channel=NS(id=3, typing=Typing),
        content='owned synthetic prompt',
        embeds=[],
        reference=None,
        id=101,
    )

async def main():
    with TemporaryDirectory() as temp:
        os.environ.update({
            'DISCORD_TOKEN': 'OWNED_SYNTHETIC_TOKEN',
            'DISCORD_GUILD_ID': '1',
            'DISCORD_USER_ID': '2',
            'DISCORD_ROLE_IDS': '40, 50',
            'CODEX_CHANNEL_ID': '3',
            'STATE_PATH': str(Path(temp) / 'state.json'),
            'ORCA_WAIT_TIMEOUT_MS': '1000',
        })
        settings = config.Settings.load()
        bot = bot_module.BridgeBot(settings)
        bot.orca = NS(list_terminals=AsyncMock(return_value=[]))

        allowed = interaction(bot, roles=(40,))
        await bot_module.terminals_command.callback(allowed)
        record('role_allowed_slash_command', bot.orca.list_terminals.await_count == 1 and allowed.response.defer.await_count == 1)

        denied_requests = [
            interaction(bot, user=7, roles=(99,)),
            interaction(bot, guild=9, user=7, roles=(40,)),
            interaction(bot, guild=None, user=7, roles=(40,)),
        ]
        for request in denied_requests:
            await bot_module.terminals_command.callback(request)
        record('wrong_role_guild_and_dm_denied_before_orca',
               all(request.response.send_message.await_count == 1 and request.response.defer.await_count == 0
                   for request in denied_requests) and bot.orca.list_terminals.await_count == 1)

        owner = interaction(bot, user=2)
        await bot_module.terminals_command.callback(owner)
        record('owner_compatibility', bot.orca.list_terminals.await_count == 2)

        bot.orca.list_terminals.reset_mock()
        role_choices = await bot_module.terminal_autocomplete(interaction(bot, roles=(50,)), '')
        denied_choices = await bot_module.terminal_autocomplete(interaction(bot, roles=(99,)), '')
        record('autocomplete_role_allow_and_denial',
               role_choices == [] and denied_choices == [] and bot.orca.list_terminals.await_count == 1)

        context_request = interaction(bot, roles=(40,))
        await bot_module.send_to_codex_context.callback(context_request, NS(content='source', embeds=[]))
        denied_context = interaction(bot, roles=(99,))
        await bot_module.send_to_codex_context.callback(denied_context, NS(content='source', embeds=[]))
        record('context_menu_authorization', context_request.response.send_modal.await_count == 1
               and denied_context.response.send_modal.await_count == 0)

        modal_call = context_request.response.send_modal.call_args
        modal = modal_call.args[0] if modal_call else None
        bot.store.connect('term', 'wt', 'tab:leaf')
        bot.forward_to_codex = AsyncMock()
        if modal is not None:
            modal.instruction._value = 'role-authorized instruction'
            await modal.on_submit(interaction(bot, roles=(40,)))
            await modal.on_submit(interaction(bot, roles=(99,)))
        record('modal_authorization_before_forward', modal is not None and bot.forward_to_codex.await_count == 1)

        bot.forward_to_codex.reset_mock()
        await bot.on_message(message(roles=(40,)))
        record('role_allowed_message_forward', bot.forward_to_codex.await_count == 1)
        bot.forward_to_codex.reset_mock()
        await bot.on_message(message(user=2))
        record('owner_message_compatibility', bot.forward_to_codex.await_count == 1)
        bot.forward_to_codex.reset_mock()
        for item in (message(roles=(99,)), message(guild=9, roles=(40,)), message(guild=None, roles=(40,))):
            await bot.on_message(item)
        record('unauthorized_messages_never_forward', bot.forward_to_codex.await_count == 0)
        await bot.close()

        os.environ['DISCORD_ROLE_IDS'] = ' '
        os.environ['STATE_PATH'] = str(Path(temp) / 'owner-only.json')
        owner_only = config.Settings.load()
        legacy_bot = bot_module.BridgeBot(owner_only)
        legacy_bot.orca = NS(list_terminals=AsyncMock(return_value=[]))
        denied_role = interaction(legacy_bot, roles=(40,))
        await bot_module.terminals_command.callback(denied_role)
        record('blank_role_list_preserves_owner_only',
               denied_role.response.send_message.await_count == 1 and legacy_bot.orca.list_terminals.await_count == 0)
        await legacy_bot.close()

        os.environ['DISCORD_ROLE_IDS'] = '40,invalid'
        invalid_rejected = False
        try:
            config.Settings.load()
        except config.ConfigError:
            invalid_rejected = True
        record('invalid_role_config_rejected', invalid_rejected)

    failed = [name for name, passed in checks.items() if not passed]
    print({'checks': checks, 'failed': failed})
    raise SystemExit(bool(failed))

asyncio.run(main())
