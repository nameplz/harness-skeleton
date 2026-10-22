import asyncio
from contextlib import asynccontextmanager
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock

import discord
from orca_discord_bridge import bot as bot_module, config, orca


def load_settings(path, channels="4, 5, 4"):
    config.load_dotenv = lambda: None
    os.environ.update({
        "DISCORD_TOKEN": "SYNTHETIC_TOKEN",
        "DISCORD_GUILD_ID": "1",
        "DISCORD_USER_ID": "2",
        "CODEX_CHANNEL_ID": "3",
        "ORCA_WAIT_TIMEOUT_MS": "1000",
        "STATE_PATH": str(path),
    })
    if channels is None:
        os.environ.pop("CODEX_CHANNEL_IDS", None)
    else:
        os.environ["CODEX_CHANNEL_IDS"] = channels
    return config.Settings.load()


@asynccontextmanager
async def typing():
    yield


def message(channel_id, message_id):
    return NS(
        author=NS(id=2, bot=False), webhook_id=None, guild=NS(id=1),
        channel=NS(id=channel_id, typing=typing), content=f"channel {channel_id}",
        reference=None, id=message_id,
    )


async def main():
    results = {}

    def record(name, passed, detail):
        results[name] = {"status": "pass" if passed else "fail", "detail": detail}

    with tempfile.TemporaryDirectory() as temp:
        state = Path(temp) / "state.json"
        settings = load_settings(state)
        bot = bot_module.BridgeBot(settings)
        bot.store.connect("term", "wt", "tab:leaf")
        bot.forward_to_codex = AsyncMock()
        try:
            for channel_id, message_id in ((3, 1), (4, 2), (5, 3)):
                await bot.on_message(message(channel_id, message_id))
            await bot.on_message(message(6, 4))
            expected = [
                ("channel 3", "Discord message 1"),
                ("channel 4", "Discord message 2"),
                ("channel 5", "Discord message 3"),
            ]
            observed = [
                (call.args[0], call.kwargs["origin"])
                for call in bot.forward_to_codex.await_args_list
            ]
            record(
                "multiple_input_channels",
                observed == expected,
                "legacy primary and comma-listed extra channels forward once; unlisted channel is ignored",
            )
        finally:
            await bot.close()

        legacy = load_settings(Path(temp) / "legacy.json", channels=None)
        legacy_bot = bot_module.BridgeBot(legacy)
        legacy_bot.store.connect("term", "wt", "tab:leaf")
        legacy_bot.forward_to_codex = AsyncMock()
        try:
            await legacy_bot.on_message(message(3, 5))
            await legacy_bot.on_message(message(4, 6))
            record(
                "legacy_single_channel",
                legacy_bot.forward_to_codex.await_count == 1
                and legacy_bot.forward_to_codex.await_args.args[0] == "channel 3",
                "unset CODEX_CHANNEL_IDS retains single-channel forwarding",
            )
        finally:
            await legacy_bot.close()

        empty = load_settings(Path(temp) / "empty.json", channels="  ")
        empty_bot = bot_module.BridgeBot(empty)
        empty_bot.store.connect("term", "wt", "tab:leaf")
        empty_bot.forward_to_codex = AsyncMock()
        try:
            await empty_bot.on_message(message(3, 7))
            await empty_bot.on_message(message(4, 8))
            record(
                "empty_list_legacy_behavior",
                empty_bot.forward_to_codex.await_count == 1,
                "empty CODEX_CHANNEL_IDS behaves like unset",
            )
        finally:
            await empty_bot.close()

        invalid = False
        try:
            load_settings(Path(temp) / "invalid.json", channels="4,not-an-id")
        except config.ConfigError as exc:
            invalid = "CODEX_CHANNEL_IDS" in str(exc)
        record("invalid_list_rejected", invalid, "malformed channel list fails with a named ConfigError")

        route_settings = load_settings(Path(temp) / "route.json")
        route_bot = bot_module.BridgeBot(route_settings)
        route_bot.store.connect("term", "wt", "tab:leaf")
        binding = orca.TerminalBinding("term", "wt", "tab", "leaf")
        route_bot.orca = NS(
            resolve_binding=AsyncMock(return_value=binding),
            exchange=AsyncMock(return_value=orca.ExchangeResult("reply", "done", False)),
        )
        class Channel(discord.TextChannel):
            def __init__(self):
                self.sent = []
            async def send(self, value):
                self.sent.append(value)
        channel = Channel()
        looked_up = []
        route_bot.get_channel = lambda channel_id: (looked_up.append(channel_id), channel)[1]
        try:
            await route_bot.forward_to_codex("synthetic prompt", origin="test")
            record(
                "primary_response_destination",
                looked_up == [3] and channel.sent == ["reply"],
                "Codex replies continue to use CODEX_CHANNEL_ID",
            )
        finally:
            await route_bot.close()

    print(json.dumps(results, ensure_ascii=False, sort_keys=True))
    return 0 if all(item["status"] == "pass" for item in results.values()) else 1


raise SystemExit(asyncio.run(main()))
