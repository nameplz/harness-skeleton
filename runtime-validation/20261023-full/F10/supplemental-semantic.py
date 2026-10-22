import asyncio
import tempfile
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock

from orca_discord_bridge import bot as bot_module, config, orca


def settings(path):
    return config.Settings("TOKEN_SENTINEL", 1, 2, 3, "fake-orca", 1000, path)


def interaction(bot, guild=1, user=2):
    return NS(
        client=bot,
        guild_id=guild,
        user=NS(id=user),
        response=NS(send_message=AsyncMock(), defer=AsyncMock()),
        followup=NS(send=AsyncMock()),
    )


def response_text(request):
    calls = request.response.send_message.await_args_list + request.followup.send.await_args_list
    return "\n".join(str(call.args[0]) for call in calls if call.args)


async def main():
    outcomes = {}
    command = bot_module.orca_group.get_command("doctor")
    outcomes["registered_command"] = command is not None
    if command is None:
        return outcomes

    with tempfile.TemporaryDirectory(prefix="f10-doctor-") as root:
        path = Path(root)
        healthy = bot_module.BridgeBot(settings(path / "healthy.json"))
        healthy.store.connect("term-1", "worktree-1", "tab-1:leaf-1")
        binding = orca.TerminalBinding("term-1", "worktree-1", "tab-1", "leaf-1")
        snapshot = orca.AgentSnapshot(
            "tab-1:leaf-1", "working", "codex", "PROMPT_SENTINEL",
            "MESSAGE_SENTINEL", "TOOL_SENTINEL", "TOOL_INPUT_SENTINEL",
            False, 10, 11,
        )
        healthy.orca = NS(
            resolve_binding=AsyncMock(return_value=binding),
            get_agent_snapshot=AsyncMock(return_value=snapshot),
        )
        request = interaction(healthy)
        await command.callback(request)
        text = response_text(request)
        outcomes["healthy_identity_and_state"] = all(
            value in text for value in ("term-1", "worktree-1", "tab-1:leaf-1", "working")
        )
        outcomes["no_sensitive_data"] = not any(
            value in text for value in (
                "TOKEN_SENTINEL", "TOOL_INPUT_SENTINEL", "PROMPT_SENTINEL",
                "MESSAGE_SENTINEL",
            )
        )
        outcomes["snapshot_requested_for_exact_binding"] = (
            healthy.orca.get_agent_snapshot.await_args_list
            == [((binding,), {})]
        )
        outcomes["private_response"] = (
            any(call.kwargs.get("ephemeral") is True for call in request.response.send_message.await_args_list)
            or any(call.kwargs.get("ephemeral") is True for call in request.followup.send.await_args_list)
            or any(call.kwargs.get("ephemeral") is True for call in request.response.defer.await_args_list)
        )

        stale = bot_module.BridgeBot(settings(path / "stale.json"))
        stale.store.connect("term-1", "old-worktree", "old-tab:old-leaf")
        moved = orca.TerminalBinding("term-1", "new-worktree", "new-tab", "new-leaf")
        stale.orca = NS(
            resolve_binding=AsyncMock(return_value=moved),
            get_agent_snapshot=AsyncMock(),
        )
        stale_request = interaction(stale)
        await command.callback(stale_request)
        stale_text = response_text(stale_request).casefold()
        outcomes["stale_binding_guidance"] = (
            "/orca connect" in stale_text
            and any(word in stale_text for word in ("stale", "오래", "다시 연결", "재연결"))
            and not stale.orca.get_agent_snapshot.await_count
        )

        missing = bot_module.BridgeBot(settings(path / "missing.json"))
        missing.orca = NS(
            resolve_binding=AsyncMock(),
            get_agent_snapshot=AsyncMock(),
        )
        missing_request = interaction(missing)
        await command.callback(missing_request)
        missing_text = response_text(missing_request).casefold()
        outcomes["missing_binding_guidance"] = (
            "/orca connect" in missing_text
            and not missing.orca.resolve_binding.await_count
        )

        errored = bot_module.BridgeBot(settings(path / "errored.json"))
        errored.store.connect("term-1", "worktree-1", "tab-1:leaf-1")
        errored.orca = NS(
            resolve_binding=AsyncMock(side_effect=orca.OrcaError("stale terminal")),
            get_agent_snapshot=AsyncMock(),
        )
        error_request = interaction(errored)
        await command.callback(error_request)
        outcomes["transport_error_guidance"] = "/orca connect" in response_text(error_request)

        for index, (guild, user) in enumerate(((7, 2), (1, 7))):
            denied = bot_module.BridgeBot(settings(path / f"denied-{index}.json"))
            denied.store.connect("term-1", "worktree-1", "tab-1:leaf-1")
            denied.orca = NS(
                resolve_binding=AsyncMock(return_value=binding),
                get_agent_snapshot=AsyncMock(return_value=snapshot),
            )
            denied_request = interaction(denied, guild=guild, user=user)
            await command.callback(denied_request)
            outcomes[f"denial_precedes_orca_{index}"] = (
                not denied.orca.resolve_binding.await_count
                and not denied.orca.get_agent_snapshot.await_count
                and bool(response_text(denied_request))
            )

        for bot in (healthy, stale, missing, errored):
            await bot.close()
    return outcomes


results = asyncio.run(main())
for name, passed in results.items():
    print(f"{name}: {'pass' if passed else 'fail'}")
assert all(results.values()), results
