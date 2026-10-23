import asyncio
import tempfile
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock

from orca_discord_bridge import bot as bot_module, config, orca

checks = {}

def record(name, passed):
    checks[name] = bool(passed)

def interaction(bot, *, guild=1, user=2):
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

def is_private(request):
    senders = (request.response.send_message, request.response.defer, request.followup.send)
    calls = [call for sender in senders for call in sender.await_args_list]
    return bool(calls) and all(call.kwargs.get("ephemeral") is True for call in calls)

def new_bot(root, name, *, binding=None, snapshot=None, resolve_error=None):
    bot = bot_module.BridgeBot(config.Settings("TOKEN_SECRET", 1, 2, 3, "fake-orca", 1000, root / f"{name}.json"))
    bot.store.connect("term-1", "worktree-1", "tab-1:leaf-1")
    client = NS(
        resolve_binding=AsyncMock(return_value=binding or orca.TerminalBinding("term-1", "worktree-1", "tab-1", "leaf-1")),
        get_agent_snapshot=AsyncMock(return_value=snapshot),
        read_screen=AsyncMock(),
    )
    if resolve_error is not None:
        client.resolve_binding.side_effect = resolve_error
    bot.orca = client
    return bot

async def main():
    command = bot_module.orca_group.get_command("doctor")
    record("registered_command", command is not None)
    if command is None:
        print({"checks": checks, "failed": [name for name, passed in checks.items() if not passed]})
        raise SystemExit(1)

    bots = []
    with tempfile.TemporaryDirectory(prefix="f24-doctor-") as temp:
        root = Path(temp)
        snapshot = NS(
            pane_key="tab-1:leaf-1", state="working", agent_type="codex",
            prompt="PROMPT_SECRET", last_assistant_message="ASSISTANT_SECRET",
            tool_name="TOOL_NAME_SECRET", tool_input="TOOL_INPUT_SECRET",
        )
        healthy = new_bot(root, "healthy", snapshot=snapshot)
        bots.append(healthy)
        request = interaction(healthy)
        await command.callback(request)
        text = response_text(request)
        record("healthy_status_and_identity",
               all(value in text for value in ("term-1", "worktree-1", "tab-1:leaf-1", "working"))
               and any(word in text.casefold() for word in ("정상", "healthy", "connected")))
        record("healthy_private_and_no_sensitive_data",
               is_private(request) and not any(secret in text for secret in (
                   "TOKEN_SECRET", "PROMPT_SECRET", "ASSISTANT_SECRET", "TOOL_NAME_SECRET", "TOOL_INPUT_SECRET")))
        record("healthy_resolve_then_structured_snapshot",
               healthy.orca.resolve_binding.await_args_list == [(('term-1',), {})]
               and healthy.orca.get_agent_snapshot.await_count == 1
               and healthy.orca.read_screen.await_count == 0)

        unknown = new_bot(root, "unknown", snapshot=None)
        bots.append(unknown)
        unknown_request = interaction(unknown)
        await command.callback(unknown_request)
        blank = new_bot(root, "blank-state", snapshot=NS(state="  "))
        bots.append(blank)
        blank_request = interaction(blank)
        await command.callback(blank_request)
        record("missing_or_blank_snapshot_state_is_explicit_unknown",
               "unknown" in response_text(unknown_request).casefold()
               and "unknown" in response_text(blank_request).casefold()
               and is_private(unknown_request) and is_private(blank_request))

        stale_checks = []
        for name, changed_binding in (
            ("stale-worktree", orca.TerminalBinding("term-1", "worktree-2", "tab-1", "leaf-1")),
            ("stale-pane", orca.TerminalBinding("term-1", "worktree-1", "tab-2", "leaf-2")),
        ):
            stale = new_bot(root, name, binding=changed_binding, snapshot=snapshot)
            bots.append(stale)
            stale_request = interaction(stale)
            await command.callback(stale_request)
            stale_text = response_text(stale_request).casefold()
            stale_checks.append("/orca connect" in stale_text
                                and any(word in stale_text for word in ("stale", "변경", "다시 연결", "재연결"))
                                and stale.orca.resolve_binding.await_count == 1
                                and stale.orca.get_agent_snapshot.await_count == 0
                                and stale.orca.read_screen.await_count == 0
                                and is_private(stale_request))
        record("stale_identity_stops_before_snapshot", all(stale_checks))

        missing_checks = []
        for field in ("terminal_handle", "worktree_id", "pane_key"):
            missing = new_bot(root, f"missing-{field}", snapshot=snapshot)
            bots.append(missing)
            saved = missing.store.state
            missing.store = NS(state=NS(
                terminal_handle=None if field == "terminal_handle" else saved.terminal_handle,
                worktree_id=None if field == "worktree_id" else saved.worktree_id,
                pane_key=None if field == "pane_key" else saved.pane_key,
            ))
            missing_request = interaction(missing)
            await command.callback(missing_request)
            missing_text = response_text(missing_request).casefold()
            missing_checks.append("/orca connect" in missing_text
                                  and not missing.orca.resolve_binding.await_count
                                  and not missing.orca.get_agent_snapshot.await_count
                                  and is_private(missing_request))
        record("missing_identity_stops_before_orca", all(missing_checks))

        denied_checks = []
        for name, guild, user in (("wrong-guild", 9, 2), ("wrong-owner", 1, 9)):
            denied = new_bot(root, name, snapshot=snapshot)
            bots.append(denied)
            denied_request = interaction(denied, guild=guild, user=user)
            await command.callback(denied_request)
            denied_checks.append(bool(response_text(denied_request))
                                 and not denied.orca.resolve_binding.await_count
                                 and not denied.orca.get_agent_snapshot.await_count
                                 and denied.orca.read_screen.await_count == 0
                                 and is_private(denied_request))
        record("authorization_precedes_orca", all(denied_checks))

        errored = new_bot(root, "error", snapshot=snapshot, resolve_error=orca.OrcaError("RAW_ERROR_SECRET"))
        bots.append(errored)
        error_request = interaction(errored)
        await command.callback(error_request)
        error_text = response_text(error_request)
        record("error_guidance_is_actionable_and_redacted",
               "/orca connect" in error_text and "RAW_ERROR_SECRET" not in error_text
               and errored.orca.get_agent_snapshot.await_count == 0 and is_private(error_request))

        for bot in bots:
            await bot.close()

    failed = [name for name, passed in checks.items() if not passed]
    print({"checks": checks, "failed": failed})
    raise SystemExit(bool(failed))

asyncio.run(main())
