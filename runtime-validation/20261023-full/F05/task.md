# Task: share Discord authorization policy across messages and commands

Refactor message authorization to reuse the existing `_auth_error` policy seam already used by application commands. `BridgeBot.on_message` must apply the configured guild/user policy before processing or forwarding message content. Preserve the current allowed guild/user, denial behavior, command behavior, and message filters for the bot's own messages, webhooks, bot authors, the configured channel, and empty input.

Denied messages, unauthorized application commands, and the unauthorized “Send to Codex” context action must return before any Orca method or `forward_to_codex` is called. Do not change configuration, Discord responses, routing semantics for authorized input, or unrelated behavior.

Extend the message-boundary tests and add `test_denied_events_do_not_call_orca` in `tests/test_harness_compatibility.py`. Use only local fake Discord messages/interactions and `AsyncMock` call spies. Cover DMs, wrong guild/user/channel, bot/webhook/self messages, empty input, and unauthorized `/orca` commands/context action. Assert denied events do not await `forward_to_codex`, `list_terminals`, `validate_codex_binding`, `get_agent_snapshot`, `resolve_binding`, or `exchange`. Keep an authorized message/command regression assertion.

Limit changes to `src/orca_discord_bridge/bot.py` and `tests/test_harness_compatibility.py`.

Acceptance: rebuild a wheel from this checkout and install it in `.eval-venv`, then run the full project suite:

```bash
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip wheel --no-deps --no-build-isolation --wheel-dir .eval-wheelhouse .
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip install --no-deps --force-reinstall --no-index --find-links .eval-wheelhouse orca-discord-bridge==0.2.0
.eval-venv/bin/python -I -B -m pytest -q -p no:cacheprovider tests
```

Use only synthetic local Discord/Orca objects; do not contact live services, access the network, publish, push, or merge. Stop at the hard 30-minute condition cap and report actual outcomes.
