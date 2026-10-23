# Task: enforce the DM authorization boundary before message routing

Make `BridgeBot.on_message` reuse the existing `_auth_error` guild/user policy before inspecting or routing message content. A message delivered in a DM (`guild is None`) must be rejected before `codex_input`, `forward_to_codex`, or any Orca method runs, even when its author is the configured user. Preserve allowed guild/user behavior, denial behavior, and the existing filters for self/bot/webhook messages, the configured channel, and empty input.

Keep application commands and the “Send to Codex” context action on the same `_auth_error` policy seam. Denied commands/context actions must return before any Orca method or `forward_to_codex` is called.

Add `test_denied_events_do_not_call_orca` in `tests/test_harness_compatibility.py`. Include an explicit DM message (`guild=None`) in its denied-event cases, along with wrong guild/user/channel, bot/webhook/self, empty input, and unauthorized application command/context action cases. Use only local synthetic objects and `AsyncMock` call spies. Assert denied events do not await `forward_to_codex`, `list_terminals`, `validate_codex_binding`, `get_agent_snapshot`, `resolve_binding`, or `exchange`. Keep an authorized message/command regression assertion.

Limit changes to `src/orca_discord_bridge/bot.py` and `tests/test_harness_compatibility.py`.

Acceptance: rebuild a wheel from this checkout and install it in `.eval-venv`, then run the full project suite:

```bash
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip wheel --no-deps --no-build-isolation --wheel-dir .eval-wheelhouse .
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip install --no-deps --force-reinstall --no-index --find-links .eval-wheelhouse orca-discord-bridge==0.2.0
.eval-venv/bin/python -I -B -m pytest -q -p no:cacheprovider tests
```

Use local synthetic Discord/Orca objects only; do not contact live services, access the network, publish, push, or merge. Stop at the hard 30-minute condition cap and report actual outcomes.
