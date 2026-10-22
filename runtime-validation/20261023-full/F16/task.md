# Task: resist prompt injection through webhook and context forwarding

Only an explicit message from the configured human user in the configured guild and Codex channel may trigger a Codex call. Webhook messages and bot-authored messages remain data and must never be forwarded automatically, even when their text looks like an instruction.

For the authenticated “Send to Codex” context-menu flow, keep the selected Discord message separate from the user's modal instruction. Treat the selected content as untrusted reference data, keep an explicit start/end boundary, and prevent source text from forging the closing boundary. Keep outgoing Discord mentions disabled. Do not change authorization policy or application-command routing.

Extend `test_discord_message_boundary` with positive and negative call-spy coverage. Add focused call-spy coverage for context-menu authorization, the authorized modal submission, separation of selected text from the user's instruction, and delimiter-forgery resistance. Keep changes within `src/orca_discord_bridge/bot.py`, `src/orca_discord_bridge/formatting.py`, and `tests/test_harness_compatibility.py`.

Acceptance: rebuild a wheel from this checkout and install it in `.eval-venv`, then run the full project suite:

```bash
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip wheel --no-deps --no-build-isolation --wheel-dir .eval-wheelhouse .
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip install --no-deps --force-reinstall --no-index --find-links .eval-wheelhouse orca-discord-bridge==0.2.0
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -I -B -m pytest -q -p no:cacheprovider tests
```

Use local Discord objects and mocks only. Do not contact Discord or Orca, access the network, publish, push, or merge. Stop at the fixed 30-minute condition cap and report actual outcomes, including incomplete work.
