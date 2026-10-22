# Task: include reply and embed context safely

When a user replies to a Discord message, include the referenced message content and embed author, title, description, fields, URL, and footer in the Codex prompt. If the reference is unresolved, fetch it once from the same channel and use the fetched message. Cap the extracted source text at 12,000 characters, delimit it with explicit start/end markers, and tell Codex the quoted content is reference data rather than instructions.

Extend `test_embed_reply_data_and_control_cleanup` for all supported embed fields, URL, the 12,000-character source cap, and explicit delimiters. Add focused compatibility coverage for an unresolved reply that is fetched and forwarded. Keep authorization and Discord application-command routing unchanged.

Limit changes to `src/orca_discord_bridge/formatting.py`, `src/orca_discord_bridge/bot.py`, and `tests/test_harness_compatibility.py`.

Acceptance: rebuild a wheel from this checkout and install it in `.eval-venv`, then run the existing full project suite:

```bash
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip wheel --no-deps --no-build-isolation --wheel-dir .eval-wheelhouse .
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip install --no-deps --force-reinstall --no-index --find-links .eval-wheelhouse orca-discord-bridge==0.2.0
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -I -B -m pytest -q -p no:cacheprovider tests
```

Use local Discord message objects and mocks only. For every pip command, set both offline variables. Do not contact Discord or Orca, access the network, publish, push, or merge. Stop at the fixed 30-minute condition cap and report incomplete work.