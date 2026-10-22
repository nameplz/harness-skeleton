# Task: support multiple Codex input channels

Keep `CODEX_CHANNEL_ID` as the required legacy/default channel and as the destination for Codex replies. Add optional `CODEX_CHANNEL_IDS` as a comma-separated list of additional inbound channel IDs. Trim whitespace around entries, ignore duplicate IDs, and always keep the legacy channel allowed. When the list is unset or empty, preserve legacy single-channel behavior. Reject a nonempty list containing a non-integer ID with a clear `ConfigError`.

Messages from the configured guild and user in the legacy channel or any listed channel should reach Codex exactly once. Messages from unlisted channels must be ignored. Keep slash-command and application-command routing unchanged.

Extend `test_discord_message_boundary` with call-spy coverage for the legacy channel, multiple listed channels, and an unlisted channel. Add configuration coverage for whitespace, duplicates, empty-list legacy behavior, and invalid IDs. Keep changes within `src/orca_discord_bridge/config.py`, `src/orca_discord_bridge/bot.py`, and `tests/test_harness_compatibility.py`.

Acceptance: rebuild a wheel from this checkout and install it in `.eval-venv`, then run the full project suite:

```bash
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip wheel --no-deps --no-build-isolation --wheel-dir .eval-wheelhouse .
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip install --no-deps --force-reinstall --no-index --find-links .eval-wheelhouse orca-discord-bridge==0.2.0
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -I -B -m pytest -q -p no:cacheprovider tests
```

Use local Discord objects and mocks only. Do not contact Discord or Orca, access the network, publish, push, or merge. Stop at the fixed 30-minute condition cap and report actual outcomes, including incomplete work.
