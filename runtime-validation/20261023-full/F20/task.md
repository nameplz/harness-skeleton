# Task: preserve Codex slash-command behavior

Preserve the Codex slash-command path used by ordinary messages in the configured Discord channel. `/clear`, `/compact`, and `/new` must be sent to the terminal exactly once and acknowledged. Only `/status` may read the terminal screen, and its response should exclude the input prompt and terminal decoration. Ordinary prompts must continue through structured status and must not screen-scrape. Keep `/help` on the no-screen command path. Extend `test_slash_screen_exception_is_narrow` to cover send count, acknowledgements, filtered `/status`, and ordinary-prompt routing. Limit changes to `src/orca_discord_bridge/orca.py` and `tests/test_harness_compatibility.py`; do not change Discord application-command routing or authorization.

Acceptance: rebuild a wheel from this checkout and install it in `.eval-venv`, then run the existing project suite:

```bash
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip wheel --no-deps --no-build-isolation --wheel-dir .eval-wheelhouse .
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip install --no-deps --force-reinstall --no-index --find-links .eval-wheelhouse orca-discord-bridge==0.2.0
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -I -B -m pytest -q -p no:cacheprovider tests
```

Use only local fake or mocked service objects. For every pip command, set both offline variables. Do not contact Discord or Orca, access the network, publish, push, or merge. Stop at the fixed 30-minute condition cap and report incomplete work.