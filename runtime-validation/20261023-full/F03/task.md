# Task: handle long and interrupted replies

Update the Discord reply path so every sent chunk stays at or below 1,900 characters, concatenating chunks preserves the cleaned output exactly, non-empty interrupted replies end with the existing interruption marker, and empty output uses the documented fallback. Extend `test_forward_output_routing_and_chunks` with focused regressions. Keep changes limited to `src/orca_discord_bridge/formatting.py`, `src/orca_discord_bridge/bot.py`, and `tests/test_harness_compatibility.py`; do not change routing, authorization, dependencies, or service behavior.

Acceptance: rebuild a wheel from this checkout and install it in `.eval-venv`, then run the existing project suite:

```bash
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip wheel --no-deps --no-build-isolation --wheel-dir .eval-wheelhouse .
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip install --no-deps --force-reinstall --no-index --find-links .eval-wheelhouse orca-discord-bridge==0.2.0
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -I -B -m pytest -q -p no:cacheprovider tests
```

Use only local fake or mocked service objects. For every pip command, set both offline variables. Do not contact Orca or Discord, access the network, publish, push, or merge. Stop at the fixed 30-minute condition cap and report incomplete work.