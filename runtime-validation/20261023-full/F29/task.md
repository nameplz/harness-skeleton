# Task: load valid non-object JSON state as disconnected state

Update `StateStore._load()` in `src/orca_discord_bridge/state.py` so valid JSON roots that are not objects (`null`, arrays, strings, numbers, and booleans) load as an empty disconnected `BridgeState` instead of raising.

Preserve missing-file behavior, valid object deserialization, and `connect()`/`disconnect()` persistence. Add focused compatibility tests for all six root categories; test both boolean values and representative integer and floating-point numbers. Keep changes within exactly `src/orca_discord_bridge/state.py` and `tests/test_harness_compatibility.py`.

Acceptance: rebuild a wheel from this checkout and install it offline, then run the full project suite and the focused compatibility module:

```bash
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip wheel --no-deps --no-build-isolation --wheel-dir .eval-wheelhouse .
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip install --no-deps --force-reinstall --no-index --find-links .eval-wheelhouse orca-discord-bridge==0.2.0
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -I -B -m pytest -q -p no:cacheprovider tests
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -I -B -m pytest -q -p no:cacheprovider tests/test_harness_compatibility.py
```

No network or live Discord/Orca service calls. Do not push, publish, or merge. Local candidate commits are allowed only after the prescribed workflow reviews. Stop at the fixed 30-minute condition cap and report incomplete work.
