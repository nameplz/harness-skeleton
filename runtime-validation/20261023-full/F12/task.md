# Task: cover stale Orca pane/worktree recovery after layout changes

Protect the Discord forwarding path when the saved Orca terminal binding becomes stale after a layout change. On each forwarded message, resolve the saved terminal handle. If the live worktree ID or pane key differs from the saved binding, validate the terminal again with that saved handle, persist the binding returned by validation, and exchange only through that validated binding. If validation fails, do not exchange or send a reply, and leave the saved binding unchanged. An unchanged binding should continue without an unnecessary revalidation.

Add a focused compatibility regression named `test_forward_recovers_stale_binding_after_layout_change`. Using local fakes and mocks, cover a pane-only change, a worktree-only change, use/persistence of the validated binding, unchanged binding, and failed revalidation without exchange or state change. Preserve authorization, command routing, and existing service behavior.

Limit changes to exactly `src/orca_discord_bridge/bot.py` and `tests/test_harness_compatibility.py`.

Acceptance: rebuild a wheel from this checkout and install it in `.eval-venv`, then run the existing full project suite:

```bash
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip wheel --no-deps --no-build-isolation --wheel-dir .eval-wheelhouse .
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip install --no-deps --force-reinstall --no-index --find-links .eval-wheelhouse orca-discord-bridge==0.2.0
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -I -B -m pytest -q -p no:cacheprovider tests
```

Use local fake Orca state only. For every pip command set both offline variables. Do not contact Orca or Discord, access the network, publish, push, or merge. Stop at the hard 30-minute condition cap and report incomplete work.
