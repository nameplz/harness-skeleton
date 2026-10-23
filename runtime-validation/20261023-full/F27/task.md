# Task: revalidate stale Orca bindings before forwarding

For each forwarded Discord message, resolve the saved Orca terminal handle. Compare the live worktree ID and pane key with the saved binding. If either differs, validate the saved handle exactly once, persist the binding returned by validation, and exchange only through that validated binding. If validation fails, do not exchange and leave the saved binding unchanged. When the live binding is unchanged, use it without revalidation.

Add one focused compatibility regression named test_forward_revalidates_stale_binding_before_exchange. Use local fakes/mocks to cover pane and worktree drift, persistence and use of the validated binding, the unchanged path, and failed validation with no exchange or state mutation. Preserve the current user-facing error handling, authorization, routing, and unrelated service behavior.

Limit product changes to exactly src/orca_discord_bridge/bot.py and tests/test_harness_compatibility.py.

Acceptance: rebuild a wheel from this checkout and install it in .eval-venv, then run the existing full project suite:

```bash
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip wheel --no-deps --no-build-isolation --wheel-dir .eval-wheelhouse .
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip install --no-deps --force-reinstall --no-index --find-links .eval-wheelhouse orca-discord-bridge==0.2.0
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -I -B -m pytest -q -p no:cacheprovider tests
```

Use local fake Orca state only. For every pip command set both offline variables. Do not contact Orca or Discord, access the network, publish, push, or merge. Stop at the fixed 30-minute condition cap and report actual outcomes.