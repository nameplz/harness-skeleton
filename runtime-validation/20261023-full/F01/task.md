# Task: distinguish subprocess cancellation from timeout

Harden `OrcaClient._run` in `src/orca_discord_bridge/orca.py` so caller cancellation and timeout remain distinct outcomes while both clean up a running direct child. Cancellation must terminate and await/reap the child, then propagate `asyncio.CancelledError`; timeout must terminate and await/reap the child, then raise the existing `OrcaError` timeout. Do not convert cancellation into a timeout or swallow either outcome.

Keep nonzero-exit and non-JSON failures visible as `OrcaError`, and preserve argv-based execution so shell-like text remains literal. Use a local fake CLI only. Extend subprocess compatibility coverage to force cancellation and timeout independently, assert that the child is reaped in each case, and retain error and literal-argv checks.

Keep product changes to `src/orca_discord_bridge/orca.py` and `tests/test_harness_compatibility.py`.

Acceptance: rebuild a wheel from this checkout and install it offline, then run the full project suite:

```bash
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip wheel --no-deps --no-build-isolation --wheel-dir .eval-wheelhouse .
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip install --no-deps --force-reinstall --no-index --find-links .eval-wheelhouse orca-discord-bridge==0.2.0
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -I -B -m pytest -q -p no:cacheprovider tests
```

For every pip command set both offline variables. Do not use live Orca/Discord services, network access, credentials, `shell=True`, direct project hooks, external headless runners, sandbox bypasses, push, publication, or merge. Stop at the fixed 30-minute cap and report incomplete work.
