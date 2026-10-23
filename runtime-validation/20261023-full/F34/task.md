# Task: migrate bridge state persistence to private SQLite

Replace `StateStore`'s JSON persistence with the Python standard library `sqlite3` while preserving its existing public API and `Settings.state_path` contract. The configured path itself becomes the SQLite database path; do not require a new setting or dependency.

On first open, migrate a valid legacy JSON object at that path, preserving `terminal_handle`, `worktree_id`, and `pane_key`. Missing, malformed, or non-object legacy JSON must initialize an empty state without crashing. Preserve state across a new `StateStore` instance, and keep `connect()` and `disconnect()` behavior unchanged. Create the database with owner-only permissions (`0600`) and keep it private after reopening/saving.

Add focused tests to `tests/test_harness_compatibility.py` for SQLite persistence, valid legacy migration, malformed/non-object migration, restart, connect/disconnect, and private file permissions. Keep the product diff limited to `src/orca_discord_bridge/state.py` and `tests/test_harness_compatibility.py`.

Acceptance: build a fresh wheel from this checkout, install it offline, and run the full project suite using the exact commands below. The independent host grader also checks migration behavior, SQLite integrity, file mode, and changed-file scope.

```bash
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip wheel --no-deps --no-build-isolation --wheel-dir .eval-wheelhouse .
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip install --no-deps --force-reinstall --no-index --find-links .eval-wheelhouse orca-discord-bridge==0.2.0
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -I -B -m pytest -q -p no:cacheprovider tests
```

Use only local synthetic files and tests. For every pip command set both offline variables. Do not contact Discord or Orca, access the network, publish, push, or merge. Stop at the fixed 30-minute condition cap and report actual outcomes.
