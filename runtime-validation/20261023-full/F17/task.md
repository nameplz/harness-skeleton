# Task: write persistent state atomically with private permissions

Update `StateStore.save()` so state is written atomically and the resulting state file is private. Preserve the existing JSON schema and connect/disconnect behavior.

Acceptance requires: create missing parent directories; replace the state atomically using a temporary file in the destination directory; ensure new and replaced state files have mode `0600` regardless of process umask; remove temporary files after success or a failed replacement; preserve the previous complete state if replacement fails; and reload the saved fields correctly.

Keep product changes within `src/orca_discord_bridge/state.py` and `tests/test_harness_compatibility.py`. Extend the existing state round-trip test or add focused tests.

Run the exact offline wheel build, install, and full test commands below. Use local temporary directories only; do not contact Discord or Orca, access the network, publish, push, or merge.

```bash
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip wheel --no-deps --no-build-isolation --wheel-dir .eval-wheelhouse .
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip install --no-deps --force-reinstall --no-index --find-links .eval-wheelhouse orca-discord-bridge==0.2.0
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -I -B -m pytest -q -p no:cacheprovider tests
```

Stop at the fixed 30-minute condition cap and report actual results. Reviewers, if launched, must be read-only.
