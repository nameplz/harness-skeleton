# Task: preserve useful assistant output in Discord

Improve the Codex assistant-output filter so it keeps useful user-facing content while abbreviating verbose changes. Preserve surrounding prose, short code/config blocks, shell command blocks, and readable links to files inside the bound worktree. Abbreviate unified diffs and oversized non-shell fenced blocks. Add regression tests for filtering and local Markdown links. Keep changes limited to `src/orca_discord_bridge/orca.py` and `tests/test_orca_parsing.py`; do not change message routing, authorization, or Discord interaction behavior.

Acceptance: rebuild a wheel from this checkout and install it in `.eval-venv`, then run the existing project suite:

```bash
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip wheel --no-deps --no-build-isolation --wheel-dir .eval-wheelhouse .
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip install --no-deps --force-reinstall --no-index --find-links .eval-wheelhouse orca-discord-bridge==0.2.0
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -I -B -m pytest -q -p no:cacheprovider tests
```

Use only local fake or mocked service objects. For every pip command, set `PIP_NO_INDEX=1` and `PIP_DISABLE_PIP_VERSION_CHECK=1`. No live Orca or Discord calls, network access, publishing, push, or merge. Stop at the fixed 30-minute condition cap and report incomplete work.