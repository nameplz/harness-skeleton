# Task: add an authenticated `/orca doctor` command

Add `/orca doctor` under the existing `/orca` command group. Check the configured guild and owner before any Orca request. If any saved binding identity field (terminal handle, worktree ID, or pane key) is missing, report that the bridge is disconnected and recommend `/orca connect` without calling Orca.

For a complete saved binding, resolve its terminal handle with `OrcaClient.resolve_binding`, compare the live worktree ID and pane key with the saved values, and report a stale binding with `/orca connect` guidance if either changed. Do not fetch agent status for a stale binding. For a matching binding, fetch the structured agent snapshot and report healthy status, terminal handle, worktree ID, pane key, and agent state; if there is no usable snapshot state, report `unknown`. Orca errors must produce actionable reconnect guidance without disclosing raw error details.

Keep every response private. Do not read the terminal screen or disclose the configured token, prompt, assistant message, or tool input. Add the focused compatibility test `test_orca_doctor_reports_identity_and_stale_guidance` covering healthy and unknown state, stale worktree and pane, missing identity fields, authorization before Orca calls, error guidance, private responses, and sensitive-data non-disclosure.

Keep product changes limited to `src/orca_discord_bridge/bot.py` and `tests/test_harness_compatibility.py`.

Acceptance: rebuild a wheel from this checkout and install it in `.eval-venv`, then run the project suite:

```bash
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip wheel --no-deps --no-build-isolation --wheel-dir .eval-wheelhouse .
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip install --no-deps --force-reinstall --no-index --find-links .eval-wheelhouse orca-discord-bridge==0.2.0
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -I -B -m pytest -q -p no:cacheprovider tests
```

Use local fake or mocked service objects only. Set `PIP_NO_INDEX=1` and `PIP_DISABLE_PIP_VERSION_CHECK=1` for every pip command. No network, live Orca/Discord calls, publishing, push, or merge. Stop at the fixed 30-minute condition cap and report incomplete work.
