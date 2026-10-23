# Task: add optional role-based authorization

Keep the existing `DISCORD_USER_ID` authorization and add optional `DISCORD_ROLE_IDS`, a comma-separated list of Discord role IDs. In the configured guild, allow a request when its user ID matches the existing owner ID or the member has at least one configured role. An absent or blank role list must preserve current owner-only behavior; malformed IDs must fail configuration loading with `ConfigError`.

Apply the same authorization decision to slash commands, terminal autocomplete, the context menu and its modal submission, and ordinary messages forwarded to Codex. Reject DMs, other guilds, users without the owner ID or a configured role, and members with only unconfigured roles before any Orca/Codex call or forwarding. Keep the current error response behavior for application commands and silent ignore behavior for unauthorized ordinary messages.

Add focused authorization tests with call spies for configured role allow, owner compatibility, wrong role/user/guild, and DMs. Keep the product change limited to `src/orca_discord_bridge/config.py`, `src/orca_discord_bridge/bot.py`, and `tests/test_harness_compatibility.py`.

Acceptance: rebuild a wheel from this checkout and install it in `.eval-venv`, then run the project suite:

```bash
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip wheel --no-deps --no-build-isolation --wheel-dir .eval-wheelhouse .
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip install --no-deps --force-reinstall --no-index --find-links .eval-wheelhouse orca-discord-bridge==0.2.0
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -I -B -m pytest -q -p no:cacheprovider tests
```

Use local fake or mocked service objects only. Set `PIP_NO_INDEX=1` and `PIP_DISABLE_PIP_VERSION_CHECK=1` for every pip command. No network, live Orca/Discord calls, publishing, push, or merge. Stop at the fixed 30-minute condition cap and report incomplete work.
