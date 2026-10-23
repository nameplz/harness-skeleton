# Task: add optional role-based authorization

Add optional `DISCORD_ROLE_IDS`, a comma-separated list of Discord role IDs, while preserving the existing `DISCORD_USER_ID` owner behavior. In the configured guild, authorize the owner or a member with at least one configured role. Missing or blank role configuration remains owner-only; malformed role IDs raise `ConfigError`.

Apply the same policy to slash commands, terminal autocomplete, the context menu and its modal submission, and ordinary messages. Reject DMs, other guilds, unauthorized users, and unconfigured roles before any Orca/Codex call or message forwarding. Preserve ephemeral denial behavior for application commands and silent ignore behavior for ordinary messages.

Add focused call-spy tests for a configured-role allow, owner compatibility, malformed configuration, and denied role/user/guild/DM paths. Limit product changes to `src/orca_discord_bridge/config.py`, `src/orca_discord_bridge/bot.py`, and `tests/test_harness_compatibility.py`.

Acceptance: rebuild and install the package offline, then run the full project suite:

```bash
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip wheel --no-deps --no-build-isolation --wheel-dir .eval-wheelhouse .
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip install --no-deps --force-reinstall --no-index --find-links .eval-wheelhouse orca-discord-bridge==0.2.0
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -I -B -m pytest -q -p no:cacheprovider tests
```

Use local fake or mocked service objects only. No network, live Orca/Discord calls, push, publication, or merge. Stop at the fixed 30-minute condition cap and report incomplete work.
