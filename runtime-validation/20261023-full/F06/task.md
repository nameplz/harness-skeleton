# Task: make the documented macOS launcher handle missing Python

Add an executable `start.command` at the project root, which is already documented in README.md. It must launch the installed bridge through a project-local `.venv` without exposing environment secrets.

- If `.venv/bin/python` exists and is executable, reuse it even when system `python3` is unavailable.
- If the venv is absent, create it with `python3 -m venv .venv`. If `python3` is unavailable, exit nonzero with a clear Python 3.11+ requirement on stderr and, when `osascript` is available, show the same message in a macOS dialog. Do not attempt pip/install/start in this case.
- Install the project into the venv and start it with `python -m orca_discord_bridge`. Repeated starts reuse the venv rather than recreating it.
- Never print `DISCORD_TOKEN` or other environment values.

Add `test_start_command_missing_python_bootstrap` in `tests/test_harness_compatibility.py`. Use only temporary directories and local fake commands to cover missing Python, first-time venv creation, repeated venv reuse, install/start calls, and token redaction. Do not run the launcher with a real interpreter or package installer.

Limit changes to exactly `start.command` and `tests/test_harness_compatibility.py`. Keep the launcher executable (mode 100755).

Acceptance: rebuild a wheel from this checkout and install it in `.eval-venv`, then run the full project suite:

```bash
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip wheel --no-deps --no-build-isolation --wheel-dir .eval-wheelhouse .
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip install --no-deps --force-reinstall --no-index --find-links .eval-wheelhouse orca-discord-bridge==0.2.0
.eval-venv/bin/python -I -B -m pytest -q -p no:cacheprovider tests
```

Set both offline variables for any pip command used during the evaluation. Use only local fakes; no live service, network, publication, push, or merge. Stop at the hard 30-minute condition cap and report actual outcomes.
