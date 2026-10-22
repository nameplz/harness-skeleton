# Task: add the documented macOS launcher

Add an executable `start.command` at the project root, already documented in README.md. On first launch, create `.venv`, install the project, and start `python -m orca_discord_bridge`; on later launches, reuse the venv and start the module without reinstalling. If the venv is absent and `python3` is unavailable, exit nonzero with a clear Python 3.11+ requirement on stderr and, when `osascript` is available, show that guidance in a macOS dialog. Do not install or start in that case. Never print environment values such as `DISCORD_TOKEN`.

Quote paths so the launcher works when the project directory contains spaces. Add `test_start_command_missing_python_bootstrap` to `tests/test_harness_compatibility.py`, using only temporary directories and fake commands to cover first launch, repeat launch without system `python3`, a missing-Python launch, paths with spaces, and token redaction. Do not run the launcher with a real interpreter or package installer.

Limit changes to exactly `start.command` and `tests/test_harness_compatibility.py`. Keep `start.command` executable (mode 100755).

Acceptance: rebuild a wheel from this checkout and install it in `.eval-venv`, then run the full project suite:

```bash
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip wheel --no-deps --no-build-isolation --wheel-dir .eval-wheelhouse .
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip install --no-deps --force-reinstall --no-index --find-links .eval-wheelhouse orca-discord-bridge==0.2.0
.eval-venv/bin/python -I -B -m pytest -q -p no:cacheprovider tests
```

Set both offline variables for every pip command used in this evaluation. Use only local fakes; no live service, network, publication, push, or merge. Stop at the hard 30-minute condition cap and report actual outcomes.
