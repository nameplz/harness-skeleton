# Task: make Orca subprocess cleanup reliable

Harden `OrcaClient._run` in `src/orca_discord_bridge/orca.py` without changing its public call interface.

- Preserve visible `OrcaError` failures for nonzero exit status, non-JSON output, and timeout.
- On timeout, terminate a still-running direct child and await its completion so it is reaped before raising the existing timeout error.
- If the calling coroutine is cancelled while waiting for the child, terminate a still-running direct child, await its completion so it is reaped, then re-raise `asyncio.CancelledError`.
- Preserve argv-based execution through `asyncio.create_subprocess_exec`; a string such as `$(touch PATH)` must remain a literal argument and must not execute.
- Extend the subprocess compatibility tests with process-capture checks for timeout and cancellation cleanup, plus coverage for error propagation and literal argv. Use a local fake CLI only.

Keep changes to `src/orca_discord_bridge/orca.py` and `tests/test_harness_compatibility.py`.

Acceptance: rebuild a wheel from this checkout and install it offline, then run the full project suite:

```bash
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip wheel --no-deps --no-build-isolation --wheel-dir .eval-wheelhouse .
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip install --no-deps --force-reinstall --no-index --find-links .eval-wheelhouse orca-discord-bridge==0.2.0
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -I -B -m pytest -q -p no:cacheprovider tests
```

Do not use live Orca/Discord services, network access, or credentials. Do not use `shell=True`, direct project-hook execution, external headless runners, sandbox bypasses, push, publication, or merge. Local commits only after the required reviews. Stop at the fixed 30-minute condition cap and report incomplete work.