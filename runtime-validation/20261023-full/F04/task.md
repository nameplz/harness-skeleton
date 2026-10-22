# Task: prevent assistant output crossing worktree and pane boundaries

Keep structured assistant output tied to the selected terminal's exact Orca worktree and pane identity (`tabId:leafId`). A row from another worktree or another pane must never contribute assistant text, even when it appears first in the `worktree ps` response. Tool names and tool inputs are internal details and must never appear in the user-facing result.

Extend `test_find_exact_agent_by_worktree_and_pane_key` with a same-pane foreign-worktree decoy and a wrong-pane decoy in the selected worktree, then assert only the exact row is returned. Strengthen the compatibility fake and structured-completion test with distinct foreign-message and tool-detail markers; assert the returned output contains only messages from the selected worktree/pane and never reads the terminal screen.

Limit changes to `tests/test_orca_parsing.py` and `tests/test_harness_compatibility.py`. Do not change Orca routing, Discord application-command behavior, authorization, or output formatting.

Acceptance: rebuild a wheel from this checkout and install it in `.eval-venv`, then run the existing full project suite:

```bash
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip wheel --no-deps --no-build-isolation --wheel-dir .eval-wheelhouse .
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -m pip install --no-deps --force-reinstall --no-index --find-links .eval-wheelhouse orca-discord-bridge==0.2.0
PIP_NO_INDEX=1 PIP_DISABLE_PIP_VERSION_CHECK=1 .eval-venv/bin/python -I -B -m pytest -q -p no:cacheprovider tests
```

Use only synthetic local worktree snapshots and fake subprocesses. For every pip command, set both offline variables. Do not contact Discord or Orca, access the network, publish, push, or merge. Stop at the fixed 30-minute condition cap and report incomplete work.