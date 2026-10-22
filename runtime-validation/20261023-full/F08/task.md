# Task: expand Orca JSON compatibility

Make the Orca JSON parsers accept these equivalent response envelopes:

- Terminal identity at `result.terminal`, `terminal`, `data.terminal`, or `result.data.terminal`.
- Worktree snapshots at `result.worktrees`, `worktrees`, `data.worktrees`, or `result.data.worktrees`.
- Worktree identity aliases `worktreeId`, `worktree_id`, or `id`.
- Terminal identity aliases `handle`/`terminalHandle`/`terminal_handle`/`id`, `worktreeId`/`worktree_id`, `tabId`/`tab_id`, `leafId`/`leaf_id`, and optional `worktreePath`/`worktree_path`.
- Agent snapshot aliases `paneKey`/`pane_key`, `agentType`/`agent_type`, `lastAssistantMessage`/`last_assistant_message`, `toolName`/`tool_name`, `toolInput`/`tool_input`, `stateStartedAt`/`state_started_at`, and `updatedAt`/`updated_at`.

Keep terminal handle, worktree ID, tab ID, and leaf ID required. Do not accept a snapshot from a different worktree or pane, and continue rejecting a known non-Codex agent. Preserve a terminal-send payload as one literal subprocess argument; never route it through a shell.

Add focused parser tests in `tests/test_orca_parsing.py` and a client compatibility regression in `tests/test_harness_compatibility.py`. The client test must cover the snake-case response shapes and non-Codex rejection. The existing subprocess protocol test must continue to prove literal argv handling.

Limit changes to exactly `src/orca_discord_bridge/orca.py`, `tests/test_orca_parsing.py`, and `tests/test_harness_compatibility.py`.

Acceptance: rebuild a wheel from this checkout and install it offline, run the full project suite, and run the focused parser/client compatibility tests plus the existing literal-argv and non-Codex tests. Use only local fixtures and fake CLI processes; no live service, network, publication, push, or merge. Set `PIP_NO_INDEX=1` and `PIP_DISABLE_PIP_VERSION_CHECK=1` for every pip command.
