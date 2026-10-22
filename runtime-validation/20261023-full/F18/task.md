# Task: expand Orca JSON compatibility for alternate wrappers

Extend the T15 compatibility behavior to two additional response envelope chains:

- Terminal identity may also appear at `response.result.terminal` or `payload.data.terminal`.
- Worktree snapshots may also appear at `response.result.worktrees` or `payload.data.worktrees`.

Continue accepting every standard wrapper and camelCase/snake_case alias listed in the F08 T15 task. Terminal handle, worktree ID, tab ID, and leaf ID remain required. Never select an agent from another worktree or pane, and continue rejecting a known non-Codex agent. Preserve terminal-send text as one literal subprocess argument; never route it through a shell.

Add focused parser coverage for both alternate envelope chains and a client compatibility regression in `tests/test_harness_compatibility.py`. Keep the existing literal-argv and non-Codex tests passing.

Limit changes to exactly `src/orca_discord_bridge/orca.py`, `tests/test_orca_parsing.py`, and `tests/test_harness_compatibility.py`.

Acceptance: rebuild a wheel from this checkout and install it offline, run the full project suite, run both focused test modules, then run the frozen host semantic checks for all standard and alternate envelopes, aliases, required identity, exact worktree/pane selection, and non-Codex rejection. Use only local fixtures and fake CLI processes; no live service, network, publication, push, or merge. Set `PIP_NO_INDEX=1` and `PIP_DISABLE_PIP_VERSION_CHECK=1` for every pip command.
