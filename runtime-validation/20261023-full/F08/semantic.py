from __future__ import annotations

import asyncio

from orca_discord_bridge.orca import (
    AgentSnapshot,
    OrcaClient,
    OrcaError,
    _find_agent_snapshot,
    _parse_terminal_binding,
)


terminal = {
    "handle": "term-1",
    "worktree_id": "wt-1",
    "tab_id": "tab-1",
    "leaf_id": "leaf-1",
    "worktree_path": "/tmp/work tree",
}
for envelope in (
    {"result": {"terminal": terminal}},
    {"terminal": terminal},
    {"data": {"terminal": terminal}},
    {"result": {"data": {"terminal": terminal}}},
):
    binding = _parse_terminal_binding(envelope)
    assert (binding.handle, binding.worktree_id, binding.pane_key) == (
        "term-1", "wt-1", "tab-1:leaf-1"
    )
    assert binding.worktree_path == "/tmp/work tree"

for key in ("handle", "worktree_id", "tab_id", "leaf_id"):
    incomplete = dict(terminal)
    incomplete.pop(key)
    try:
        _parse_terminal_binding({"terminal": incomplete})
    except OrcaError:
        pass
    else:
        raise AssertionError(f"missing {key} was accepted")

row = {
    "pane_key": "tab-1:leaf-1",
    "state": "working",
    "agent_type": "codex",
    "prompt": "owned",
    "last_assistant_message": "done",
    "tool_name": "Read",
    "tool_input": "file.py",
    "state_started_at": "10",
    "updated_at": 11,
}
for envelope in (
    {"result": {"worktrees": [{"worktree_id": "wt-1", "agents": [row]}]}},
    {"worktrees": [{"id": "wt-1", "agents": [row]}]},
    {"data": {"worktrees": [{"worktreeId": "wt-1", "agents": [row]}]}},
    {"result": {"data": {"worktrees": [{"worktree_id": "wt-1", "agents": [row]}]}}},
):
    snapshot = _find_agent_snapshot(envelope, worktree_id="wt-1", pane_key="tab-1:leaf-1")
    assert snapshot is not None
    assert (
        snapshot.agent_type,
        snapshot.last_assistant_message,
        snapshot.tool_name,
        snapshot.tool_input,
        snapshot.state_started_at,
        snapshot.updated_at,
    ) == ("codex", "done", "Read", "file.py", 10, 11)

foreign = {"result": {"worktrees": [
    {"id": "other", "agents": [row]},
    {"id": "wt-1", "agents": [{**row, "pane_key": "other:leaf"}]},
]}}
assert _find_agent_snapshot(foreign, worktree_id="wt-1", pane_key="tab-1:leaf-1") is None

client = OrcaClient("unused")
async def resolve(_handle: str):
    return _parse_terminal_binding({"terminal": {
        "handle": "term-1", "worktree_id": "wt-1", "tab_id": "tab-1", "leaf_id": "leaf-1"
    }})

async def non_codex(_binding):
    return AgentSnapshot("tab-1:leaf-1", "working", "claude", "", "", "", "", False, 0, 0)

client.resolve_binding = resolve
client.get_agent_snapshot = non_codex
try:
    asyncio.run(client.validate_codex_binding("term-1"))
except OrcaError:
    pass
else:
    raise AssertionError("non-Codex agent was accepted")

print("host semantic checks passed: all terminal/worktree envelopes and aliases, required identity, exact worktree/pane, and non-Codex rejection")
