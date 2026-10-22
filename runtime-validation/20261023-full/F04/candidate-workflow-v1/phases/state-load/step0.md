# Step 0: non-object-state

## Read

- `TASK.md`
- `README.md`
- `pyproject.toml`
- `src/orca_discord_bridge/state.py`
- `tests/test_harness_compatibility.py`

## Work

Implement only the behavior in `TASK.md`, add regression coverage for null, array, string, number, and boolean JSON roots, and preserve the other listed behaviors.

## Acceptance

Rebuild/install the wheel and run the exact command sequence in `TASK.md`. Report commands and outcomes.

## Constraints

No live services, network, direct candidate hook execution, push, publish, or merge. The main session owns the phase metadata and any local commit.
