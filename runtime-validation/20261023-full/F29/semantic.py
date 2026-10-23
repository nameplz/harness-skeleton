from __future__ import annotations

import json
from pathlib import Path
import tempfile

from orca_discord_bridge.state import BridgeState, StateStore

failures = []


def check(name: str, path: Path, expected: BridgeState = BridgeState()) -> None:
    try:
        actual = StateStore(path).state
        if actual != expected:
            failures.append(f"{name}: got {actual!r}")
    except Exception as exc:
        failures.append(f"{name}: raised {type(exc).__name__}: {exc}")


with tempfile.TemporaryDirectory() as temp:
    root = Path(temp)
    for index, value in enumerate((None, [], "state", 0, 1.5, True, False)):
        path = root / f"non-object-{index}.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        check(f"non-object-{index}", path)

    check("missing-file", root / "missing.json")
    path = root / "object.json"
    path.write_text(json.dumps({"terminal_handle": "term", "worktree_id": "wt", "pane_key": "tab:leaf"}), encoding="utf-8")
    check("valid-object", path, BridgeState("term", "wt", "tab:leaf"))

    path = root / "roundtrip" / "state.json"
    store = StateStore(path)
    try:
        store.connect("term", "wt", "tab:leaf")
        check("connect", path, BridgeState("term", "wt", "tab:leaf"))
        store.disconnect()
        check("disconnect", path)
    except Exception as exc:
        failures.append(f"connect/disconnect raised {type(exc).__name__}: {exc}")

if failures:
    raise AssertionError("; ".join(failures))
print("host state checks passed: seven non-object roots, missing/object state, connect/disconnect")
