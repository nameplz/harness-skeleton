import json
import sqlite3
import stat
import tempfile
from pathlib import Path

from orca_discord_bridge.state import StateStore

FIELDS = ("terminal_handle", "worktree_id", "pane_key")

def empty(store):
    return all(getattr(store.state, name) is None for name in FIELDS)

def verify_database(path):
    assert path.read_bytes().startswith(b"SQLite format 3\x00")
    with sqlite3.connect(path) as db:
        assert db.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600

results = {}
def check(name, fn):
    try:
        detail = fn()
        results[name] = {"status": "pass", "detail": detail}
    except Exception as exc:
        results[name] = {"status": "fail", "detail": f"{type(exc).__name__}: {exc}"}

def restart_and_commands():
    with tempfile.TemporaryDirectory(prefix="t13-state-") as temp:
        path = Path(temp) / "state.sqlite"
        store = StateStore(path)
        assert empty(store)
        store.connect("terminal-1", "worktree-2", "pane-3")
        verify_database(path)
        reopened = StateStore(path)
        assert (reopened.state.terminal_handle, reopened.state.worktree_id, reopened.state.pane_key) == ("terminal-1", "worktree-2", "pane-3")
        reopened.disconnect()
        assert empty(StateStore(path))
        verify_database(path)
    return "state survives reopen; connect/disconnect persist; SQLite file remains 0600"

def valid_legacy_migration():
    with tempfile.TemporaryDirectory(prefix="t13-legacy-") as temp:
        path = Path(temp) / "configured-state.json"
        expected = {"terminal_handle": "legacy-terminal", "worktree_id": "legacy-worktree", "pane_key": "legacy-pane"}
        path.write_text(json.dumps(expected), encoding="utf-8")
        store = StateStore(path)
        assert tuple(getattr(store.state, key) for key in FIELDS) == tuple(expected[key] for key in FIELDS)
        verify_database(path)
        again = StateStore(path)
        assert tuple(getattr(again.state, key) for key in FIELDS) == tuple(expected[key] for key in FIELDS)
    return "valid legacy object migrates at the configured path and survives reopen"

def invalid_legacy_migration():
    values = {"malformed": "{broken", "array": "[]", "null": "null", "string": '"state"', "number": "17", "boolean": "true"}
    with tempfile.TemporaryDirectory(prefix="t13-invalid-") as temp:
        for label, raw in values.items():
            path = Path(temp) / f"{label}.json"
            path.write_text(raw, encoding="utf-8")
            store = StateStore(path)
            assert empty(store), label
            verify_database(path)
            assert empty(StateStore(path)), label
    return "malformed and non-object legacy inputs become empty, valid private SQLite databases"

check("restart_connect_disconnect", restart_and_commands)
check("valid_legacy_migration", valid_legacy_migration)
check("malformed_and_non_object_migration", invalid_legacy_migration)
print(json.dumps(results, sort_keys=True))
raise SystemExit(0 if all(item["status"] == "pass" for item in results.values()) else 1)
