import json
import os
from pathlib import Path
import stat
import tempfile

from orca_discord_bridge.state import StateStore

checks = {}
def record(name, value):
    checks[name] = "pass" if value else "fail"

def saved(path):
    store = StateStore(path)
    store.connect("term", "worktree", "tab:leaf")
    return store

with tempfile.TemporaryDirectory() as root:
    root = Path(root)
    parent_path = root / "missing" / "nested" / "state.json"
    old_umask = os.umask(0o000)
    try:
        saved(parent_path)
    finally:
        os.umask(old_umask)
    record("parent_creation", parent_path.is_file() and parent_path.parent.is_dir())
    record("success_temp_cleanup", list(parent_path.parent.iterdir()) == [parent_path])
    reloaded = StateStore(parent_path).state
    record("reload_round_trip", (reloaded.terminal_handle, reloaded.worktree_id, reloaded.pane_key) == ("term", "worktree", "tab:leaf"))
    mode_results = [stat.S_IMODE(parent_path.stat().st_mode) == 0o600]
    for index, mask in enumerate((0o027, 0o077), start=1):
        mode_path = root / f"umask-{index}" / "state.json"
        old_umask = os.umask(mask)
        try:
            saved(mode_path)
        finally:
            os.umask(old_umask)
        mode_results.append(stat.S_IMODE(mode_path.stat().st_mode) == 0o600)
    record("mode_varied_umask", all(mode_results))

with tempfile.TemporaryDirectory() as root:
    root = Path(root)
    path = root / "state.json"
    old = {"terminal_handle": "old", "worktree_id": "old-wt", "pane_key": "old-pane"}
    path.write_text(json.dumps(old), encoding="utf-8")
    path.chmod(0o644)
    before = path.read_bytes()
    store = StateStore(path)
    replace = os.replace
    observed = {}
    def checked_replace(source, target):
        source, target = Path(source), Path(target)
        observed["same_directory"] = source.parent == path.parent and target == path
        observed["old_intact"] = path.read_bytes() == before
        observed["temp_private"] = stat.S_IMODE(source.stat().st_mode) == 0o600
        observed["temp_complete"] = json.loads(source.read_text(encoding="utf-8")) == {"terminal_handle":"term","worktree_id":"worktree","pane_key":"tab:leaf"}
        return replace(source, target)
    os.replace = checked_replace
    old_umask = os.umask(0o000)
    try:
        store.connect("term", "worktree", "tab:leaf")
    finally:
        os.umask(old_umask)
        os.replace = replace
    record("atomic_same_directory_replace", all(observed.get(key, False) for key in ("same_directory","old_intact","temp_private","temp_complete")))
    record("existing_file_mode_restricted", stat.S_IMODE(path.stat().st_mode) == 0o600)

with tempfile.TemporaryDirectory() as root:
    root = Path(root)
    path = root / "state.json"
    path.write_text(json.dumps({"terminal_handle":"old","worktree_id":"old-wt","pane_key":"old-pane"}), encoding="utf-8")
    before = path.read_bytes()
    store = StateStore(path)
    replace = os.replace
    error_seen = False
    def fail_replace(source, target):
        raise OSError("injected local replace failure")
    os.replace = fail_replace
    try:
        try:
            store.connect("new", "new-wt", "new-pane")
        except OSError:
            error_seen = True
    finally:
        os.replace = replace
    record("failed_replace_preserves_old_and_cleans_temp", error_seen and path.read_bytes() == before and list(path.parent.iterdir()) == [path])

print(json.dumps(checks, sort_keys=True))
raise SystemExit(0 if all(v == "pass" for v in checks.values()) else 1)
