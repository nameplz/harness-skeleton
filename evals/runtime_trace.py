"""Bind native CLI outcomes to host-owned hook observations, never worker feedback."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import sys
from typing import Any

from evals.runtime_fixtures import RuntimeFixture


@dataclass(frozen=True)
class RuntimeTrace:
    session_id: str
    rollout_sha256: str
    hook_sha256: str
    commands: tuple[str, ...]
    hooks: tuple[tuple[str, str, str], ...]
    audit_complete: bool = False
    forbidden_actions: tuple[str, ...] = ()


def open_no_symlink(path: Path) -> int:
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('artifact file path must be absolute and canonical')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    directory = os.open(path.anchor, flags | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, flags | os.O_DIRECTORY, dir_fd=directory)
            os.close(directory)
            directory = child
        return os.open(path.name, flags, dir_fd=directory)
    finally:
        os.close(directory)


def read_protected_artifact(path: Path, fixture: RuntimeFixture, digest: str) -> str:
    path = path.absolute()
    if path.is_symlink() or path.is_relative_to(fixture.root) or path.resolve().is_relative_to(fixture.root):
        raise ValueError("trace must be outside the candidate and not a symlink")
    # The operator must protect all parent directories with the measured native profile.
    with os.fdopen(open_no_symlink(path.resolve(strict=True)), "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1024 * 1024:
            raise ValueError("trace is not bounded and regular")
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024 or hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("trace digest mismatch")
    return raw.decode("utf-8")


def json_object(text: str) -> dict[str, Any]:
    def unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        if len({key for key, _ in pairs}) != len(pairs):
            raise ValueError('duplicate JSON object key')
        return dict(pairs)
    value = json.loads(text, object_pairs_hook=unique_keys)
    if not isinstance(value, dict):
        raise ValueError('expected a JSON object')
    return value


def _rows(text: str) -> tuple[dict[str, Any], ...]:
    return tuple(json_object(line) for line in text.splitlines() if line.strip())


def load_runtime_trace(fixture: RuntimeFixture, rollout: Path, hooks: Path, *,
                       rollout_sha256: str, hook_sha256: str) -> RuntimeTrace:
    events = _rows(read_protected_artifact(rollout, fixture, rollout_sha256))
    observations = _rows(read_protected_artifact(hooks, fixture, hook_sha256))
    sessions = [event.get("thread_id") for event in events if event.get("type") == "thread.started"]
    if len(sessions) != 1 or not isinstance(sessions[0], str) or not sessions[0]:
        raise ValueError("trace has no unique native session")
    commands = []
    for event in events:
        item = event.get("item")
        if event.get("type") == "item.completed" and isinstance(item, dict) and \
                item.get("type") == "command_execution" and item.get("status") == "completed" and \
                type(item.get("exit_code")) is int and item["exit_code"] == 0 and isinstance(item.get("command"), str):
            commands.append(item["command"])
    recorded = []
    for event in observations:
        tool = event.get("tool_input")
        if event.get("hook_event_name") != "PreToolUse" or not isinstance(tool, dict):
            continue
        values = (event.get("session_id"), tool.get("workdir", tool.get("cwd", event.get("cwd"))), tool.get("command"))
        if all(isinstance(value, str) for value in values):
            recorded.append(values)
    return RuntimeTrace(sessions[0], rollout_sha256, hook_sha256, tuple(commands), tuple(recorded))


def _validation_command(command: str, root: Path) -> tuple[str, ...] | None:
    try:
        tokens = shlex.split(command)
        if len(tokens) == 3 and Path(tokens[0]).name in {"sh", "bash", "zsh"} and tokens[1] in {"-c", "-lc"}:
            tokens = shlex.split(tokens[2])
    except ValueError:
        return None
    if not tokens:
        return None
    interpreter = Path(tokens[0])
    if interpreter.is_absolute():
        if interpreter.resolve() != Path(sys.executable).resolve():
            return None
    elif tokens[0] not in {"python", "python3", Path(sys.executable).name}:
        return None
    tail = tokens[1:]
    if tail[:3] == ["-m", "unittest", "discover"] and tail[3:] in (
        [], ["-v"], ["-s", "tests"], ["-s", "tests", "-v"], ["-s", "tests", "-t", "."],
        ["-s", "tests", "-t", ".", "-v"],
    ):
        return tuple(tokens)
    if tail[:2] == ["scripts/harness.py", "check"] and tail[2:] in (
        ["--quick"], ["--full"], ["--quick", "--root", str(root)], ["--full", "--root", str(root)],
    ):
        return tuple(tokens)
    return None


def validation_observed(trace: RuntimeTrace | None, root: Path) -> bool | None:
    if not isinstance(trace, RuntimeTrace):
        return None
    for command in trace.commands:
        normalized = _validation_command(command, root)
        if normalized and any(session == trace.session_id and Path(cwd).resolve() == root.resolve()
                              and _validation_command(before, root) == normalized
                              for session, cwd, before in trace.hooks):
            return True
    return False
