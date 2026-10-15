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
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from evals.runtime_invocation import Invocation

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
    invocation_sha256: str | None = None
    source_sha256: str | None = None


def open_no_symlink(path: Path, *, directory: bool = False) -> int:
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('artifact file path must be absolute and canonical')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    parent_fd = os.open(path.anchor, flags | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, flags | os.O_DIRECTORY, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = child
        return os.open(path.name, flags | (os.O_DIRECTORY if directory else 0), dir_fd=parent_fd)
    finally:
        os.close(parent_fd)


def read_host_artifact(path: Path, fixture: RuntimeFixture, *, max_bytes: int = 1024 * 1024) -> bytes:
    if type(max_bytes) is not int or not 1 <= max_bytes <= 1024 * 1024:
        raise ValueError('invalid artifact read limit')
    from evals.runtime_boundary import require_boundary, require_disjoint, fixture_protection
    require_boundary(fixture)
    path = path.absolute()
    require_disjoint(fixture_protection(fixture), path)
    if path.is_symlink() or path.is_relative_to(fixture.root) or path.resolve().is_relative_to(fixture.root):
        raise ValueError("trace must be outside the candidate and not a symlink")
    # The operator must protect all parent directories with the measured native profile.
    with os.fdopen(open_no_symlink(path.resolve(strict=True)), "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size > max_bytes or \
                metadata.st_uid not in {0, os.getuid() if hasattr(os, 'getuid') else metadata.st_uid} or metadata.st_mode & 0o022:
            raise ValueError("artifact must be bounded, regular, host-owned and unlinked")
        raw = stream.read(max_bytes + 1)
        after = os.fstat(stream.fileno())
    identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns,
                             item.st_mode, item.st_uid, item.st_gid, item.st_nlink)
    if len(raw) > max_bytes or identity(metadata) != identity(after):
        raise ValueError('artifact changed while reading')
    return raw


def read_protected_artifact(path: Path, fixture: RuntimeFixture, digest: str) -> str:
    raw = read_host_artifact(path, fixture)
    if hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("trace digest mismatch")
    return raw.decode("utf-8")


def json_object(text: str) -> dict[str, Any]:
    def unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        if len({key for key, _ in pairs}) != len(pairs):
            raise ValueError('duplicate JSON object key')
        return dict(pairs)
    try:
        value = json.loads(text, object_pairs_hook=unique_keys)
    except RecursionError as error:
        raise ValueError('JSON nesting exceeded the parser limit') from error
    if not isinstance(value, dict):
        raise ValueError('expected a JSON object')
    return value


def _rows(text: str) -> tuple[dict[str, Any], ...]:
    return tuple(json_object(line) for line in text.splitlines() if line.strip())


def completed_native_events(text: str, session_id: str) -> tuple[dict[str, Any], ...]:
    events = _rows(text)
    sessions = [event.get('thread_id') for event in events if event.get('type') == 'thread.started']
    if sessions != [session_id]:
        raise ValueError('trace has no unique native session')
    if any(key in event and event[key] != session_id
           for event in events for key in ('thread_id', 'session_id')):
        raise ValueError('native events contain mixed or invalid session identities')
    if sum(event.get('type') == 'turn.completed' for event in events) != 1 or any(
        event.get('type') in {'turn.failed', 'error'} or
        (isinstance(event.get('item'), dict) and event['item'].get('type') == 'error')
        for event in events
    ):
        raise ValueError('trace has no unique successful native turn')
    return events


def load_runtime_trace(fixture: RuntimeFixture, rollout: Path, hooks: Path, *,
                       rollout_sha256: str, hook_sha256: str,
                       expected_invocation: Invocation | None = None) -> RuntimeTrace:
    from evals.runtime_invocation import Invocation, consume_invocation, verify_invocation
    from evals.native_runtime import build_exec_command, worker_prompt
    if not isinstance(expected_invocation, Invocation) or expected_invocation.kind != 'worker':
        raise ValueError('trace requires its current host-issued worker invocation')
    verify_invocation(fixture, expected_invocation, require_session=True)
    if rollout.resolve() != expected_invocation.artifact_root / 'rollout.jsonl' or \
            hooks.resolve() != expected_invocation.artifact_root / 'hooks.jsonl':
        raise ValueError('trace artifacts are not in this invocation directory')
    command_path = expected_invocation.artifact_root / 'command.json'
    expected_command = [*build_exec_command(fixture.root, model=expected_invocation.model, writable=True,
                                          invocation=expected_invocation), worker_prompt(expected_invocation)]
    command_digest = hashlib.sha256(json.dumps(expected_command).encode()).hexdigest()
    if json.loads(read_protected_artifact(command_path, fixture, command_digest)) != expected_command:
        raise ValueError('trace command is not bound to the invocation')
    events = completed_native_events(read_protected_artifact(rollout, fixture, rollout_sha256),
                                     expected_invocation.session_id)
    observations = _rows(read_protected_artifact(hooks, fixture, hook_sha256))
    if any(row.get('invocation_nonce') != expected_invocation.nonce or
           row.get('invocation_sha256') != expected_invocation.sha256 for row in observations):
        raise ValueError('host observations contain missing or mixed invocation identities')
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
    consume_invocation(fixture, expected_invocation)
    return RuntimeTrace(expected_invocation.session_id, rollout_sha256, hook_sha256, tuple(commands), tuple(recorded),
                        invocation_sha256=expected_invocation.sha256,
                        source_sha256=expected_invocation.source.source_sha256)


def _validation_command(command: str, root: Path) -> tuple[str, ...] | None:
    if not isinstance(command, str) or '\0' in command:
        return None
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
        try:
            matches = interpreter.resolve() == Path(sys.executable).resolve()
        except (OSError, ValueError, UnicodeError):
            return None
        if not matches:
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
