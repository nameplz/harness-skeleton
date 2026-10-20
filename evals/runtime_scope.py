"""Content permission does not authorize changes to an entry's metadata."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any, NamedTuple, TYPE_CHECKING

from evals.runtime_access import bounded_tree, require_profile, snapshot_file_mode
from evals.runtime_cases import case_spec

if TYPE_CHECKING:
    from evals.runtime_fixtures import RuntimeFixture


class EntryMetadata(NamedTuple):
    path: str
    kind: str
    mode: int
    uid: int
    gid: int
    links: int


def is_git(path: str) -> bool:
    return path == '.git' or path.startswith('.git/')


def tree_metadata(root: Path) -> tuple[EntryMetadata, ...]:
    # Directory nlink changes when valid child directories are added.
    return tuple(sorted(EntryMetadata(path.relative_to(root).as_posix(),
        'directory' if stat.S_ISDIR(row.st_mode) else 'regular', stat.S_IMODE(row.st_mode),
        row.st_uid, row.st_gid, 0 if stat.S_ISDIR(row.st_mode) else row.st_nlink)
        for path, row in bounded_tree(root)))


def metadata_digest(rows: tuple[EntryMetadata, ...] | list[list[str | int]]) -> str:
    return hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def content_allowed(case: str, path: str) -> bool:
    policy = case_spec(case)
    return path in policy.allowed_changes or (
        policy.allow_test_changes and path.startswith('tests/') and path.endswith('.py'))


def metadata_failures(fixture: RuntimeFixture, rows: list[list[str | int]]) -> list[str]:
    baseline = {row.path: row for row in fixture.seed_metadata}
    if '.' not in baseline:
        return ['scope metadata baseline unavailable']
    current = {row[0]: EntryMetadata(*row) for row in rows}
    failures = [f'scope metadata changed: {path}' for path, row in baseline.items()
                if current.get(path) != row]
    owner = (baseline['.'].uid, baseline['.'].gid)
    parents = {parent.as_posix() for row in current.values() if row.kind == 'regular'
               and content_allowed(fixture.case, row.path) for parent in Path(row.path).parents}
    for path, row in current.items():
        if path in baseline:
            continue
        if (row.uid, row.gid) != owner or row.mode & 0o7022:
            failures.append(f'unsafe new entry metadata: {path}')
        if row.kind == 'directory' and path not in parents:
            failures.append(f'out-of-scope directory: {path}')
    return failures


def snapshot_owner(profile: str) -> tuple[int, int]:
    return (0, 0) if require_profile(profile) else (os.getuid(), os.getgid())


def verify_snapshot_metadata(fixture: RuntimeFixture, snapshot: Path, manifest: dict[str, Any]) -> None:
    uid, gid = snapshot_owner(fixture.execution_profile)
    omitted = {row.relative_path for row in fixture.metadata_only_seeds}
    expected = tuple(EntryMetadata(row[0], row[1],
        0o555 if row[1] == 'directory' else snapshot_file_mode(row[2], fixture.execution_profile),
        uid, gid, 0 if row[1] == 'directory' else 1)
        for row in manifest['tree_metadata'] if row[0] not in omitted)
    if tree_metadata(snapshot) != expected:
        raise ValueError('review snapshot metadata changed')
