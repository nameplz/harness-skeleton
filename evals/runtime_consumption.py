"""One atomic, protected consumption authority for a complete review group."""

from __future__ import annotations

from contextlib import contextmanager
from collections.abc import Iterator
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from evals.runtime_cases import case_spec
from evals.runtime_fixtures import RuntimeFixture
from evals.runtime_invocation import Invocation, verify_invocation
from evals.runtime_trace import json_object, open_no_symlink, read_host_artifact

LEDGER = '.review-consumption.json'
TEMPORARY = '.review-consumption.tmp'
MAX_CONSUMED = 4096


def _private(metadata: os.stat_result, *, directory: bool = False) -> None:
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(metadata.st_mode) or metadata.st_uid != os.getuid() or \
            stat.S_IMODE(metadata.st_mode) != (0o700 if directory else 0o600) or \
            not directory and metadata.st_nlink != 1:
        raise ValueError('review consumption authority must remain private and host-owned')


@contextmanager
def _locked(parent: Path) -> Iterator[int]:
    import fcntl
    directory = open_no_symlink(parent, directory=True)
    try:
        _private(os.fstat(directory), directory=True)
        try:
            fcntl.flock(directory, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('review consumption is already in progress') from None
        current = parent.lstat()
        _private(current, directory=True)
        if (current.st_dev, current.st_ino) != (os.fstat(directory).st_dev, os.fstat(directory).st_ino):
            raise ValueError('review consumption directory changed')
        yield directory
    finally:
        os.close(directory)


def _records(parent: Path, fixture: RuntimeFixture) -> dict[str, str]:
    path = parent / LEDGER
    try:
        _private(path.lstat())
    except FileNotFoundError:
        return {}
    row = json_object(read_host_artifact(path, fixture).decode())
    if set(row) != {'schema', 'consumed'} or type(row['schema']) is not int or row['schema'] != 1 or \
            not isinstance(row['consumed'], dict) or len(row['consumed']) > MAX_CONSUMED or any(
                not isinstance(value, str) or not re.fullmatch('[0-9a-f]{64}', value)
                for pair in row['consumed'].items() for value in pair):
        raise ValueError('invalid review consumption ledger')
    return row['consumed']


def _commit(directory: int, records: dict[str, str]) -> None:
    try:
        stale = os.stat(TEMPORARY, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        _private(stale)
        os.unlink(TEMPORARY, dir_fd=directory)
    try:
        fd = os.open(TEMPORARY, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write((json.dumps({'schema': 1, 'consumed': records}, sort_keys=True) + '\n').encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(TEMPORARY, LEDGER, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        try:
            os.unlink(TEMPORARY, dir_fd=directory)
        except FileNotFoundError:
            pass  # A completed rename already removed the temporary name.


def consume_reviews(fixture: RuntimeFixture, invocations: tuple[Invocation, ...], *,
                    review_digest: str, kind: str) -> None:
    required = set(case_spec(fixture.case).required_review_roles)
    if not isinstance(invocations, tuple) or not 1 <= len(invocations) <= 2 or any(
            not isinstance(launch, Invocation) for launch in invocations) or \
            len(invocations) != len(required) or {launch.kind for launch in invocations} != required or \
            any(launch.source != invocations[0].source for launch in invocations) or \
            len({launch.session_id for launch in invocations}) != len(invocations) or \
            len({(launch.execution_root, launch.final_manifest_sha256) for launch in invocations}) != 1 or \
            not isinstance(review_digest, str) or not re.fullmatch('[0-9a-f]{64}', review_digest) or \
            kind not in ('native', 'legacy'):
        raise ValueError('review consumption requires its complete group and one frozen source')
    parent = invocations[0].source.path.parent
    with _locked(parent) as directory:
        for launch in invocations:
            verify_invocation(fixture, launch, require_session=True)
        records = _records(parent, fixture)
        if any(launch.sha256 in records or os.path.lexists(launch.artifact_root / 'consumed.json')
               for launch in invocations):
            raise ValueError('review invocation evidence was already consumed')
        if len(records) + len(invocations) > MAX_CONSUMED:
            raise ValueError('review consumption ledger exceeded its bound')
        digests = sorted(launch.sha256 for launch in invocations)
        group = hashlib.sha256(json.dumps({'invocations': digests, 'kind': kind,
            'review_sha256': review_digest}, sort_keys=True).encode()).hexdigest()
        _commit(directory, {**records, **dict.fromkeys(digests, group)})
