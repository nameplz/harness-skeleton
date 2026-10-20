"""Fixed bounded failure probes; payloads and candidate Python are never imported."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import runpy
import stat
import sys

MAX_INPUT_BYTES = 1024 * 1024
MAX_OUTPUT_BYTES = 65536
TIMEOUT_SECONDS = 0.2
METADATA_PATH = 'data/oversized.txt'
CASES = ('large-file', 'tool-timeout')
VARIANTS = ('pilot', 'unseen')


def digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _metadata(item: os.stat_result) -> tuple[int, ...]:
    return (item.st_dev, item.st_ino, item.st_mode, item.st_nlink, item.st_uid, item.st_gid,
            item.st_size, item.st_mtime_ns, item.st_ctime_ns)


def _directory(path: Path) -> int:
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('probe path must be canonical')
    chain = (path, *path.parents)
    namespace = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid)
    before = tuple(entry.lstat() for entry in chain)
    if any(not stat.S_ISDIR(item.st_mode) for item in before):
        raise ValueError('probe directory must not contain symlink ancestors')
    # Root-deny profiles admit metadata traversal, but not reading ancestor directories.
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        after = tuple(entry.lstat() for entry in chain)
        if namespace(os.fstat(fd)) != namespace(before[0]) or tuple(map(namespace, before)) != tuple(map(namespace, after)):
            raise ValueError('probe directory namespace changed')
        return fd
    except BaseException:
        os.close(fd)
        raise


def metadata_observation(root: Path, *, expected_uid: int | None = None) -> dict[str, object]:
    if expected_uid is not None and (type(expected_uid) is not int or not 0 <= expected_uid < 2**32):
        raise ValueError('invalid metadata owner identity')
    owner = os.getuid() if expected_uid is None else expected_uid
    path = root / METADATA_PATH
    fd = _directory(path.parent)
    try:
        before = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != owner:
            raise ValueError('metadata resource must be regular, single-link and operator-owned')
        after = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
        if _metadata(before) != _metadata(after) or _metadata(after) != _metadata(path.lstat()) \
                or _metadata(os.fstat(fd)) != _metadata(path.parent.lstat()):
            raise ValueError('metadata resource namespace changed')
        return {'kind': 'regular', 'size': before.st_size, 'mode': stat.S_IMODE(before.st_mode),
                'nlink': 1, 'metadata_sha256': digest(_metadata(before))}
    finally:
        os.close(fd)


def _source_bytes(path: Path) -> bytes:
    parent = _directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally:
        os.close(parent)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_INPUT_BYTES:
            raise ValueError('probe source must be bounded and regular')
        raw = stream.read(MAX_INPUT_BYTES + 1)
        after = os.fstat(stream.fileno())
    if len(raw) > MAX_INPUT_BYTES or _metadata(before) != _metadata(after) \
            or _metadata(after) != _metadata(path.lstat()):
        raise ValueError('probe source identity changed')
    return raw


def source_sha256() -> str:
    parent = Path(__file__).resolve().parent
    return digest({'helper': hashlib.sha256(_source_bytes(Path(__file__).absolute())).hexdigest(),
                   'runner': hashlib.sha256(_source_bytes(parent / 'command_runner.py')).hexdigest()})


def policy_sha256(case: str, variant: str) -> str:
    if case not in CASES or variant not in VARIANTS:
        raise ValueError('unknown bounded probe')
    return digest({'schema': 1, 'case': case, 'variant': variant, 'max_input_bytes': MAX_INPUT_BYTES,
                   'max_output_bytes': MAX_OUTPUT_BYTES, 'timeout_seconds': TIMEOUT_SECONDS,
                   'sleep_seconds': 2 if variant == 'pilot' else 3})


def observe(case: str, variant: str) -> dict[str, object]:
    policy = policy_sha256(case, variant)
    before = source_sha256()
    root = Path.cwd().resolve()
    if case == 'large-file':
        observation = {**metadata_observation(root), 'payload_bytes_read': 0, 'max_bytes': MAX_INPUT_BYTES}
        state = 'size_limited' if observation['size'] > MAX_INPUT_BYTES else 'failed'
    else:
        runner = runpy.run_path(str(Path(__file__).resolve().parent / 'command_runner.py'))['run_bounded_command']
        seconds = 2 if variant == 'pilot' else 3
        result = runner([sys.executable, '-I', '-B', '-c', f'import time; time.sleep({seconds})'],
                        cwd=root, timeout_seconds=TIMEOUT_SECONDS, max_output_bytes=MAX_OUTPUT_BYTES)
        observation = {'started': result.started, 'returncode': result.returncode,
                       'timed_out': result.timed_out, 'output_limited': result.output_limited,
                       'timeout_seconds': TIMEOUT_SECONDS, 'max_output_bytes': MAX_OUTPUT_BYTES}
        state = ('timed_out' if result.started and result.timed_out and not result.output_limited
                 else ('failed' if result.started and not result.output_limited else 'unknown'))
    unchanged = before == source_sha256()
    if case == 'large-file':
        unchanged = unchanged and metadata_observation(root) == {
            key: value for key, value in observation.items() if key not in {'payload_bytes_read', 'max_bytes'}}
    return {'schema': 1, 'case': case, 'variant': variant, 'root': str(root),
            'policy_sha256': policy, 'source_sha256': before, 'evidence_unchanged': unchanged,
            'actual_validation_state': state if unchanged else 'unknown', 'validation_ok': False,
            'complete': False, 'invocation_nonce': os.environ.get('HARNESS_EVAL_NONCE'),
            'invocation_sha256': os.environ.get('HARNESS_EVAL_INVOCATION_SHA256'), 'observation': observation}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--case', choices=CASES, required=True)
    parser.add_argument('--variant', choices=VARIANTS, default='pilot')
    args = parser.parse_args()
    try:
        report = observe(args.case, args.variant)
    except (OSError, ValueError):
        print(json.dumps({'error': 'bounded probe unavailable'}))
        return 2
    print(json.dumps(report, sort_keys=True))
    return 1  # Expected failure handling is never positive validation.


if __name__ == '__main__':
    raise SystemExit(main())
