"""Fixed Linux actor ownership; trusted root controls preparation and evidence."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import closing, contextmanager
import os
from pathlib import Path
import stat

from evals.native_cgroup import _require_root_linux

DIRECT_PROFILE = 'direct'
SUPERVISED_PROFILE = 'linux-systemd-uid2000'
ACTOR_UID = ACTOR_GID = 2000
MAX_ENTRIES = 4096
MAX_TREE_BYTES = 32 * 1024 * 1024
MAX_TREE_DEPTH = 32
MAX_PATH_BYTES = 4096


def _tree_rows(path: Path, fd: int, depth: int) -> Iterator[tuple[Path, os.stat_result, int]]:
    yield path, os.fstat(fd), depth
    with os.scandir(fd) as entries:
        for entry in entries:
            child = path / entry.name
            metadata = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                child_fd = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                   dir_fd=fd)
                try:
                    current = os.fstat(child_fd)
                    if (metadata.st_dev,metadata.st_ino) != (current.st_dev,current.st_ino):
                        raise ValueError('tree directory changed during traversal')
                    yield from _tree_rows(child, child_fd, depth + 1)
                finally:
                    os.close(child_fd)
            else:
                yield child, metadata, depth + 1


def bounded_tree(root: Path) -> tuple[tuple[Path, os.stat_result], ...]:
    """Stream no-follow directory descriptors with one bound for every entry."""
    from evals.runtime_trace import open_no_symlink
    if not stat.S_ISDIR(root.lstat().st_mode):
        raise ValueError('tree root must be a directory without symlinks')
    fd = open_no_symlink(root, directory=True)
    rows = []; total = 0
    try:
        with closing(_tree_rows(root, fd, 0)) as entries:
            for path, metadata, depth in entries:
                if not stat.S_ISDIR(metadata.st_mode) and not (
                        stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1):
                    raise ValueError('tree entries must be directories or regular single-link files')
                total += metadata.st_size if stat.S_ISREG(metadata.st_mode) else 0
                if len(rows) >= MAX_ENTRIES or total > MAX_TREE_BYTES or depth > MAX_TREE_DEPTH or \
                        len(os.fsencode(path.relative_to(root))) > MAX_PATH_BYTES:
                    raise ValueError('tree exceeds traversal bounds')
                rows.append((path,metadata))
        return tuple(rows)
    finally:
        os.close(fd)


@contextmanager
def actor_slot() -> Iterator[None]:
    """Serialize preparation/inspection against the native launcher's fixed UID."""
    _require_root_linux()
    from evals.native_supervisor import _lock, _idle_actor_uid
    with _lock():
        _idle_actor_uid()
        try:
            yield
        except BaseException as original:
            try:
                _idle_actor_uid()
            except BaseException as cleanup:
                raise BaseExceptionGroup('actor slot cleanup failed', [original, cleanup]) from None
            raise
        else:
            _idle_actor_uid()


def require_profile(profile: str) -> bool:
    if not isinstance(profile, str) or profile not in (DIRECT_PROFILE, SUPERVISED_PROFILE):
        raise ValueError('unknown evaluation execution profile')
    if profile == SUPERVISED_PROFILE:
        _require_root_linux()
        return True
    return False


def expected_uid(profile: str) -> int:
    return ACTOR_UID if require_profile(profile) else os.getuid()


def actor_permissions(metadata: os.stat_result) -> int:
    shift = 6 if metadata.st_uid == ACTOR_UID else 3 if metadata.st_gid == ACTOR_GID else 0
    return (metadata.st_mode >> shift) & 7


def _root_chain(path: Path) -> tuple[os.stat_result, ...]:
    _require_root_linux()
    if not path.is_absolute() or '..' in path.parts or path != path.resolve(strict=True) or any(
            ord(char) < 32 or ord(char) == 127 or char == '*' for char in str(path)):
        raise ValueError('root-controlled path must be canonical')
    metadata = tuple(part.lstat() for part in (path, *path.parents))
    if any(not stat.S_ISDIR(item.st_mode) or item.st_uid != 0 or item.st_mode & 0o022
           for item in metadata):
        raise ValueError('ancestry must remain root-owned and not actor-writable')
    return metadata


def require_private_parent(path: Path) -> None:
    metadata = _root_chain(path)[0]
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise ValueError('evidence parent must be root-private mode0700')


def require_private_file(path: Path) -> None:
    require_private_parent(path.parent)
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_nlink != 1 \
            or stat.S_IMODE(metadata.st_mode) != 0o600:
        raise ValueError('evidence file must be root-private, regular and single-link')


def preflight_workspace(root: Path) -> None:
    require_private_parent(root.parent)
    if not root.is_absolute() or '..' in root.parts or root != root.resolve() or os.path.lexists(root) or any(
            ord(char) < 32 or ord(char) == 127 or char == '*' for char in str(root)):
        raise ValueError('actor fixture requires a fresh canonical directory')
    if any(not actor_permissions(row) & 1 for row in _root_chain(root.parent)[1:]):
        raise ValueError('actor cannot traverse the selected fixture ancestry')


def _seed_entries(root: Path) -> tuple[Path, ...]:
    rows = bounded_tree(root)
    if any(item.st_uid != 0 or item.st_mode & 0o7022 for _, item in rows):
        raise ValueError('seed entries must be root-owned without special or public write modes')
    return tuple(path for path, _ in rows)


def handoff_workspace(root: Path) -> None:
    require_private_parent(root.parent)
    entries = _seed_entries(root)  # Validate the complete private seed before changing any owner.
    for path in reversed(entries):
        os.chown(path, ACTOR_UID, ACTOR_GID, follow_symlinks=False)


def expose_workspace(root: Path) -> None:
    require_private_parent(root.parent)
    if root.lstat().st_uid != ACTOR_UID or not stat.S_ISDIR(root.lstat().st_mode):
        raise ValueError('workspace handoff is incomplete')
    os.chown(root.parent, 0, ACTOR_GID, follow_symlinks=False)
    root.parent.chmod(0o710)
    require_workspace(root)


def require_workspace(root: Path, *, writable: bool = True) -> None:
    parents = _root_chain(root.parent)
    if any(not actor_permissions(row) & 1 for row in parents):
        raise ValueError('actor workspace ancestry is not traversable')
    if not root.is_absolute() or root != root.resolve(strict=True) or any(
            ord(char) < 32 or ord(char) == 127 or char == '*' for char in str(root)):
        raise ValueError('workspace must be canonical')
    metadata = root.lstat()
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError('workspace must be a directory')
    if writable:
        if metadata.st_uid != ACTOR_UID or metadata.st_gid != ACTOR_GID or actor_permissions(metadata) != 7:
            raise ValueError('workspace must belong to the dedicated actor')
    elif metadata.st_uid != 0 or metadata.st_mode & 0o7222 or actor_permissions(metadata) & 5 != 5:
        raise ValueError('review snapshot must be root-owned and actor-readable without write access')


def require_readable_parent(path: Path) -> None:
    if any(not actor_permissions(row) & 1 for row in _root_chain(path)):
        raise ValueError('snapshot ancestry is not actor-traversable')


def snapshot_file_mode(mode: int, profile: str) -> int:
    """Keep original candidate modes in manifests; project copies for their reader."""
    if type(mode) is not int or not 0 <= mode <= 0o777 or mode & 0o7000:
        raise ValueError('snapshot source mode must not contain special permission bits')
    if require_profile(profile):
        return 0o555 if mode & 0o111 else 0o444
    return mode & ~0o222


def require_snapshot(root: Path) -> None:
    require_workspace(root, writable=False)
    for _, metadata in bounded_tree(root):
        required = 5 if stat.S_ISDIR(metadata.st_mode) else 4
        if metadata.st_uid != 0 or metadata.st_mode & 0o7222 or \
                actor_permissions(metadata) & required != required:
            raise ValueError('review entries must remain root-owned, readable and read-only')


def write_host_file(path: Path, raw: bytes, profile: str) -> None:
    if not require_profile(profile):
        with path.open('xb') as stream:
            stream.write(raw)
        return
    require_private_parent(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o600)
        stream.write(raw)
    require_private_file(path)


def require_direct(profile: str) -> None:
    if require_profile(profile):
        # shortcut: enable the collector only with protected supervisor lifecycle receipts.
        raise ValueError('supervised profile collection requires protected lifecycle receipt integration')
