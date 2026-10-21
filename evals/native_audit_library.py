"""Root-controlled descriptor pinning for audit and the qualified libbpf ABI."""

import ctypes as C
import hashlib
import os
from pathlib import Path
import platform
import stat
import threading

_loaded: dict[tuple[str, str], tuple[object, int, tuple[int, int]]] = {}
_load_lock = threading.Lock()
BPF_LIBRARY = ('/usr/lib/aarch64-linux-gnu/libbpf.so.1.3.0',
               'bbd39c9b5a29fd87a828a66ec097e25301dfb5af2694788a4de385570b22e1bc')


def load_library(path: Path, digest: str):
    with _load_lock:
        return _load(path, digest)


def _load(path: Path, digest: str):
    from evals.native_cgroup import _require_root_linux
    from evals.runtime_access import _root_chain
    from evals.runtime_trace import open_no_symlink
    _require_root_linux()
    if platform.machine() != 'aarch64':
        raise ValueError('audit library requires pinned Linux ARM64 ABI')
    _root_chain(path.parent)
    fd = open_no_symlink(path)
    retained = False
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022 or \
                not 0 < metadata.st_size <= 2 * 1024 * 1024:
            raise ValueError('audit library is not root-controlled')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            actual = hashlib.file_digest(stream, 'sha256').hexdigest()
        if actual != digest:
            raise ValueError('audit library differs from pin')
        key, identity = (str(path), digest), (metadata.st_dev, metadata.st_ino)
        if key in _loaded:
            library, previous_fd, previous_identity = _loaded[key]
            held = os.fstat(previous_fd)
            if previous_identity != identity or (held.st_dev, held.st_ino) != identity:
                raise ValueError('mapped audit library inode changed')
            return library
        if key != BPF_LIBRARY and sum(item != BPF_LIBRARY for item in _loaded) >= 2:
            raise ValueError('audit library handle bound exceeded')
        library = C.CDLL(f'/proc/self/fd/{fd}', use_errno=True)
        # dlopen caches fd pathnames: retain names until process exit to prevent aliases.
        _loaded[key] = (library, fd, identity)
        retained = True
        return library
    finally:
        if not retained:
            os.close(fd)
