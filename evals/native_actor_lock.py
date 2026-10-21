"""One-use duplicate of the capture's held supervisor lock description."""
from __future__ import annotations

import os
from pathlib import Path
import stat
import threading

from evals.native_cgroup import _require_root_linux

LOCK_PATH = Path('/run/harness-eval-supervisor.lock')


def _lock_identity(stream) -> tuple[int, int]:
    _require_root_linux()
    current, named = os.fstat(stream.fileno()), LOCK_PATH.lstat()
    if not stat.S_ISREG(current.st_mode) or current.st_uid != 0 or current.st_mode & 0o077 \
            or current.st_nlink != 1 or (current.st_dev, current.st_ino) != (named.st_dev, named.st_ino):
        raise ValueError('supervisor lock identity changed')
    return current.st_dev, current.st_ino


class ActorLockLease:
    def __init__(self, capture) -> None:
        self._capture = capture
        self._thread = threading.get_ident()
        self._identity = _lock_identity(capture._lock_stream)
        self._stream = os.fdopen(os.dup(capture._lock_stream.fileno()), 'rb')
        self.consumed = False

    def take(self):
        self._capture._owner_check()
        if threading.get_ident() != self._thread or not self._capture.ready or self._capture._closed \
                or self._stream is None or self.consumed:
            raise ValueError('supervisor lock lease is unavailable')
        if _lock_identity(self._capture._lock_stream) != self._identity \
                or _lock_identity(self._stream) != self._identity:
            raise ValueError('supervisor lock lease identity changed')
        stream = self._stream
        self._stream = None
        self.consumed = True
        return stream

    def close(self) -> None:
        self._capture._owner_check()
        if self._stream is not None:
            self._stream.close()
            self._stream = None
