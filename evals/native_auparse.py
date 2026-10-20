"""Pinned Linux ARM64 libauparse feed adapter; raw fields never leave memory.

This decodes authenticated KernelMessages, not logs supplied by the candidate.
Completeness is separate from PID/cgroup attribution and action classification.
"""

from __future__ import annotations

import ctypes as C
from pathlib import Path
import re
import threading
from typing import Callable

from evals.native_audit_events import (
    AuditKey, AuditLimits, AuditRecord, AuditSegment, AuditSummary, EventLedger,
    CONTROL_SETTINGS, validate_control,
)
from evals.native_audit_wire import KernelMessage
from evals.native_audit_library import load_library

LIBRARY = Path('/usr/lib/aarch64-linux-gnu/libauparse.so.0.0.0')
LIBRARY_SHA256 = '77e749f8cd1843b65e47ce398f3fe3daead49f5af8df4f157cddd24d57d162c5'
CALLBACK = C.CFUNCTYPE(None, C.c_void_p, C.c_int, C.c_void_p)
SYSCALL_REQUIRED = frozenset(('arch', 'syscall', 'a0', 'a1', 'a2', 'a3',
    'items', 'pid', 'ppid', 'uid', 'gid', 'euid', 'suid', 'fsuid', 'egid', 'sgid', 'fsgid'))
DECIMAL = frozenset(('syscall', 'items', 'pid', 'ppid', 'uid', 'gid', 'euid', 'suid',
    'fsuid', 'egid', 'sgid', 'fsgid', 'auid', 'ses', 'item', 'inode', 'ouid', 'ogid',
    'fd0', 'fd1', 'list', 'res', 'code', 'sig', 'old')) | CONTROL_SETTINGS
HEX = frozenset(('arch', 'a0', 'a1', 'a2', 'a3'))
FIELDS = {
    1300: SYSCALL_REQUIRED | {'success', 'exit', 'auid', 'ses', 'exe', 'key'},
    1302: frozenset(('item', 'name', 'nametype', 'inode', 'dev', 'mode', 'ouid', 'ogid', 'rdev')),
    1305: frozenset(('uid', 'auid', 'ses', 'op', 'key', 'list', 'res', 'old')) | CONTROL_SETTINGS,
    1306: frozenset(('saddr',)), 1307: frozenset(('cwd',)),
    1317: frozenset(('fd0', 'fd1')), 1323: frozenset(('fd', 'flags')),
    1326: frozenset(('arch', 'syscall', 'pid', 'uid', 'gid', 'sig', 'code')),
    1337: frozenset(('oflag', 'mode', 'resolve')),
}
INTERPRETED = frozenset(('exe', 'key', 'name', 'cwd'))


def _library():
    return load_library(LIBRARY, LIBRARY_SHA256)


def _bind(lib, name: str, result, args):
    function = getattr(lib, 'auparse_' + name)
    function.restype = result
    function.argtypes = args
    return function


def _value(name: str, raw: bytes) -> int | bool | bytes:
    if type(raw) is not bytes or not 0 < len(raw) <= 8192:
        raise ValueError('invalid audit field length')
    if name == 'success':
        if raw not in (b'yes', b'no'):
            raise ValueError('invalid audit syscall success')
        return raw == b'yes'
    if name in DECIMAL or name in HEX or name in ('exit', 'fd', 'mode', 'oflag', 'flags', 'resolve'):
        pattern, base, limit = rb'[0-9]{1,20}', 10, 2**64
        if name in HEX:
            pattern, base = rb'[0-9a-fA-F]{1,16}', 16
        elif name in ('mode', 'oflag'):
            pattern, base = rb'0[0-7]{0,22}', 8
        elif name in ('flags', 'resolve'):
            pattern, base = rb'0x[0-9a-fA-F]{1,16}', 16
        elif name in ('exit', 'fd'):
            pattern, limit = rb'-?[0-9]{1,19}', 2**63
        if not re.fullmatch(pattern, raw):
            raise ValueError('invalid audit numeric field')
        value = int(raw, base)
        maximum = 64 if name in ('items', 'item') else 2**31-1 if name in ('pid', 'ppid') else limit-1
        if not -2**63 <= value <= maximum:
            raise ValueError('audit numeric field exceeded its bound')
        return value
    if name == 'saddr':
        if len(raw) > 512 or len(raw) % 2 or not re.fullmatch(rb'[0-9a-fA-F]+', raw):
            raise ValueError('invalid audit socket address')
        return bytes.fromhex(raw.decode('ascii'))
    return raw


class AuditDecoder:
    """A single receiver thread owns feed, callback, finish and close."""

    def __init__(self, *, key: bytes, on_event: Callable[[AuditSegment], None] | None = None,
                 limits: AuditLimits = AuditLimits()) -> None:
        self._ledger = EventLedger(key=key, on_event=on_event, limits=limits)
        self._owner = threading.get_ident()
        self._failed = self._busy = self._finished = False
        self._interrupt: BaseException | None = None
        self._au = None
        self._lib = _library()
        self._api = {}
        P, I, U, S = C.c_void_p, C.c_int, C.c_uint, C.c_char_p
        signatures = {
            'init': (P, [I, P]), 'destroy': (None, [P]), 'feed': (I, [P, S, C.c_size_t]),
            'flush_feed': (I, [P]), 'feed_has_data': (I, [P]),
            'add_callback': (None, [P, CALLBACK, P, P]), 'set_escape_mode': (None, [P, I]),
            'get_time': (C.c_long, [P]), 'get_milli': (U, [P]), 'get_serial': (C.c_ulong, [P]),
            'get_num_records': (U, [P]), 'get_type': (I, [P]),
            **{n: (I, [P]) for n in ('first_record', 'next_record', 'first_field', 'next_field')},
            **{n: (S, [P]) for n in ('get_field_name', 'get_field_str', 'interpret_field')},
        }
        self._api = {name: _bind(self._lib, name, result, args)
                     for name, (result, args) in signatures.items()}
        self._callback_handle = CALLBACK(self._callback)
        self._au = self._api['init'](7, None)
        if not self._au:
            raise ValueError('audit parser initialization failed')
        try:
            self._api['set_escape_mode'](self._au, 0)  # Preserve actual pathname bytes.
            self._api['add_callback'](self._au, self._callback_handle, None, None)
        except BaseException:
            self.close()
            raise

    def __enter__(self) -> AuditDecoder:
        self._check()
        return self

    def __exit__(self, *_args) -> None:
        self.close()

    def _check(self) -> None:
        if threading.get_ident() != self._owner or self._busy or not self._au or self._finished:
            raise ValueError('audit parser is closed, reentered or owned by another thread')
        if self._interrupt is not None:
            interrupt, self._interrupt = self._interrupt, None
            raise interrupt
        if self._failed:
            raise ValueError('audit parser failed')

    def _call(self, name: str, *args) -> int:
        self._busy = True
        try:
            result = self._api[name](self._au, *args)
        finally:
            self._busy = False
        self._check()
        if result != 0:
            raise ValueError('audit parser operation failed')
        return result

    def _callback(self, au, kind, _user) -> None:
        if self._failed:
            return
        try:
            if au != self._au or kind != 0 or not self._busy:
                raise ValueError('invalid audit callback')
            key = AuditKey(self._api['get_time'](au), self._api['get_milli'](au), self._api['get_serial'](au))
            count = self._api['get_num_records'](au)
            if not 0 < count <= 64 or self._api['first_record'](au) != 1:
                raise ValueError('invalid audit callback record count')
            records = []
            for index in range(count):
                kind = self._api['get_type'](au)
                records.append(AuditRecord(kind, self._fields(au, kind)))
                if self._api['next_record'](au) != int(index + 1 < count):
                    raise ValueError('audit callback record traversal differs')
            self._ledger.segment(AuditSegment(key, tuple(records)))
        except Exception:
            self._failed = True  # Never retain raw exception messages/tracebacks from C fields.
        except BaseException as error:
            self._failed = True
            self._interrupt = error

    def _fields(self, au, kind: int) -> tuple[tuple[str, int | bool | bytes], ...]:
        wanted = FIELDS.get(kind, frozenset())
        if not wanted:
            return ()  # EXECVE/PROCTITLE/comm/env/buffers are never traversed.
        values = {}
        step = self._api['first_field'](au)
        for _ in range(128):
            if step == 0:
                break
            if step != 1:
                raise ValueError('audit field traversal failed')
            raw_name = self._api['get_field_name'](au)
            name = raw_name.decode('ascii') if type(raw_name) is bytes and len(raw_name) <= 32 else ''
            if name in wanted:
                if name in values:
                    raise ValueError('duplicate audit field')
                api = 'interpret_field' if name in INTERPRETED else 'get_field_str'
                values[name] = _value(name, self._api[api](au))
            step = self._api['next_field'](au)
        else:
            raise ValueError('audit field count exceeded its bound')
        required = SYSCALL_REQUIRED if kind == 1300 else {'item', 'name', 'nametype'} if kind == 1302 else \
            {'cwd'} if kind == 1307 else {'saddr'} if kind == 1306 else set()
        if not required <= values.keys():
            raise ValueError('required audit fields are missing')
        if kind == 1300 and ('success' in values) != ('exit' in values):
            raise ValueError('audit syscall return fields are incomplete')
        if kind == 1305:
            validate_control(values)
        # Kernel task exit may omit both; never invent an outcome for that event.
        return tuple(values.items())

    def consume(self, message: KernelMessage) -> None:
        self._check()
        try:
            line = self._ledger.record(message)
            if line is not None:
                self._call('feed', line, len(line))
        except BaseException:
            self._failed = True
            raise

    def finish(self) -> AuditSummary:
        self._check()
        try:
            self._call('flush_feed')
            if self._api['feed_has_data'](self._au) != 0:
                raise ValueError('audit parser retained incomplete data')
            result = self._ledger.finish()
            self._finished = True
            return result
        except BaseException:
            self._failed = True
            raise

    def close(self) -> None:
        if threading.get_ident() != self._owner or self._busy:
            raise ValueError('audit parser cannot close during callback or from another thread')
        if self._au:
            self._api['destroy'](self._au)
            self._au = None
