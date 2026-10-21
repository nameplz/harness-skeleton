"""Bounded in-memory audit completeness ledger; not OS action attestation.

Only the event envelope is parsed here. Audit fields come from pinned auparse.
Trusted consumers may inspect ephemeral records; persist only the projection.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field, replace
import hashlib
import hmac
import json
import re
import struct
from typing import Callable

from evals.native_audit_wire import KernelMessage, MAX_EVENT

TYPE_NAMES = {
    1130: b'SERVICE_START', 1131: b'SERVICE_STOP',
    1300: b'SYSCALL', 1302: b'PATH', 1305: b'CONFIG_CHANGE',
    1306: b'SOCKADDR', 1307: b'CWD', 1309: b'EXECVE', 1317: b'FD_PAIR',
    1320: b'EOE', 1321: b'BPRM_FCAPS', 1322: b'CAPSET', 1323: b'MMAP',
    1326: b'SECCOMP', 1327: b'PROCTITLE', 1334: b'BPF', 1337: b'OPENAT2',
}
HEADER = re.compile(rb'audit\((0|[1-9][0-9]{0,18})\.([0-9]{3}):(0|[1-9][0-9]{0,19})\):')
CONTROL_SETTINGS = frozenset(('audit_enabled', 'audit_failure', 'audit_pid', 'audit_rate_limit',
    'audit_backlog_limit', 'audit_backlog_wait_time', 'lost', 'backlog_wait_time_actual'))


def validate_control(values: dict[str, int | bool | bytes]) -> None:
    """Validate supported Linux6.8 record forms; this proves no control ownership."""
    operation, result = values.get('op'), values.get('res')
    if type(operation) is not bytes or type(result) is not int or result not in (0, 1):
        raise ValueError('audit control operation or result is incomplete')
    settings = CONTROL_SETTINGS & values.keys()
    if operation in (b'add_rule', b'remove_rule'):
        if type(values.get('list')) is not int or not 0 <= values['list'] < 8 or settings or 'old' in values:
            raise ValueError('audit rule-change fields are incomplete')
    elif operation == b'set':
        if len(settings) != 1 or 'list' in values or any(type(values.get(name)) is not int or
                not 0 <= values[name] < 2**32 for name in (*settings, 'old')):
            raise ValueError('audit status-change fields are incomplete')
    else:
        raise ValueError('unsupported audit control operation')


def validate_service(values: dict[str, int | bool | bytes]) -> None:
    required = {'pid', 'uid', 'auid', 'ses', 'unit', 'success'}
    if not required <= values.keys() or type(values['success']) is not bool \
            or type(values['unit']) is not bytes or not values['unit'] or any(
                type(values[name]) is not int or not 0 <= values[name] < 2**32
                for name in ('uid', 'auid', 'ses')) or type(values['pid']) is not int \
            or not 1 <= values['pid'] < 2**31:
        raise ValueError('audit service fields are incomplete or unsupported')


def validate_bpf(values: dict[str, int | bool | bytes]) -> None:
    if set(values) != {'prog_id', 'op'} or type(values['prog_id']) is not int \
            or not 0 <= values['prog_id'] < 2**32 or values['op'] not in (b'LOAD', b'UNLOAD'):
        raise ValueError('audit BPF fields are incomplete or unsupported')


@dataclass(frozen=True, order=True)
class AuditKey:
    seconds: int
    milli: int
    serial: int


@dataclass(frozen=True)
class AuditRecord:
    kind: int
    values: tuple[tuple[str, int | bool | bytes], ...] = field(repr=False)


@dataclass(frozen=True)
class AuditSegment:
    key: AuditKey
    records: tuple[AuditRecord, ...] = field(repr=False)


@dataclass(frozen=True)
class AuditLimits:
    pending: int = 4096
    records: int = 64
    events: int = 131072
    frames: int = 1048576
    bytes: int = 128 * 1024 * 1024


@dataclass(frozen=True)
class AuditSummary:
    events: int
    frames: int
    bytes: int
    types: tuple[tuple[int, int], ...]
    stream_hmac: str
    events_hmac: str

    def projection(self) -> dict[str, object]:
        return {'events': self.events, 'frames': self.frames, 'bytes': self.bytes,
                'types': [list(row) for row in self.types],
                'stream_hmac': self.stream_hmac, 'events_hmac': self.events_hmac}


@dataclass(frozen=True)
class _Pending:
    types: tuple[int, ...] = ()
    records: tuple[AuditRecord, ...] = field(default=(), repr=False)
    eoe: bool = False


def _key_valid(key: AuditKey) -> bool:
    return type(key) is AuditKey and all(type(v) is int for v in (
        key.seconds, key.milli, key.serial)) and 0 <= key.seconds < 2**63 and \
        0 <= key.milli < 1000 and 0 <= key.serial < 2**64


class EventLedger:
    """One receiver owns this state; callbacks execute synchronously on it."""

    def __init__(self, *, key: bytes, on_event: Callable[[AuditSegment], None] | None = None,
                 limits: AuditLimits = AuditLimits()) -> None:
        if type(key) is not bytes or len(key) != 32 or type(limits) is not AuditLimits or \
                any(type(v) is not int or not 0 < v <= getattr(AuditLimits(), name)
                    for name, v in vars(limits).items()) or \
                (on_event is not None and not callable(on_event)):
            raise ValueError('invalid audit ledger configuration')
        self._key = key
        self._consumer = on_event
        self._limits = limits
        self._pending: dict[AuditKey, _Pending] = {}
        self._closed: set[AuditKey] = set()
        self._stream = hmac.new(key, b'audit-stream-v1', hashlib.sha256)
        self._events = hmac.new(key, b'audit-events-v1', hashlib.sha256)
        self._types: Counter[int] = Counter()
        self._frames = self._bytes = 0
        self._failed = self._finished = False
        self._dispatching = False

    def _active(self) -> None:
        if self._failed or self._finished or self._dispatching:
            raise ValueError('audit ledger is unavailable')

    def record(self, message: KernelMessage) -> bytes | None:
        """Register a validated kernel frame before feeding the returned auparse line."""
        self._active()
        try:
            return self._record(message)
        except BaseException:
            self._failed = True
            raise

    def _record(self, message: KernelMessage) -> bytes | None:
        if type(message) is not KernelMessage or type(message.kind) is not int or \
                message.kind not in TYPE_NAMES or type(message.sequence) is not int or \
                message.sequence != 0 or type(message.flags) is not int or message.flags != 0 or \
                type(message.payload) is not bytes or \
                not 0 < len(message.payload) <= MAX_EVENT:
            raise ValueError('invalid audit event frame')
        body = message.payload.removesuffix(b'\0')
        match = HEADER.match(body)
        if not match or any(v in body for v in (b'\0', b'\n', b'\r')):
            raise ValueError('invalid audit event envelope')
        key = AuditKey(*(int(value) for value in match.groups()))
        tail = body[match.end():]
        if not _key_valid(key) or key in self._closed or \
                (message.kind == 1320 and tail.strip(b' ')) or \
                (message.kind != 1320 and not tail.startswith(b' ')):
            raise ValueError('audit event identity or terminator differs')
        current = self._pending.get(key, _Pending())
        if current.eoe or len(current.types) >= self._limits.records or \
                self._frames >= self._limits.frames or \
                self._bytes + len(message.payload) > self._limits.bytes or \
                (key not in self._pending and (len(self._pending) >= self._limits.pending or
                 len(self._closed) + len(self._pending) >= self._limits.events)):
            raise ValueError('audit stream exceeded its bound or reused an event')
        self._frames += 1
        self._bytes += len(message.payload)
        self._types[message.kind] += 1
        self._stream.update(struct.pack('!HI', message.kind, len(message.payload)))
        self._stream.update(message.payload)
        self._pending[key] = replace(current, types=(*current.types, message.kind),
                                      eoe=message.kind == 1320)
        self._maybe_emit(key)
        if message.kind == 1320:
            return None  # EOE is authoritative outside auparse, including partial callbacks.
        return b'type=' + TYPE_NAMES[message.kind] + b' msg=' + body + b'\n'

    def segment(self, segment: AuditSegment) -> None:
        self._active()
        try:
            self._segment(segment)
        except BaseException:
            self._failed = True
            raise

    def _segment(self, segment: AuditSegment) -> None:
        if type(segment) is not AuditSegment or not _key_valid(segment.key) or \
                segment.key not in self._pending or type(segment.records) is not tuple or \
                not 0 < len(segment.records) <= self._limits.records:
            raise ValueError('invalid audit callback identity or size')
        current = self._pending[segment.key]
        records = (*current.records, *segment.records)
        for record in segment.records:
            if type(record) is not AuditRecord or type(record.kind) is not int or \
                    record.kind not in TYPE_NAMES or record.kind == 1320 or \
                    type(record.values) is not tuple or len(record.values) > 32:
                raise ValueError('invalid audit callback record')
            names = set()
            for pair in record.values:
                if type(pair) is not tuple or len(pair) != 2:
                    raise ValueError('invalid audit callback field')
                name, value = pair
                if type(name) is not str or not re.fullmatch('[a-z0-9_]{1,32}', name) or \
                        name in names or type(value) not in (int, bool, bytes) or \
                        (type(value) is bytes and len(value) > MAX_EVENT) or \
                        (type(value) is int and not -2**63 <= value < 2**64):
                    raise ValueError('invalid audit callback value')
                names.add(name)
            if record.kind == 1305:
                validate_control(dict(record.values))
            elif record.kind == 1334:
                validate_bpf(dict(record.values))
            elif record.kind in (1130, 1131):
                validate_service(dict(record.values))
        counts = Counter(record.kind for record in records)
        expected = Counter(kind for kind in current.types if kind != 1320)
        if len(records) > self._limits.records or counts[1300] > 1 or \
                any(count > expected[kind] for kind, count in counts.items()):
            raise ValueError('audit callback contains extra or duplicate records')
        self._pending[segment.key] = replace(current, records=records)
        self._maybe_emit(segment.key)

    def _maybe_emit(self, key: AuditKey, *, final: bool = False) -> None:
        current = self._pending[key]
        expected = Counter(kind for kind in current.types if kind != 1320)
        if Counter(record.kind for record in current.records) != expected:
            return
        standalone = expected in tuple(Counter({kind: 1}) for kind in (1130, 1131, 1305, 1334))
        if not current.eoe and not (final and standalone):
            return
        records = current.records
        if not standalone:
            calls = [dict(record.values) for record in records if record.kind == 1300]
            paths = [dict(record.values) for record in records if record.kind == 1302]
            if len(calls) != 1 or type(calls[0].get('items')) is not int or \
                    not 0 <= calls[0]['items'] <= self._limits.records or \
                    any(type(p.get('item')) is not int or type(p.get('name')) is not bytes for p in paths) or \
                    sorted(p['item'] for p in paths) != list(range(calls[0]['items'])):
                raise ValueError('audit syscall or PATH coverage is incomplete')
        event = AuditSegment(key, records)
        projection = {'key': [key.seconds, key.milli, key.serial], 'types': current.types,
                      'records': [[r.kind, [[n, self._project(v)] for n, v in r.values]] for r in records]}
        encoded = json.dumps(projection, sort_keys=True, separators=(',', ':')).encode()
        self._events.update(struct.pack('!I', len(encoded)) + encoded)
        if self._consumer is not None:
            self._dispatching = True
            try:
                self._consumer(event)
            except Exception:
                raise ValueError('audit event consumption failed') from None
            finally:
                self._dispatching = False
        self._closed.add(key)
        del self._pending[key]

    def _project(self, value: int | bool | bytes) -> object:
        if type(value) is bytes:
            return {'hmac': hmac.new(self._key, b'audit-field-v1\0' + value, hashlib.sha256).hexdigest()}
        return value

    def finish(self) -> AuditSummary:
        """Call only after auparse flush and an empty feed buffer; cannot be reused."""
        self._active()
        try:
            for key in tuple(self._pending):
                self._maybe_emit(key, final=True)
            if self._pending or not self._closed:
                raise ValueError('audit stream is empty or incomplete')
            self._finished = True
            return AuditSummary(len(self._closed), self._frames, self._bytes,
                tuple(sorted(self._types.items())), self._stream.hexdigest(), self._events.hexdigest())
        except BaseException:
            self._failed = True
            raise
