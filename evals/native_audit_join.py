"""Bounded exact-key join; object semantics and protected grading remain separate."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import struct
from typing import Callable

from evals.native_audit_events import AuditKey, AuditRecord, AuditSegment
from evals.native_bpf_audit import AUDIT_WIRE, BpfAuditEvent, decode_audit_binding
from evals.native_bpf_generations import TaskAttribution


@dataclass(frozen=True)
class AuditJoinSummary:
    syscalls: int
    seccomp: int
    actor_records: int
    sha256: str


class AuditJoinLedger:
    def __init__(self, *, observer_pid: int, on_action: Callable | None = None,
                 pending_limit: int = 4096) -> None:
        if type(observer_pid) is not int or not 2 <= observer_pid < 2**31 or \
                type(pending_limit) is not int or not 1 <= pending_limit <= 4096 or \
                (on_action is not None and not callable(on_action)):
            raise ValueError('invalid audit join boundary')
        self._observer_pid, self._limit, self._consumer = observer_pid, pending_limit, on_action
        self._audit: dict[AuditKey, AuditSegment] = {}
        self._bindings: dict[AuditKey, dict[int, tuple[BpfAuditEvent, TaskAttribution]]] = {}
        self._closed: set[AuditKey] = set()
        self._counts = {1300: 0, 1326: 0}
        self._actor_records = 0
        self._digest = hashlib.sha256()
        self._failed = self._finished = self._busy = False

    def _available(self) -> None:
        if self._failed or self._finished or self._busy:
            raise ValueError('audit join is unavailable')

    def _admit_key(self, key: AuditKey) -> None:
        if type(key) is not AuditKey or any(type(v) is not int for v in vars(key).values()) or \
                not 0 < key.seconds < 2**63 or not 0 <= key.milli < 1000 or \
                not 0 < key.serial < 2**32 or key in self._closed or \
                len(self._closed) >= 131072 or \
                (key not in self._audit and key not in self._bindings and
                 len(self._audit.keys() | self._bindings.keys()) >= self._limit):
            raise ValueError('invalid, duplicate or excessive audit join key')

    def observe_bpf(self, event: BpfAuditEvent, task: TaskAttribution) -> None:
        self._available()
        try:
            if type(event) is not BpfAuditEvent or any(type(v) is not int for v in vars(event).values()):
                raise ValueError('audit join requires a numeric kernel binding')
            decode_audit_binding(AUDIT_WIRE.pack(*vars(event).values()))
            if type(task) is not TaskAttribution or type(task.token) is not int or \
                    not 1 <= task.token <= 4096 or task.role not in ('guardian', 'launcher', 'actor', 'descendant'):
                raise ValueError('audit binding has no exact task attribution')
            key = AuditKey(event.audit_seconds, event.audit_milli, event.audit_serial)
            self._admit_key(key)
            current = self._bindings.get(key, {})
            if event.audit_type in current:
                raise ValueError('duplicate BPF audit binding')
            self._bindings[key] = {**current, event.audit_type: (event, task)}
            self._try_join(key)
        except BaseException as error:
            self._failed = True
            if isinstance(error, (struct.error, OverflowError)):
                raise ValueError('invalid numeric audit binding') from None
            raise

    def observe_audit(self, segment: AuditSegment) -> None:
        self._available()
        try:
            if type(segment) is not AuditSegment or type(segment.records) is not tuple or \
                    not 0 < len(segment.records) <= 64 or any(type(r) is not AuditRecord for r in segment.records):
                raise ValueError('invalid decoded audit event')
            relevant = [r for r in segment.records if r.kind in (1300, 1326)]
            if not relevant:
                return
            calls = [dict(r.values) for r in relevant if r.kind == 1300]
            if len(calls) == 1 and calls[0].get('euid') != 2000:
                # Audit control can force the observer's own root syscall to be logged.
                if len(relevant) != 1 or calls[0].get('uid') != 0 or calls[0].get('euid') != 0 or \
                        calls[0].get('pid') != self._observer_pid or not any(r.kind == 1305 for r in segment.records):
                    raise ValueError('unexpected nonactor audit syscall')
                return
            key = segment.key
            self._admit_key(key)
            if key in self._audit or len({r.kind for r in relevant}) != len(relevant):
                raise ValueError('duplicate audit event or syscall record')
            self._audit[key] = segment
            self._try_join(key)
        except BaseException:
            self._failed = True
            raise

    @staticmethod
    def _match(record: AuditRecord, event: BpfAuditEvent) -> None:
        row = dict(record.values)
        if row.get('pid') != event.tgid or type(row.get('pid')) is not int:
            raise ValueError('audit TGID differs from exact kernel task')
        if record.kind == 1326:
            if row.get('uid') != 2000 or row.get('gid') != 2000:
                raise ValueError('seccomp identity differs from the actor UID')
            return
        if any(row.get(n) != 2000 for n in ('uid','gid','euid','suid','fsuid','egid','sgid','fsgid')) or \
                row.get('arch') != event.arch or row.get('syscall') != event.syscall_nr:
            raise ValueError('audit syscall identity differs from kernel binding')
        if event.return_valid:
            if type(row.get('success')) is not bool or row['success'] != (event.return_valid == 1) or \
                    type(row.get('exit')) is not int or row['exit'] != event.return_code:
                raise ValueError('audit syscall result differs from kernel binding')
        elif 'success' in row or 'exit' in row:
            raise ValueError('audit invented an unavailable syscall result')

    def _try_join(self, key: AuditKey) -> None:
        segment, bindings = self._audit.get(key), self._bindings.get(key)
        if segment is None or bindings is None:
            return
        records = [r for r in segment.records if r.kind in (1300, 1326)]
        expected = {r.kind for r in records}
        if not bindings.keys() <= expected:
            raise ValueError('BPF binding has no matching audit record type')
        if bindings.keys() != expected:
            return
        tasks = [bindings[r.kind][1] for r in records]
        if any(task != tasks[0] for task in tasks):
            raise ValueError('audit event spans different exact task instances')
        for record in records:
            self._match(record, bindings[record.kind][0])
        if self._consumer is not None:
            self._busy = True
            try:
                self._consumer(segment, tasks[0])
            except Exception:
                raise ValueError('joined audit consumption failed') from None
            finally:
                self._busy = False
        for record in records:
            event, task = bindings[record.kind]
            self._digest.update(json.dumps([asdict(event), asdict(task)],
                sort_keys=True, separators=(',', ':')).encode())
            self._counts[record.kind] += 1
            self._actor_records += task.role in ('actor', 'descendant')
        self._closed.add(key)
        del self._audit[key]
        del self._bindings[key]

    def finish(self) -> AuditJoinSummary:
        self._available()
        self._finished = True
        if self._audit or self._bindings or not self._counts[1300] or not self._actor_records:
            raise ValueError('audit task join is empty or incomplete')
        return AuditJoinSummary(self._counts[1300], self._counts[1326],
                                self._actor_records, self._digest.hexdigest())
