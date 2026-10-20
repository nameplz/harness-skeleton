"""Owned UID audit transport with exact rollback; not action-audit attestation.

The dedicated actor lock spans listener setup, caller-controlled execution and
final drain. The caller must finish all actors before closing this primitive.
Supervisor admission and policy receipts are deliberately not connected yet.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
import os
import secrets
import select
import threading
import time
from typing import Callable

from evals.native_audit_control import (
    AuditChannel, AuditStatus, ControlReceipt, STATUS, GET, SET, ADD_RULE, DEL_RULE, LIST_RULES,
)
from evals.native_audit_events import AuditSegment, AuditSummary
from evals.native_audit_rule import build_rule
from evals.native_audit_wire import HEADER, decode_event, decode_replace
from evals.native_auparse import AuditDecoder
from evals.native_cgroup import _require_root_linux
from evals.native_supervisor import _idle_actor_uid, _lock

BACKLOG_LIMIT = 8192
STATUS_FIELDS = {'enabled': (1, 1), 'pid': (4, 3), 'backlog_limit': (16, 5)}


@dataclass(frozen=True)
class AuditCaptureResult:
    baseline: AuditStatus
    final: AuditStatus
    rule_sha256: str
    events: AuditSummary
    controls: tuple[ControlReceipt, ...]
    replacement_notifications: int


class AuditCapture:
    def __init__(self, *, on_event: Callable[[AuditSegment], None] | None = None) -> None:
        self._owner = threading.get_ident()
        self._consumer = on_event
        self._lock_stream = self._listener = self._decoder = self._rule = self._baseline = None
        self._receipts: tuple[ControlReceipt, ...] = ()
        self._attempted: frozenset[str] = frozenset()
        self._listener_usable = self._parse_failed = self._foreign = False
        self._releasing_pid = False
        self._replacements = 0
        self._started = self._closed = False
        self.ready = self.restored = False
        self.result: AuditCaptureResult | None = None

    def _owner_check(self) -> None:
        if threading.get_ident() != self._owner:
            raise ValueError('audit capture is owned by another thread')

    def __enter__(self) -> AuditCapture:
        self._owner_check()
        if self._started or self._closed:
            raise ValueError('audit capture cannot be reused')
        self._started = True
        _require_root_linux()
        try:
            self._lock_stream = _lock()
            _idle_actor_uid()
            baseline = self._status()
            if not baseline.pristine or self._rules():
                raise ValueError('audit baseline is not pristine')
            self._baseline = baseline
            self._rule = build_rule()
            self._rule.validate()
            self._decoder = AuditDecoder(key=secrets.token_bytes(32), on_event=self._consumer)
            self._listener = AuditChannel().__enter__()
            self._set('pid', os.getpid(), listener=True)
            self._listener_usable = True
            self._set('backlog_limit', BACKLOG_LIMIT)
            self._attempted = self._attempted | {'rule'}
            self._control(ADD_RULE, self._rule.payload)
            if self._rules() != (self._rule.payload,):
                raise ValueError('installed audit rule differs from exact owned rule')
            self._set('enabled', 1)
            expected = {**vars(baseline), 'enabled': 1, 'pid': os.getpid(), 'backlog_limit': BACKLOG_LIMIT}
            if vars(self._status()) != expected:
                raise ValueError('active audit status differs from owned configuration')
            self.ready = True
            return self
        except BaseException as original:
            try:
                self.close()
            except BaseException as cleanup:
                raise BaseExceptionGroup('audit setup and rollback failed', [original, cleanup]) from None
            raise

    def __exit__(self, _kind, original, _trace) -> None:
        try:
            self.close()
        except BaseException as cleanup:
            if original is not None:
                raise BaseExceptionGroup('audit operation and cleanup failed', [original, cleanup]) from None
            raise
        finally:
            if original is not None:
                self.result = None

    def _control(self, kind: int, payload: bytes = b'') -> tuple[bytes, ...]:
        if len(self._receipts) >= 8192:
            raise ValueError('audit control transaction bound exceeded')
        with AuditChannel() as channel:
            result = channel.request(kind, payload, pump=self.drain)
            self._receipts = (*self._receipts, *channel.receipts)
            return result

    def _status(self) -> AuditStatus:
        return AuditStatus.decode(self._control(GET)[0])

    def _rules(self) -> tuple[bytes, ...]:
        return self._control(LIST_RULES)

    def _set(self, field: str, value: int, *, listener: bool = False) -> None:
        mask, index = STATUS_FIELDS[field]
        values = [0] * 11
        values[0], values[index] = mask, value
        self._attempted = self._attempted | {field}
        payload = STATUS.pack(*values)
        if listener:
            self._listener.request(SET, payload)
            self._receipts = (*self._receipts, *self._listener.receipts)
        else:
            self._control(SET, payload)

    def fileno(self) -> int:
        self._owner_check()
        if not self.ready or self._closed:
            raise ValueError('audit capture is not ready')
        return self._listener.fileno()

    def drain(self) -> int:
        self._owner_check()
        if not self._listener_usable or self._closed:
            return 0
        count = 0
        while count < 256:
            try:
                raw, ancillary, flags, address = self._listener.recvmsg()
            except BlockingIOError:
                break
            except BaseException:
                self._parse_failed = True
                raise
            count += 1
            try:
                if type(raw) is bytes and len(raw) >= HEADER.size and HEADER.unpack_from(raw)[1] == 1329:
                    if not self._releasing_pid or self._replacements:
                        raise ValueError('unsolicited or duplicate audit replacement probe')
                    decode_replace(raw, expected_pid=os.getpid(), address=address, flags=flags, ancillary=ancillary)
                    self._replacements += 1
                    continue
                if self._parse_failed:
                    continue  # Drain after integrity failure so rollback can restore the kernel.
                message = decode_event(raw, address=address, flags=flags, ancillary=ancillary)
                self._decoder.consume(message)
            except BaseException:
                self._parse_failed = True
                raise
        return count

    def _verify_active(self) -> None:
        status = self._status()
        expected = {**vars(self._baseline), 'enabled': 1, 'pid': os.getpid(),
                    'backlog_limit': BACKLOG_LIMIT, 'backlog': status.backlog,
                    'backlog_wait_time_actual': status.backlog_wait_time_actual}
        if vars(status) != expected or self._rules() != (self._rule.payload,):
            raise ValueError('active audit configuration continuity is unproven')

    def _remove_owned_rule(self) -> None:
        errors = []
        for attempt in range(3):
            try:
                rules = self._rules()
            except BaseException as error:
                errors.append(error)
                break
            self._foreign = any(rule != self._rule.payload for rule in rules)
            owned = rules.count(self._rule.payload)
            if owned > 1:
                errors.append(ValueError('duplicate owned audit rule'))
                break
            if not owned:
                if rules:
                    errors.append(ValueError('foreign audit rules remain'))
                break
            if attempt == 2:
                errors.append(ValueError('owned audit rule remains after bounded removal'))
                break
            try:
                self._control(DEL_RULE, self._rule.payload)
            except BaseException as error:
                errors.append(error)
        if errors:
            if len(errors) == 1:
                raise errors[0]
            raise BaseExceptionGroup('audit rule removal failed', errors)

    def _restore_field(self, field: str) -> None:
        if field not in self._attempted:
            return
        rules = self._rules()
        if self._foreign or any(rule != self._rule.payload for rule in rules):
            self._foreign = True
            raise ValueError('foreign audit configuration is preserved')
        status = self._status()
        if status.pid not in (0, os.getpid()):
            raise ValueError('audit listener ownership changed')
        mutable = {'enabled', 'pid', 'backlog_limit', 'lost', 'backlog', 'backlog_wait_time_actual'}
        if any(getattr(status, f.name) != getattr(self._baseline, f.name)
               for f in fields(status) if f.name not in mutable):
            raise ValueError('unowned audit status fields changed')
        current, target = getattr(status, field), getattr(self._baseline, field)
        owned = {'enabled': 1, 'pid': os.getpid(), 'backlog_limit': BACKLOG_LIMIT}[field]
        if current not in (target, owned):
            raise ValueError('audit status value no longer belongs to this capture')
        if current != target:
            if field == 'pid':
                self._releasing_pid = True
            self._set(field, target)

    def _final_drain(self) -> None:
        deadline = time.monotonic() + 3
        quiet = 0
        while time.monotonic() < deadline:
            self.drain()
            backlog = self._status().backlog
            readable = False
            if self._listener_usable:
                readable = bool(select.select([self._listener.fileno()], [], [], 0.05)[0])
            quiet = quiet + 1 if backlog == 0 and not readable else 0
            if quiet >= 2:
                return
        raise TimeoutError('audit final drain did not quiesce')

    def close(self) -> None:
        self._owner_check()
        if self._closed:
            if not self.restored:
                raise ValueError('audit capture restoration previously failed')
            return
        errors = []
        was_ready = self.ready
        self.ready = False
        final = summary = None
        def recover(operation):
            try:
                return operation()
            except BaseException as error:
                errors.append(error)
                return None
        if self._baseline is not None:
            # A live actor must remain monitored; keep the listener and lock for retry.
            _idle_actor_uid()
            recover(self._final_drain)
            if was_ready:
                recover(self._verify_active)
            if 'rule' in self._attempted:
                recover(self._remove_owned_rule)
            recover(lambda: self._restore_field('enabled'))
            recover(self._final_drain)
            recover(lambda: self._restore_field('backlog_limit'))
            recover(lambda: self._restore_field('pid'))
            recover(self._final_drain)
            final = recover(self._status)
            rules = recover(self._rules)
            self.restored = final == self._baseline and rules == ()
            if not self.restored:
                errors.append(ValueError('audit baseline restoration is unproven'))
            if was_ready and self._decoder is not None:
                if self._replacements != 1:
                    errors.append(ValueError('owned audit replacement probe is missing'))
                summary = recover(self._decoder.finish)
            if self._parse_failed:
                errors.append(ValueError('audit event decoding failed'))
        if self._baseline is not None and not self.restored:
            if len(errors) == 1:
                raise errors[0]
            raise BaseExceptionGroup('audit restoration requires recovery', errors)
        for resource in (self._decoder, self._listener, self._lock_stream):
            if resource is not None:
                recover(resource.close)
        self._closed = True
        if errors:
            if len(errors) == 1:
                raise errors[0]
            raise BaseExceptionGroup('audit capture cleanup failed', errors)
        if was_ready:
            self.result = AuditCaptureResult(self._baseline, final, self._rule.sha256,
                                             summary, self._receipts, self._replacements)
