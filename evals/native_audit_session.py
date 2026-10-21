"""Supervised audit transport lifecycle; no semantic audit or grader attestation."""
from __future__ import annotations

import os

from evals.native_audit_capture import AuditCapture
from evals.native_audit_join import AuditJoinLedger
from evals.native_bpf_observer import BpfObserver


class AuditedSupervisor:
    def __init__(self) -> None:
        self._join = AuditJoinLedger(observer_pid=os.getpid())
        self.audit_join = None
        self.capture = AuditCapture(on_event=self._join.observe_audit)
        self.process = None
        self.bpf = None
        self._failed = False

    def start(self, command, *, cwd, environment, admission_timeout_seconds):
        entered = False
        try:
            self.capture.__enter__()
            entered = True
            self.bpf = BpfObserver(on_audit=self._join.observe_bpf,
                audit_pump=self.capture.drain)
            self.bpf.start()
            from evals.native_supervisor import start_supervised
            self.process = start_supervised(command, cwd=cwd, environment=environment,
                admission_timeout_seconds=admission_timeout_seconds,
                lock_lease=self.capture.lock_lease(), defer_release=True, bpf_pump=self.bpf.drain)
            return self.process
        except BaseException as original:
            if entered:
                cleanup = self.cleanup(None, failed=True)
                if cleanup is not None:
                    raise self.retain_recovery(BaseExceptionGroup(
                        'audited supervisor startup and cleanup failed', [original, cleanup])) from None
            raise self.retain_recovery(original)

    def retain_recovery(self, error: BaseException) -> BaseException:
        if getattr(self.capture, '_closed', False) is False or (self.bpf is not None and not self.bpf._closed) or (self.process is not None
                and getattr(self.process, 'cleanup_result', None) is None):
            error.audit_recovery = self
        return error

    def recover(self) -> None:
        error = self.cleanup(None, failed=True)
        if error is not None:
            raise error

    def release(self, exchange) -> None:
        exchange.attach_audit(self.capture)
        exchange.attach_bpf(self.bpf)
        self.bpf.bind(self.process.binding)
        if not self.bpf.ready:
            raise ValueError('supervised actor lacks BPF admission')
        self.capture.release(self.process)

    def _finish_join(self) -> None:
        if self.bpf is None or not self.bpf._closed or self.bpf.result is None or \
                not self.capture.restored or self.capture.result is None or \
                self.process.cleanup_result is None:
            raise ValueError('exact audit join lacks completed capture and cleanup')
        self.audit_join = self._join.finish()

    def cleanup(self, exchange, *, failed: bool) -> BaseException | None:
        failures = []
        self._failed = self._failed or failed
        def recover(operation):
            try:
                operation()
            except BaseException as error:
                failures.append(error)
        if self._failed and self.bpf is not None and not self.bpf._finished and not self.bpf._closed:
            recover(self.bpf.abort)
        if self.process is not None:
            recover(self.process.finish_actor)
        if self.bpf is not None:
            if self.bpf._capturing and not self.bpf._finished and not self.bpf._closed:
                recover(self.bpf.finish)
            if exchange is not None and exchange._bpf is self.bpf:
                before = len(failures)
                recover(lambda: exchange.detach_bpf(self.bpf))
                if len(failures) != before:
                    recover(exchange.selector.close)
            recover(self.bpf.close)
        bpf_closed = self.bpf is None or self.bpf._closed
        if not bpf_closed and not failures:
            failures.append(ValueError('BPF resource release remains unproven'))
        if exchange is not None and exchange._audit is self.capture:
            before = len(failures)
            recover(lambda: exchange.detach_audit(self.capture))
            if len(failures) != before:
                recover(exchange.selector.close)
        if bpf_closed:
            recover(self.capture.close)
        if self.process is not None:
            if bpf_closed:
                self.process._bpf_pump = None
            recover(self.process.cleanup)
        if bpf_closed and self.capture.restored is False:
            recover(self.capture.close)
        if exchange is not None:
            recover(exchange.selector.close)
        self._failed = self._failed or bool(failures)
        if not self._failed and self.process is not None and self.audit_join is None:
            recover(self._finish_join)
        self._failed = self._failed or bool(failures)
        if self._failed:
            self.audit_join = None
            self.capture.result = None
            if self.bpf is not None:
                self.bpf.result = None
        if failures:
            if len(failures) == 1:
                return self.retain_recovery(failures[0])
            return self.retain_recovery(BaseExceptionGroup('audited supervisor cleanup failed', failures))
        return None
