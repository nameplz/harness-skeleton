"""Supervised audit transport lifecycle; no semantic audit or grader attestation."""
from __future__ import annotations

from evals.native_audit_capture import AuditCapture


class AuditedSupervisor:
    def __init__(self) -> None:
        self.capture = AuditCapture()
        self.process = None

    def start(self, command, *, cwd, environment, admission_timeout_seconds):
        entered = False
        try:
            self.capture.__enter__()
            entered = True
            from evals.native_supervisor import start_supervised
            self.process = start_supervised(command, cwd=cwd, environment=environment,
                admission_timeout_seconds=admission_timeout_seconds,
                lock_lease=self.capture.lock_lease(), defer_release=True)
            return self.process
        except BaseException as original:
            if entered:
                try:
                    self.capture.__exit__(type(original), original, original.__traceback__)
                except BaseException as cleanup:
                    raise self.retain_recovery(cleanup)
            raise self.retain_recovery(original)

    def retain_recovery(self, error: BaseException) -> BaseException:
        if getattr(self.capture, '_closed', False) is False or (self.process is not None
                and getattr(self.process, 'cleanup_result', None) is None):
            error.audit_recovery = self
        return error

    def recover(self) -> None:
        error = self.cleanup(None, failed=True)
        if error is not None:
            raise error

    def release(self, exchange) -> None:
        exchange.attach_audit(self.capture)
        self.capture.release(self.process)

    def cleanup(self, exchange, *, failed: bool) -> BaseException | None:
        failures = []
        def recover(operation):
            try:
                operation()
            except BaseException as error:
                failures.append(error)
        if self.process is not None:
            recover(self.process.finish_actor)
        if exchange is not None and exchange._audit is self.capture:
            before = len(failures)
            recover(lambda: exchange.detach_audit(self.capture))
            if len(failures) != before:
                recover(exchange.selector.close)
        recover(self.capture.close)
        if self.process is not None:
            recover(self.process.cleanup)
        if self.capture.restored is False:
            recover(self.capture.close)
        if exchange is not None:
            recover(exchange.selector.close)
        if failed or failures:
            self.capture.result = None
        if failures:
            if len(failures) == 1:
                return self.retain_recovery(failures[0])
            return self.retain_recovery(BaseExceptionGroup('audited supervisor cleanup failed', failures))
        return None
