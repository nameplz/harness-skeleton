import socket
import time
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch

from evals.native_audit_session import AuditedSupervisor
from evals.native_config import _ConfigExchange
from evals.native_supervisor import SupervisorProcess


class BpfSessionTests(unittest.TestCase):
    def test_BPF_pump_without_audit_lease_is_rejected_before_any_spawn_or_path_access(self):
        from pathlib import Path
        from evals.native_supervisor import start_supervised
        with patch('evals.native_supervisor._require_root_linux'), \
                patch('evals.native_supervisor._trusted_file', side_effect=AssertionError('late rejection')) as trusted, \
                patch('evals.native_supervisor._spawn_proxy') as spawn:
            with self.assertRaises(ValueError):
                start_supervised(('/bin/true',), cwd=Path('/srv/actor'), environment={}, bpf_pump=lambda: None)
        trusted.assert_not_called(); spawn.assert_not_called()

    def test_repeat_cleanup_cannot_finalize_join_twice_or_launder_failure(self):
        with patch('evals.native_audit_session.AuditCapture'):
            owner=AuditedSupervisor();owner.bpf=Mock();owner.bpf._closed=True;owner.bpf._finished=True
            owner.capture.restored=True;owner.process=Mock();owner._join=Mock()
            joined=object();owner._join.finish.return_value=joined
            self.assertIsNone(owner.cleanup(None,failed=False));self.assertIs(owner.audit_join,joined)
            self.assertIsNone(owner.cleanup(None,failed=False));owner._join.finish.assert_called_once()
            self.assertIsNone(owner.cleanup(None,failed=True));self.assertIsNone(owner.audit_join)
            self.assertIsNone(owner.cleanup(None,failed=False));owner._join.finish.assert_called_once()
            self.assertIsNone(owner.audit_join)

    def test_real_join_guard_rejects_missing_capture_or_kernel_result(self):
        for missing in ('capture','bpf','cleanup','closed'):
            with self.subTest(missing=missing), patch('evals.native_audit_session.AuditCapture'):
                owner=AuditedSupervisor();owner.bpf=Mock();owner.bpf._closed=True
                owner.bpf.result=object();owner.capture.restored=True;owner.capture.result=object()
                owner.process=Mock();owner.process.cleanup_result=object();owner._join=Mock()
                if missing=='capture':owner.capture.result=None
                elif missing=='bpf':owner.bpf.result=None
                elif missing=='cleanup':owner.process.cleanup_result=None
                else:owner.bpf._closed=False
                with self.assertRaises(ValueError):owner._finish_join()
                owner._join.finish.assert_not_called()
                self.assertIsNone(owner.audit_join)

    def test_final_audit_join_follows_final_decoder_drain_and_process_cleanup(self):
        for failed in (False,True):
            with self.subTest(failed=failed), patch('evals.native_audit_session.AuditCapture') as capture_class:
                owner=AuditedSupervisor();order=[]
                owner.bpf=Mock();owner.bpf._closed=True;owner.bpf._finished=True
                owner.capture.restored=True;owner.capture.close.side_effect=lambda:order.append('audit-final')
                owner.process=Mock();owner.process.cleanup.side_effect=lambda:order.append('process-cleanup')
                owner._join=Mock();owner._join.finish.side_effect=lambda:order.append('join-final') or 'joined'
                error=owner.cleanup(None,failed=failed)
                self.assertIsNone(error)
                self.assertEqual(['audit-final','process-cleanup']+([] if failed else ['join-final']),order)
                self.assertEqual(None if failed else 'joined',owner.audit_join)

    def test_capture_precedes_BPF_and_BPF_binding_precedes_G_release(self):
        order = []
        capture = MagicMock(); capture.__enter__.side_effect = lambda: order.append('audit')
        observer = Mock(); observer.start.side_effect = lambda: order.append('bpf')
        observer.bind.side_effect = lambda binding: order.append('bind'); observer.ready = True
        capture.release.side_effect = lambda process: order.append('G')
        process = Mock()
        with patch('evals.native_audit_session.AuditCapture', return_value=capture), \
                patch('evals.native_audit_session.BpfObserver', return_value=observer), \
                patch('evals.native_supervisor.start_supervised', side_effect=lambda *a, **kw: (order.append('launch'), process)[1]) as launch:
            owner = AuditedSupervisor(); owner.start((), cwd=None, environment={}, admission_timeout_seconds=1)
            owner.release(Mock())
        self.assertEqual(['audit', 'bpf', 'launch', 'bind', 'G'], order)
        self.assertEqual(observer.drain, launch.call_args.kwargs['bpf_pump'])

    def test_unproven_close_cannot_silently_succeed(self):
        capture = MagicMock(); capture._closed = False
        observer = Mock(); observer._closed = False; observer._finished = True
        with patch('evals.native_audit_session.AuditCapture', return_value=capture):
            owner = AuditedSupervisor(); owner.bpf = observer
            error = owner.cleanup(None, failed=False)
        self.assertIsInstance(error, ValueError)
        self.assertIs(owner, error.audit_recovery)
        capture.close.assert_not_called()

    def test_BPF_selector_has_separate_output_budget_and_does_not_hold_transport_open(self):
        pairs = [socket.socketpair() for _ in range(3)]
        streams = [pair[0].makefile('rb', buffering=0) for pair in pairs[:2]]
        self.addCleanup(lambda: [stream.close() for stream in streams])
        self.addCleanup(lambda: [stream.close() for pair in pairs for stream in pair])
        exchange = _ConfigExchange(SimpleNamespace(stdout=streams[0], stderr=streams[1]), time.monotonic()+1, 1)
        self.addCleanup(exchange.selector.close)
        observer = Mock(); observer.fileno.return_value = pairs[2][0].fileno()
        observer.drain.side_effect = lambda: pairs[2][0].recv(65536)
        exchange.attach_bpf(observer)
        with self.assertRaises(ValueError):exchange.attach_bpf(observer)
        pairs[2][1].sendall(b'x'*4096); exchange.pump()
        self.assertEqual([0, 0], exchange.counts)
        for stream in streams:exchange.selector.unregister(stream)
        self.assertFalse(exchange._transport_open())
        observer.fileno.return_value += 100
        with self.assertRaises(ValueError):exchange.detach_bpf(observer)
        observer.fileno.return_value -= 100
        exchange.detach_bpf(observer)
        self.assertFalse(exchange.selector.get_map())

    def test_both_pumps_run_even_when_audit_raises_during_guardian_cleanup(self):
        process = SupervisorProcess()
        audit = Mock(); audit.drain.side_effect = KeyboardInterrupt()
        process._audit_lease = SimpleNamespace(_capture=audit)
        process._bpf_pump = Mock()
        with self.assertRaises(KeyboardInterrupt):process._pump_audit()
        process._bpf_pump.assert_called_once()

    def test_unproven_BPF_close_keeps_original_audit_lock_until_recovery(self):
        capture = MagicMock(); capture._closed = False; capture.restored = False
        observer = Mock(); observer._closed = False; observer._finished = True
        observer.close.side_effect = ValueError('BPF still owned')
        with patch('evals.native_audit_session.AuditCapture', return_value=capture):
            owner = AuditedSupervisor(); owner.bpf = observer; owner.process = Mock()
            error = owner.cleanup(None, failed=True)
        capture.close.assert_not_called()
        self.assertIs(owner, error.audit_recovery)
        def close_bpf():observer._closed = True
        def close_audit():capture._closed = True; capture.restored = True
        observer.close.side_effect = close_bpf; capture.close.side_effect = close_audit
        owner.recover()
        capture.close.assert_called_once()
        self.assertIsNone(observer.result); self.assertIsNone(capture.result)

    def test_parse_failure_with_closed_BPF_still_restores_audit_and_remains_failed(self):
        capture = MagicMock(); capture._closed = False; capture.restored = True
        observer = Mock(); observer._closed = False; observer._finished = False; observer._started = True
        observer.finish.side_effect = ValueError('invalid lifecycle')
        observer.close.side_effect = lambda: setattr(observer, '_closed', True)
        exchange = Mock(); exchange._audit = capture; exchange._bpf = observer
        order = []
        observer.finish.side_effect = lambda: (order.append('finish'), (_ for _ in ()).throw(ValueError('invalid lifecycle')))[1]
        exchange.detach_bpf.side_effect = lambda b: order.append('detach')
        observer.close.side_effect = lambda: (order.append('close'), setattr(observer, '_closed', True))
        capture.close.side_effect = lambda: order.append('audit')
        with patch('evals.native_audit_session.AuditCapture', return_value=capture):
            owner = AuditedSupervisor(); owner.bpf = observer; owner.process = Mock()
            error = owner.cleanup(exchange, failed=False)
        self.assertIsInstance(error, ValueError)
        self.assertEqual(['finish', 'detach', 'close', 'audit'], order)
        self.assertIsNone(capture.result); self.assertIsNone(observer.result)
