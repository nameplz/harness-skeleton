from dataclasses import replace
import fcntl
import os
from pathlib import Path
import selectors
import socket
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch

from evals.native_audit_capture import AuditCapture
from evals.native_config import _ConfigExchange
from evals.native_supervisor import SupervisorProcess
from tests import test_native_supervisor as supervisor_tests


class AuditAdmissionTests(unittest.TestCase):
    def test_one_use_lease_shares_flock_until_last_description_is_closed(self):
        with TemporaryDirectory() as temp:
            path=Path(temp)/'lock'
            with path.open('w+b') as original, path.open('r+b') as competitor:
                fcntl.flock(original,fcntl.LOCK_EX|fcntl.LOCK_NB)
                capture=AuditCapture();capture.ready=True;capture._lock_stream=original
                with patch('evals.native_actor_lock._lock_identity',return_value=(1,2)):
                    lease=capture.lock_lease();duplicate=lease.take()
                    with self.assertRaises(ValueError):lease.take()
                    with self.assertRaises(ValueError):capture.lock_lease()
                    original.close()
                    with self.assertRaises(BlockingIOError):fcntl.flock(competitor,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    duplicate.close()
                    fcntl.flock(competitor,fcntl.LOCK_EX|fcntl.LOCK_NB)

    def test_closed_or_no_longer_ready_capture_lease_never_admits(self):
        with TemporaryDirectory() as temp, (Path(temp)/'lock').open('w+b') as stream:
            capture=AuditCapture();capture.ready=True;capture._lock_stream=stream
            with patch('evals.native_actor_lock._lock_identity',return_value=(1,2)):
                lease=capture.lock_lease();capture.ready=False
                with self.assertRaises(ValueError):lease.take()
                lease.close()
            with self.assertRaises(ValueError):capture.lock_lease()

    def test_release_is_one_use_and_requires_fresh_matching_cgroup_and_audit(self):
        binding=supervisor_tests.NativeSupervisorTests();binding.setUp();binding=binding.binding
        for change in (None,'binding','audit'):
            capture=AuditCapture();capture.ready=True;capture._lease=SimpleNamespace(consumed=True)
            process=SupervisorProcess();process.binding=binding;process._closed=False
            process._released=False;process._release_attempted=False;process._rpc=Mock()
            process._audit_lease=capture._lease
            capture._lease._capture=capture
            with patch('evals.native_audit_capture.bind_actor_cgroup',return_value=replace(binding,inode=45) if change=='binding' else binding), \
                    patch.object(capture,'_verify_active',side_effect=ValueError('audit failed') if change=='audit' else None):
                if change:
                    with self.assertRaises(ValueError):capture.release(process)
                    process._rpc.sendall.assert_not_called()
                else:
                    capture.release(process);process._rpc.sendall.assert_called_once_with(b'G')
                    with self.assertRaises(ValueError):capture.release(process)

    def test_audit_selector_drain_has_separate_bounds_and_detaches_before_close(self):
        pairs=[socket.socketpair() for _ in range(3)]
        try:
            process=SimpleNamespace(stdout=pairs[0][0].makefile('rb',buffering=0),stderr=pairs[1][0].makefile('rb',buffering=0))
            capture=Mock();capture.fileno.return_value=pairs[2][0].fileno()
            capture.drain.side_effect=lambda:pairs[2][0].recv(65536)
            exchange=_ConfigExchange(process, __import__('time').monotonic()+1,1)
            exchange.attach_audit(capture)
            with self.assertRaises(ValueError):exchange.attach_audit(capture)
            pairs[2][1].sendall(b'x'*4096);exchange.pump()
            self.assertEqual([0,0],exchange.counts);self.assertEqual(b'',exchange.buffer)
            capture.drain.assert_called_once()
            exchange.detach_audit(capture)
            self.assertEqual(2,len(exchange.selector.get_map()))
            exchange.selector.close();process.stdout.close();process.stderr.close()
        finally:
            for pair in pairs:
                for stream in pair:stream.close()


class AuditSessionOrderTests(unittest.TestCase):
    def test_cleanup_order_and_each_original_baseexception_are_preserved(self):
        from evals.native_audit_session import AuditedSupervisor
        for fault in (None,'finish','detach','capture','process'):
            order=[]
            def operation(name):
                def run(*args):
                    order.append(name)
                    if name==fault:raise KeyboardInterrupt(name)
                return run
            capture=Mock();capture.close.side_effect=operation('capture')
            process=Mock();process.finish_actor.side_effect=operation('finish')
            process.cleanup.side_effect=operation('process')
            exchange=Mock();exchange._audit=capture
            exchange.detach_audit.side_effect=operation('detach')
            exchange.selector.close.side_effect=operation('selector')
            with patch('evals.native_audit_session.AuditCapture',return_value=capture):
                owned=AuditedSupervisor();owned.process=process
                error=owned.cleanup(exchange,failed=True)
            self.assertIsNone(capture.result)
            self.assertEqual(['finish','detach'],order[:2])
            self.assertLess(order.index('capture'),order.index('process'))
            self.assertEqual('selector',order[-1])
            if fault:self.assertIsInstance(error,BaseException)
            else:self.assertIsNone(error)


class AdmissionDrainTests(unittest.TestCase):
    def test_guardian_status_wait_pumps_audit_without_releasing_actor(self):
        import json
        import time
        reader,writer=socket.socketpair()
        try:
            process=SupervisorProcess();process._status=reader;process._buffer=b''
            process._audit_lease=SimpleNamespace(_capture=Mock())
            def drain():
                writer.sendall(b'{"kind":"ready","actor":23,"guardian":10}\n')
            process._audit_lease._capture.drain.side_effect=drain
            result=process._receive(0.1)
            self.assertEqual('ready',json.loads(result)['kind'])
            process._audit_lease._capture.drain.assert_called_once()
        finally:reader.close();writer.close()


class AuditRecoveryTests(unittest.TestCase):
    def test_actor_cleanup_retry_can_restore_audit_after_initial_idle_refusal(self):
        from evals.native_audit_session import AuditedSupervisor
        capture=Mock();capture.restored=False
        attempts=[]
        def close():
            attempts.append('close')
            if len(attempts)==1:raise ValueError('actor still active')
            capture.restored=True
        capture.close.side_effect=close
        with patch('evals.native_audit_session.AuditCapture',return_value=capture):
            owned=AuditedSupervisor();owned.process=Mock()
            owned.process.finish_actor.side_effect=KeyboardInterrupt('first actor cleanup')
            error=owned.cleanup(None,failed=True)
        self.assertIsInstance(error,BaseExceptionGroup)
        self.assertTrue(capture.restored)
        self.assertIsNone(capture.result)
        self.assertEqual(2,len(attempts))

    def test_changed_descriptor_cannot_be_detached_as_a_matching_attachment(self):
        pairs=[socket.socketpair() for _ in range(3)]
        try:
            streams=[pair[0].makefile('rb',buffering=0) for pair in pairs[:2]]
            exchange=_ConfigExchange(SimpleNamespace(stdout=streams[0],stderr=streams[1]),__import__('time').monotonic()+1,1)
            capture=Mock();capture.fileno.return_value=pairs[2][0].fileno()
            exchange.attach_audit(capture);capture.fileno.return_value=9999
            with self.assertRaises(ValueError):exchange.detach_audit(capture)
            exchange.selector.close()
            for stream in streams:stream.close()
        finally:
            for pair in pairs:
                for stream in pair:stream.close()


class ActorLockIdentityTests(unittest.TestCase):
    def test_lock_metadata_must_match_protected_named_regular_inode(self):
        import stat
        from evals.native_actor_lock import _lock_identity
        valid=SimpleNamespace(st_mode=stat.S_IFREG|0o600,st_uid=0,st_nlink=1,st_dev=2,st_ino=3)
        cases=({},{}),({'st_uid':2000},{}),({'st_mode':stat.S_IFIFO|0o600},{}), \
              ({'st_mode':stat.S_IFREG|0o660},{}),({'st_nlink':2},{}),({}, {'st_ino':4})
        for descriptor_changes,named_changes in cases:
            current=SimpleNamespace(**{**vars(valid),**descriptor_changes})
            named=SimpleNamespace(**{**vars(valid),**named_changes})
            with patch('evals.native_actor_lock._require_root_linux'), \
                    patch('evals.native_actor_lock.os.fstat',return_value=current), \
                    patch('evals.native_actor_lock.Path.lstat',return_value=named):
                if descriptor_changes or named_changes:
                    with self.assertRaises(ValueError):_lock_identity(Mock())
                else:self.assertEqual((2,3),_lock_identity(Mock()))

    def test_changed_lease_identity_or_closed_original_does_not_transfer_duplicate(self):
        for changed in ('inode','closed'):
            with TemporaryDirectory() as temp, (Path(temp)/'lock').open('w+b') as original:
                capture=AuditCapture();capture.ready=True;capture._lock_stream=original
                with patch('evals.native_actor_lock._lock_identity',return_value=(2,3)) as identity:
                    lease=capture.lock_lease()
                    if changed=='inode':identity.return_value=(2,4)
                    else:
                        original.close();identity.side_effect=ValueError('closed original')
                    with self.assertRaises(ValueError):lease.take()
                    self.assertFalse(lease.consumed)
                    lease.close()


class RecoveryExposureTests(unittest.TestCase):
    def test_failed_capture_entry_exposes_owner_and_callable_recovery(self):
        from evals.native_audit_session import AuditedSupervisor
        capture=MagicMock();capture.restored=False;capture._closed=False
        original=BaseExceptionGroup('setup rollback failed',[ValueError('setup'),OSError(5,'rollback')])
        capture.__enter__.side_effect=original
        with patch('evals.native_audit_session.AuditCapture',return_value=capture), \
                patch('evals.native_supervisor.start_supervised') as launch:
            owned=AuditedSupervisor()
            with self.assertRaises(BaseExceptionGroup) as raised:
                owned.start((),cwd=Path('/'),environment={},admission_timeout_seconds=1)
        self.assertIs(original,raised.exception)
        self.assertIs(owned,raised.exception.audit_recovery)
        launch.assert_not_called()
        def restored():capture.restored=True;capture._closed=True
        capture.close.side_effect=restored
        raised.exception.audit_recovery.recover()
        self.assertTrue(capture.restored)
        self.assertIsNone(capture.result)

    def test_failed_cleanup_exposes_recovery_without_accepted_result(self):
        from evals.native_audit_session import AuditedSupervisor
        capture=MagicMock();capture.restored=False;capture._closed=False
        capture.close.side_effect=OSError(5,'rollback')
        with patch('evals.native_audit_session.AuditCapture',return_value=capture):
            owned=AuditedSupervisor();owned.process=Mock()
            error=owned.cleanup(None,failed=True)
        self.assertIs(owned,error.audit_recovery)
        self.assertIsNone(capture.result)
        def restored():capture.restored=True;capture._closed=True
        capture.close.side_effect=restored
        error.audit_recovery.recover()
        self.assertTrue(capture.restored)
        self.assertIsNone(capture.result)


    def test_closed_capture_with_failed_process_cleanup_still_retains_owner(self):
        from evals.native_audit_session import AuditedSupervisor
        capture=MagicMock();capture.restored=True;capture._closed=True
        process=Mock();process.cleanup_result=None
        process.cleanup.side_effect=ValueError('process cleanup previously failed')
        with patch('evals.native_audit_session.AuditCapture',return_value=capture):
            owned=AuditedSupervisor();owned.process=process
            error=owned.cleanup(None,failed=True)
        self.assertIs(owned,error.audit_recovery)
        with self.assertRaisesRegex(ValueError,'previously failed'):
            error.audit_recovery.recover()
        self.assertIsNone(process.cleanup_result)
        self.assertIsNone(capture.result)
