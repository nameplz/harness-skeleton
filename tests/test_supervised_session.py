from dataclasses import asdict
import errno
import hashlib
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from evals.native_config import BinaryPin, _cleanup as direct_cleanup, trusted_binary_identity, trusted_supervised_binary_identity
from evals.native_session import NativeSessionError, inspect_native_session, native_session
from tests import test_native_session


class FakeAuditCapture:
    """Transport test double only; real audit/UID/flock qualification is on Linux."""
    def __init__(self, *, on_event=None):
        self._consumer=on_event
        self.reader,self.writer=socket.socketpair()
        self.reader.setblocking(False)
        self.ready=True;self.result=None;self.entered=False;self.released=False;self.restored=False
        self.lease=object()
    def __enter__(self):self.entered=True;return self
    def __exit__(self,*args):self.close()
    def fileno(self):return self.reader.fileno()
    def lock_lease(self):return self.lease
    def release(self,process):self.released=True
    def drain(self):
        try:self.reader.recv(65536)
        except BlockingIOError:pass
    def close(self):
        self.restored=True;self.ready=False;self.reader.close();self.writer.close()


class FakeBpfObserver:
    """Transport double; pinned kernel capture is verified separately on Linux."""
    def __init__(self, *, on_audit=None, audit_pump=None):
        self._on_audit=on_audit
        self.reader, self.writer = socket.socketpair()
        self.reader.setblocking(False)
        self._started = self._finished = self._closed = self.ready = False
        self.result = None
    def start(self):self._started = self._capturing = True
    def fileno(self):return self.reader.fileno()
    def bind(self, binding):self.ready = True
    def abort(self):self.ready = False; self.result = None
    def drain(self):
        try:self.reader.recv(65536)
        except BlockingIOError:pass
    def finish(self):self._finished = True
    def close(self):
        self.reader.close(); self.writer.close(); self._closed = True


class SupervisedSessionTests(unittest.TestCase):
    def setUp(self):
        # Host transport doubles cannot issue kernel audit-join evidence.
        joined=patch('evals.native_audit_session.AuditedSupervisor._finish_join')
        joined.start();self.addCleanup(joined.stop)
        self.audit_captures=[]
        def capture(*, on_event=None):
            value=FakeAuditCapture(on_event=on_event);self.audit_captures.append(value);return value
        patched=patch('evals.native_audit_session.AuditCapture',side_effect=capture)
        patched.start();self.addCleanup(patched.stop)
        patched = patch('evals.native_audit_session.BpfObserver', side_effect=FakeBpfObserver)
        patched.start(); self.addCleanup(patched.stop)

    def test_supervised_preflight_requires_audit_before_deferred_release(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve();command=test_native_session.NativeSessionTests()._server(root);process=self.launch(root,command)
            with patch('evals.native_session.build_session_command',return_value=command), \
                    patch('evals.native_session.trusted_supervised_binary_identity',return_value=(1,)), \
                    patch('evals.native_supervisor.start_supervised',return_value=process) as launch:
                inspect_native_session(root,binary=self.binary(),model='gpt-6.1-sol',disabled_servers=('docs',),supervised=True)
            self.assertEqual(1,len(self.audit_captures))
            capture=self.audit_captures[0]
            self.assertTrue(capture.entered and capture.released and capture.restored)
            self.assertTrue(launch.call_args.kwargs['defer_release'])
            self.assertIs(capture.lease,launch.call_args.kwargs['lock_lease'])

    def test_audit_setup_oserror_keeps_recovery_on_sanitized_top_level_error(self):
        with TemporaryDirectory() as temp, \
                patch('evals.native_session.trusted_supervised_binary_identity',return_value=(1,)), \
                patch.object(FakeAuditCapture,'__enter__',side_effect=OSError(5,'SENTINEL')), \
                patch('evals.native_supervisor.start_supervised') as launch:
            with self.assertRaises(OSError) as raised:
                inspect_native_session(Path(temp),binary=self.binary(),model='gpt-6.1-sol',supervised=True)
        self.assertNotIn('SENTINEL',str(raised.exception))
        self.assertIs(self.audit_captures[0],raised.exception.audit_recovery.capture)
        launch.assert_not_called()
        raised.exception.audit_recovery.recover()
        self.assertTrue(self.audit_captures[0].restored)
        self.assertIsNone(self.audit_captures[0].result)

    def binary(self):
        path=Path(sys.executable).resolve()
        with path.open('rb') as stream:
            return BinaryPin(path,hashlib.file_digest(stream,'sha256').hexdigest())

    def test_root_guard_is_explicit_and_does_not_weaken_direct_guard(self):
        pin=BinaryPin(Path('/opt/bin/codex'),'a'*64)
        metadata=SimpleNamespace(st_dev=1,st_ino=2,st_size=3,st_mtime_ns=4,st_mode=0o100555,st_uid=0,st_gid=0,st_nlink=1)
        with patch('evals.native_config.verify_binary'),patch('evals.native_config._require_root_linux'), \
                patch.object(Path,'lstat',return_value=metadata),patch('evals.native_config.os.access',return_value=True), \
                patch('evals.native_config.os.getxattr',side_effect=OSError(errno.ENODATA,'no acl'),create=True):
            identity=trusted_supervised_binary_identity(pin)
            self.assertEqual((1,2,3,4,0o100555,0,0,1),identity)
            with self.assertRaises(ValueError):trusted_binary_identity(pin)

    def test_supervised_guard_rejects_writable_owner_acl_unknown_acl_and_unpinned(self):
        pin=BinaryPin(Path('/opt/bin/codex'),'a'*64)
        metadata=SimpleNamespace(st_dev=1,st_ino=2,st_size=3,st_mtime_ns=4,st_mode=0o100555,st_uid=0,st_gid=0,st_nlink=1)
        for change,acl in (({'st_mode':0o100775},OSError(errno.ENODATA,'none')),
                ({'st_uid':2000},OSError(errno.ENODATA,'none')),({},b'extended acl'),
                ({},OSError(errno.ENOTSUP,'cannot inspect acl'))):
            row=SimpleNamespace(**{**vars(metadata),**change})
            with self.subTest(change=change,acl=type(acl).__name__),patch('evals.native_config.verify_binary'), \
                    patch('evals.native_config._require_root_linux'),patch.object(Path,'lstat',return_value=row), \
                    patch('evals.native_config.os.getxattr',side_effect=acl if isinstance(acl,Exception) else None,return_value=acl,create=True), \
                    self.assertRaises(ValueError):trusted_supervised_binary_identity(pin)
        with patch('evals.native_config._require_root_linux'), \
                patch('evals.native_config.verify_binary',side_effect=ValueError('pin mismatch')), \
                self.assertRaises(ValueError):trusted_supervised_binary_identity(pin)
        with patch('evals.native_config._require_root_linux',side_effect=ValueError('not root')), \
                patch('evals.native_config.verify_binary') as verified,self.assertRaises(ValueError):
            trusted_supervised_binary_identity(pin)
        verified.assert_not_called()

    def launch(self, root, command):
        outer=self
        class FakeSupervisor:
            def __init__(self):
                self.actor=subprocess.Popen(command,cwd=root,env={'PATH':os.environ.get('PATH','/usr/bin:/bin')},
                    stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0,start_new_session=True)
                self.stdin,self.stdout,self.stderr=self.actor.stdin,self.actor.stdout,self.actor.stderr
                self.finish_calls=0;self.cleanup_calls=0;self.cleanup_result=None
                self.binding=object()
            @property
            def returncode(self):return self.actor.returncode
            def poll(self):return self.actor.poll()
            def wait(self,timeout=None):return self.actor.wait(timeout=timeout)
            def finish_actor(self):
                if self.finish_calls:return
                self.finish_calls+=1
                try:os.killpg(self.actor.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                self.actor.wait(timeout=2)
            def cleanup(self):
                self.cleanup_calls+=1
                error=direct_cleanup(self.actor,None)
                if error is not None:raise error
                self.cleanup_result=SimpleNamespace(empty_verified=True)
                return self.cleanup_result
        return FakeSupervisor()

    def test_supervised_preflight_preserves_actor_status_and_avoids_proxy_group_cleanup(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve();command=test_native_session.NativeSessionTests()._server(root);process=self.launch(root,command)
            with patch('evals.native_session.build_session_command',return_value=command), \
                    patch('evals.native_session.trusted_supervised_binary_identity',return_value=(1,)), \
                    patch('evals.native_supervisor.start_supervised',return_value=process) as launch, \
                    patch('evals.native_session._cleanup') as wrong_cleanup:
                result=inspect_native_session(root,binary=self.binary(),model='gpt-6.1-sol',disabled_servers=('docs',),supervised=True)
            self.assertEqual(0,result.returncode);self.assertEqual(1,process.finish_calls);self.assertEqual(1,process.cleanup_calls)
            self.assertNotIn('SENTINEL',str(asdict(result)));wrong_cleanup.assert_not_called()
            self.assertEqual(command,launch.call_args.args[0])

    def test_detached_stdout_holder_is_killed_before_final_drain(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve();command=test_native_session.NativeSessionTests()._server(root)
            script=root/'fake-server.py'
            script.write_text("import os,time\nif os.fork()==0:\n while True:time.sleep(1)\n"+script.read_text())
            process=self.launch(root,command)
            with patch('evals.native_session.build_session_command',return_value=command), \
                    patch('evals.native_session.trusted_supervised_binary_identity',return_value=(1,)), \
                    patch('evals.native_supervisor.start_supervised',return_value=process):
                result=inspect_native_session(root,binary=self.binary(),model='gpt-6.1-sol',disabled_servers=('docs',),supervised=True,timeout_seconds=3)
            self.assertEqual(0,result.returncode);self.assertEqual(1,process.finish_calls)

    def test_keyboard_interrupt_is_preserved_and_cleanup_runs(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve();command=test_native_session.NativeSessionTests()._server(root);process=self.launch(root,command)
            with patch('evals.native_session.build_session_command',return_value=command), \
                    patch('evals.native_session.trusted_supervised_binary_identity',return_value=(1,)), \
                    patch('evals.native_supervisor.start_supervised',return_value=process):
                with self.assertRaises(KeyboardInterrupt):
                    with native_session(root,binary=self.binary(),model='gpt-6.1-sol',disabled_servers=('docs',),supervised=True):
                        raise KeyboardInterrupt
            self.assertEqual(1,process.cleanup_calls);self.assertIsNotNone(process.actor.returncode)

    def test_invalid_backend_or_unbound_invocation_fails_before_launch(self):
        with TemporaryDirectory() as temp,patch('evals.native_supervisor.start_supervised') as launch:
            for kwargs in ({'supervised':1},{'supervised':'yes'},{'supervised':True,'invocation':object()}):
                with self.subTest(kwargs=kwargs),self.assertRaises(ValueError):
                    with native_session(Path(temp),binary=self.binary(),model='gpt-6.1-sol',**kwargs):pass
        launch.assert_not_called()

    def test_shutdown_timeout_with_closed_output_still_cleans_the_actor(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve();command=test_native_session.NativeSessionTests()._server(root)
            script=root/'fake-server.py';script.write_text(script.read_text()+"\nimport os,time\nos.close(1);os.close(2);time.sleep(60)\n")
            process=self.launch(root,command)
            with patch('evals.native_session.build_session_command',return_value=command), \
                    patch('evals.native_session.trusted_supervised_binary_identity',return_value=(1,)), \
                    patch('evals.native_supervisor.start_supervised',return_value=process):
                with self.assertRaisesRegex(ValueError,'timed out'):
                    inspect_native_session(root,binary=self.binary(),model='gpt-6.1-sol',disabled_servers=('docs',),supervised=True,timeout_seconds=0.3)
            self.assertEqual(1,process.cleanup_calls);self.assertIsNotNone(process.actor.returncode)

    def test_cleanup_failure_retains_keyboard_interrupt_and_metadata(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve();command=test_native_session.NativeSessionTests()._server(root);process=self.launch(root,command)
            cleanup=process.cleanup
            def failed_cleanup():
                cleanup()
                raise OSError(5,'SENTINEL cleanup diagnostic')
            process.cleanup=failed_cleanup
            with patch('evals.native_session.build_session_command',return_value=command), \
                    patch('evals.native_session.trusted_supervised_binary_identity',return_value=(1,)), \
                    patch('evals.native_supervisor.start_supervised',return_value=process):
                with self.assertRaises(BaseExceptionGroup) as raised:
                    with native_session(root,binary=self.binary(),model='gpt-6.1-sol',disabled_servers=('docs',),supervised=True):
                        raise KeyboardInterrupt
            self.assertTrue(any(isinstance(error,KeyboardInterrupt) for error in raised.exception.exceptions))
            self.assertTrue(any(isinstance(error,OSError) and error.errno==5 for error in raised.exception.exceptions))
            self.assertEqual(1,process.cleanup_calls)

    def test_supervisor_spawn_error_is_sanitized(self):
        with TemporaryDirectory() as temp,patch('evals.native_session.trusted_supervised_binary_identity',return_value=(1,)), \
                patch('evals.native_supervisor.start_supervised',side_effect=PermissionError(13,'SENTINEL')):
            with self.assertRaises(PermissionError) as raised:
                inspect_native_session(Path(temp),binary=self.binary(),model='gpt-6.1-sol',supervised=True)
        self.assertEqual(13,raised.exception.errno)
        self.assertNotIn('SENTINEL',str(raised.exception))

    def test_root_guard_rejects_inode_metadata_change_during_acl_checks(self):
        pin=BinaryPin(Path('/opt/bin/codex'),'a'*64)
        values={'st_dev':1,'st_ino':2,'st_size':3,'st_mtime_ns':4,'st_mode':0o100555,'st_uid':0,'st_gid':0,'st_nlink':1}
        metadata=SimpleNamespace(**values);changed=SimpleNamespace(**{**values,'st_ino':3})
        with patch('evals.native_config.verify_binary'),patch('evals.native_config._require_root_linux'), \
                patch.object(Path,'lstat',side_effect=[metadata]*5+[changed]), \
                patch('evals.native_config.os.getxattr',side_effect=OSError(errno.ENODATA,'none'),create=True), \
                self.assertRaisesRegex(ValueError,'changed'):
            trusted_supervised_binary_identity(pin)

    def test_supervised_inspection_rejects_turn_requests_before_any_transport_write(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve();command=test_native_session.NativeSessionTests()._server(root);process=self.launch(root,command)
            with patch('evals.native_session.build_session_command',return_value=command), \
                    patch('evals.native_session.trusted_supervised_binary_identity',return_value=(1,)), \
                    patch('evals.native_supervisor.start_supervised',return_value=process):
                with native_session(root,binary=self.binary(),model='gpt-6.1-sol',disabled_servers=('docs',),supervised=True) as (exchange,evidence):
                    self.assertTrue(exchange.process.stdin.closed)
                    with self.assertRaises((ValueError,OSError)):
                        exchange.process.stdin.write(b'{"id":99,"method":"turn/start","params":{}}\n')
                    with self.assertRaises((ValueError,OSError)):
                        os.write(exchange.process.stdin.fileno(),b'blocked')
                    with self.assertRaises(OSError):
                        os.write(exchange.process.stdout.fileno(),b'blocked')
                    exchange.turn_handler=lambda event: None
                    request={'id':99,'method':'turn/start','params':{'threadId':evidence.thread_id,'input':[]}}
                    with patch('evals.native_config.os.write',wraps=os.write) as transport_write:
                        for send in (lambda:exchange.send(request),lambda:exchange.request(99,'turn/start',{}),
                                     lambda:exchange.send_raw(b'{"id":99,"method":"turn/start","params":{}}\n')):
                            with self.assertRaisesRegex(ValueError,'inspection'):
                                send()
                        transport_write.assert_not_called()
            self.assertEqual(1,process.cleanup_calls)
