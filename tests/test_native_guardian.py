from contextlib import ExitStack
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import Mock, patch

from evals import native_guardian as guardian


class NativeGuardianTests(unittest.TestCase):
    def activate(self, stack, config, **changes):
        environment = {'LISTEN_FDS': '1', 'LISTEN_PID': str(os.getpid()),
                       'LISTEN_FDNAMES': 'guardian-status', **changes}
        stream = Mock();stream.getsockopt.return_value=socket.SOCK_STREAM;stream.recv.return_value=b'C'
        libc = Mock();libc.prctl.return_value=0
        patches = (
            ('os.getuid', {'return_value': 2000}), ('os.getgid', {'return_value': 2000}),
            ('os.fstat', {'return_value': Mock(st_mode=0o140600)}),
            ('socket.socket', {'return_value': stream}), ('fcntl.fcntl', {}),
            ('ctypes.CDLL', {'return_value': libc}), ('os.fork', {'return_value': 23}),
            ('os.pipe', {'return_value': (4, 5)}),
            ('_await_actor_filter', {}), ('_install_io_uring_filter', {}),
            ('os.close', {}), ('os.waitpid', {'return_value': (23, 7 << 8)}),
            ('sys.argv', {'new': ['guardian.py', str(config)]}))
        for name, kwargs in patches:stack.enter_context(patch('evals.native_guardian.'+name, **kwargs))
        stack.enter_context(patch.dict(guardian.os.environ, environment, clear=True))
        return stream, libc

    def test_guardian_parent_reports_metadata_only_and_requires_cleanup_ack(self):
        with tempfile.TemporaryDirectory() as temp:
            config=Path(temp)/'launch.json';config.write_text(json.dumps({'command':['/bin/true'],'environment':{'SAFE':'literal'}}))
            for ack in (b'C',b'',b'X'):
                with self.subTest(ack=ack), ExitStack() as stack:
                    stream,libc=self.activate(stack,config);stream.recv.return_value=ack
                    if ack==b'C':guardian.main()
                    else:
                        with self.assertRaises(ValueError):guardian.main()
                    messages=[json.loads(call.args[0]) for call in stream.sendall.call_args_list]
                    self.assertEqual([{'kind':'ready','actor':23,'guardian':os.getpid()},
                                      {'kind':'exited','actor':23,'wait_status':1792}],messages)
                    self.assertEqual([5,0,1,2],[call.args[0] for call in guardian.os.close.call_args_list])

    def test_parent_never_reports_ready_when_actor_filter_is_unproven(self):
        with tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
            config=Path(temp)/'launch.json';config.write_text('{}')
            stream,_=self.activate(stack,config)
            guardian._await_actor_filter.side_effect=ValueError('fixed missing ack')
            with self.assertRaises(ValueError):guardian.main()
            stream.sendall.assert_not_called()
            guardian.os.waitpid.assert_not_called()

    def test_bad_activation_or_dump_protection_never_forks(self):
        for changes in ({'LISTEN_FDS':'2'},{'LISTEN_PID':'1'},{'LISTEN_FDNAMES':'unknown'}):
            with ExitStack() as stack:
                self.activate(stack,Path('/unused'),**changes)
                with self.assertRaises(ValueError):guardian.main()
                guardian.os.fork.assert_not_called()
        with ExitStack() as stack:
            stream,libc=self.activate(stack,Path('/unused'));libc.prctl.return_value=-1
            with self.assertRaises(ValueError):guardian.main()
            guardian.os.fork.assert_not_called()

    def test_actor_closes_status_and_executes_only_explicit_environment(self):
        with tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
            config=Path(temp)/'launch.json';config.write_text(json.dumps({'command':['/bin/true'],'environment':{'SAFE':'literal'}}))
            stream,libc=self.activate(stack,config)
            guardian.os.fork.return_value=0
            stack.enter_context(patch('evals.native_guardian.os.closerange'))
            stack.enter_context(patch('evals.native_guardian.os.dup2'))
            stack.enter_context(patch('evals.native_guardian.os.write', return_value=1))
            stack.enter_context(patch('evals.native_guardian.os.read',return_value=b'G'))
            executed=stack.enter_context(patch('evals.native_guardian.os.execve',side_effect=OSError('fixed exec failure')))
            exited=stack.enter_context(patch('evals.native_guardian.os._exit',side_effect=SystemExit(126)))
            with self.assertRaises(SystemExit):guardian.main()
            stream.close.assert_called_once()
            guardian.os.closerange.assert_called_once_with(4,1024)
            executed.assert_called_once_with('/bin/true',['/bin/true'],{'SAFE':'literal'})
            exited.assert_called_once_with(126)
            stream.sendall.assert_not_called()


class ActorSeccompTests(unittest.TestCase):
    def decide(self, arch, number):
        accumulator = 0
        pc = 0
        while pc < len(guardian.IO_URING_FILTER):
            code, jt, jf, value = guardian.IO_URING_FILTER[pc]
            if code == 0x20:
                accumulator = {0: number & 0xffffffff, 4: arch}[value]
            elif code == 0x15:
                pc += jt if accumulator == value else jf
            elif code == 0x06:
                return value
            else:
                self.fail('unsupported fixed filter instruction')
            pc += 1
        self.fail('filter has no terminal decision')

    def test_native_filter_denies_all_ring_operations_only_and_kills_foreign_abi(self):
        for number in range(512):
            expected = 0x50026 if number in (425, 426, 427) else 0x7fff0000
            self.assertEqual(expected, self.decide(0xc00000b7, number))
            self.assertEqual(0x80000000, self.decide(0x40000028, number))

    def test_install_requires_qualified_abi_nnp_and_successful_logged_filter(self):
        libc = Mock()
        with patch('evals.native_guardian.sys.platform', 'linux'), \
                patch('evals.native_guardian.os.uname', return_value=Mock(machine='aarch64')):
            for nnp, installed, mode, valid in ((1, 0, 2, True), (0, 0, 2, False),
                    (1, -1, 2, False), (1, 0, 0, False)):
                with self.subTest(nnp=nnp, installed=installed, mode=mode):
                    libc.reset_mock()
                    libc.prctl.side_effect = lambda operation, *args: nnp if operation == 39 else mode
                    libc.syscall.return_value = installed
                    if valid:
                        guardian._install_io_uring_filter(libc)
                        self.assertEqual((277, 1, 2), libc.syscall.call_args.args[:3])
                    else:
                        with self.assertRaises(ValueError):
                            guardian._install_io_uring_filter(libc)
                    if nnp != 1:
                        libc.syscall.assert_not_called()
        with patch('evals.native_guardian.os.uname', return_value=Mock(machine='x86_64')):
            libc.reset_mock()
            with self.assertRaises(ValueError):guardian._install_io_uring_filter(libc)
            libc.syscall.assert_not_called()

    def test_readiness_requires_fixed_ack_within_bound(self):
        for ready, raw, valid in ((True, b'F', True), (False, b'F', False),
                (True, b'', False), (True, b'X', False), (True, b'FF', False)):
            with patch('evals.native_guardian.select.select', return_value=([4] if ready else [], [], [])), \
                    patch('evals.native_guardian.os.read', return_value=raw), \
                    patch('evals.native_guardian.os.close') as close:
                if valid:guardian._await_actor_filter(4)
                else:
                    with self.assertRaises(ValueError):guardian._await_actor_filter(4)
                close.assert_called_once_with(4)


class ActorReleaseOrderingTests(unittest.TestCase):
    def test_policy_and_readiness_precede_release_and_exec_and_failure_never_reads_g(self):
        for installation_ok in (True,False):
            with self.subTest(installation_ok=installation_ok), ExitStack() as stack:
                events=[]
                for name in ('close','dup2','closerange'):
                    stack.enter_context(patch('evals.native_guardian.os.'+name))
                def install(libc):
                    events.append('filter')
                    if not installation_ok:raise ValueError('fixed install failure')
                stack.enter_context(patch('evals.native_guardian._install_io_uring_filter',side_effect=install))
                write=stack.enter_context(patch('evals.native_guardian.os.write',side_effect=lambda *args:events.append('ack') or 1))
                read=stack.enter_context(patch('evals.native_guardian.os.read',side_effect=lambda *args:events.append('G') or b'G'))
                def execute(*args):events.append('exec');raise OSError('fixed exec exit')
                execve=stack.enter_context(patch('evals.native_guardian.os.execve',side_effect=execute))
                exit_=stack.enter_context(patch('evals.native_guardian.os._exit',side_effect=SystemExit(126)))
                with self.assertRaises(SystemExit):
                    guardian._run_actor({'command':['/bin/true'],'environment':{}},Mock(),4,5)
                self.assertEqual(['filter','ack','G','exec'] if installation_ok else ['filter'],events)
                exit_.assert_called_once_with(126)
                if installation_ok:
                    write.assert_called_once_with(3,b'F')
                    read.assert_called_once_with(0,1)
                else:
                    write.assert_not_called();read.assert_not_called();execve.assert_not_called()
