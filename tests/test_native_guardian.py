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
                    self.assertEqual([0,1,2],[call.args[0] for call in guardian.os.close.call_args_list])

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
            stack.enter_context(patch('evals.native_guardian.os.read',return_value=b'G'))
            executed=stack.enter_context(patch('evals.native_guardian.os.execve',side_effect=OSError('fixed exec failure')))
            exited=stack.enter_context(patch('evals.native_guardian.os._exit',side_effect=SystemExit(126)))
            with self.assertRaises(SystemExit):guardian.main()
            stream.close.assert_called_once()
            guardian.os.closerange.assert_called_once_with(3,1024)
            executed.assert_called_once_with('/bin/true',['/bin/true'],{'SAFE':'literal'})
            exited.assert_called_once_with(126)
            stream.sendall.assert_not_called()
