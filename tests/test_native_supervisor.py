from contextlib import ExitStack
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import signal
import select
import socket
import subprocess
import tempfile
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

from evals.native_cgroup import CgroupBinding, CleanupObservation, Namespace, ProcessIdentity
from evals.native_supervisor import (SupervisorProcess, _SocketInput, parse_status,
                                     start_supervised, validate_launch)


class NativeSupervisorTests(unittest.TestCase):
    def setUp(self):
        self.binding = CgroupBinding('harness-eval-' + 'a' * 32 + '.service', 'b' * 32,
            Namespace('11111111-1111-4111-8111-111111111111', 11, 12), 31, 44,
            ProcessIdentity(23, 99), ProcessIdentity(10, 88))

    def ready(self, **changes):
        return (json.dumps({'kind': 'ready', 'actor': 23, 'guardian': 10, **changes}) + '\n').encode()

    def exited(self, **changes):
        return (json.dumps({'kind': 'exited', 'actor': 23, 'wait_status': 7 << 8, **changes}) + '\n').encode()

    def test_strict_ready_status(self):
        self.assertEqual((23, 10), parse_status(self.ready(), kind='ready'))
        for raw in (self.ready(actor=True), self.ready(actor=1), self.ready(guardian=23),
                    self.ready(extra=1), self.ready(kind='exited'), b'{"kind":"ready","actor":23,"actor":24,"guardian":10}\n',
                    b'{}', b'x' * 1025, b'\xff\n', b'{}\n{}\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse_status(raw, kind='ready')

    def test_only_terminal_wait_status_and_bound_actor_are_accepted(self):
        self.assertEqual(7, parse_status(self.exited(), kind='exited', actor=23))
        self.assertEqual(-9, parse_status(self.exited(wait_status=9), kind='exited', actor=23))
        self.assertEqual(-11, parse_status(self.exited(wait_status=139), kind='exited', actor=23))
        for changes in ({'actor': 24}, {'wait_status': True}, {'wait_status': -1},
                        {'wait_status': 65536}, {'wait_status': 0x137f}, {'wait_status': 65},
                        {'wait_status': 0xffff}, {'wait_status': 256 + 9}, {'extra': 1}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                parse_status(self.exited(**changes), kind='exited', actor=23)

    def test_launch_limits_do_not_coerce_types_or_expand_systemd_specifiers(self):
        validate_launch(('/opt/bin/codex', 'arg with spaces'), Path('/srv/actor'), {'PATH': '/usr/bin'}, 5)
        invalid = [(['relative'], Path('/srv/actor'), {}, 5),
            (('relative',), Path('/srv/actor'), {}, 5),
            (('/bin/true', ''), Path('/srv/actor'), {}, 5),
            (('/bin/true',), Path('/srv/%u'), {}, 5),
            (('/bin/true',), Path('/srv/../actor'), {}, 5),
            (('/bin/true',), Path('/srv/actor'), {'LISTEN_FDS': '3'}, 5),
            (('/bin/true',), Path('/srv/actor'), {'X': '\x00'}, 5),
            (('/bin/true',), Path('/srv/actor'), {'X': 1}, 5),
            (('/bin/true',), Path('/srv/actor'), {}, True),
            (('/bin/true',), Path('/srv/actor'), {}, float('nan')),
            (('/bin/true',), Path('/srv/actor'), {}, 11),
            (('/bin/true', 'x' * 262145), Path('/srv/actor'), {}, 5)]
        for args in invalid:
            with self.subTest(args=args), self.assertRaises(ValueError):
                validate_launch(*args)

    def handle(self, stream):
        handle = SupervisorProcess.__new__(SupervisorProcess)
        handle.binding = self.binding
        handle._status = stream
        handle._buffer = b''
        handle.returncode = None
        return handle

    def test_poll_preserves_partial_frames_and_wait_uses_actor_status(self):
        reader, writer = socket.socketpair()
        self.addCleanup(reader.close); self.addCleanup(writer.close)
        handle = self.handle(reader)
        writer.sendall(self.exited()[:12])
        self.assertIsNone(handle.poll())
        writer.sendall(self.exited()[12:])
        self.assertEqual(7, handle.wait(timeout=0.2))
        self.assertEqual(7, handle.poll())

    def test_wait_times_out_and_missing_status_fails_closed(self):
        reader, writer = socket.socketpair()
        self.addCleanup(reader.close); self.addCleanup(writer.close)
        handle = self.handle(reader)
        with self.assertRaises(subprocess.TimeoutExpired):handle.wait(timeout=0.001)
        writer.close()
        with self.assertRaisesRegex(ValueError, 'status'):
            handle.poll()
        self.assertIsNone(handle.returncode)

    def test_status_output_bound_is_enforced(self):
        reader, writer = socket.socketpair()
        self.addCleanup(reader.close); self.addCleanup(writer.close)
        handle = self.handle(reader)
        writer.sendall(b'x' * 1025)
        with self.assertRaises(ValueError):handle.wait(timeout=0.2)

    def test_half_close_delivers_input_eof_without_closing_output(self):
        own, peer = socket.socketpair()
        self.addCleanup(own.close); self.addCleanup(peer.close)
        stream = _SocketInput(own)
        self.assertEqual(1, stream.write(b'G'))
        self.assertEqual(b'G', peer.recv(1))
        stream.close();stream.close()
        self.assertTrue(stream.closed)
        self.assertEqual(b'', peer.recv(1))
        peer.sendall(b'output')
        self.assertEqual(b'output', own.recv(6))

    def cleanup_handle(self):
        reader, writer = socket.socketpair()
        self.addCleanup(reader.close);self.addCleanup(writer.close)
        handle = self.handle(reader)
        handle._directory = Path('/run/harness-test')
        handle._proxy = Mock(returncode=0)
        handle._proxy.wait.return_value = 0
        handle._closed = False
        handle.cleanup_observation = None
        handle.cleanup_result = None
        handle.lifecycle_result = None
        handle.stdin = io.BytesIO();handle.stdout = io.BytesIO();handle.stderr = io.BytesIO()
        handle._resources = (handle.stdin, handle.stdout, handle.stderr)
        return handle, writer

    def observation(self, **changes):
        return replace(CleanupObservation(self.binding, (self.binding.actor,), (), (), 0, 0, (), ()), **changes)

    def test_cleanup_orders_empty_proof_before_ack_and_reaps_guardian(self):
        handle, peer = self.cleanup_handle()
        peer.sendall(self.exited())
        order = []
        with patch('evals.native_supervisor.kill_actor_cgroup', side_effect=lambda *a, **kw: (order.append('kill') or self.observation())), \
                patch('evals.native_supervisor._task', return_value=None), \
                patch('evals.native_supervisor._stop_unit', side_effect=lambda *a: order.append('stop')), \
                patch('evals.native_supervisor._unit_gone', return_value=True), \
                patch('evals.native_supervisor.shutil.rmtree'), \
                patch('evals.native_supervisor._release_resources', side_effect=lambda *a: order.append('release')):
            result = handle.cleanup()
        self.assertEqual(b'C', peer.recv(1))
        self.assertTrue(result.empty_verified)
        self.assertEqual(7, result.actor_returncode)
        self.assertEqual(0, result.proxy_returncode)
        self.assertEqual(['kill', 'stop', 'release'], order)
        self.assertIs(result, handle.cleanup())

    def test_finish_actor_preserves_output_until_exchange_drains_it(self):
        handle, peer = self.cleanup_handle()
        peer.sendall(self.exited())
        with patch('evals.native_supervisor.kill_actor_cgroup', return_value=self.observation()), \
                patch('evals.native_supervisor._task', return_value=None), \
                patch('evals.native_supervisor._stop_unit'), \
                patch('evals.native_supervisor._unit_gone', return_value=True), \
                patch('evals.native_supervisor.shutil.rmtree'):
            result = handle.finish_actor()
            self.assertTrue(result.empty_verified)
            self.assertFalse(handle.stdout.closed)
            self.assertFalse(handle.stderr.closed)
            self.assertIs(result, handle.finish_actor())
            self.assertIs(result, handle.cleanup())
            self.assertTrue(handle.stdout.closed)

    def test_nonempty_proof_never_acknowledges_or_claims_success(self):
        handle, peer = self.cleanup_handle()
        peer.settimeout(0.01)
        with patch('evals.native_supervisor.kill_actor_cgroup', return_value=self.observation(populated=1)), \
                patch('evals.native_supervisor._stop_unit') as stop, \
                patch('evals.native_supervisor._release_resources'), \
                patch('evals.native_supervisor._unit_gone', return_value=True), \
                patch('evals.native_supervisor.shutil.rmtree'):
            with self.assertRaises(ValueError):handle.cleanup()
        stop.assert_called_once()
        with self.assertRaises(socket.timeout):peer.recv(1)
        self.assertIsNone(handle.cleanup_result)

    def test_cancellation_during_cleanup_still_stops_unit_and_releases_resources(self):
        handle, peer = self.cleanup_handle()
        with patch('evals.native_supervisor.kill_actor_cgroup', side_effect=KeyboardInterrupt), \
                patch('evals.native_supervisor._stop_unit') as stop, \
                patch('evals.native_supervisor._release_resources') as release, \
                patch('evals.native_supervisor._unit_gone', return_value=True), \
                patch('evals.native_supervisor.shutil.rmtree'):
            with self.assertRaises(KeyboardInterrupt):handle.cleanup()
        stop.assert_called_once();release.assert_called_once()

    def test_guardian_or_proxy_failure_cannot_be_clean(self):
        for task, rc in ((Mock(identity=self.binding.guardian), 0), (None, 1)):
            handle, peer = self.cleanup_handle();peer.sendall(self.exited())
            handle._proxy.returncode = rc
            handle._proxy.wait.return_value = rc
            with self.subTest(rc=rc), patch('evals.native_supervisor.kill_actor_cgroup', return_value=self.observation()), \
                    patch('evals.native_supervisor._task', return_value=task), \
                    patch('evals.native_supervisor._stop_unit'), \
                    patch('evals.native_supervisor._release_resources'), \
                    patch('evals.native_supervisor._unit_gone', return_value=True), \
                    patch('evals.native_supervisor.shutil.rmtree'):
                with self.assertRaises(ValueError):handle.cleanup()

    def test_admission_binds_before_release_and_failure_unwinds_owned_resources(self):
        from evals import native_supervisor as module
        real_mkdtemp = tempfile.mkdtemp
        for fault in (None, 'peer', 'spawn', 'cancel', 'lost-binding'):
            with self.subTest(fault=fault), TemporaryDirectory() as temp, ExitStack() as stack:
                cwd = Path(temp).resolve()
                pairs = [socket.socketpair() for _ in range(3)]
                connections = dict(zip(('rpc', 'stderr', 'status'), (pair[0] for pair in pairs)))
                peers = [pair[1] for pair in pairs]
                self.addCleanup(lambda pairs=pairs: [stream.close() for pair in pairs for stream in pair])
                created = []
                def mkdtemp(**kwargs):
                    directory = real_mkdtemp(dir=cwd)
                    created.append(Path(directory))
                    return directory
                proxy = Mock(returncode=0)
                proxy.wait.return_value = 0
                def spawn(command, **kwargs):
                    self.assertFalse(kwargs['shell'])
                    self.assertEqual({'PATH': '/usr/bin:/bin'}, kwargs['env'])
                    self.assertNotIn('--pipe', command)
                    self.assertIn('--collect', command)
                    if fault == 'spawn':raise OSError('controlled spawn error')
                    peers[-1].sendall(self.ready())
                    return proxy
                def accepted(listeners, resources, deadline):
                    resources.extend(connections.values())
                    return connections, [(10, 1000 if fault == 'peer' else 0, 0)] * 3
                def admitted(unit, actor, guardian):
                    if fault == 'cancel':raise KeyboardInterrupt
                    if fault == 'lost-binding':raise ValueError('binding failed')
                    self.assertEqual((23, 10), (actor, guardian))
                    self.assertFalse(select.select([peers[0]], [], [], 0)[0])
                    return replace(self.binding, unit=unit)
                for target, kwargs in (
                    ('_require_root_linux', {}), ('_trusted_file', {'side_effect': lambda path: path}),
                    ('_lock', {'return_value': io.BytesIO()}), ('_idle_actor_uid', {}),
                    ('socket.socket', {'side_effect': lambda *a: Mock()}),
                    ('os.chown', {}), ('os.fchown', {}), ('tempfile.mkdtemp', {'side_effect': mkdtemp}),
                    ('subprocess.Popen', {'side_effect': spawn}), ('_accept_channels', {'side_effect': accepted}),
                    ('_admit_actor', {'side_effect': admitted}), ('_stop_unit', {}),
                    ('_unit_gone', {'return_value': True})):
                    stack.enter_context(patch('evals.native_supervisor.' + target, **kwargs))
                if fault:
                    expected = KeyboardInterrupt if fault == 'cancel' else (OSError if fault == 'spawn' else ValueError)
                    with self.assertRaises(expected):
                        start_supervised(('/bin/true',), cwd=cwd, environment={'SAFE': 'literal'})
                    self.assertFalse(created[0].exists())
                    self.assertTrue(module._lock.return_value.closed)
                    if fault != 'spawn':self.assertEqual(b'', peers[0].recv(1))
                else:
                    process = start_supervised(('/bin/true',), cwd=cwd, environment={'SAFE': 'literal'})
                    self.assertEqual(b'G', peers[0].recv(1))
                    self.assertEqual(23, process.pid)
                    self.assertEqual({'command': ['/bin/true'], 'environment': {'SAFE': 'literal'}},
                                     json.loads((created[0] / 'launch.json').read_text()))
                    module._release_resources(reversed(process._resources))
                    module.shutil.rmtree(created[0])

    def test_stop_cannot_target_arbitrary_service_and_proxy_timeout_is_reaped(self):
        from evals import native_supervisor as module
        with patch.object(module.subprocess, 'run') as run:
            for unit in ('sshd.service', '../bad', '--all'):
                with self.assertRaises(ValueError):module._stop_unit(unit)
                with self.assertRaises(ValueError):module._unit_gone(unit)
        run.assert_not_called()
        handle, peer = self.cleanup_handle()
        handle._proxy.wait.side_effect = [subprocess.TimeoutExpired('proxy', 5), 0]
        with self.assertRaises(ValueError):handle._reap_proxy()
        handle._proxy.kill.assert_called_once()
        self.assertEqual(2, handle._proxy.wait.call_count)

    def test_unsupported_host_fails_without_spawning(self):
        with patch('evals.native_supervisor._require_root_linux', side_effect=ValueError('unsupported')), \
                patch('evals.native_supervisor.subprocess.Popen') as spawn:
            with self.assertRaises(ValueError):
                start_supervised(('/bin/true',), cwd=Path('/srv/actor'), environment={})
        spawn.assert_not_called()

    def test_kernel_identity_and_filesystem_guards(self):
        from types import SimpleNamespace
        from evals import native_supervisor as module
        with TemporaryDirectory() as temp:
            directory = Path(temp).resolve()
            target = directory / 'source.py';target.write_bytes(b'fixed source')
            def root_dir(path):return os.open(directory, os.O_RDONLY)
            with patch.object(module, '_root_directory', side_effect=root_dir), \
                    patch.object(module.os, 'fstat', return_value=SimpleNamespace(st_mode=0o100444, st_uid=0)):
                self.assertEqual(target, module._trusted_file(target))
            with patch.object(module, '_root_directory', side_effect=root_dir), \
                    patch.object(module.os, 'fstat', return_value=SimpleNamespace(st_mode=0o100666, st_uid=2000)), \
                    self.assertRaises(ValueError):
                module._trusted_file(target)
            with patch.object(module, '_root_directory', side_effect=root_dir), \
                    patch.object(module.os, 'fstat', return_value=SimpleNamespace(st_mode=0o100600, st_uid=0)):
                lock = module._lock()
                try:
                    with self.assertRaises(BlockingIOError):module._lock()
                finally:lock.close()
            with patch.object(module, '_root_directory', side_effect=root_dir), \
                    patch.object(module.os, 'fstat', return_value=SimpleNamespace(st_mode=0o100644, st_uid=0)), \
                    self.assertRaises(ValueError):module._lock()
        with patch.object(module.Path, 'iterdir', return_value=iter([Path('/proc/23')])), \
                patch.object(module, '_read_kernel', return_value=b'Uid:\t2000 2000 2000 2000\n'), \
                self.assertRaises(ValueError):module._idle_actor_uid()
        with patch.object(module.Path, 'iterdir', return_value=iter([Path('/proc/23')])), \
                patch.object(module, '_read_kernel', side_effect=FileNotFoundError):module._idle_actor_uid()
        with patch.object(module.Path, 'iterdir', return_value=iter([Path('/proc/23')])), \
                patch.object(module, '_read_kernel', return_value=b'Name:\tunavailable\n'), \
                self.assertRaises(ValueError):module._idle_actor_uid()

    def test_manager_and_resource_release_failures_are_not_hidden(self):
        from evals import native_supervisor as module
        with patch.object(module.subprocess, 'run', return_value=Mock(returncode=1)), \
                patch.object(module, '_unit_gone', return_value=False), self.assertRaises(ValueError):
            module._stop_unit(self.binding.unit)
        with patch.object(module.subprocess, 'run', return_value=Mock(returncode=0, stdout=b'LoadState=not-found\n')), \
                patch.object(module.Path, 'exists', return_value=False):
            self.assertTrue(module._unit_gone(self.binding.unit))
        first=Mock();first.close.side_effect=ValueError('first failure');second=Mock()
        with self.assertRaises(BaseExceptionGroup):module._release_resources((first,second))
        second.close.assert_called_once()

    def test_original_cancellation_survives_secondary_manager_failure(self):
        handle, peer = self.cleanup_handle()
        with patch('evals.native_supervisor.kill_actor_cgroup', side_effect=KeyboardInterrupt), \
                patch('evals.native_supervisor._stop_unit'), \
                patch('evals.native_supervisor._unit_gone', side_effect=OSError('manager unavailable')), \
                patch('evals.native_supervisor._release_resources'):
            with self.assertRaises(BaseExceptionGroup) as raised:handle.cleanup()
        def leaves(error):
            return sum((leaves(child) for child in error.exceptions), []) if isinstance(error, BaseExceptionGroup) else [error]
        self.assertTrue(any(isinstance(error, KeyboardInterrupt) for error in leaves(raised.exception)))

    def test_writable_alias_cannot_bypass_executable_path_provenance(self):
        from types import SimpleNamespace
        from evals import native_supervisor as module
        import sys
        with TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            alias = root / 'alias'
            alias.symlink_to(Path(sys.executable).resolve())
            def directory(path):return os.open(path, os.O_RDONLY)
            with patch.object(module, '_require_root_linux'), \
                    patch.object(module, '_root_directory', side_effect=directory), \
                    patch.object(module.os, 'fstat', return_value=SimpleNamespace(st_mode=0o100555, st_uid=0)), \
                    patch.object(module, '_lock') as locked:
                with self.assertRaisesRegex(ValueError, 'canonical'):
                    start_supervised((str(alias),), cwd=root, environment={})
            locked.assert_not_called()
            alias.unlink();alias.symlink_to(root / 'replacement')
            self.assertNotEqual(alias.resolve(), Path(sys.executable).resolve())

    def test_launch_files_are_sealed_before_directory_exposure_even_with_umask_zero(self):
        from evals import native_supervisor as module
        with TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            root.chmod(0o700)
            real_chmod = Path.chmod
            observed = []
            def chmod(path, mode, **kwargs):
                if path == root and mode == 0o750:
                    observed.append('expose')
                    self.assertEqual({'guardian.py', 'launch.json', 'private'}, {p.name for p in root.iterdir()})
                    for name in ('guardian.py', 'launch.json'):
                        sealed = root / name
                        self.assertEqual(0o440, sealed.stat().st_mode & 0o777)
                        if os.geteuid() == 0:
                            continue  # Real UID2000 racing writes are qualified in the guest.
                        try:
                            fd = os.open(sealed, os.O_WRONLY | os.O_NONBLOCK)
                        except PermissionError:
                            continue
                        else:
                            os.close(fd)
                            self.fail('same-UID unprivileged writer can open sealed launch file')
                return real_chmod(path, mode, **kwargs)
            old_umask = os.umask(0)
            try:
                with patch.object(module.os, 'chown'), patch.object(module.os, 'fchown'), \
                        patch.object(Path, 'chmod', new=chmod):
                    module._write_launch(root, b'fixed helper', ('/bin/true',), {'SAFE': 'literal'})
            finally:
                os.umask(old_umask)
            self.assertEqual(['expose'], observed)
            self.assertEqual(b'fixed helper', (root / 'guardian.py').read_bytes())
            self.assertEqual({'command': ['/bin/true'], 'environment': {'SAFE': 'literal'}},
                             json.loads((root / 'launch.json').read_bytes()))
