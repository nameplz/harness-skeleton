import ctypes as C
import errno
import hashlib
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from evals import native_bpf_object as bpf


def fake_api():
    api = SimpleNamespace()
    api.error = Mock(return_value=0)
    api.open = Mock(return_value=100)
    api.load = Mock(return_value=0)
    api.close = Mock()
    api.next_program = Mock(side_effect=lambda obj, prev: {None: 1, 1: 2, 2: 3, 3: None}[prev])
    api.program_name = Mock(side_effect=lambda p: {1: b'observe_fork', 2: b'observe_exec', 3: b'observe_exit'}[p])
    api.program_section = Mock(side_effect=lambda p: {
        1: b'tp_btf/sched_process_fork', 2: b'tp_btf/sched_process_exec', 3: b'tp_btf/sched_process_exit'}[p])
    api.program_fd = Mock(side_effect=lambda p: 1000+p)
    api.attach = Mock(side_effect=lambda p: 100+p)
    api.link_fd = Mock(side_effect=lambda p: 2000+p)
    api.destroy = Mock(return_value=0)
    api.next_map = Mock(side_effect=lambda obj, prev: {None: 11, 11: 12, 12: None}[prev])
    api.map_name = Mock(side_effect=lambda p: {11: b'events', 12: b'counters'}[p])
    api.map_type = Mock(side_effect=lambda p: {11: 27, 12: 2}[p])
    api.map_entries = Mock(side_effect=lambda p: {11: 1 << 24, 12: 1}[p])
    api.map_key = Mock(side_effect=lambda p: {11: 0, 12: 4}[p])
    api.map_value = Mock(side_effect=lambda p: {11: 0, 12: 24}[p])
    api.map_fd = Mock(side_effect=lambda p: 3000+p)
    api.new_ring = Mock(return_value=4000)
    api.ring_fd = Mock(return_value=77)
    api.consume = Mock(return_value=0)
    api.free_ring = Mock()
    api.lookup = Mock(return_value=0)
    def info(fd, data, size):
        values = C.cast(data, C.POINTER(C.c_uint))
        values[0] = 26 if fd < 2000 else 1 if fd < 3000 else {3011: 27, 3012: 2}[fd]
        values[1] = fd
        return 0
    api.info = Mock(side_effect=info)
    def absent(identifier):C.set_errno(errno.ENOENT);return -1
    api.program_by_id = Mock(side_effect=absent)
    api.link_by_id = Mock(side_effect=absent)
    api.map_by_id = Mock(side_effect=absent)
    return api


class BpfObjectTests(unittest.TestCase):
    def test_identity_query_failure_retains_object_until_recovery_can_bind_all_ids(self):
        api = fake_api(); fill = api.info.side_effect
        api.info.side_effect = lambda *args: (C.set_errno(errno.EPERM), -1)[1]
        owner = bpf.NativeBpfObject()
        with patch.object(bpf, 'qualified_object', return_value=b'ELF'), \
                patch.object(bpf, 'load_api', return_value=api), self.assertRaises(BaseException):
            owner.start(lambda *args: 0)
        self.assertFalse(owner._closed)
        api.close.assert_not_called()
        api.info.side_effect = fill
        owner.close()
        self.assertTrue(owner._closed)
        self.assertEqual(3, len(owner.program_ids))
        self.assertEqual(2, len(owner.map_ids))

    def test_callback_baseexception_is_not_lost_at_the_C_boundary(self):
        api = fake_api(); owner = bpf.NativeBpfObject()
        failure = KeyboardInterrupt()
        def receive(*args):raise failure
        with patch.object(bpf, 'qualified_object', return_value=b'ELF'), \
                patch.object(bpf, 'load_api', return_value=api):owner.start(receive)
        owner._callback(None, None, 0)
        with self.assertRaises(KeyboardInterrupt) as caught:owner.drain()
        self.assertIs(failure, caught.exception)
        owner.close()

    def start(self, api):
        owner = bpf.NativeBpfObject()
        with patch.object(bpf, 'qualified_object', return_value=b'ELF'), \
                patch.object(bpf, 'load_api', return_value=api):
            owner.start(lambda *args: 0)
        return owner

    def test_exact_shape_callback_fd_and_owned_ids_close(self):
        api = fake_api(); owner = self.start(api)
        self.assertEqual(77, owner.fileno())
        self.assertEqual(0, owner.drain())
        self.assertEqual((0, 0, 0), tuple(vars(owner.counters()).values()))
        self.assertEqual((1001, 1002, 1003), owner.program_ids)
        owner.close(); owner.close()
        self.assertTrue(owner._closed)
        self.assertEqual(3, api.destroy.call_count)
        api.free_ring.assert_called_once(); api.close.assert_called_once()
        with self.assertRaises(ValueError):owner.fileno()

    def test_wrong_program_or_map_shape_stops_before_loading(self):
        for name in ('program_name', 'program_section', 'map_type', 'map_entries', 'map_key', 'map_value'):
            api = fake_api(); setattr(api, name, Mock(return_value=b'wrong' if name.startswith('program') else 99))
            with self.subTest(name=name), self.assertRaises(ValueError):self.start(api)
            api.load.assert_not_called(); api.attach.assert_not_called(); api.close.assert_called_once()

    def test_partial_attach_failure_releases_already_attached_link(self):
        api = fake_api(); api.attach.side_effect = [101, None]
        with self.assertRaises(OSError):self.start(api)
        api.destroy.assert_called_once_with(101); api.close.assert_called_once()

    def test_changed_epoll_fd_and_negative_consume_are_not_accepted(self):
        api = fake_api(); owner = self.start(api)
        api.ring_fd.return_value = 78
        with self.assertRaises(ValueError):owner.fileno()
        api.ring_fd.return_value = 77; api.consume.return_value = -5
        with self.assertRaises(OSError):owner.drain()
        owner.close()

    def test_destroy_error_never_reuses_freed_pointer_and_absence_is_required(self):
        api = fake_api(); owner = self.start(api)
        api.destroy.side_effect = [-5, 0, 0]
        api.link_by_id.side_effect = lambda identifier: (C.set_errno(errno.EPERM), -1)[1]
        with self.assertRaises(BaseException):owner.close()
        self.assertFalse(owner._closed)
        calls = api.destroy.call_count
        api.link_by_id.side_effect = lambda identifier: (C.set_errno(errno.ENOENT), -1)[1]
        owner.close()
        self.assertTrue(owner._closed); self.assertEqual(calls, api.destroy.call_count)

    def test_pinned_read_rejects_digest_symlink_size_and_writability(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve()/'object'; path.write_bytes(b'ELF'); path.chmod(0o444)
            digest = hashlib.sha256(b'ELF').hexdigest()
            real_fstat = bpf.os.fstat
            def metadata(fd):
                real = real_fstat(fd)
                return SimpleNamespace(**{**{name: getattr(real, name) for name in (
                    'st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')}, 'st_uid': 0})
            with patch('evals.runtime_access._root_chain'), patch.object(bpf.os, 'fstat', side_effect=metadata):
                self.assertEqual(b'ELF', bpf.read_pinned(path, digest, 3))
                for pin, limit in ((digest, 2), ('0'*64, 3)):
                    with self.assertRaises(ValueError):bpf.read_pinned(path, pin, limit)
                path.chmod(0o666)
                with self.assertRaises(ValueError):bpf.read_pinned(path, digest, 3)
                path.chmod(0o444); alias = path.with_name('alias'); alias.symlink_to(path)
                with self.assertRaises(OSError):bpf.read_pinned(alias, digest, 3)
