import ctypes as C
from contextlib import contextmanager
from unittest.mock import Mock,patch
import unittest

from evals.native_cgroup import kernel_cgroup_id


class CgroupHandleTests(unittest.TestCase):
    def test_same_bound_fd_returns_full_kernfs_id_not_inode(self):
        from evals.native_cgroup import _KernelHandle
        @contextmanager
        def bound(binding):yield 55
        function=Mock()
        def fill(fd,name,handle,mount,flags):
            self.assertEqual((55,b'',0x1000),(fd,name,flags))
            value=C.cast(handle,C.POINTER(_KernelHandle)).contents
            value.handle_bytes=8;value.handle_type=0xfe
            value.identifier=0x10000002c
            C.cast(mount,C.POINTER(C.c_int)).contents.value=42
            return 0
        function.side_effect=fill
        library=Mock();library.name_to_handle_at=function
        with patch('evals.native_cgroup._open_bound',bound),patch('evals.native_cgroup.platform.machine',return_value='aarch64'),patch('evals.native_cgroup.C.CDLL',return_value=library):
            self.assertEqual(0x10000002c,kernel_cgroup_id(object()))

    def test_unsupported_or_malformed_handle_does_not_fall_back_to_inode(self):
        from evals.native_cgroup import _KernelHandle
        @contextmanager
        def bound(binding):yield 55
        for failure in ('error','type','size','zero'):
            def fill(fd,name,handle,mount,flags):
                value=C.cast(handle,C.POINTER(_KernelHandle)).contents
                value.handle_bytes=4 if failure=='size' else 8
                value.handle_type=1 if failure=='type' else 0xfe
                value.identifier=0 if failure=='zero' else 44
                C.cast(mount,C.POINTER(C.c_int)).contents.value=42
                C.set_errno(95)
                return -1 if failure=='error' else 0
            library=Mock();library.name_to_handle_at.side_effect=fill
            with patch('evals.native_cgroup._open_bound',bound),patch('evals.native_cgroup.platform.machine',return_value='aarch64'),patch('evals.native_cgroup.C.CDLL',return_value=library),self.assertRaises((OSError,ValueError)):
                kernel_cgroup_id(object())


    def test_unqualified_architecture_fails_before_opening_a_binding(self):
        with patch('evals.native_cgroup.platform.machine',return_value='x86_64'), \
                patch('evals.native_cgroup._open_bound') as opened,self.assertRaises(ValueError):
            kernel_cgroup_id(object())
        opened.assert_not_called()
