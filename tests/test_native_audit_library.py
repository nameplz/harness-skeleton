import hashlib
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from evals import native_audit_library as library


class AuditLibraryTests(unittest.TestCase):
    def test_exact_libbpf_pin_has_a_separate_single_handle_slot(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = tuple(Path(directory).resolve()/name for name in ('bpf.so', 'one.so', 'two.so', 'four.so'))
            for path in paths:path.write_bytes(b'x')
            digest = hashlib.sha256(b'x').hexdigest()
            metadata = SimpleNamespace(st_mode=stat.S_IFREG|0o444, st_uid=0, st_size=1, st_dev=1, st_ino=2)
            with patch('evals.native_cgroup._require_root_linux'), \
                    patch('evals.runtime_access._root_chain'), \
                    patch.object(library.platform, 'machine', return_value='aarch64'), \
                    patch.object(library.os, 'fstat', return_value=metadata), \
                    patch.object(library.C, 'CDLL', side_effect=lambda *a, **kw: object()), \
                    patch.object(library, 'BPF_LIBRARY', (str(paths[0]), digest)), \
                    patch.dict(library._loaded, {}, clear=True):
                try:
                    for path in paths[:3]:library.load_library(path, digest)
                    with self.assertRaises(ValueError):library.load_library(paths[3], digest)
                    self.assertEqual(3, len(library._loaded))
                finally:
                    for _, fd, _ in library._loaded.values():os.close(fd)
                    library._loaded.clear()

    def test_different_libraries_keep_unique_live_fd_names_and_cache_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            paths=tuple(Path(directory).resolve()/name for name in ('one.so','two.so','three.so'))
            for index,path in enumerate(paths):path.write_bytes(bytes([index]))
            metadata=SimpleNamespace(st_mode=stat.S_IFREG|0o444,st_uid=0,st_size=1,st_dev=1,st_ino=2)
            calls=[]
            def load(name,**kwargs):calls.append(name);return object()
            with patch('evals.native_cgroup._require_root_linux'), \
                    patch('evals.runtime_access._root_chain'), \
                    patch.object(library.platform,'machine',return_value='aarch64'), \
                    patch.object(library.os,'fstat',return_value=metadata), \
                    patch.object(library.C,'CDLL',side_effect=load), \
                    patch.dict(library._loaded,{},clear=True):
                try:
                    first=library.load_library(paths[0],hashlib.sha256(paths[0].read_bytes()).hexdigest())
                    second=library.load_library(paths[1],hashlib.sha256(paths[1].read_bytes()).hexdigest())
                    self.assertIsNot(first,second)
                    self.assertNotEqual(calls[0],calls[1])
                    self.assertIs(first,library.load_library(paths[0],hashlib.sha256(paths[0].read_bytes()).hexdigest()))
                    with self.assertRaises(ValueError):
                        library.load_library(paths[2],hashlib.sha256(paths[2].read_bytes()).hexdigest())
                    self.assertEqual(2,len(calls))
                finally:
                    for handle,fd,identity in library._loaded.values():os.close(fd)
                    library._loaded.clear()
            for name in calls:
                with self.assertRaises(OSError):os.fstat(int(name.rsplit('/',1)[1]))
