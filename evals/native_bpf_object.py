"""Pinned libbpf 1.3 lifecycle object; caller holds the actor lock until close."""

from __future__ import annotations

import ctypes as C
import errno
import hashlib
import os
from pathlib import Path
import platform
import stat
import struct
import time
from types import SimpleNamespace

from evals.native_audit_library import BPF_LIBRARY, load_library
from evals.native_bpf_events import BpfCounters

OBJECT = Path('/opt/harness-native/bpf/lifecycle-6.8.0-147.o')
OBJECT_SHA = 'ba97fec4c0acf695c9e2e04c67148276b87894f895047bf562402f58f77f4735'
SOURCE_SHA = '166eb328d0c65660c61536e3f007217a562c1daeee04afa83da3ef6dc607cd68'
BTF_SHA = 'ff35ff5afb91dfb3a1cb6db29a417a39f4f598c9ebfba75186592d4a58a1d277'
CALLBACK = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_void_p, C.c_size_t)
PROGRAMS = {b'observe_' + name: b'tp_btf/sched_process_' + name
            for name in (b'fork', b'exec', b'exit')}
MAPS = {b'events': (27, 1 << 24, 0, 0), b'counters': (2, 1, 4, 24)}


def read_pinned(path: Path, digest: str, limit: int) -> bytes:
    from evals.runtime_access import _root_chain
    from evals.runtime_trace import open_no_symlink
    _root_chain(path.parent)
    with os.fdopen(open_no_symlink(path), 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_mode & 0o022 or \
                before.st_nlink != 1 or not 0 < before.st_size <= limit:
            raise ValueError('BPF artifact must be root-controlled, bounded and regular')
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mode', 'st_uid', 'st_nlink', 'st_mtime_ns', 'st_ctime_ns')
        if len(raw) != before.st_size or hashlib.sha256(raw).hexdigest() != digest or any(
                getattr(before, name) != getattr(after, name) for name in fields):
            raise ValueError('BPF artifact differs from its pin or changed during read')
    return raw


def qualified_object() -> bytes:
    from evals.native_cgroup import _require_root_linux
    _require_root_linux()
    if platform.machine() != 'aarch64' or platform.release() != '6.8.0-147-generic':
        raise ValueError('BPF observer requires its qualified kernel and ARM64 ABI')
    read_pinned(Path('/sys/kernel/btf/vmlinux'), BTF_SHA, 16 << 20)
    read_pinned(Path(__file__).with_name('bpf') / 'lifecycle.bpf.c', SOURCE_SHA, 65536)
    return read_pinned(OBJECT, OBJECT_SHA, 2 << 20)


def load_api():
    library = load_library(Path(BPF_LIBRARY[0]), BPF_LIBRARY[1])
    P, I, U, S = C.c_void_p, C.c_int, C.c_uint, C.c_char_p
    signatures = (
        ('open', 'bpf_object__open_mem', P, [P, C.c_size_t, P]),
        ('load', 'bpf_object__load', I, [P]), ('close', 'bpf_object__close', None, [P]),
        ('error', 'libbpf_get_error', C.c_long, [P]),
        ('next_program', 'bpf_object__next_program', P, [P, P]),
        ('program_name', 'bpf_program__name', S, [P]),
        ('program_section', 'bpf_program__section_name', S, [P]),
        ('program_fd', 'bpf_program__fd', I, [P]), ('attach', 'bpf_program__attach_trace', P, [P]),
        ('link_fd', 'bpf_link__fd', I, [P]), ('destroy', 'bpf_link__destroy', I, [P]),
        ('next_map', 'bpf_object__next_map', P, [P, P]), ('map_name', 'bpf_map__name', S, [P]),
        ('map_type', 'bpf_map__type', U, [P]), ('map_entries', 'bpf_map__max_entries', U, [P]),
        ('map_key', 'bpf_map__key_size', U, [P]), ('map_value', 'bpf_map__value_size', U, [P]),
        ('map_fd', 'bpf_map__fd', I, [P]), ('lookup', 'bpf_map_lookup_elem', I, [I, P, P]),
        ('new_ring', 'ring_buffer__new', P, [I, CALLBACK, P, P]),
        ('consume', 'ring_buffer__consume', I, [P]), ('ring_fd', 'ring_buffer__epoll_fd', I, [P]),
        ('free_ring', 'ring_buffer__free', None, [P]),
        ('info', 'bpf_obj_get_info_by_fd', I, [I, P, C.POINTER(U)]),
        ('program_by_id', 'bpf_prog_get_fd_by_id', I, [U]),
        ('link_by_id', 'bpf_link_get_fd_by_id', I, [U]), ('map_by_id', 'bpf_map_get_fd_by_id', I, [U]),
    )
    result = {}
    for alias, name, returned, arguments in signatures:
        function = getattr(library, name)
        function.restype, function.argtypes = returned, arguments
        result[alias] = function
    printer = library.libbpf_set_print
    printer.restype, printer.argtypes = P, [P]
    printer(None)  # No unbounded verifier/log output from the privileged loader.
    return SimpleNamespace(**result)


class NativeBpfObject:
    def __init__(self) -> None:
        self.api = self._object = self._ring = self._memory = self._callback = None
        self._links: list[int] = []
        self._pending_ids: list[tuple[str, int, int]] = []
        self._callback_error: BaseException | None = None
        self.program_ids: tuple[int, ...] = ()
        self.link_ids: tuple[int, ...] = ()
        self.map_ids: tuple[int, ...] = ()
        self._fd = self._stats_fd = None
        self._started = self._closed = False

    def _pointer(self, pointer):
        error = self.api.error(pointer)
        if not pointer or error:
            raise OSError(-error if error < 0 else C.get_errno() or errno.EINVAL,
                          'owned BPF pointer operation failed')
        return pointer

    def _numeric_id(self, fd: int, kind: int) -> int:
        if fd < 0:
            raise ValueError('owned BPF descriptor unavailable')
        data, size = (C.c_ubyte * 256)(), C.c_uint(256)
        if self.api.info(fd, C.byref(data), C.byref(size)) != 0 or size.value < 8:
            raise OSError(C.get_errno(), 'owned BPF identity unavailable')
        actual_type, identifier = struct.unpack_from('=2I', bytes(data))
        if actual_type != kind or not identifier:
            raise ValueError('owned BPF object type or identity differs')
        return identifier

    def _shape(self):
        programs, maps, current = {}, {}, None
        while True:
            current = self.api.next_program(self._object, current)
            if not current:
                break
            name = self.api.program_name(current)
            if name not in PROGRAMS or name in programs or self.api.program_section(current) != PROGRAMS[name]:
                raise ValueError('unexpected BPF program shape')
            programs[name] = current
        current = None
        while True:
            current = self.api.next_map(self._object, current)
            if not current:
                break
            name = self.api.map_name(current)
            shape = tuple(operation(current) for operation in (
                self.api.map_type, self.api.map_entries, self.api.map_key, self.api.map_value))
            if name not in MAPS or name in maps or shape != MAPS[name]:
                raise ValueError('unexpected BPF map shape')
            maps[name] = current
        if set(programs) != set(PROGRAMS) or set(maps) != set(MAPS):
            raise ValueError('incomplete BPF programs or maps')
        return programs, maps

    def _capture_ids(self) -> None:
        while self._pending_ids:
            category, fd, kind = self._pending_ids[0]
            identifier = self._numeric_id(fd, kind)
            if category == 'program':
                self.program_ids += (identifier,)
            elif category == 'map':
                self.map_ids += (identifier,)
            else:
                self.link_ids += (identifier,)
            self._pending_ids.pop(0)

    def _receive(self, context, data, size) -> int:
        try:
            if self._callback_error is None:
                return self._consumer(context, data, size)
        except BaseException as error:
            self._callback_error = error
        return 0

    def start(self, callback) -> None:
        if self._started or self._closed:
            raise ValueError('BPF object cannot be reused')
        self._started = True
        try:
            raw = qualified_object()
            self.api = load_api()
            self._memory = C.create_string_buffer(raw)
            self._object = self._pointer(self.api.open(self._memory, len(raw), None))
            programs, maps = self._shape()
            self._load_and_attach(programs, maps)
            self._stats_fd = self.api.map_fd(maps[b'counters'])
            self._consumer = callback
            self._callback = CALLBACK(self._receive)
            self._ring = self._pointer(self.api.new_ring(self.api.map_fd(maps[b'events']), self._callback, None, None))
            self._fd = self.api.ring_fd(self._ring)
            if self._fd < 0:
                raise ValueError('BPF ring epoll descriptor unavailable')
        except BaseException as original:
            try:
                self.close()
            except BaseException as cleanup:
                raise BaseExceptionGroup('BPF object setup and rollback failed', [original, cleanup]) from None
            raise

    def _load_and_attach(self, programs, maps) -> None:
        code = self.api.load(self._object)
        for name, pointer in maps.items():
            fd = self.api.map_fd(pointer)
            if fd >= 0:
                self._pending_ids.append(('map', fd, MAPS[name][0]))
        for program in programs.values():
            fd = self.api.program_fd(program)
            if fd >= 0:
                self._pending_ids.append(('program', fd, 26))
        self._capture_ids()
        if code != 0:
            raise OSError(C.get_errno(), 'owned BPF object load failed')
        if len(self.map_ids) != 2 or len(self.program_ids) != 3:
            raise ValueError('loaded BPF descriptors are incomplete')
        for program in programs.values():
            link = self._pointer(self.api.attach(program))
            self._links.append(link)
            # tp_btf uses BPF_TRACE_RAW_TP and a RAW_TRACEPOINT link on this kernel.
            self._pending_ids.append(('link', self.api.link_fd(link), 1))
            self._capture_ids()

    def fileno(self) -> int:
        if self._closed or not self._ring or self.api.ring_fd(self._ring) != self._fd:
            raise ValueError('BPF ring descriptor changed or closed')
        return self._fd

    def drain(self) -> int:
        self.fileno()
        code = self.api.consume(self._ring)
        if code < 0:
            raise OSError(-code, 'owned BPF consume failed')
        if self._callback_error is not None:
            raise self._callback_error
        return code

    def counters(self) -> BpfCounters:
        if self._closed or not self._object or self._stats_fd is None:
            raise ValueError('BPF counters are unavailable')
        key, values = C.c_uint(), (C.c_uint64 * 3)()
        if self.api.lookup(self._stats_fd, C.byref(key), C.byref(values)) != 0:
            raise OSError(C.get_errno(), 'owned BPF counter lookup failed')
        return BpfCounters(*values)

    def detach(self) -> None:
        failures = []
        while self._links:
            # libbpf frees this C pointer even when destroy returns an error.
            link = self._links.pop()
            try:
                code = self.api.destroy(link)
                if code:
                    raise OSError(-code, 'owned BPF link destruction failed')
            except BaseException as error:
                failures.append(error)
        if failures:
            raise BaseExceptionGroup('BPF link destruction failed', failures)

    def _verify_absent(self) -> None:
        deadline = time.monotonic() + 3
        while True:
            live = False
            for operation, identifiers in ((self.api.program_by_id, self.program_ids),
                    (self.api.link_by_id, self.link_ids), (self.api.map_by_id, self.map_ids)):
                for identifier in identifiers:
                    fd = operation(identifier)
                    if fd >= 0:
                        os.close(fd)
                        live = True
                    elif C.get_errno() != errno.ENOENT:
                        raise OSError(C.get_errno(), 'owned BPF absence is unproven')
            if not live:
                return
            if time.monotonic() >= deadline:
                raise TimeoutError('owned BPF objects remain live')
            time.sleep(0.02)

    def close(self) -> None:
        if self._closed:
            return
        # Keep live descriptors available if identity reads need a recovery retry.
        self._capture_ids()
        failures = []
        def recover(operation):
            try:
                operation()
            except BaseException as error:
                failures.append(error)
        recover(self.detach)
        if self._ring is not None:
            ring, self._ring = self._ring, None
            recover(lambda: self.api.free_ring(ring))
        if self._object is not None:
            obj, self._object = self._object, None
            recover(lambda: self.api.close(obj))
        before = len(failures)
        if self.api is not None:
            recover(self._verify_absent)
        self._closed = len(failures) == before and not self._links
        if self._closed:
            self._callback = self._memory = None
        if failures:
            raise BaseExceptionGroup('BPF object release failed', failures)
