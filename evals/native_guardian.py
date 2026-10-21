"""Standalone root-installed helper: only guardian owns the systemd status FD."""

import ctypes
import fcntl
import json
import os
import select
from pathlib import Path
import socket
import stat
import sys



# Linux6.8 AArch64 seccomp_data offsets and asm-generic io_uring syscall IDs.
IO_URING_FILTER = (
    (0x20, 0, 0, 4),                 # LD arch
    (0x15, 1, 0, 0xc00000b7),        # native ABI only
    (0x06, 0, 0, 0x80000000),        # KILL_PROCESS
    (0x20, 0, 0, 0),                 # LD nr
    (0x15, 3, 0, 425),
    (0x15, 2, 0, 426),
    (0x15, 1, 0, 427),
    (0x06, 0, 0, 0x7fff0000),        # ALLOW
    (0x06, 0, 0, 0x00050026),        # ERRNO | ENOSYS
)


class SockFilter(ctypes.Structure):
    _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte),
                ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint32)]


class SockFprog(ctypes.Structure):
    _fields_ = [('len', ctypes.c_ushort), ('filter', ctypes.POINTER(SockFilter))]


def _install_io_uring_filter(libc) -> None:
    if sys.platform != 'linux' or os.uname().machine != 'aarch64':
        raise ValueError('actor filter requires qualified Linux AArch64 ABI')
    libc.prctl.restype = ctypes.c_int
    libc.prctl.argtypes = [ctypes.c_int, *([ctypes.c_ulong] * 4)]
    if libc.prctl(39, 0, 0, 0, 0) != 1:  # PR_GET_NO_NEW_PRIVS
        raise ValueError('actor filter requires inherited no_new_privs')
    instructions = (SockFilter * len(IO_URING_FILTER))(
        *(SockFilter(*row) for row in IO_URING_FILTER))
    program = SockFprog(len(instructions), instructions)
    libc.syscall.restype = ctypes.c_long
    libc.syscall.argtypes = [ctypes.c_long, ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p]
    # SECCOMP_SET_MODE_FILTER, FILTER_FLAG_LOG; no listener or privileged broker.
    if libc.syscall(277, 1, 2, ctypes.byref(program)) != 0 or \
            libc.prctl(21, 0, 0, 0, 0) != 2:
        raise ValueError('actor io_uring filter installation failed')


def _await_actor_filter(fd: int) -> None:
    try:
        if not select.select([fd], [], [], 5)[0] or os.read(fd, 2) != b'F':
            raise ValueError('actor filter readiness missing')
    finally:
        os.close(fd)


def _run_actor(spec: dict, libc, ready_read: int, ready_write: int) -> None:
    try:
        os.close(ready_read)
        os.dup2(ready_write, 3, inheritable=False)
        os.closerange(4, 1024)
        _install_io_uring_filter(libc)
        if os.write(3, b'F') != 1:
            os._exit(125)
        os.close(3)
        if os.read(0, 1) != b'G':
            os._exit(125)
        os.execve(spec['command'][0], spec['command'], spec['environment'])
    except BaseException:
        os._exit(126)


def main() -> None:
    if sys.flags.optimize or os.getuid() != 2000 or os.getgid() != 2000 or \
            os.environ.get('LISTEN_FDS') != '1' or \
            os.environ.get('LISTEN_PID') != str(os.getpid()) or \
            os.environ.get('LISTEN_FDNAMES') != 'guardian-status' or \
            not stat.S_ISSOCK(os.fstat(3).st_mode):
        raise ValueError('invalid guardian activation')
    status = socket.socket(fileno=3)
    if status.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM:
        raise ValueError('invalid guardian channel')
    status.settimeout(350)
    fcntl.fcntl(3, fcntl.F_SETFD, fcntl.FD_CLOEXEC)
    libc = ctypes.CDLL(None, use_errno=True)
    # Same-UID candidates must not ptrace the guardian or reopen its private FD.
    if libc.prctl(4, 0, 0, 0, 0) != 0 or libc.prctl(3, 0, 0, 0, 0) != 0:
        raise ValueError('guardian dump protection failed')
    spec = json.loads(Path(sys.argv[1]).read_bytes())
    ready_read, ready_write = os.pipe()
    child = os.fork()
    if child == 0:
        status.close()
        _run_actor(spec, libc, ready_read, ready_write)
        os._exit(126)
    os.close(ready_write)
    _await_actor_filter(ready_read)
    for fd in (0, 1, 2):
        os.close(fd)
    status.sendall((json.dumps({'kind': 'ready', 'actor': child, 'guardian': os.getpid()}) + '\n').encode())
    _, wait_status = os.waitpid(child, 0)
    status.sendall((json.dumps({'kind': 'exited', 'actor': child, 'wait_status': wait_status}) + '\n').encode())
    if status.recv(1) != b'C':
        raise ValueError('guardian cleanup acknowledgment missing')
    status.close()


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        # Never print the launch specification, argv, environment or candidate data.
        raise SystemExit(124) from None
