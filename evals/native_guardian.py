"""Standalone root-installed helper: only guardian owns the systemd status FD."""

import ctypes
import fcntl
import json
import os
from pathlib import Path
import socket
import stat
import sys


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
    child = os.fork()
    if child == 0:
        try:
            status.close()
            os.closerange(3, 1024)
            if os.read(0, 1) != b'G':
                os._exit(125)
            os.execve(spec['command'][0], spec['command'], spec['environment'])
        except BaseException:
            os._exit(126)
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
