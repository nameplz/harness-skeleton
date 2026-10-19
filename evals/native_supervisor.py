"""Opt-in root Linux actor launcher; not yet wired to native sessions/receipts."""

from __future__ import annotations

from dataclasses import dataclass
import errno
import fcntl
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import select
import shutil
import socket
import stat
import struct
import subprocess
import tempfile
import time
from uuid import uuid4

from evals.native_cgroup import (CgroupBinding, CleanupObservation, UNIT, _read_kernel,
    _require_root_linux, _root_directory, _task, bind_actor_cgroup, kill_actor_cgroup)
from evals.runtime_trace import json_object

LIMIT = 262144
STATUS_LIMIT = 1024
MANAGER_ENV = {'PATH': '/usr/bin:/bin'}
PROPERTIES = ('KillMode=control-group', 'TimeoutStartSec=10s', 'TimeoutStopSec=1s',
    'SendSIGKILL=yes', 'NoNewPrivileges=yes', 'Delegate=no', 'TasksMax=128',
    'MemoryMax=1073741824', 'CPUQuota=200%', 'RuntimeMaxSec=350s',
    'CapabilityBoundingSet=', 'AmbientCapabilities=', 'LimitNOFILE=1024', 'UMask=0077')


def parse_status(raw: bytes, *, kind: str, actor: int | None = None):
    """Interpret only fixed guardian metadata; this function does not authenticate it."""
    try:
        if type(raw) is not bytes or not 1 <= len(raw) <= STATUS_LIMIT or \
                not raw.endswith(b'\n') or raw.count(b'\n') != 1:
            raise ValueError
        row = json_object(raw.decode('ascii'))
        pid = row.get('actor')
        if type(pid) is not int or not 2 <= pid < 2**31:
            raise ValueError
        if kind == 'ready' and set(row) == {'kind', 'actor', 'guardian'} and row['kind'] == kind:
            guardian = row['guardian']
            if type(guardian) is int and 2 <= guardian < 2**31 and guardian != pid:
                return pid, guardian
        if kind == 'exited' and set(row) == {'kind', 'actor', 'wait_status'} and row['kind'] == kind and pid == actor:
            status = row['wait_status']
            if type(status) is int and 0 <= status <= 65535 and (
                    status & 255 == 0 or (status >> 8 == 0 and 1 <= status & 127 <= 64)):
                return os.waitstatus_to_exitcode(status)
    except (ValueError, UnicodeError, TypeError, RecursionError):
        pass
    raise ValueError('invalid guardian status')


def validate_launch(command: tuple[str, ...], cwd: Path, environment: dict[str, str], timeout: float) -> None:
    if not isinstance(command, tuple) or not 1 <= len(command) <= 4096 or any(
            not isinstance(value, str) or not value or '\x00' in value for value in command) or \
            not Path(command[0]).is_absolute() or not isinstance(cwd, Path) or not cwd.is_absolute() or \
            '..' in cwd.parts or any(char in str(cwd) for char in ('%', '\n', '\r', '\x00')) or \
            not isinstance(environment, dict) or len(environment) > 128 or any(
                not isinstance(key, str) or not re.fullmatch('[A-Za-z_][A-Za-z_0-9]*', key) or
                key.startswith('LISTEN_') or not isinstance(value, str) or '\x00' in value
                for key, value in environment.items()) or \
            type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 10:
        raise ValueError('invalid supervised launch')
    if len(json.dumps({'command': command, 'environment': environment}).encode()) > LIMIT:
        raise ValueError('supervised launch exceeds its bound')


class _SocketInput(io.RawIOBase):
    """Closing stdin must half-close RPC even while stdout retains the same socket."""
    def __init__(self, stream: socket.socket):
        self._socket = stream.dup()

    def fileno(self) -> int:
        return self._socket.fileno()

    def write(self, data: bytes) -> int:
        return self._socket.send(data)

    def close(self) -> None:
        if self.closed:
            return
        try:
            self._socket.shutdown(socket.SHUT_WR)
        except OSError as error:
            if error.errno != errno.ENOTCONN:
                raise
        finally:
            self._socket.close()
            super().close()


@dataclass(frozen=True)
class SupervisorCleanup:
    observation: CleanupObservation
    actor_returncode: int
    proxy_returncode: int
    guardian_reaped: bool
    unit_gone: bool

    @property
    def empty_verified(self) -> bool:
        return self.observation.empty_verified and self.guardian_reaped and self.unit_gone and self.proxy_returncode == 0


def _stop_unit(unit: str) -> None:
    if not isinstance(unit, str) or not UNIT.fullmatch(unit):
        raise ValueError('invalid supervisor unit')
    result = subprocess.run(['/usr/bin/systemctl', '--no-ask-password', 'stop', unit],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env=MANAGER_ENV, timeout=8)
    if result.returncode and not _unit_gone(unit):
        raise ValueError('supervisor unit stop failed')


def _unit_gone(unit: str) -> bool:
    if not isinstance(unit, str) or not UNIT.fullmatch(unit):
        raise ValueError('invalid supervisor unit')
    result = subprocess.run(['/usr/bin/systemctl', '--no-ask-password', 'show', unit, '--property=LoadState'],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=MANAGER_ENV, timeout=5)
    return result.returncode == 0 and result.stdout == b'LoadState=not-found\n' and \
        not Path('/sys/fs/cgroup/system.slice', unit).exists()


def _release_resources(resources) -> None:
    failures = []
    for resource in resources:
        try:
            resource.close()
        except BaseException as error:
            failures.append(error)
    if failures:
        raise BaseExceptionGroup('supervisor resource release failed', failures)


class SupervisorProcess:
    """Actor streams/status, deliberately separate from the systemd-run proxy."""
    binding: CgroupBinding
    returncode: int | None
    cleanup_observation: CleanupObservation | None
    cleanup_result: SupervisorCleanup | None
    lifecycle_result: SupervisorCleanup | None

    @property
    def pid(self) -> int:
        return self.binding.actor.pid

    def _receive(self, timeout: float) -> bytes | None:
        deadline = time.monotonic() + timeout
        while b'\n' not in self._buffer:
            if not select.select([self._status], [], [], max(0, deadline - time.monotonic()))[0]:
                return None
            chunk = self._status.recv(STATUS_LIMIT + 1)
            if not chunk:
                raise ValueError('guardian status channel closed')
            self._buffer += chunk
            if len(self._buffer) > STATUS_LIMIT:
                raise ValueError('guardian status exceeded its bound')
        raw, _, self._buffer = self._buffer.partition(b'\n')
        if self._buffer:
            raise ValueError('unexpected extra guardian status')
        return raw + b'\n'

    def poll(self) -> int | None:
        if self.returncode is None:
            raw = self._receive(0)
            if raw is not None:
                self.returncode = parse_status(raw, kind='exited', actor=self.pid)
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        if timeout is not None and (type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout < 0):
            raise ValueError('invalid supervisor wait limit')
        if self.returncode is None:
            raw = self._receive(350 if timeout is None else timeout)
            if raw is None:
                raise subprocess.TimeoutExpired('supervised actor', timeout)
            self.returncode = parse_status(raw, kind='exited', actor=self.pid)
        return self.returncode

    def finish_actor(self) -> SupervisorCleanup:
        """Stop the actor tree and guardian, preserving streams for final output drain."""
        if self.lifecycle_result is not None:
            return self.lifecycle_result
        failures = []
        result = None
        try:
            observation = kill_actor_cgroup(self.binding, timeout_seconds=5)
            self.cleanup_observation = observation
            if not observation.empty_verified:
                raise ValueError('supervised actor cgroup remains populated')
            code = self.wait(timeout=5)
            self._status.sendall(b'C')
            proxy_code = self._proxy.wait(timeout=5)
            guardian = _task(self.binding.guardian.pid)
            reaped = guardian is None or guardian.identity != self.binding.guardian
            if proxy_code != 0 or not reaped:
                raise ValueError('guardian or supervisor proxy did not exit cleanly')
            result = (observation, code, proxy_code, reaped)
        except BaseException as error:
            failures.append(error)
        finally:
            for operation in (lambda: _stop_unit(self.binding.unit), self._reap_proxy):
                try:
                    operation()
                except BaseException as error:
                    failures.append(error)
        gone = False
        try:
            gone = _unit_gone(self.binding.unit)
            if not gone:
                raise ValueError('supervisor unit remains loaded')
        except BaseException as error:
            failures.append(error)
        if failures:
            if len(failures) == 1:
                raise failures[0]
            raise BaseExceptionGroup('supervisor lifecycle failed', failures)
        self.lifecycle_result = SupervisorCleanup(*result, gone)
        return self.lifecycle_result

    def cleanup(self) -> SupervisorCleanup:
        if self._closed:
            if self.cleanup_result is None:
                raise ValueError('supervisor cleanup previously failed')
            return self.cleanup_result
        failures = []
        result = None
        try:
            result = self.finish_actor()
        except BaseException as error:
            failures.append(error)
        finally:
            try:
                _release_resources(reversed(self._resources))
            except BaseException as error:
                failures.append(error)
            try:
                if not _unit_gone(self.binding.unit):
                    raise ValueError('supervisor unit remains loaded')
                shutil.rmtree(self._directory)
            except BaseException as error:
                failures.append(error)
            self._closed = True
        if failures:
            if len(failures) == 1:
                raise failures[0]
            raise BaseExceptionGroup('supervisor cleanup failed', failures)
        self.cleanup_result = result
        return result

    def _reap_proxy(self) -> None:
        try:
            self._proxy.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._proxy.kill()
            self._proxy.wait(timeout=5)
            raise ValueError('supervisor proxy required forced termination') from None


def _trusted_file(path: Path) -> Path:
    path = path.resolve(strict=True)
    directory = _root_directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
                raise ValueError('supervisor executable/source must be root-owned')
        finally:
            os.close(fd)
    finally:
        os.close(directory)
    return path


def _idle_actor_uid() -> None:
    for index, entry in enumerate(Path('/proc').iterdir()):
        if index >= 65536:
            raise ValueError('dedicated UID scan exceeds its bound')
        if not entry.name.isdecimal():
            continue
        try:
            rows = dict(row.split(b':', 1) for row in _read_kernel(entry / 'status').splitlines() if b':' in row)
        except (FileNotFoundError, ProcessLookupError):
            continue
        uids = rows.get(b'Uid', b'').split()
        if len(uids) != 4 or any(not uid.isdigit() or not 0 <= int(uid) < 2**32 for uid in uids):
            raise ValueError('dedicated UID kernel identity unavailable')
        if b'2000' in uids:
            raise ValueError('dedicated supervisor UID is already active')


def _lock():
    directory = _root_directory(Path('/run'))
    try:
        fd = os.open('harness-eval-supervisor.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                     0o600, dir_fd=directory)
    finally:
        os.close(directory)
    stream = os.fdopen(fd, 'rb')
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o077:
            raise ValueError('invalid supervisor lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return stream
    except BaseException:
        stream.close()
        raise


def _write_launch(directory: Path, helper_bytes: bytes, command: tuple[str, ...], environment: dict[str, str]) -> Path:
    private = directory / 'private'
    private.mkdir(mode=0o700)
    for name, raw in (('guardian.py', helper_bytes), ('launch.json', json.dumps(
            {'command': command, 'environment': environment}, allow_nan=False).encode())):
        fd = os.open(directory / name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o440)
        with os.fdopen(fd, 'w+b') as stream:
            if stream.write(raw) != len(raw):
                raise OSError('supervisor launch file write incomplete')
            stream.flush()
            os.fchown(stream.fileno(), 0, 2000)
            os.fchmod(stream.fileno(), 0o440)
            stream.seek(0)
            if stream.read(len(raw) + 1) != raw:
                raise ValueError('supervisor launch file changed before sealing')
    # Expose only sealed read-only files; the private socket subtree stays root-only.
    os.chown(directory, 0, 2000)
    directory.chmod(0o750)
    return private


def _spawn_proxy(unit: str, cwd: Path, directory: Path, python: Path):
    private = directory / 'private'
    properties = (*PROPERTIES, 'StandardInput=file:' + str(private / 'rpc'),
        'StandardOutput=file:' + str(private / 'rpc'), 'StandardError=file:' + str(private / 'stderr'),
        'OpenFile=' + str(private / 'status') + ':guardian-status')
    wrapper = ('/usr/bin/systemd-run', '--system', '--wait', '--quiet', '--collect', '--service-type=exec',
        '--expand-environment=no', '--no-ask-password', '--unit=' + unit, '--uid=2000', '--gid=2000',
        '--working-directory=' + str(cwd), *('--property=' + value for value in properties),
        str(python), '-I', '-B', str(directory / 'guardian.py'), str(directory / 'launch.json'))
    return subprocess.Popen(wrapper, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, env=MANAGER_ENV, cwd='/', shell=False)


def _accept_channels(listeners, resources, deadline: float):
    connections, peers = {}, []
    for name, listener in listeners.items():
        listener.settimeout(max(0.001, deadline - time.monotonic()))
        stream, _ = listener.accept()
        resources.append(stream)
        peers.append(struct.unpack('3i', stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)))
        connections[name] = stream
    return connections, peers


def _admit_actor(unit: str, actor: int, guardian: int) -> CgroupBinding:
    group = Path('/sys/fs/cgroup/system.slice') / unit / 'actor'
    group.mkdir(mode=0o700)
    (group / 'cgroup.procs').write_text(str(actor))
    binding = bind_actor_cgroup(unit, actor)
    if binding.guardian.pid != guardian:
        raise ValueError('supervisor guardian identity changed before admission')
    return binding


def start_supervised(command: tuple[str, ...], *, cwd: Path, environment: dict[str, str],
                     admission_timeout_seconds: float = 10) -> SupervisorProcess:
    """Admit a root-owned executable; caller enforces run deadline and calls cleanup."""
    validate_launch(command, cwd, environment, admission_timeout_seconds)
    _require_root_linux()
    if _trusted_file(Path(command[0])) != Path(command[0]):
        raise ValueError('supervised executable must use its canonical path')
    source = _trusted_file(Path(__file__).with_name('native_guardian.py'))
    helper_bytes = _read_kernel(source)
    python = _trusted_file(Path('/usr/bin/python3'))
    if cwd.is_symlink() or cwd.resolve(strict=True) != cwd or not cwd.is_dir():
        raise ValueError('supervised cwd must be a canonical directory')
    lock = _lock()
    directory = None
    handle = SupervisorProcess()
    handle.returncode, handle.cleanup_observation, handle.cleanup_result = None, None, None
    handle.lifecycle_result = None
    handle._buffer, handle._closed = b'', False
    resources = [lock]
    proxy = None
    unit = 'harness-eval-' + uuid4().hex + '.service'
    deadline = time.monotonic() + admission_timeout_seconds
    try:
        _idle_actor_uid()
        directory = Path(tempfile.mkdtemp(prefix='harness-eval-', dir='/run'))
        private = _write_launch(directory, helper_bytes, command, environment)
        listeners = {}
        for name in ('rpc', 'stderr', 'status'):
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            resources.append(listener)
            listener.bind(str(private / name))
            listener.listen(1)
            listeners[name] = listener
        proxy = _spawn_proxy(unit, cwd, directory, python)
        handle._proxy = proxy
        connections, peers = _accept_channels(listeners, resources, deadline)
        handle._status = connections['status']
        ready = handle._receive(max(0, deadline - time.monotonic()))
        actor, guardian = parse_status(ready, kind='ready')
        if peers != [(guardian, 0, 0)] * 3:
            raise ValueError('supervisor channel peer identity differs from guardian startup')
        handle.binding = _admit_actor(unit, actor, guardian)
        rpc = connections['rpc']
        handle.stdin = _SocketInput(rpc)
        resources.append(handle.stdin)
        handle.stdout = rpc.makefile('rb', buffering=0)
        resources.append(handle.stdout)
        handle.stderr = connections['stderr'].makefile('rb', buffering=0)
        resources.append(handle.stderr)
        handle._directory, handle._resources, handle._proxy = directory, tuple(resources), proxy
        handle.helper_sha256 = hashlib.sha256(helper_bytes).hexdigest()
        handle.command_sha256 = hashlib.sha256(json.dumps(command).encode()).hexdigest()
        handle.environment_sha256 = hashlib.sha256(json.dumps(environment, sort_keys=True).encode()).hexdigest()
        rpc.sendall(b'G')
        return handle
    except BaseException as original:
        failures = [original]
        for operation in (lambda: _stop_unit(unit),
                          lambda: handle._reap_proxy() if proxy is not None else None,
                          lambda: _release_resources(reversed(resources))):
            try:
                operation()
            except BaseException as error:
                failures.append(error)
        if directory is not None:
            try:
                if not _unit_gone(unit):
                    raise ValueError('failed admission unit remains loaded')
                shutil.rmtree(directory)
            except BaseException as error:
                failures.append(error)
        if len(failures) == 1:
            raise
        raise BaseExceptionGroup('supervisor admission failed', failures) from None
