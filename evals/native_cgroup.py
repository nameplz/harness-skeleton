"""Root-only Linux cleanup observation; not a native receipt or an action audit."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from uuid import UUID

LIMIT = 65536
MAX_TRACKED = 4096
UNIT = re.compile(r'harness-eval-[0-9a-f]{32}\.service\Z')


@dataclass(frozen=True, order=True)
class ProcessIdentity:
    pid: int
    start_ticks: int


@dataclass(frozen=True)
class Task:
    identity: ProcessIdentity
    parent_pid: int
    state: str
    cgroup: bytes


@dataclass(frozen=True)
class Namespace:
    boot_id: str
    pid: int
    cgroup: int


@dataclass(frozen=True)
class CgroupBinding:
    unit: str
    invocation_id: str
    namespace: Namespace
    device: int
    inode: int
    actor: ProcessIdentity
    guardian: ProcessIdentity


@dataclass(frozen=True)
class CleanupObservation:
    binding: CgroupBinding
    observed_processes: tuple[ProcessIdentity, ...]
    members: tuple[ProcessIdentity, ...]
    remaining_generations: tuple[ProcessIdentity, ...]
    populated: int
    frozen: int
    procs: tuple[int, ...]
    threads: tuple[int, ...]

    @property
    def empty_verified(self) -> bool:
        return not (self.members or self.remaining_generations or self.populated
                    or self.frozen or self.procs or self.threads)


def _identity(value: ProcessIdentity) -> None:
    if not isinstance(value, ProcessIdentity) or type(value.pid) is not int or not 2 <= value.pid < 2**31 \
            or type(value.start_ticks) is not int or not 0 <= value.start_ticks < 2**64:
        raise ValueError('invalid process generation')


def parse_pids(raw: bytes) -> tuple[int, ...]:
    if type(raw) is not bytes or len(raw) > LIMIT:
        raise ValueError('invalid cgroup task list')
    parts = raw.split()
    if len(parts) > 1024 or any(
            not part.isdigit() or not 2 <= int(part) < 2**31 for part in parts):
        raise ValueError('invalid cgroup task list')
    # Kernel task lists may contain duplicate PIDs during concurrent changes.
    return tuple(sorted({int(part) for part in parts}))


def parse_events(raw: bytes) -> tuple[int, int]:
    if type(raw) is not bytes or len(raw) > LIMIT:
        raise ValueError('invalid cgroup events')
    rows = [line.split() for line in raw.splitlines()]
    if len(rows) != 2 or any(len(row) != 2 for row in rows):
        raise ValueError('invalid cgroup events')
    values = dict(rows)
    if set(values) != {b'populated', b'frozen'} or any(v not in {b'0', b'1'} for v in values.values()):
        raise ValueError('invalid cgroup events')
    return int(values[b'populated']), int(values[b'frozen'])


def parse_task_stat(pid: int, raw: bytes) -> tuple[ProcessIdentity, int, str]:
    if type(raw) is not bytes or len(raw) > LIMIT:
        raise ValueError('invalid task stat')
    try:
        prefix, tail = raw.rsplit(b') ', 1)
        fields = tail.split()
        identity = ProcessIdentity(pid, int(fields[19]))
        parent, state = int(fields[1]), fields[0].decode('ascii')
        if type(pid) is not int or not 1 <= pid < 2**31 or int(prefix.split(b' (', 1)[0]) != pid \
                or not 0 <= parent < 2**31 or not 0 <= identity.start_ticks < 2**64 \
                or state not in tuple('RSDZTWtXxKPI'):
            raise ValueError('invalid task stat')
        return identity, parent, state
    except (ValueError, IndexError, UnicodeError):
        raise ValueError('invalid task stat') from None


def _require_root_linux() -> None:
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise ValueError('cgroup observation requires the trusted Linux root operator')


def _namespace() -> Namespace:
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if str(UUID(boot)) != boot:
        raise ValueError('invalid boot identity')
    own_pid = Path('/proc/self/ns/pid').stat().st_ino
    own_cgroup = Path('/proc/self/ns/cgroup').stat().st_ino
    if own_pid != Path('/proc/1/ns/pid').stat().st_ino or \
            own_cgroup != Path('/proc/1/ns/cgroup').stat().st_ino:
        raise ValueError('cleanup observer must use the init process namespaces')
    return Namespace(boot, own_pid, own_cgroup)


def _path(unit: str) -> Path:
    if not isinstance(unit, str) or not UNIT.fullmatch(unit):
        raise ValueError('cleanup requires a dedicated harness transient unit')
    return Path('/sys/fs/cgroup/system.slice') / unit / 'actor'


def _read_at(directory: int, name: str) -> bytes:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    with os.fdopen(fd, 'rb') as stream:
        raw = stream.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError('kernel observation exceeded its bound')
    return raw


def _read_kernel(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        raw = stream.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError('kernel observation exceeded its bound')
    return raw


def _task(pid: int) -> Task | None:
    try:
        path = Path('/proc') / str(pid)
        before, _, _ = parse_task_stat(pid, _read_kernel(path / 'stat'))
        membership = _read_kernel(path / 'cgroup').splitlines()
        after, parent, state = parse_task_stat(pid, _read_kernel(path / 'stat'))
        if before != after or len(membership) != 1 or not membership[0].startswith(b'0::/'):
            raise ValueError('process identity or unified membership unavailable')
        return Task(after, parent, state, membership[0][3:])
    except (FileNotFoundError, ProcessLookupError):
        return None


def _secure_actor(pid: int) -> None:
    rows = _read_kernel(Path('/proc') / str(pid) / 'status').splitlines()
    values = dict(row.split(b':', 1) for row in rows if b':' in row)
    if values.get(b'Uid', b'').split() != [b'2000'] * 4 or \
            values.get(b'Gid', b'').split() != [b'2000'] * 4 or \
            b'Groups' not in values or not set(values[b'Groups'].split()) <= {b'2000'} or \
            values.get(b'NoNewPrivs', b'').strip() != b'1' or any(
                key not in values or int(values[key].strip(), 16) != 0
                for key in (b'CapInh', b'CapPrm', b'CapEff', b'CapAmb')):
        raise ValueError('actor identity or privileges differ from the dedicated UID')


def _manager(unit: str) -> tuple[str, int]:
    result = subprocess.run(['/usr/bin/systemctl', '--no-ask-password', '--no-pager', 'show', unit,
        '--property=InvocationID', '--property=MainPID', '--property=ControlGroup'],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env={'PATH': '/usr/bin:/bin'}, timeout=5, check=False)
    rows = result.stdout.splitlines()
    if result.returncode or len(result.stdout) > 4096 or len(rows) != 3:
        raise ValueError('service identity unavailable')
    try:
        values = dict(row.split(b'=', 1) for row in rows)
        invocation, pid = values[b'InvocationID'].decode('ascii'), int(values[b'MainPID'])
        if set(values) != {b'InvocationID', b'MainPID', b'ControlGroup'} or \
                not re.fullmatch('[0-9a-f]{32}', invocation) or not 2 <= pid < 2**31 or \
                values[b'ControlGroup'] != ('/system.slice/' + unit).encode():
            raise ValueError('service identity unavailable')
        return invocation, pid
    except (ValueError, KeyError, UnicodeError):
        raise ValueError('service identity unavailable') from None


def _root_directory(path: Path) -> int:
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            metadata = os.fstat(fd)
            if metadata.st_uid != 0 or metadata.st_mode & 0o022:
                raise ValueError('cgroup control path must remain root-owned')
        return fd
    except BaseException:
        os.close(fd)
        raise


def bind_actor_cgroup(unit: str, actor_pid: int) -> CgroupBinding:
    """Bind an already admitted trusted barrier; this does not provide that barrier."""
    _require_root_linux()
    path = _path(unit)
    _identity(ProcessIdentity(actor_pid, 0))
    namespace = _namespace()
    invocation, guardian_pid = _manager(unit)
    actor, guardian = _task(actor_pid), _task(guardian_pid)
    if actor is None or guardian is None or actor.parent_pid != guardian_pid or \
            actor.state in {'Z', 'X', 'x'} or actor.cgroup != ('/system.slice/' + unit + '/actor').encode() or \
            guardian.cgroup != ('/system.slice/' + unit).encode():
        raise ValueError('actor and guardian do not match their cgroup admission')
    _secure_actor(actor_pid)
    _secure_actor(guardian_pid)
    fd = _root_directory(path)
    try:
        metadata = os.fstat(fd)
        return CgroupBinding(unit, invocation, namespace, metadata.st_dev, metadata.st_ino,
                             actor.identity, guardian.identity)
    finally:
        os.close(fd)


@contextmanager
def _open_bound(binding: CgroupBinding):
    _require_root_linux()
    if not isinstance(binding, CgroupBinding):
        raise ValueError('cleanup requires its host cgroup binding')
    if not isinstance(binding.namespace, Namespace) or \
            not isinstance(binding.namespace.boot_id, str) or \
            str(UUID(binding.namespace.boot_id)) != binding.namespace.boot_id or any(
                type(value) is not int or value <= 0 for value in
                (binding.namespace.pid, binding.namespace.cgroup, binding.inode)) or \
            type(binding.device) is not int or binding.device < 0 or \
            not isinstance(binding.invocation_id, str) or not re.fullmatch('[0-9a-f]{32}', binding.invocation_id) or \
            binding.actor == binding.guardian:
        raise ValueError('invalid host cgroup identity')
    path = _path(binding.unit)
    _identity(binding.actor)
    _identity(binding.guardian)
    invocation, guardian_pid = _manager(binding.unit)
    guardian, own = _task(guardian_pid), _task(os.getpid())
    if binding.namespace != _namespace() or invocation != binding.invocation_id or \
            guardian is None or guardian.identity != binding.guardian or \
            guardian.cgroup != ('/system.slice/' + binding.unit).encode() or own is None or \
            own.cgroup == ('/system.slice/' + binding.unit + '/actor').encode() or \
            own.cgroup.startswith(('/system.slice/' + binding.unit + '/actor/').encode()):
        raise ValueError('cgroup execution identity changed or observer is inside actor')
    fd = _root_directory(path)
    try:
        metadata = os.fstat(fd)
        if (metadata.st_dev, metadata.st_ino) != (binding.device, binding.inode):
            raise ValueError('cgroup directory identity changed')
        yield fd
        current = path.lstat()
        if (current.st_dev, current.st_ino) != (binding.device, binding.inode) or \
                binding.namespace != _namespace() or _manager(binding.unit) != (binding.invocation_id, guardian_pid):
            raise ValueError('cgroup identity changed during cleanup')
    finally:
        os.close(fd)


def _matching_tasks(binding: CgroupBinding) -> tuple[Task, ...]:
    prefix = ('/system.slice/' + binding.unit + '/actor').encode()
    result = []
    with os.scandir('/proc') as entries:
        for index, entry in enumerate(entries):
            if index >= LIMIT:
                raise ValueError('global process observation exceeded its bound')
            if not entry.name.isascii() or not entry.name.isdecimal():
                continue
            task = _task(int(entry.name))
            if task is not None and (task.cgroup == prefix or task.cgroup.startswith(prefix + b'/')
                                     or task.cgroup == prefix + b' (deleted)'):
                result.append(task)
    return tuple(result)


def kill_actor_cgroup(binding: CgroupBinding, *, tracked: tuple[ProcessIdentity, ...] = (),
                      timeout_seconds: float = 5) -> CleanupObservation:
    """Kill the bound actor leaf and verify kernel state, including zombie generations."""
    if type(timeout_seconds) not in (float, int) or not 0 < timeout_seconds <= 10 or \
            not isinstance(tracked, tuple) or len(tracked) > MAX_TRACKED:
        raise ValueError('invalid cleanup limits')
    for identity in tracked:
        _identity(identity)
    with _open_bound(binding) as fd:
        before = _matching_tasks(binding)
        known = tuple(sorted({binding.actor, *tracked, *(task.identity for task in before)}))
        if len(known) > MAX_TRACKED:
            raise ValueError('tracked process generations exceeded their bound')
        kill_fd = os.open('cgroup.kill', os.O_WRONLY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            if os.write(kill_fd, b'1') != 1:
                raise OSError('cgroup kill write incomplete')
        finally:
            os.close(kill_fd)
        deadline = time.monotonic() + timeout_seconds
        while True:
            populated, frozen = parse_events(_read_at(fd, 'cgroup.events'))
            procs, threads = (parse_pids(_read_at(fd, name)) for name in ('cgroup.procs', 'cgroup.threads'))
            members = tuple(sorted(task.identity for task in _matching_tasks(binding)))
            remaining = tuple(identity for identity in known
                              if (task := _task(identity.pid)) is not None and task.identity == identity)
            result = CleanupObservation(binding, known, members, remaining, populated, frozen, procs, threads)
            if result.empty_verified or time.monotonic() >= deadline:
                return result
            time.sleep(0.01)
