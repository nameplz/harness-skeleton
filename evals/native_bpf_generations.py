"""Bounded task attribution for validated lifecycle records, not an action audit.

The transport ledger must independently prove complete counters and sequences.
Task instances use local tokens: Linux de_thread can reuse a retired leader's
PID and start_boottime for a live thread executing a new image.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import hashlib
import json
import struct

from evals.native_bpf_events import BpfEvent, WIRE, decode_event
from evals.native_bpf_audit import AUDIT_WIRE, BpfAuditEvent, decode_audit_binding
from evals.native_cgroup import CgroupBinding, _identity

MAX_TASKS = 4096


@dataclass(frozen=True)
class TaskInstance:
    token: int
    parent: int
    group: int
    tid: int
    tgid: int
    start_ns: int
    cgroup_id: int
    role: str
    last_ns: int
    ended: str = ''


@dataclass(frozen=True)
class TaskAttribution:
    token: int
    role: str


@dataclass(frozen=True)
class GenerationSummary:
    instances: int
    forks: int
    execs: int
    exits: int
    aliases: int
    sha256: str


class GenerationLedger:
    def __init__(self, binding: CgroupBinding, *, actor_cgroup_id: int,
                 guardian_cgroup_id: int, clock_ticks: int) -> None:
        if type(binding) is not CgroupBinding:
            raise ValueError('task ledger requires a host cgroup binding')
        _identity(binding.actor)
        _identity(binding.guardian)
        if binding.actor.pid == binding.guardian.pid or any(
                type(value) is not int or not 0 < value < 2**64
                for value in (actor_cgroup_id, guardian_cgroup_id)) or \
                actor_cgroup_id == guardian_cgroup_id or type(clock_ticks) is not int or \
                not 0 < clock_ticks <= 1000000:
            raise ValueError('invalid task ledger binding or clock')
        self.binding = binding
        self.actor_cgroup_id, self.guardian_cgroup_id = actor_cgroup_id, guardian_cgroup_id
        self.clock_ticks = clock_ticks
        self._nodes: dict[int, TaskInstance] = {}
        self._active: dict[int, int] = {}
        self._seen: set[tuple[int, int]] = set()
        self._retired: dict[int, int] = {}
        self._released = self._aborted = self._failed = self._finished = False
        self._actor_exec = self._audit_actor_leaf = False
        self._counts = {1: 0, 2: 0, 3: 0}
        self._aliases = 0
        self.result: GenerationSummary | None = None
        self._hash = hashlib.sha256(json.dumps(
            {'binding': asdict(binding), 'actor_cgroup_id': actor_cgroup_id,
             'guardian_cgroup_id': guardian_cgroup_id, 'clock_ticks': clock_ticks},
            sort_keys=True, separators=(',', ':')).encode())

    def _available(self) -> None:
        if self._failed or self._finished:
            raise ValueError('task attribution ledger is unavailable')

    def _task(self, tid: int, tgid: int, start_ns: int, timestamp: int) -> TaskInstance:
        token = self._active.get(tid)
        node = self._nodes.get(token)
        if node is None or (node.tgid, node.start_ns) != (tgid, start_ns) or timestamp < node.last_ns:
            raise ValueError('unknown task generation or backward lifecycle time')
        return node

    def _new(self, event: BpfEvent, *, parent: int, group: int, role: str,
             alias: bool = False) -> TaskInstance:
        key = (event.tid, event.start_ns)
        if len(self._nodes) >= MAX_TASKS or event.tid in self._active or (key in self._seen and not alias):
            raise ValueError('reused or excessive task instance')
        token = len(self._nodes) + 1
        node = TaskInstance(token, parent, group or token, event.tid, event.tgid,
                            event.start_ns, event.cgroup_id, role, event.timestamp_ns)
        self._nodes[token] = node
        self._active[event.tid] = token
        self._seen.add(key)
        return node

    def _anchor(self, event: BpfEvent) -> bool:
        guardian = self.binding.guardian
        if not self._nodes:
            if event.kind != 2 or (event.tid, event.tgid, event.old_tid) != (guardian.pid,) * 3 or \
                    event.start_ns * self.clock_ticks // 10**9 != guardian.start_ticks or \
                    event.cgroup_id != self.guardian_cgroup_id:
                raise ValueError('missing bound guardian exec anchor')
            self._new(event, parent=0, group=0, role='guardian')
            return True
        return False

    def observe(self, event: BpfEvent) -> None:
        self._available()
        try:
            if type(event) is not BpfEvent or any(type(v) is not int for v in vars(event).values()):
                raise ValueError('task ledger requires a validated numeric record')
            raw = WIRE.pack(*vars(event).values())
            decode_event(raw)
            if event.cgroup_id != event.current_cgroup_id:
                raise ValueError('lifecycle task and current cgroup disagree')
            if not self._anchor(event):
                if event.kind == 1:
                    self._fork(event)
                elif event.kind == 2:
                    self._exec(event)
                else:
                    self._exit(event)
            self._counts[event.kind] += 1
            self._hash.update(raw)
        except BaseException as error:
            self._failed = True
            if isinstance(error, (struct.error, OverflowError)):
                raise ValueError('invalid numeric lifecycle record') from None
            raise

    def attribute(self, event: BpfAuditEvent, *, prefix: bool = False) -> TaskAttribution:
        """Resolve at BPF delivery, before a later lifecycle event can retire a TID."""
        self._available()
        try:
            if type(event) is not BpfAuditEvent or any(type(v) is not int for v in vars(event).values()) or \
                    type(prefix) is not bool:
                raise ValueError('task attribution requires a validated audit binding')
            decode_audit_binding(AUDIT_WIRE.pack(*vars(event).values()))
            if prefix and (self._released or self._aborted or len(self._nodes) != 2 or len(self._active) != 2):
                raise ValueError('audit prefix is outside withheld guardian/launcher admission')
            node = self._nodes.get(self._active.get(event.tid))
            if node is None or (node.tgid, node.start_ns) != (event.tgid, event.start_ns) or \
                    (not prefix and event.timestamp_ns < node.last_ns):
                raise ValueError('audit binding has an unknown task generation or backward time')
            role = node.role
            if role == 'actor' and not self._actor_exec:
                role = 'launcher'
                if event.cgroup_id == self.actor_cgroup_id:
                    self._audit_actor_leaf = True
                elif event.cgroup_id != self.guardian_cgroup_id or self._audit_actor_leaf:
                    raise ValueError('launcher cgroup handoff regressed or escaped')
            elif event.cgroup_id != node.cgroup_id:
                raise ValueError('audit binding escaped its exact task cgroup')
            self._nodes[node.token] = replace(node, last_ns=max(node.last_ns, event.timestamp_ns))
            return TaskAttribution(node.token, role)
        except BaseException as error:
            self._failed = True
            if isinstance(error, (struct.error, OverflowError)):
                raise ValueError('invalid numeric task audit binding') from None
            raise

    def _fork(self, event: BpfEvent) -> None:
        parent = self._task(event.related_tid, event.related_tgid,
                            event.related_start_ns, event.timestamp_ns)
        if event.start_ns < parent.start_ns or event.cgroup_id != parent.cgroup_id:
            raise ValueError('fork time or cgroup differs from parent')
        if parent.role == 'guardian':
            actor = self.binding.actor
            if len(self._nodes) != 1 or self._released or self._aborted or \
                    (event.tid, event.tgid) != (actor.pid,) * 2 or \
                    event.start_ns * self.clock_ticks // 10**9 != actor.start_ticks:
                raise ValueError('missing bound actor fork anchor')
            group, role = 0, 'actor'
        else:
            if not self._released or not self._actor_exec or \
                    event.cgroup_id != self.actor_cgroup_id or \
                    (event.tid != event.tgid and event.tgid != parent.tgid):
                raise ValueError('invalid actor descendant fork')
            group, role = (parent.group if event.tid != event.tgid else 0), 'descendant'
        self._new(event, parent=parent.token, group=group, role=role)
        self._nodes[parent.token] = replace(parent, last_ns=event.timestamp_ns)

    def prepare_release(self) -> None:
        self._available()
        if self._released or self._aborted or len(self._nodes) != 2 or len(self._active) != 2:
            self._failed = True
            raise ValueError('incomplete or repeated task admission')
        self._released = True

    def abort(self) -> None:
        self._available()
        self._aborted = True

    def _group_live(self, group: int) -> tuple[TaskInstance, ...]:
        return tuple(self._nodes[token] for token in self._active.values()
                     if self._nodes[token].group == group)

    def _exec(self, event: BpfEvent) -> None:
        if not self._released or event.tid != event.tgid or \
                event.cgroup_id != self.actor_cgroup_id:
            raise ValueError('exec outside admitted actor leaf')
        if event.old_tid != event.tid:
            self._alias(event)
            return
        node = self._task(event.tid, event.tgid, event.start_ns, event.timestamp_ns)
        if node.role == 'guardian' or len(self._group_live(node.group)) != 1:
            raise ValueError('exec has unretired thread group members')
        if node.cgroup_id != event.cgroup_id:
            if node.role != 'actor' or self._actor_exec or node.cgroup_id != self.guardian_cgroup_id:
                raise ValueError('unexpected task cgroup transition')
            self._actor_exec = True
        self._nodes[node.token] = replace(node, cgroup_id=event.cgroup_id, last_ns=event.timestamp_ns)

    def _alias(self, event: BpfEvent) -> None:
        token = self._active.get(event.old_tid)
        caller = self._nodes.get(token)
        leader = self._nodes.get(self._retired.get(caller.group)) if caller is not None else None
        if caller is None or leader is None or caller.tid == caller.tgid or \
                (caller.tgid, leader.tid, leader.tgid) != (event.tgid,) * 3 or \
                leader.start_ns != event.start_ns or leader.ended != 'exit' or \
                caller.cgroup_id != event.cgroup_id or leader.cgroup_id != event.cgroup_id or \
                event.timestamp_ns < max(caller.last_ns, leader.last_ns) or \
                len(self._group_live(caller.group)) != 1:
            raise ValueError('nonleader exec lacks a live caller and retired group leader')
        # de_thread absorbs the caller and adopts the leader's start_boottime.
        del self._active[caller.tid]
        self._nodes[caller.token] = replace(caller, ended='alias', last_ns=event.timestamp_ns)
        self._new(event, parent=leader.parent, group=leader.group, role=leader.role, alias=True)
        del self._retired[caller.group]
        self._aliases += 1

    def _exit(self, event: BpfEvent) -> None:
        node = self._task(event.tid, event.tgid, event.start_ns, event.timestamp_ns)
        expected = self.guardian_cgroup_id if node.role == 'guardian' else self.actor_cgroup_id
        if event.cgroup_id != expected or (not self._released and not self._aborted):
            raise ValueError('exit outside admitted cleanup boundary')
        if node.role == 'guardian' and len(self._active) != 1:
            raise ValueError('guardian exited before actor tasks ended')
        if node.role == 'actor' and not self._actor_exec and not self._aborted:
            raise ValueError('actor exit before initial leaf exec')
        del self._active[node.tid]
        self._nodes[node.token] = replace(node, cgroup_id=event.cgroup_id,
                                          last_ns=event.timestamp_ns, ended='exit')
        if node.tid == node.tgid and self._group_live(node.group):
            self._retired[node.group] = node.token

    def finish(self) -> GenerationSummary:
        self._available()
        self._finished = True
        if self._aborted or not self._released or not self._actor_exec or self._active:
            raise ValueError('task attribution is incomplete or aborted')
        digest = self._hash.copy()
        digest.update(json.dumps([asdict(n) for n in self._nodes.values()],
                                 sort_keys=True, separators=(',', ':')).encode())
        self.result = GenerationSummary(len(self._nodes), self._counts[1], self._counts[2],
                                        self._counts[3], self._aliases, digest.hexdigest())
        return self.result

    def finish_abort(self) -> None:
        """Verify aborted teardown without issuing a successful observation."""
        self._available()
        self._finished = True
        if not self._aborted or self._active:
            raise ValueError('aborted task teardown is incomplete')
