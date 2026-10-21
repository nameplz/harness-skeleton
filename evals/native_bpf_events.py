"""Bounded numeric CO-RE lifecycle transport, not attribution or grading evidence."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import struct

WIRE = struct.Struct('=6Q8I')
MAX_EVENTS = 131072


@dataclass(frozen=True)
class BpfEvent:
    sequence: int
    timestamp_ns: int
    cgroup_id: int
    current_cgroup_id: int
    start_ns: int
    related_start_ns: int
    kind: int
    tid: int
    tgid: int
    related_tid: int
    related_tgid: int
    old_tid: int
    cpu: int
    reserved: int


def decode_event(raw: bytes) -> BpfEvent:
    if type(raw) is not bytes or len(raw) != WIRE.size:
        raise ValueError('unsupported BPF lifecycle record ABI')
    event = BpfEvent(*WIRE.unpack(raw))
    def pid(value: int) -> bool:
        return 2 <= value < 2**31
    if not 0 < event.sequence <= MAX_EVENTS or event.kind not in (1, 2, 3) or \
            not pid(event.tid) or not pid(event.tgid) or not event.cgroup_id or \
            not event.current_cgroup_id or not 0 < event.start_ns <= event.timestamp_ns or \
            event.cpu >= 4096 or event.reserved:
        raise ValueError('invalid BPF lifecycle identity')
    if event.kind == 1:
        if not pid(event.related_tid) or not pid(event.related_tgid) or \
                not 0 < event.related_start_ns <= event.timestamp_ns or event.old_tid:
            raise ValueError('invalid BPF fork relation')
    elif event.related_tid or event.related_tgid or event.related_start_ns or \
            (event.kind == 2 and not pid(event.old_tid)) or (event.kind == 3 and event.old_tid):
        raise ValueError('invalid BPF exec/exit relation')
    return event


@dataclass(frozen=True)
class BpfCounters:
    attempted: int
    emitted: int
    dropped: int


@dataclass(frozen=True)
class BpfSummary:
    events: int
    types: tuple[tuple[int, int], ...]
    sha256: str


class BpfLedger:
    def __init__(self) -> None:
        self._seen: set[int] = set()
        self._counts: dict[int, int] = {}
        self._hash = hashlib.sha256()
        self._failed = self._finished = False

    def consume(self, raw: bytes) -> BpfEvent:
        if self._failed or self._finished:
            raise ValueError('BPF lifecycle ledger is unavailable')
        try:
            event = decode_event(raw)
            if len(self._seen) >= MAX_EVENTS or event.sequence in self._seen:
                raise ValueError('duplicate or excessive BPF lifecycle record')
            self._seen.add(event.sequence)
            self._counts[event.kind] = self._counts.get(event.kind, 0) + 1
            self._hash.update(raw)
            return event
        except BaseException:
            self._failed = True
            raise

    def finish(self, counters: BpfCounters) -> BpfSummary:
        if self._failed or self._finished:
            raise ValueError('BPF lifecycle ledger is unavailable')
        self._finished = True
        count = len(self._seen)
        if type(counters) is not BpfCounters or any(type(v) is not int or not 0 <= v < 2**64
                for v in vars(counters).values()) or counters.dropped or \
                counters.attempted != counters.emitted or counters.emitted != count or \
                max(self._seen, default=0) != count:
            raise ValueError('BPF lifecycle counters or sequence coverage are incomplete')
        # Atomic numbering can race with ring reservations across CPUs. Check the
        # complete bounded set, not a global monotonic order the producer cannot promise.
        return BpfSummary(count, tuple(sorted(self._counts.items())), self._hash.hexdigest())
