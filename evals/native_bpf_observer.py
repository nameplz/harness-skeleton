"""Single-owner numeric lifecycle capture with pre-release task attribution."""

from __future__ import annotations

import ctypes as C
from dataclasses import dataclass
import os
import threading

from evals.native_bpf_events import BpfLedger, BpfSummary, WIRE
from evals.native_bpf_generations import GenerationLedger, GenerationSummary
from evals.native_bpf_object import NativeBpfObject
from evals.native_cgroup import CgroupBinding, kernel_cgroup_ids
from evals.native_supervisor import _idle_actor_uid


@dataclass(frozen=True)
class BpfObservation:
    transport: BpfSummary
    generations: GenerationSummary


class BpfObserver:
    def __init__(self) -> None:
        self._owner = threading.get_ident()
        self._object = NativeBpfObject()
        self._ledger = BpfLedger()
        self._generations: GenerationLedger | None = None
        self._prefix = []
        self._error: BaseException | None = None
        self._started = self._closed = self._finished = self._draining = self._aborted = False
        self._capturing = False
        self.ready = False
        self.result: BpfObservation | None = None

    def _owner_check(self) -> None:
        if threading.get_ident() != self._owner:
            raise ValueError('BPF observer is owned by another thread')

    def _latch(self, error: BaseException) -> None:
        if self._error is None:
            self._error = error
        self.ready = False
        self.result = None

    def start(self) -> None:
        self._owner_check()
        if self._started or self._closed:
            raise ValueError('BPF observer cannot be reused')
        self._started = True
        try:
            self._object.start(self._receive)
            self._capturing = True
        except BaseException as error:
            self._latch(error)
            self._closed = self._object._closed
            raise

    def _receive(self, _context, data, size: int) -> int:
        try:
            self._owner_check()
            if self._error is not None:
                return 0
            if not self._draining or size != WIRE.size or not data:
                raise ValueError('unexpected BPF callback state or record size')
            event = self._ledger.consume(C.string_at(data, size))
            if self._generations is None:
                if len(self._prefix) >= 16:
                    raise ValueError('BPF pre-admission prefix exceeded its bound')
                self._prefix.append(event)
            else:
                self._generations.observe(event)
        except BaseException as error:
            # ctypes callbacks must never unwind through libbpf's C stack.
            self._latch(error)
        return 0

    def fileno(self) -> int:
        self._owner_check()
        if not self._started or self._closed:
            raise ValueError('BPF observer descriptor is unavailable')
        return self._object.fileno()

    def drain(self, *, recovering: bool = False) -> int:
        self._owner_check()
        if type(recovering) is not bool or self._draining or not self._started or self._closed:
            raise ValueError('BPF observer drain is unavailable or reentrant')
        self._draining = True
        try:
            count = self._object.drain()
        except BaseException as error:
            self._latch(error)
            raise
        finally:
            self._draining = False
        if self._error is not None and not recovering:
            raise self._error
        return count

    def bind(self, binding: CgroupBinding) -> None:
        self._owner_check()
        if self._generations is not None or self._aborted or self._finished:
            raise ValueError('BPF admission cannot be repeated')
        try:
            self.drain()
            ids = kernel_cgroup_ids(binding)
            self._generations = GenerationLedger(binding, actor_cgroup_id=ids.actor,
                guardian_cgroup_id=ids.parent, clock_ticks=os.sysconf('SC_CLK_TCK'))
            for event in self._prefix:
                self._generations.observe(event)
            self._prefix.clear()
            self._generations.prepare_release()
            self.ready = True
        except BaseException as error:
            self._latch(error)
            raise

    def abort(self) -> None:
        self._owner_check()
        if self._finished or self._closed:
            raise ValueError('BPF observation is already finalized or closed')
        self._aborted = True
        self.ready = False
        self.result = None
        if self._generations is not None and self._error is None and not self._finished:
            self._generations.abort()

    def finish(self) -> BpfObservation | None:
        self._owner_check()
        if self._finished or not self._capturing or self._closed:
            raise ValueError('BPF observer finalization is unavailable')
        _idle_actor_uid()  # No detach while a guardian or actor can still run.
        self._finished = True
        try:
            self._object.detach()
        except BaseException as error:
            self._latch(error)
        try:
            self.drain(recovering=True)
            counters = self._object.counters()
            self.drain(recovering=True)
            if counters != self._object.counters():
                raise ValueError('detached BPF counters are not stable')
            if self._error is not None:
                raise self._error
            transport = self._ledger.finish(counters)
            if self._aborted:
                if self._generations is not None:
                    self._generations.finish_abort()
                return None
            if self._generations is None:
                raise ValueError('BPF observation was never bound')
            if not transport.events:
                raise ValueError('BPF observation has no lifecycle records')
            self.result = BpfObservation(transport, self._generations.finish())
            return self.result
        except BaseException as error:
            self._latch(error)
            raise
        finally:
            self.ready = False

    def close(self) -> None:
        self._owner_check()
        if self._closed:
            return
        _idle_actor_uid()
        self.ready = False
        try:
            self._object.close()
        except BaseException as error:
            self._latch(error)
            raise
        finally:
            self._closed = self._object._closed
            if self._closed:
                self._capturing = False
