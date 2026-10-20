"""Pinned Linux audit request/reply semantics; no kernel mutation on import.

Live channels request capped ACKs and leave extended ACKs disabled. Any TLV or
uncapped response is rejected, never interpreted or logged as diagnostic text.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields
import hashlib
import itertools
import secrets
import select
import socket
import struct
import threading
import time
from typing import Callable

from evals.native_audit_wire import HEADER, Ancillary, decode_control

STATUS = struct.Struct('=11I')
GET, SET, ADD_RULE, DEL_RULE, LIST_RULES = 1000, 1001, 1011, 1012, 1013
MAX_REPLY_BYTES = 65536
MAX_RULES = 64
_sequences = itertools.count(secrets.randbelow(2**30)+1)


@dataclass(frozen=True)
class AuditStatus:
    mask: int
    enabled: int
    failure: int
    pid: int
    rate_limit: int
    backlog_limit: int
    lost: int
    backlog: int
    feature_bitmap: int
    backlog_wait_time: int
    backlog_wait_time_actual: int

    @classmethod
    def decode(cls, payload: bytes) -> AuditStatus:
        if type(payload) is not bytes or len(payload) != STATUS.size:
            raise ValueError('unsupported audit status ABI')
        result = cls(*STATUS.unpack(payload))
        if result.mask != 0 or result.enabled not in (0, 1, 2) or result.failure not in (0, 1, 2) or \
                result.pid >= 2**31 or not 0 < result.backlog_limit <= 262144:
            raise ValueError('invalid audit status fields')
        return result

    def encode(self) -> bytes:
        values = tuple(getattr(self, f.name) for f in fields(self))
        if any(type(value) is not int or not 0 <= value < 2**32 for value in values):
            raise ValueError('invalid audit status fields')
        return STATUS.pack(*values)

    @property
    def pristine(self) -> bool:
        return self.enabled == self.pid == self.rate_limit == self.lost == self.backlog == 0


@dataclass(frozen=True)
class AuditRequest:
    kind: int
    payload: bytes = field(repr=False)
    sequence: int
    port_id: int

    @property
    def packet(self) -> bytes:
        if type(self.kind) is not int or self.kind not in (GET, SET, ADD_RULE, DEL_RULE, LIST_RULES) or \
                type(self.sequence) is not int or not 0 < self.sequence < 2**31 or \
                type(self.port_id) is not int or not 0 < self.port_id < 2**32 or \
                type(self.payload) is not bytes or len(self.payload) > 4096 or \
                (self.kind in (GET, LIST_RULES) and self.payload) or \
                (self.kind == SET and len(self.payload) != STATUS.size):
            raise ValueError('invalid audit request identity or body')
        return HEADER.pack(HEADER.size+len(self.payload), self.kind, 5,
                           self.sequence, self.port_id) + self.payload


class AuditReplies:
    """Consume a complete bounded transaction; partial answers are unavailable."""

    def __init__(self, request: AuditRequest) -> None:
        if type(request) is not AuditRequest:
            raise ValueError('invalid audit request')
        self._packet = request.packet
        self._request = request
        self._answers: tuple[bytes, ...] = ()
        self._ack = False
        self._done = request.kind != LIST_RULES
        self._failed = False
        self._bytes = 0

    @property
    def complete(self) -> bool:
        return not self._failed and self._ack and self._done and \
            (self._request.kind != GET or len(self._answers) == 1)

    @property
    def answers(self) -> tuple[bytes, ...]:
        if not self.complete:
            raise ValueError('audit control transaction is incomplete')
        return self._answers

    def consume(self, raw: bytes, *, address: tuple[int, int] = (0, 0),
                flags: int = 0, ancillary: Ancillary = ()) -> bool:
        if self._failed or self.complete:
            raise ValueError('audit control transaction is closed')
        try:
            messages = decode_control(raw, sequence=self._request.sequence,
                port_id=self._request.port_id, address=address, flags=flags, ancillary=ancillary)
            self._bytes += len(raw)
            if self._bytes > MAX_REPLY_BYTES:
                raise ValueError('audit control response exceeded its byte bound')
            for message in messages:
                if self.complete:
                    raise ValueError('audit control transaction has extra replies')
                self._message(message.kind, message.flags, message.payload)
            return self.complete
        except BaseException:
            self._failed = True
            raise

    def _message(self, kind: int, flags: int, payload: bytes) -> None:
        if kind == 2:
            if self._ack or flags != 256 or len(payload) != 20 or payload[4:] != self._packet[:16]:
                raise ValueError('audit ACK echo, flags or size differs')
            error, = struct.unpack_from('=i', payload)
            if error > 0 or error < -4095:
                raise ValueError('invalid audit ACK error')
            if error:
                raise OSError(-error, 'audit control request failed')
            self._ack = True
        elif kind == 3:
            if self._request.kind != LIST_RULES or self._done or flags != 2 or \
                    payload not in (b'', b'\0' * 4):
                raise ValueError('audit rule dump terminator differs')
            self._done = True
        elif kind == self._request.kind and kind in (GET, LIST_RULES):
            if flags != (2 if kind == LIST_RULES else 0) or \
                    (kind == LIST_RULES and self._done) or not 0 < len(payload) <= 4096 or \
                    len(self._answers) >= (1 if kind == GET else MAX_RULES):
                raise ValueError('audit control reply type, size or order differs')
            if kind == GET:
                AuditStatus.decode(payload)
            self._answers = (*self._answers, payload)
        else:
            raise ValueError('unexpected audit control reply')


@dataclass(frozen=True)
class ControlReceipt:
    kind: int
    sequence: int
    port_id: int
    request_sha256: str
    reply_datagrams: int
    reply_bytes: int


def _open_socket():
    from evals.native_cgroup import _require_root_linux
    _require_root_linux()
    stream = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW | socket.SOCK_CLOEXEC, 9)
    try:
        stream.bind((0, 0))
        stream.setsockopt(270, 10, 1)  # SOL_NETLINK / NETLINK_CAP_ACK; no extended ACK opt-in.
        stream.setsockopt(socket.SOL_SOCKET, 40, 1)  # SO_RXQ_OVFL; never suppress ENOBUFS.
        stream.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
        stream.setblocking(False)
        return stream
    except BaseException:
        stream.close()
        raise


class AuditChannel:
    """Root control socket; fresh channels share a non-repeating process sequence."""

    def __init__(self) -> None:
        self._owner = threading.get_ident()
        self._failed = self._busy = False
        self._socket = _open_socket()
        self.receipts: tuple[ControlReceipt, ...] = ()

    def __enter__(self) -> AuditChannel:
        self._check()
        return self

    def __exit__(self, *_args) -> None:
        self.close()

    def _check(self) -> None:
        if threading.get_ident() != self._owner or self._failed or self._busy or self._socket is None:
            raise ValueError('audit channel is closed, failed, reentered or owned by another thread')

    def fileno(self) -> int:
        self._check()
        return self._socket.fileno()

    def recvmsg(self):
        self._check()
        return self._socket.recvmsg(65536, 128, socket.MSG_DONTWAIT)

    def request(self, kind: int, payload: bytes = b'', *,
                pump: Callable[[], None] | None = None) -> tuple[bytes, ...]:
        self._check()
        if len(self.receipts) >= 64:
            raise ValueError('audit channel transaction bound exceeded')
        self._busy = True
        try:
            port = self._socket.getsockname()
            if type(port) is not tuple or len(port) != 2 or type(port[1]) is not int or port[1] != 0:
                raise ValueError('audit channel port identity differs')
            request = AuditRequest(kind, payload, next(_sequences), port[0])
            packet = request.packet
            replies = AuditReplies(request)
            if self._socket.sendto(packet, (0, 0)) != len(packet):
                raise ValueError('audit request send was incomplete')
            deadline = time.monotonic() + 3
            datagrams = 0
            while datagrams < 64:
                if pump is not None:
                    pump()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('audit control response deadline expired')
                readable, _, _ = select.select([self._socket], [], [], min(0.01, remaining))
                if not readable:
                    continue
                try:
                    raw, ancillary, flags, address = self._socket.recvmsg(65536, 128, socket.MSG_DONTWAIT)
                except BlockingIOError:
                    continue
                datagrams += 1
                if replies.consume(raw, address=address, flags=flags, ancillary=ancillary):
                    self.receipts = (*self.receipts, ControlReceipt(kind, request.sequence, request.port_id,
                        hashlib.sha256(packet).hexdigest(), datagrams, replies._bytes))
                    return replies.answers
            raise ValueError('audit control response datagram bound exceeded')
        except BaseException:
            self._failed = True
            raise
        finally:
            self._busy = False

    def close(self) -> None:
        if threading.get_ident() != self._owner or self._busy:
            raise ValueError('audit channel cannot close during a transaction or from another thread')
        if self._socket is not None:
            self._socket.close()
            self._socket = None
