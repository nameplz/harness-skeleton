"""Bounded Linux audit framing, in memory only; not action-audit attestation.

The pinned Linux 6.8 unicast event ABI reports payload length in nlmsg_len.
Control replies use standard Netlink lengths. Never log or serialize payloads;
the trusted caller must sanitize them and prove event coverage separately.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import socket
import struct

HEADER = struct.Struct('=IHHII')
MAX_DATAGRAM = 65536
MAX_EVENT = 8970
MAX_MESSAGES = 64
RXQ_OVERFLOW = 40  # Linux SO_RXQ_OVFL; this module does not open sockets.
Ancillary = tuple[tuple[int, int, bytes], ...] | list[tuple[int, int, bytes]]


@dataclass(frozen=True)
class KernelMessage:
    kind: int
    sequence: int
    payload: bytes = field(repr=False)
    flags: int = 0


def _envelope(raw: bytes, address: tuple[int, int], flags: int,
              ancillary: Ancillary) -> None:
    if type(raw) is not bytes or not HEADER.size <= len(raw) <= MAX_DATAGRAM or \
            type(address) is not tuple or len(address) != 2 or any(
                type(value) is not int or value != 0 for value in address) or \
            type(flags) is not int or flags != 0:
        raise ValueError('audit kernel datagram unavailable or truncated')
    if type(ancillary) not in (tuple, list) or len(ancillary) > 1:
        raise ValueError('invalid audit ancillary data')
    for entry in tuple(ancillary):
        if type(entry) is not tuple or len(entry) != 3:
            raise ValueError('invalid audit ancillary data')
        level, kind, value = entry
        if type(level) is not int or level != socket.SOL_SOCKET or \
                type(kind) is not int or kind != RXQ_OVERFLOW or \
                type(value) is not bytes or value != b'\0' * 4:
            raise ValueError('audit socket overflow or unknown ancillary data')


def decode_event(raw: bytes, *, address: tuple[int, int] = (0, 0), flags: int = 0,
                 ancillary: Ancillary = ()) -> KernelMessage:
    """Decode one legacy unicast event; caller supplies actual recvmsg metadata."""
    _envelope(raw, address, flags, ancillary)
    size, kind, message_flags, sequence, origin = HEADER.unpack_from(raw)
    if not 0 < size <= MAX_EVENT or len(raw) != HEADER.size + size or \
            not 1100 <= kind <= 2999 or message_flags or sequence or origin:
        raise ValueError('invalid legacy audit event framing')
    return KernelMessage(kind, sequence, raw[HEADER.size:])


def decode_replace(raw: bytes, *, expected_pid: int, address: tuple[int, int] = (0, 0),
                   flags: int = 0, ancillary: Ancillary = ()) -> None:
    """Validate the standard-length audit_replace liveness probe, not a log event."""
    _envelope(raw, address, flags, ancillary)
    if type(expected_pid) is not int or not 2 <= expected_pid < 2**31 or \
            raw != HEADER.pack(20, 1329, 0, 0, 0) + struct.pack('=i', expected_pid):
        raise ValueError('audit replacement probe identity or framing differs')


def decode_control(raw: bytes, *, sequence: int, port_id: int,
                   address: tuple[int, int] = (0, 0), flags: int = 0,
                   ancillary: Ancillary = ()) -> tuple[KernelMessage, ...]:
    """Decode standard replies; ACK/error/TLV semantics remain the caller's duty."""
    _envelope(raw, address, flags, ancillary)
    if type(sequence) is not int or not 0 < sequence < 2**31 or \
            type(port_id) is not int or not 0 < port_id < 2**32:
        raise ValueError('invalid audit request identity')
    result = []
    offset = 0
    while offset < len(raw):
        if len(result) >= MAX_MESSAGES or len(raw) - offset < HEADER.size:
            raise ValueError('audit control framing exceeded its bound')
        size, kind, message_flags, actual_sequence, origin = HEADER.unpack_from(raw, offset)
        end = offset + size
        expected_origin = port_id if kind == 2 else 0
        allowed_flags = (0, 256, 512, 768) if kind == 2 else ((0, 2) if kind in (3, 1013) else (0,))
        if size < HEADER.size or end > len(raw) or kind not in (2, 3, 1000, 1013) or \
                message_flags not in allowed_flags or actual_sequence != sequence or origin != expected_origin:
            raise ValueError('audit control reply identity or framing differs')
        result.append(KernelMessage(kind, actual_sequence, raw[offset + HEADER.size:end], message_flags))
        if end == len(raw):
            break
        aligned = offset + ((size + 3) & ~3)
        if aligned > len(raw) or any(raw[end:aligned]):
            raise ValueError('invalid audit control alignment')
        offset = aligned
    return tuple(result)
