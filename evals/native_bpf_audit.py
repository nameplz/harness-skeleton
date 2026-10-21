"""Numeric exact audit-key/task bindings from the pinned kernel fexit hook."""
from __future__ import annotations

from dataclasses import dataclass
import struct

AUDIT_WIRE = struct.Struct('=6Qq12I')


@dataclass(frozen=True)
class BpfAuditEvent:
    sequence: int
    timestamp_ns: int
    cgroup_id: int
    start_ns: int
    audit_seconds: int
    audit_serial: int
    return_code: int
    tid: int
    tgid: int
    audit_type: int
    audit_milli: int
    arch: int
    syscall_nr: int
    context: int
    return_valid: int
    status: int
    cpu: int
    kind: int
    reserved: int


def decode_audit_binding(raw: bytes) -> BpfAuditEvent:
    if type(raw) is not bytes or len(raw) != AUDIT_WIRE.size:
        raise ValueError('unsupported BPF audit binding ABI')
    event = BpfAuditEvent(*AUDIT_WIRE.unpack(raw))
    if not 0 < event.sequence <= 131072 or event.kind != 4 or event.status or event.reserved or \
            not 2 <= event.tid < 2**31 or not 2 <= event.tgid < 2**31 or \
            not event.cgroup_id or not 0 < event.start_ns <= event.timestamp_ns or \
            not 0 < event.audit_seconds < 2**63 or not 0 < event.audit_serial < 2**32 or \
            event.audit_milli >= 1000 or event.cpu >= 4096 or event.audit_type not in (1300, 1326):
        raise ValueError('invalid BPF audit binding identity or stamp')
    if event.audit_type == 1300:
        if event.context != 1 or event.arch != 0xc00000b7 or event.syscall_nr >= 2**31 or \
                event.return_valid not in (0, 1, 2):
            raise ValueError('invalid BPF syscall audit context')
    elif any((event.arch, event.syscall_nr, event.context, event.return_valid, event.return_code)):
        raise ValueError('seccomp binding cannot invent syscall outcome fields')
    return event
