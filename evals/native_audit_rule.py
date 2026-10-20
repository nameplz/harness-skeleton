"""One pinned libaudit rule: all syscall exits for the dedicated actor EUID."""

from __future__ import annotations

import ctypes as C
from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import re
import secrets
import struct

from evals.native_audit_library import load_library

LIBRARY = Path('/usr/lib/aarch64-linux-gnu/libaudit.so.1.0.0')
LIBRARY_SHA256 = '1b2f25df278672d99dd964a0b1af2353d5eae301430c11c0e545ca66e88b4b6f'
RULE_KEY = re.compile('harness-v4-[0-9a-f]{32}')


class RuleData(C.Structure):
    _fields_ = [('flags', C.c_uint), ('action', C.c_uint), ('field_count', C.c_uint),
                ('mask', C.c_uint*64), ('fields', C.c_uint*64), ('values', C.c_uint*64),
                ('fieldflags', C.c_uint*64), ('buflen', C.c_uint)]


@dataclass(frozen=True)
class AuditRule:
    key: str = field(repr=False)
    payload: bytes = field(repr=False)

    def validate(self) -> None:
        if type(self.key) is not str or not RULE_KEY.fullmatch(self.key) or \
                type(self.payload) is not bytes or len(self.payload) != 1040+len(self.key) or \
                self.payload[1040:] != self.key.encode('ascii'):
            raise ValueError('invalid owned audit rule identity')
        expected = RuleData()
        expected.flags, expected.action, expected.field_count = 4, 2, 2
        for index in range(64):
            expected.mask[index] = 0xffffffff if index != 63 else 0xffff
        expected.fields[0], expected.fields[1] = 2, 210  # AUDIT_EUID / AUDIT_FILTERKEY.
        expected.values[0], expected.values[1] = 2000, len(self.key)
        expected.fieldflags[0] = expected.fieldflags[1] = 0x40000000  # AUDIT_EQUAL.
        expected.buflen = len(self.key)
        if self.payload[:1040] != bytes(expected):
            raise ValueError('owned audit rule does not match fixed UID policy')

    @property
    def sha256(self) -> str:
        self.validate()
        return hashlib.sha256(self.payload).hexdigest()


def _library():
    return load_library(LIBRARY, LIBRARY_SHA256)


def _bind(library, name, result, arguments):
    function = getattr(library, name)
    function.restype, function.argtypes = result, arguments
    return function


def build_rule(key: str | None = None) -> AuditRule:
    key = 'harness-v4-'+secrets.token_hex(16) if key is None else key
    if type(key) is not str or not RULE_KEY.fullmatch(key) or C.sizeof(RuleData) != 1040:
        raise ValueError('invalid owned audit rule key or ABI')
    library = _library()
    P, I, S = C.c_void_p, C.c_int, C.c_char_p
    create = _bind(library, 'audit_rule_create_data', P, [])
    free = _bind(library, 'audit_rule_free_data', None, [P])
    pair = _bind(library, 'audit_rule_fieldpair_data', I, [C.POINTER(P), S, I])
    syscall = _bind(library, 'audit_rule_syscallbyname_data', I, [P, S])
    pointer = P(create())
    if not pointer:
        raise ValueError('audit rule allocation failed')
    try:
        if pair(C.byref(pointer), C.create_string_buffer(b'euid=2000'), 4) != 0 or \
                syscall(pointer, b'getpid') != 0 or syscall(pointer, b'all') != 0 or \
                pair(C.byref(pointer), C.create_string_buffer(b'key='+key.encode()), 4) != 0 or \
                syscall(pointer, b'all') != 0:
            raise ValueError('audit rule construction failed')
        size = RuleData.from_address(pointer.value).buflen
        if size != len(key):
            raise ValueError('audit rule string length differs')
        raw = bytearray(C.string_at(pointer, 1040+size))
        struct.pack_into('=II', raw, 0, 4, 2)
        # Linux removes reserved class bits from the last syscall mask word.
        struct.pack_into('=I', raw, 12+63*4, 0xffff)
        rule = AuditRule(key, bytes(raw))
        rule.validate()
        return rule
    finally:
        free(pointer)
