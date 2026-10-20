import ctypes as C
from dataclasses import replace
import unittest
from unittest.mock import patch

from evals.native_audit_rule import AuditRule, build_rule, RuleData
from tests.test_native_auparse import Function


KEY = 'harness-v4-'+'a'*32


class FakeAuditLibrary:
    def __init__(self):
        self.buffer=C.create_string_buffer(1200)
        self.data=RuleData.from_buffer(self.buffer)
        self.freed=False
        self.fail=False
        self.audit_rule_create_data=Function(lambda:C.addressof(self.buffer))
        self.audit_rule_free_data=Function(lambda p:setattr(self,'freed',True))
        self.audit_rule_fieldpair_data=Function(self.field)
        self.audit_rule_syscallbyname_data=Function(self.syscall)

    def field(self, pointer, pair, flags):
        if self.fail:return -1
        value=C.string_at(pair)
        index=self.data.field_count
        self.data.field_count+=1
        self.data.fieldflags[index]=0x40000000
        if value==b'euid=2000':
            self.data.fields[index]=2;self.data.values[index]=2000  # Linux6.8 AUDIT_EUID.
        else:
            assert value.startswith(b'key=')
            key=value[4:];self.data.fields[index]=210;self.data.values[index]=len(key)
            self.data.buflen=len(key);C.memmove(C.addressof(self.buffer)+1040,key,len(key))
        return 0

    def syscall(self, pointer, name):
        if name==b'all':
            for index in range(64):self.data.mask[index]=0xffffffff
        return 0


class AuditRuleTests(unittest.TestCase):
    def build(self, library=None):
        lib=library or FakeAuditLibrary()
        with patch('evals.native_audit_rule._library',return_value=lib):
            return build_rule(KEY),lib

    def test_public_libaudit_allocation_is_freed_and_rule_has_exact_uid_and_key(self):
        rule,library=self.build()
        self.assertTrue(library.freed)
        self.assertEqual(1040,C.sizeof(RuleData))
        self.assertEqual(KEY.encode(),rule.payload[1040:])
        self.assertEqual(2,RuleData.from_buffer_copy(rule.payload[:1040]).fields[0])
        self.assertEqual(0xffff,RuleData.from_buffer_copy(rule.payload[:1040]).mask[-1])
        self.assertEqual(64,len(rule.sha256))
        self.assertNotIn(KEY,repr(rule))
        rule.validate()

    def test_invalid_fixed_rule_identity_or_shape_is_rejected(self):
        rule,_=self.build()
        for key in ('other','harness-v4-'+ 'a'*31,'harness-v4-'+ 'A'*32):
            with self.assertRaises(ValueError):replace(rule,key=key).validate()
        for offset,value in ((0,1),(4,0),(8,1),(12,0),(268,111),(524,0),(780,0),(1036,1)):
            raw=bytearray(rule.payload);C.c_uint.from_buffer(raw,offset).value=value
            with self.subTest(offset=offset),self.assertRaises(ValueError):
                AuditRule(KEY,bytes(raw)).validate()
        for payload in (b'',rule.payload+b'\0',rule.payload[:-1], 'data'):
            with self.assertRaises(ValueError):AuditRule(KEY,payload).validate()

    def test_failure_frees_library_allocation_and_does_not_echo_key(self):
        library=FakeAuditLibrary();library.fail=True
        with patch('evals.native_audit_rule._library',return_value=library):
            with self.assertRaises(ValueError) as caught:build_rule(KEY)
        self.assertTrue(library.freed)
        self.assertNotIn(KEY,str(caught.exception))
