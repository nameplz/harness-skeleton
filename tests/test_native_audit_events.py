from dataclasses import replace
import json
import unittest

from evals.native_audit_events import (
    AuditKey, AuditLimits, AuditRecord, AuditSegment, EventLedger,
)
from evals.native_audit_wire import KernelMessage


KEY = AuditKey(1700000000, 123, 10)


def message(kind, key=KEY, body=b'field=private-canary'):
    header = f'audit({key.seconds}.{key.milli:03d}:{key.serial}):'.encode()
    return KernelMessage(kind, 0, header + (b' ' + body if kind != 1320 else b' '))


def syscall(**changes):
    values = dict(arch=0xc00000b7, syscall=56, success=False, exit=-13,
        a0=0xffffffffffffff9c, a1=123, a2=0, a3=0, items=1, pid=2001,
        ppid=2000, uid=2000, gid=2000, euid=2000, suid=2000, fsuid=2000,
        egid=2000, sgid=2000, fsgid=2000)
    return AuditRecord(1300, tuple({**values, **changes}.items()))


def path(item=0):
    return AuditRecord(1302, (('item', item), ('name', b'/private-canary'),
                             ('nametype', b'NORMAL')))


class NativeAuditEventTests(unittest.TestCase):
    def ledger(self, **kwargs):
        return EventLedger(key=b'k' * 32, **kwargs)

    def put(self, ledger, records, key=KEY):
        for record in records:
            self.assertIn(b'msg=audit(', ledger.record(message(record.kind, key)))
        ledger.segment(AuditSegment(key, tuple(records)))

    def complete(self, ledger, key=KEY):
        self.put(ledger, (syscall(), path()), key)
        self.assertIsNone(ledger.record(message(1320, key)))

    def test_seccomp_kernel_record_is_complete_but_does_not_attest_action_policy(self):
        values = dict(pid=2001,uid=2000,gid=2000,arch=0xc00000b7,syscall=425,
                      sig=0,compat=0,code=0x50000)
        ledger=self.ledger();self.put(ledger,(AuditRecord(1326,tuple(values.items())),))
        self.assertEqual(((1326,1),),ledger.finish().types)
        for bad in ({}, {**values,'code':0x50026}, {**values,'pid':0},
                    {**values,'compat':2}, {**values,'sig':65}, {**values,'arch':2**32}):
            ledger=self.ledger();ledger.record(message(1326))
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                ledger.segment(AuditSegment(KEY,(AuditRecord(1326,tuple(bad.items())),)))

    def test_standalone_kernel_bpf_records_require_exact_fields_without_inventing_actor(self):
        for operation in (b'LOAD',b'UNLOAD'):
            ledger=self.ledger();self.put(ledger,(AuditRecord(1334,(('prog_id',23),('op',operation))),))
            summary=ledger.finish();self.assertEqual(1,summary.events)
            self.assertEqual(((1334,1),),summary.types)
        for values in ((),(('prog_id',23),),(('prog_id',-1),('op',b'LOAD')),
                       (('prog_id',2**32),('op',b'LOAD')),(('prog_id',23),('op',b'unknown'))):
            ledger=self.ledger();ledger.record(message(1334))
            with self.subTest(values=values),self.assertRaises(ValueError):
                ledger.segment(AuditSegment(KEY,(AuditRecord(1334,values),)))

    def test_standalone_service_metadata_requires_result_and_identity_without_authority_claim(self):
        values=(('pid',1),('uid',0),('auid',2**32-1),('ses',2**32-1),('unit',b'owned-service'),('success',True))
        for kind in (1130,1131):
            ledger=self.ledger();self.put(ledger,(AuditRecord(kind,values),))
            self.assertEqual(1,ledger.finish().events)
            for incomplete in ((),values[:-1],tuple((n,v) for n,v in values if n!='unit')):
                ledger=self.ledger();ledger.record(message(kind))
                with self.assertRaises(ValueError):ledger.segment(AuditSegment(KEY,(AuditRecord(kind,incomplete),)))

    def test_complete_failed_syscall_has_ephemeral_fields_and_safe_summary(self):
        observed = []
        ledger = self.ledger(on_event=observed.append)
        self.complete(ledger)
        summary = ledger.finish()
        self.assertEqual((1, 3), (summary.events, summary.frames))
        self.assertEqual(((1300, 1), (1302, 1), (1320, 1)), summary.types)
        self.assertEqual(-13, dict(observed[0].records[0].values)['exit'])
        for value in (summary, ledger, observed[0], path(), AuditSegment(KEY, (path(),))):
            self.assertNotIn('private-canary', repr(value))
        self.assertEqual(64, len(summary.stream_hmac))
        self.assertNotEqual(summary.stream_hmac, summary.events_hmac)

    def test_interleaved_timestamp_identity_does_not_merge_reused_serial(self):
        other = replace(KEY, milli=124)
        ledger = self.ledger()
        self.put(ledger, (syscall(), path()), KEY)
        self.put(ledger, (syscall(), path()), other)
        ledger.record(message(1320, other))
        ledger.record(message(1320, KEY))
        self.assertEqual(2, ledger.finish().events)

    def test_early_partial_callback_merges_with_late_path_after_proctitle(self):
        ledger = self.ledger()
        self.put(ledger, (syscall(), AuditRecord(1327, ())))
        ledger.record(message(1302))
        ledger.record(message(1320))
        ledger.segment(AuditSegment(KEY, (path(),)))
        self.assertEqual(1, ledger.finish().events)

    def test_missing_eoe_or_callback_is_incomplete_even_after_flush(self):
        for mode in ('eoe', 'callback'):
            ledger = self.ledger()
            ledger.record(message(1300))
            if mode != 'path':
                ledger.record(message(1302))
            if mode != 'eoe':
                ledger.record(message(1320))
            if mode != 'callback':
                ledger.segment(AuditSegment(KEY, (syscall(), path()) if mode != 'path' else (syscall(),)))
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                ledger.finish()

    def test_missing_path_record_is_rejected_when_last_callback_arrives(self):
        ledger = self.ledger()
        ledger.record(message(1300)); ledger.record(message(1320))
        with self.assertRaises(ValueError):
            ledger.segment(AuditSegment(KEY, (syscall(),)))
        with self.assertRaises(ValueError): ledger.finish()

    def test_duplicate_eoe_late_record_and_closed_callback_fail_closed(self):
        for kind in (1320, 1302):
            ledger = self.ledger(); self.complete(ledger)
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                ledger.record(message(kind))
            with self.assertRaises(ValueError): ledger.finish()
        ledger = self.ledger(); self.complete(ledger)
        with self.assertRaises(ValueError): ledger.segment(AuditSegment(KEY, (path(),)))

    def test_extra_callback_unknown_key_and_duplicate_syscall_are_rejected(self):
        for segment in (AuditSegment(replace(KEY, serial=11), (path(),)),
                        AuditSegment(KEY, (syscall(), syscall(), path())),
                        AuditSegment(KEY, (syscall(), path(), path()))):
            ledger = self.ledger()
            ledger.record(message(1300)); ledger.record(message(1302))
            with self.subTest(segment=segment), self.assertRaises(ValueError):
                ledger.segment(segment)

    def test_path_items_are_exact_unique_and_contiguous(self):
        for paths in ((path(1),), (path(0), path(0)), (path(0), path(2))):
            ledger = self.ledger()
            records = (syscall(items=len(paths)), *paths)
            self.put(ledger, records)
            with self.subTest(items=tuple(dict(p.values)['item'] for p in paths)), self.assertRaises(ValueError):
                ledger.record(message(1320))

    def test_config_change_without_uid_or_eoe_is_structurally_complete(self):
        # Linux audit_log_rule_change emits session info but no UID; ownership is separate.
        ledger = self.ledger()
        self.put(ledger, (AuditRecord(1305, (('auid', 4294967295), ('op', b'remove_rule'),
                                           ('list', 4), ('res', 1))),))
        self.assertEqual(1, ledger.finish().events)
        ledger = self.ledger()
        with self.assertRaises(ValueError):self.put(ledger, (AuditRecord(1326, ()),))

    def test_control_records_require_complete_known_rule_or_status_form(self):
        rule = {'op': b'add_rule', 'list': 4, 'res': 1}
        setting = {'op': b'set', 'audit_enabled': 0, 'old': 1, 'res': 1}
        bad = [{}, *[{n: v for n, v in rule.items() if n != missing} for missing in rule],
               *[{n: v for n, v in setting.items() if n != missing} for missing in setting],
               {**rule, 'res': True}, {**rule, 'list': 8}, {**rule, 'op': b'private-canary'},
               {**setting, 'audit_pid': 0}, {**setting, 'old': -1}, {**setting, 'res': 2}]
        for values in bad:
            ledger = self.ledger(); ledger.record(message(1305))
            with self.subTest(fields=tuple(values)), self.assertRaises(ValueError):
                ledger.segment(AuditSegment(KEY, (AuditRecord(1305, tuple(values.items())),)))
            with self.assertRaises(ValueError): ledger.finish()
        ledger = self.ledger(); self.put(ledger, (AuditRecord(1305, tuple(setting.items())),))
        self.assertEqual(1, ledger.finish().events)

    def test_header_type_sequence_and_newline_validation_never_echoes_payload(self):
        bad = [KernelMessage(1300, 0, value) for value in (
            b'audit(1.12:3): private-canary', b'audit(01.123:3): x',
            b'audit(1.123:03): x', b'audit(1.123:3): x\nx',
            b'audit(1.123:3): x\x00x', b'audit(1.123:3): x\x00\x00',
            b'audit(1.123:18446744073709551616): x')]
        bad += [replace(message(1300), sequence=1), replace(message(1300), kind=True),
                replace(message(1300), kind=2999), replace(message(1300), payload='x'),
                message(1320, body=b'ignored')]
        bad[-1] = replace(bad[-1], payload=bad[-1].payload + b'private-canary')
        for packet in bad:
            ledger = self.ledger()
            with self.subTest(packet=repr(packet)), self.assertRaises(ValueError) as caught:
                ledger.record(packet)
            self.assertNotIn('private-canary', str(caught.exception))
        ledger = self.ledger()
        self.assertIsInstance(ledger.record(replace(message(1300), payload=message(1300).payload+b'\0')), bytes)

    def test_record_and_pending_event_bounds_are_enforced(self):
        for limits, action in (
            (AuditLimits(frames=1), lambda l: (l.record(message(1300)), l.record(message(1302)))),
            (AuditLimits(bytes=10), lambda l: l.record(message(1300))),
            (AuditLimits(pending=1), lambda l: (l.record(message(1300)), l.record(message(1300, replace(KEY, serial=11))))),
            (AuditLimits(records=1), lambda l: (l.record(message(1300)), l.record(message(1302)))),
            (AuditLimits(events=1), lambda l: (self.complete(l), self.complete(l, replace(KEY, serial=11))))):
            ledger = self.ledger(limits=limits)
            with self.subTest(limits=limits), self.assertRaises(ValueError): action(ledger)

    def test_summary_requires_nonempty_complete_stream_and_key_is_per_run(self):
        with self.assertRaises(ValueError): self.ledger().finish()
        summaries = []
        for key in (b'a'*32, b'b'*32):
            ledger = EventLedger(key=key); self.complete(ledger); summaries.append(ledger.finish())
            with self.assertRaises(ValueError): ledger.record(message(1300))
        self.assertNotEqual(summaries[0].stream_hmac, summaries[1].stream_hmac)
        for key in (b'', b'k'*31, 'k'*32):
            with self.assertRaises(ValueError): EventLedger(key=key)

    def test_consumer_failure_latches_without_private_exception_text(self):
        def consumer(event): raise RuntimeError('private-canary')
        ledger = self.ledger(on_event=consumer)
        with self.assertRaisesRegex(ValueError, '^audit event consumption failed$') as caught:
            self.complete(ledger)
        self.assertIsNone(caught.exception.__cause__)
        with self.assertRaises(ValueError): ledger.finish()

    def test_public_projection_contains_only_numeric_metadata_and_keyed_values(self):
        ledger = self.ledger(); self.complete(ledger)
        encoded = json.dumps(ledger.finish().projection())
        self.assertNotIn('private-canary', encoded)
        self.assertNotIn('k'*32, encoded)

    def test_limits_cannot_disable_hard_bounds_or_use_boolean_values(self):
        for limits in (AuditLimits(frames=True), AuditLimits(bytes=0), AuditLimits(events=131073)):
            with self.assertRaises(ValueError): self.ledger(limits=limits)

    def test_consumer_reentry_fails_closed(self):
        calls = []
        def consume(event):
            calls.append(event.key)
            ledger.finish()
        ledger = self.ledger(on_event=consume)
        with self.assertRaises(ValueError): self.complete(ledger)
        self.assertEqual([KEY], calls)
        with self.assertRaises(ValueError): ledger.finish()
