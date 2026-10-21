import struct
import unittest

from evals.native_bpf_events import BpfCounters, BpfLedger, decode_event

WIRE=struct.Struct('=6Q8I')
def frame(**changes):
    values=dict(sequence=1,timestamp_ns=100,cgroup_id=44,current_cgroup_id=44,start_ns=10,
        related_start_ns=0,kind=2,tid=23,tgid=23,related_tid=0,related_tgid=0,old_tid=23,cpu=0,reserved=0)
    return WIRE.pack(*{**values,**changes}.values())


class BpfEventTests(unittest.TestCase):
    def test_exact_numeric_abi_has_no_string_projection(self):
        event=decode_event(frame())
        self.assertEqual(80,WIRE.size)
        self.assertEqual((23,10,44),(event.tid,event.start_ns,event.cgroup_id))
        self.assertNotIn('comm',vars(event))

    def test_bad_shape_kind_identity_and_reserved_bytes_fail_closed(self):
        for raw in (b'',frame()+b'x','text',frame(kind=4),frame(sequence=0),frame(tid=1),
                frame(cgroup_id=0),frame(current_cgroup_id=0),frame(start_ns=0),
                frame(timestamp_ns=9),frame(cpu=4096),frame(reserved=1)):
            with self.subTest(raw=type(raw).__name__),self.assertRaises(ValueError):decode_event(raw)

    def test_kind_specific_fields_require_exact_fork_exec_exit_forms(self):
        decode_event(frame(kind=1,related_tid=22,related_tgid=22,related_start_ns=9,old_tid=0))
        decode_event(frame(kind=3,old_tid=0))
        for changes in ({'kind':1,'old_tid':0},{'kind':3},{'related_tid':22},{'old_tid':0},
                {'kind':1,'related_tid':22,'related_tgid':22,'related_start_ns':101,'old_tid':0}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):decode_event(frame(**changes))

    def test_atomic_sequence_order_can_differ_from_ring_reservation_order(self):
        ledger=BpfLedger();ledger.consume(frame(sequence=2));ledger.consume(frame(sequence=1))
        summary=ledger.finish(BpfCounters(2,2,0))
        self.assertEqual(2,summary.events)
        self.assertEqual(((2,2),),summary.types)
        self.assertEqual(64,len(summary.sha256))
        with self.assertRaises(ValueError):ledger.finish(BpfCounters(2,2,0))
        with self.assertRaises(ValueError):ledger.consume(frame(sequence=3))

    def test_duplicate_or_bad_event_latches_failure(self):
        for raw in (frame(),frame(kind=4)):
            ledger=BpfLedger();ledger.consume(frame())
            with self.assertRaises(ValueError):ledger.consume(raw)
            with self.assertRaises(ValueError):ledger.finish(BpfCounters(1,1,0))

    def test_counters_gap_loss_and_inconsistent_totals_never_pass(self):
        for counters in (None,BpfCounters(2,1,1),BpfCounters(2,1,0),BpfCounters(2,2,0),
                BpfCounters(True,1,0),BpfCounters(1,1,-1),BpfCounters(1,1,2**64)):
            ledger=BpfLedger();ledger.consume(frame())
            with self.subTest(counters=counters),self.assertRaises(ValueError):ledger.finish(counters)
        ledger=BpfLedger();ledger.consume(frame(sequence=2))
        with self.assertRaises(ValueError):ledger.finish(BpfCounters(1,1,0))

    def test_event_bound_is_enforced_before_accepting_another_record(self):
        from unittest.mock import patch
        ledger=BpfLedger()
        with patch('evals.native_bpf_events.MAX_EVENTS',1):
            ledger.consume(frame())
            with self.assertRaises(ValueError):ledger.consume(frame(sequence=2))

    def test_empty_stream_is_not_claimed_as_hook_qualification(self):
        summary=BpfLedger().finish(BpfCounters(0,0,0))
        self.assertEqual(0,summary.events)


    def test_callback_interrupt_invalidates_ledger(self):
        from unittest.mock import patch
        ledger=BpfLedger()
        with patch('evals.native_bpf_events.decode_event',side_effect=KeyboardInterrupt),self.assertRaises(KeyboardInterrupt):
            ledger.consume(frame())
        with self.assertRaises(ValueError):ledger.finish(BpfCounters(0,0,0))
