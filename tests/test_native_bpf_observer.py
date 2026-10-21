import ctypes as C
from dataclasses import replace
import threading
import unittest
from unittest.mock import Mock, patch

from evals import native_bpf_observer as bpf
from evals.native_bpf_events import BpfCounters, WIRE
from evals.native_bpf_audit import AUDIT_WIRE, BpfAuditEvent
from evals.native_bpf_generations import TaskAttribution
from tests.test_native_audit_join import binding as audit_binding
from evals.native_cgroup import CgroupIds
from tests.test_native_bpf_generations import BINDING, event


class Engine:
    def __init__(self):
        self.rows = []; self.count = 0; self._closed = False; self.batch_limit = 131072
        self.detach = Mock(); self.close = Mock(side_effect=self.closed)
    def closed(self):self._closed = True
    def start(self, callback):self.callback = callback
    def fileno(self):return 77
    def drain(self):
        rows, self.rows = self.rows[:self.batch_limit], self.rows[self.batch_limit:]
        for raw in rows:
            data = C.create_string_buffer(raw)
            self.callback(None, C.addressof(data), len(raw))
        return len(rows)
    def counters(self):return BpfCounters(self.count, self.count, 0)
    def feed(self, *events):
        for row in events:
            self.count += 1
            wire = AUDIT_WIRE if type(row) is BpfAuditEvent else WIRE
            self.rows.append(wire.pack(*vars(replace(row, sequence=self.count)).values()))


class BpfObserverTests(unittest.TestCase):
    def setUp(self):
        self.engine = Engine()
        for target, value in (
                ('NativeBpfObject', self.engine), ('kernel_cgroup_ids', CgroupIds(54, 55)),
                ('_idle_actor_uid', None)):
            patcher = patch.object(bpf, target, return_value=value)
            patcher.start(); self.addCleanup(patcher.stop)
        self.owner = bpf.BpfObserver(); self.owner.start()

    def admit(self):
        self.engine.feed(event(2, 22, cgroup=54), event(1, 23, parent=22, parent_start=1000000000, cgroup=54))
        self.owner.bind(BINDING)
        self.engine.feed(event(2, 23))

    def test_audit_prefix_is_resolved_after_anchors_and_later_binding_uses_live_generation(self):
        consumer=Mock();self.owner._on_audit=consumer
        self.engine.feed(audit_binding(tid=22,tgid=22,start_ns=1000000000,timestamp_ns=4000000000,cgroup_id=54),
            event(2,22,cgroup=54),event(1,23,parent=22,parent_start=1000000000,cgroup=54),
            audit_binding(tid=23,tgid=23,start_ns=2000000000,timestamp_ns=4000000000,cgroup_id=54))
        self.owner.bind(BINDING)
        self.assertEqual([TaskAttribution(1,'guardian'),TaskAttribution(2,'launcher')],
                         [call.args[1] for call in consumer.call_args_list])
        self.engine.feed(event(2,23),audit_binding(tid=23,tgid=23,start_ns=2000000000,timestamp_ns=4000000000,cgroup_id=55))
        self.owner.drain()
        self.assertEqual(TaskAttribution(2,'actor'),consumer.call_args.args[1])

    def test_pre_admission_numeric_prefix_has_a_hard_bound(self):
        self.owner._on_audit=Mock()
        self.engine.feed(event(2,22,cgroup=54),event(1,23,parent=22,parent_start=1000000000,cgroup=54),
            audit_binding(tid=23,tgid=23,start_ns=2000000000,timestamp_ns=4000000000,cgroup_id=54))
        with patch.object(bpf,'MAX_PREFIX',2),self.assertRaises(ValueError):self.owner.bind(BINDING)
        self.assertFalse(self.owner.ready)

    def test_withheld_prefix_drains_every_batch_before_anchor_resolution(self):
        self.owner._on_audit=Mock();self.engine.batch_limit=2
        for serial in range(5):
            self.engine.feed(audit_binding(tid=22,tgid=22,start_ns=1000000000,
                timestamp_ns=4000000000,cgroup_id=54,audit_serial=serial+1))
        self.engine.feed(event(2,22,cgroup=54),event(1,23,parent=22,parent_start=1000000000,cgroup=54))
        self.owner.bind(BINDING)
        self.assertTrue(self.owner.ready);self.assertEqual([],self.engine.rows)
        self.assertEqual(5,self.owner._on_audit.call_count)

    def test_missing_audit_consumer_never_silently_discards_binding(self):
        self.admit();self.owner.drain()
        self.engine.feed(audit_binding(tid=23,tgid=23,start_ns=2000000000,timestamp_ns=4000000000,cgroup_id=55))
        with self.assertRaises(ValueError):self.owner.drain()
        self.assertFalse(self.owner.ready)

    def test_complete_bpf_drain_pumps_audit_between_every_batch(self):
        order=[];self.owner._audit_pump=lambda:order.append('audit')
        original=self.engine.drain
        def drain():order.append('bpf');return original()
        self.engine.drain=drain;self.engine.batch_limit=1
        self.admit();self.engine.feed(event(3,23),event(3,22,cgroup=54))
        self.owner.finish()
        self.assertTrue(order)
        for index,value in enumerate(order):
            if value=='bpf':self.assertEqual('audit',order[index-1])

    def test_final_drain_consumes_all_batches_before_accepting_counter_totals(self):
        self.owner._on_audit=Mock();self.admit();self.engine.batch_limit=2
        for serial in range(1,6):
            self.engine.feed(audit_binding(tid=23,tgid=23,start_ns=2000000000,
                timestamp_ns=4000000000,cgroup_id=55,audit_serial=serial))
        self.engine.feed(event(3,23),event(3,22,cgroup=54))
        self.assertEqual(10,self.owner.finish().transport.events)
        self.assertEqual([],self.engine.rows)

    def test_prefix_binding_complete_transport_and_attribution(self):
        self.admit()
        self.engine.feed(event(3, 23), event(3, 22, cgroup=54))
        summary = self.owner.finish()
        self.assertEqual((5, 2), (summary.transport.events, summary.generations.instances))
        self.engine.detach.assert_called_once()
        self.owner.close(); self.assertTrue(self.owner._closed)
        with self.assertRaises(ValueError):self.owner.start()

    def test_abort_cannot_change_a_finalized_or_closed_observation(self):
        self.admit(); self.engine.feed(event(3, 23), event(3, 22, cgroup=54))
        summary = self.owner.finish()
        for closed in (False, True):
            if closed:self.owner.close()
            with self.assertRaises(ValueError):self.owner.abort()
            self.assertIs(summary, self.owner.result)

    def test_missing_admission_anchor_never_becomes_ready(self):
        self.engine.feed(event(2, 22, cgroup=54))
        with self.assertRaises(ValueError):self.owner.bind(BINDING)
        self.assertFalse(self.owner.ready)
        self.assertIsNone(self.owner.result)

    def test_callback_failure_is_latched_without_crossing_C_and_raw_drain_continues(self):
        self.admit(); self.owner.drain()
        failure = KeyboardInterrupt()
        self.owner._generations.observe = Mock(side_effect=failure)
        self.engine.feed(event(2, 23), event(3, 23))
        with self.assertRaises(KeyboardInterrupt) as caught:self.owner.drain()
        self.assertIs(failure, caught.exception)
        self.assertEqual([], self.engine.rows)
        self.owner.drain(recovering=True)
        with self.assertRaises(BaseException):self.owner.finish()
        self.owner.close(); self.assertTrue(self.owner._closed)
        self.assertIsNone(self.owner.result)

    def test_counter_loss_and_live_generations_never_produce_result(self):
        self.admit(); self.engine.feed(event(3, 23), event(3, 22, cgroup=54))
        self.engine.counters = Mock(return_value=BpfCounters(6, 5, 1))
        with self.assertRaises(ValueError):self.owner.finish()
        self.owner.close(); self.assertIsNone(self.owner.result)

    def test_pre_release_abort_drains_teardown_without_accepting_a_trial(self):
        self.engine.feed(event(2, 22, cgroup=54), event(1, 23, parent=22, parent_start=1000000000, cgroup=54))
        self.owner.bind(BINDING); self.owner.abort()
        self.engine.feed(event(3, 23), event(3, 22, cgroup=54))
        self.owner.drain(recovering=True)
        self.assertIsNone(self.owner.finish())
        self.owner.close(); self.assertIsNone(self.owner.result)

    def test_failed_partial_start_does_not_finalize_or_detach_before_id_recovery(self):
        engine = Engine(); engine.start = Mock(side_effect=ValueError('identity pending'))
        with patch.object(bpf, 'NativeBpfObject', return_value=engine):owner = bpf.BpfObserver()
        with self.assertRaises(ValueError):owner.start()
        self.assertFalse(owner._capturing)
        with self.assertRaises(ValueError):owner.finish()
        engine.detach.assert_not_called()
        owner.close()

    def test_inflight_fork_exec_during_cancellation_is_drained_without_a_success_result(self):
        self.admit(); self.owner.abort()
        self.engine.feed(event(1, 24, parent=23, parent_start=2000000000),
                         event(2, 24), event(3, 24), event(3, 23), event(3, 22, cgroup=54))
        self.owner.drain(recovering=True)
        self.assertIsNone(self.owner.finish())
        self.owner.close(); self.assertIsNone(self.owner.result)

    def test_other_thread_and_reentry_are_rejected(self):
        failures = []
        def other():
            try:self.owner.drain()
            except BaseException as error:failures.append(error)
        thread = threading.Thread(target=other); thread.start(); thread.join()
        self.assertIsInstance(failures[0], ValueError)
        self.owner._draining = True
        with self.assertRaises(ValueError):self.owner.drain()
        self.owner._draining = False
        self.owner.close()

    def test_failed_resource_close_retains_owner_for_retry(self):
        self.engine.close.side_effect = OSError('close failed')
        with self.assertRaises(OSError):self.owner.close()
        self.assertFalse(self.owner._closed)
        self.engine.close.side_effect = self.engine.closed
        self.owner.close(); self.assertTrue(self.owner._closed)
