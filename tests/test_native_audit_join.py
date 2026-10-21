from dataclasses import replace
import struct
import unittest

from evals.native_bpf_audit import AUDIT_WIRE, BpfAuditEvent, decode_audit_binding
from evals.native_audit_join import AuditJoinLedger
from evals.native_bpf_generations import TaskAttribution
from evals.native_audit_events import AuditRecord, AuditSegment
from tests.test_native_audit_events import KEY, syscall
from tests.test_native_bpf_events import frame
from evals.native_bpf_events import BpfCounters, BpfLedger


def binding(**changes):
    fields=dict(sequence=1,timestamp_ns=100,cgroup_id=44,start_ns=10,
        audit_seconds=KEY.seconds,audit_serial=KEY.serial,return_code=-13,
        tid=2001,tgid=2001,audit_type=1300,audit_milli=KEY.milli,arch=0xc00000b7,
        syscall_nr=56,context=1,return_valid=2,status=0,cpu=0,kind=4,reserved=0)
    return BpfAuditEvent(**{**fields,**changes})


def segment(**changes):
    return AuditSegment(KEY,(syscall(items=0,**changes),))


class AuditBindingTransportTests(unittest.TestCase):
    def raw(self,event):return AUDIT_WIRE.pack(*vars(event).values())

    def test_numeric_binding_exact_abi_and_shared_sequence_counter(self):
        event=binding();raw=self.raw(event)
        self.assertEqual(104,len(raw));self.assertEqual(event,decode_audit_binding(raw))
        ledger=BpfLedger();ledger.consume(frame(sequence=2));self.assertEqual(event,ledger.consume(raw))
        self.assertEqual(((2,1),(4,1)),ledger.finish(BpfCounters(2,2,0)).types)

    def test_invalid_abi_stamp_task_status_or_context_never_pass(self):
        for changes in ({'audit_serial':0},{'audit_serial':2**32},{'audit_milli':1000},
                {'audit_seconds':0},{'audit_seconds':2**63},{'status':1},{'reserved':1},
                {'kind':3},{'audit_type':1336},{'tid':1},{'tgid':1},{'start_ns':101},
                {'context':2},{'return_valid':3},{'cpu':4096}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):
                decode_audit_binding(self.raw(binding(**changes)))
        for raw in (b'',b'x'*103,b'x'*105):
            with self.assertRaises(ValueError):decode_audit_binding(raw)

    def test_seccomp_is_exact_key_identity_only_and_cannot_invent_syscall_fields(self):
        event=binding(audit_type=1326,arch=0,syscall_nr=0,context=0,return_valid=0,return_code=0)
        self.assertEqual(event,decode_audit_binding(self.raw(event)))
        with self.assertRaises(ValueError):decode_audit_binding(self.raw(replace(event,syscall_nr=425)))


class AuditJoinTests(unittest.TestCase):
    def ledger(self,**kwargs):return AuditJoinLedger(observer_pid=9000,**kwargs)
    def bind(self,ledger,event=None):ledger.observe_bpf(event or binding(),TaskAttribution(2,'actor'))

    def test_either_transport_order_joins_exact_key_without_retaining_private_fields(self):
        for bpf_first in (True,False):
            seen=[];ledger=self.ledger(on_action=lambda event,task:seen.append(task))
            if bpf_first:self.bind(ledger)
            ledger.observe_audit(segment())
            if not bpf_first:self.bind(ledger)
            result=ledger.finish()
            self.assertEqual((1,0),(result.syscalls,result.seccomp))
            self.assertEqual([TaskAttribution(2,'actor')],seen)
            self.assertEqual(64,len(result.sha256))
            with self.assertRaises(ValueError):ledger.finish()
            with self.assertRaises(ValueError):ledger.observe_audit(segment())

    def test_same_key_can_contain_distinct_syscall_and_seccomp_bindings(self):
        ledger=self.ledger()
        sec=AuditRecord(1326,tuple(dict(pid=2001,uid=2000,gid=2000,arch=0xc00000b7,
            syscall=425,sig=0,compat=0,code=0x50000).items()))
        ledger.observe_audit(AuditSegment(KEY,(syscall(items=0),sec)))
        self.bind(ledger)
        self.bind(ledger,binding(sequence=2,audit_type=1326,arch=0,syscall_nr=0,
            context=0,return_valid=0,return_code=0))
        result=ledger.finish();self.assertEqual((1,1),(result.syscalls,result.seccomp))

    def test_same_event_cannot_span_different_task_tokens_or_roles(self):
        sec=AuditRecord(1326,tuple(dict(pid=2001,uid=2000,gid=2000,arch=0xc00000b7,
            syscall=425,sig=0,compat=0,code=0x50000).items()))
        for task in (TaskAttribution(3,'actor'),TaskAttribution(2,'launcher')):
            ledger=self.ledger();ledger.observe_audit(AuditSegment(KEY,(syscall(items=0),sec)))
            self.bind(ledger)
            with self.assertRaises(ValueError):
                ledger.observe_bpf(binding(sequence=2,audit_type=1326,arch=0,syscall_nr=0,
                    context=0,return_valid=0,return_code=0),task)
            with self.assertRaises(ValueError):ledger.finish()

    def test_mismatch_duplicate_missing_and_wrong_task_never_finalize(self):
        for change in ({'pid':2002},{'syscall':57},{'arch':1},{'exit':-1},
                {'success':True},{'uid':0},{'euid':0}):
            ledger=self.ledger();self.bind(ledger)
            with self.subTest(change=change),self.assertRaises(ValueError):ledger.observe_audit(segment(**change))
            with self.assertRaises(ValueError):ledger.finish()
        for first in ('bpf','audit'):
            ledger=self.ledger()
            if first=='bpf':self.bind(ledger)
            else:ledger.observe_audit(segment())
            with self.assertRaises(ValueError):ledger.finish()
        for duplicate in ('bpf','audit'):
            ledger=self.ledger();self.bind(ledger);ledger.observe_audit(segment())
            with self.assertRaises(ValueError):
                if duplicate=='bpf':self.bind(ledger)
                else:ledger.observe_audit(segment())

    def test_only_own_root_control_syscall_metadata_is_exempt_from_actor_join(self):
        root=syscall(items=0,pid=9000,uid=0,euid=0)
        control=AuditRecord(1305,(('op',b'set'),('audit_enabled',1),('old',0),('res',1)))
        for row in (AuditSegment(KEY,(root,)),AuditSegment(KEY,(replace(root,values=tuple({**dict(root.values),'pid':9001}.items())),control))):
            ledger=self.ledger()
            with self.assertRaises(ValueError):ledger.observe_audit(row)
        ledger=self.ledger();ledger.observe_audit(AuditSegment(KEY,(root,control)))
        # Metadata alone cannot prove actor observation.
        with self.assertRaises(ValueError):ledger.finish()

    def test_unmatched_bound_and_consumer_failure_latch(self):
        ledger=self.ledger(pending_limit=1);self.bind(ledger)
        with self.assertRaises(ValueError):self.bind(ledger,binding(audit_serial=KEY.serial+1))
        ledger=self.ledger(on_action=lambda *args:(_ for _ in ()).throw(RuntimeError('private-canary')))
        self.bind(ledger)
        with self.assertRaises(ValueError) as error:ledger.observe_audit(segment())
        self.assertNotIn('private-canary',str(error.exception))
        with self.assertRaises(ValueError):ledger.finish()


class ExactTaskAttributionTests(unittest.TestCase):
    def record(self,tid=23,**changes):
        return binding(tid=tid,tgid=tid,start_ns=1000000000 if tid==22 else 2000000000,
            timestamp_ns=4000000000,cgroup_id=54 if tid==22 else 55,**changes)

    def test_prefix_is_only_trusted_guardian_or_launcher_and_handoff_never_reverses(self):
        from tests.test_native_bpf_generations import BINDING,event
        from evals.native_bpf_generations import GenerationLedger
        ledger=GenerationLedger(BINDING,actor_cgroup_id=55,guardian_cgroup_id=54,clock_ticks=100)
        ledger.observe(event(2,22,cgroup=54));ledger.observe(event(1,23,parent=22,parent_start=1000000000,cgroup=54))
        self.assertEqual(TaskAttribution(1,'guardian'),ledger.attribute(self.record(22),prefix=True))
        self.assertEqual(TaskAttribution(2,'launcher'),ledger.attribute(self.record(),prefix=True))
        with self.assertRaises(ValueError):ledger.attribute(replace(self.record(),cgroup_id=54),prefix=True)

    def test_foreign_pid_generation_group_and_cgroup_reject_without_pid_time_guessing(self):
        from tests.test_native_bpf_generations import admitted
        for changes in ({'tid':24},{'start_ns':2000000001},{'tgid':24},{'cgroup_id':54},
                        {'timestamp_ns':3999999999}):
            ledger=admitted()
            with self.subTest(changes=changes),self.assertRaises(ValueError):
                ledger.attribute(replace(self.record(),**changes))
            with self.assertRaises(ValueError):ledger.finish()

    def test_nonleader_exec_binding_uses_new_token_and_absorbed_tid_is_rejected(self):
        from tests.test_native_bpf_generations import admitted,event
        ledger=admitted()
        self.assertEqual(TaskAttribution(2,'actor'),ledger.attribute(self.record()))
        ledger.observe(event(1,24,tgid=23,parent=23,parent_start=2000000000))
        ledger.observe(event(3,23));ledger.observe(event(2,23,old=24))
        self.assertEqual(TaskAttribution(4,'actor'),ledger.attribute(self.record()))
        with self.assertRaises(ValueError):
            ledger.attribute(replace(self.record(),tid=24,start_ns=3000000000))
