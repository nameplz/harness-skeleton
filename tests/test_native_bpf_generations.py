from dataclasses import replace
import unittest

from evals.native_bpf_events import BpfEvent
from evals.native_bpf_generations import GenerationLedger
from evals.native_cgroup import CgroupBinding,Namespace,ProcessIdentity

BINDING=CgroupBinding('harness-eval-'+'a'*32+'.service','b'*32,
    Namespace('00000000-0000-0000-0000-000000000001',1,2),3,44,
    ProcessIdentity(23,200),ProcessIdentity(22,100))

def event(kind,tid,*,start=None,tgid=None,parent=0,parent_start=0,parent_tgid=None,cgroup=55,old=None,time=4000000000):
    start=start if start is not None else {22:1000000000,23:2000000000,24:3000000000}.get(tid,3000000001)
    return BpfEvent(1,time,cgroup,cgroup,start,parent_start,kind,tid,tgid or tid,
        parent,parent_tgid or parent,tid if kind==2 and old is None else old or 0,0,0)


def admitted():
    ledger=GenerationLedger(BINDING,actor_cgroup_id=55,guardian_cgroup_id=54,clock_ticks=100)
    ledger.observe(event(2,22,cgroup=54))
    ledger.observe(event(1,23,parent=22,parent_start=1000000000,cgroup=54))
    ledger.prepare_release()
    ledger.observe(event(2,23))
    return ledger


def finish(ledger):
    ledger.observe(event(3,23));ledger.observe(event(3,22,cgroup=54))
    return ledger.finish()


class BpfGenerationTests(unittest.TestCase):
    def test_repeated_nonleader_alias_and_surviving_thread_fork_preserve_history(self):
        ledger = admitted()
        for thread, start in ((24, 3000000000), (25, 3000000001)):
            ledger.observe(event(1, thread, start=start, tgid=23, parent=23, parent_start=2000000000))
            ledger.observe(event(3, 23))
            ledger.observe(event(1, 26, start=3000000000+thread, parent=thread, parent_tgid=23, parent_start=start))
            ledger.observe(event(3, 26, start=3000000000+thread))
            ledger.observe(event(2, 23, old=thread))
        summary = finish(ledger)
        self.assertEqual((8, 2), (summary.instances, summary.aliases))

    def test_cross_cpu_sequence_and_unrelated_task_timestamps_need_not_be_sorted(self):
        ledger = admitted()
        ledger.observe(event(1, 24, parent=23, parent_start=2000000000))
        ledger.observe(replace(event(2, 24, time=4000000002), sequence=9, cpu=1))
        ledger.observe(replace(event(2, 23, time=4000000001), sequence=8, cpu=0))
        ledger.observe(event(3, 24, time=4000000003))
        ledger.observe(event(3, 23, time=4000000003))
        ledger.observe(event(3, 22, cgroup=54, time=4000000004))
        self.assertEqual(3, ledger.finish().instances)

    def test_anchored_normal_fork_exec_exit_finishes_all_tasks(self):
        ledger=admitted()
        ledger.observe(event(1,24,parent=23,parent_start=2000000000))
        ledger.observe(event(2,24));ledger.observe(event(3,24))
        summary=finish(ledger)
        self.assertEqual((3,2,3,3,0),(summary.instances,summary.forks,summary.execs,summary.exits,summary.aliases))
        self.assertEqual(64,len(summary.sha256))
        with self.assertRaises(ValueError):ledger.finish()

    def test_admission_anchors_are_required_before_release(self):
        ledger=GenerationLedger(BINDING,actor_cgroup_id=55,guardian_cgroup_id=54,clock_ticks=100)
        with self.assertRaises(ValueError):ledger.prepare_release()
        for first in (event(2,22,start=1000000001,cgroup=55),event(2,24,cgroup=54),event(3,22,cgroup=54)):
            ledger=GenerationLedger(BINDING,actor_cgroup_id=55,guardian_cgroup_id=54,clock_ticks=100)
            with self.subTest(kind=first.kind,tid=first.tid),self.assertRaises(ValueError):ledger.observe(first)

    def test_actor_cannot_exec_before_release_or_fork_from_wrong_parent(self):
        for bad in (event(2,23),event(1,23,parent=24,parent_start=3000000000,cgroup=54)):
            ledger=GenerationLedger(BINDING,actor_cgroup_id=55,guardian_cgroup_id=54,clock_ticks=100)
            ledger.observe(event(2,22,cgroup=54))
            with self.assertRaises(ValueError):ledger.observe(bad)

    def test_unknown_generation_foreign_cgroup_and_tgid_are_rejected(self):
        for bad in (event(3,24),event(2,23,start=2000000001),event(2,23,cgroup=56),
                event(1,24,parent=23,parent_start=2000000001),
                event(1,24,tgid=99,parent=23,parent_start=2000000000)):
            ledger=admitted()
            with self.subTest(bad=bad),self.assertRaises(ValueError):ledger.observe(bad)
            with self.assertRaises(ValueError):ledger.finish()

    def test_pid_reuse_requires_new_nanosecond_generation(self):
        ledger=admitted()
        for start in (3000000000,3000000001):
            ledger.observe(event(1,24,start=start,parent=23,parent_start=2000000000))
            ledger.observe(event(3,24,start=start))
        self.assertEqual(4,finish(ledger).instances)
        ledger=admitted();ledger.observe(event(1,24,parent=23,parent_start=2000000000));ledger.observe(event(3,24))
        with self.assertRaises(ValueError):ledger.observe(event(1,24,parent=23,parent_start=2000000000))

    def test_nonleader_exec_adopts_only_its_retired_group_leader_identity(self):
        ledger=admitted()
        ledger.observe(event(1,24,tgid=23,parent=23,parent_start=2000000000))
        ledger.observe(event(3,23))
        ledger.observe(event(2,23,old=24))
        summary=finish(ledger)
        self.assertEqual((4,1,3),(summary.instances,summary.aliases,summary.exits))

    def test_arbitrary_resurrection_and_missing_nonleader_relation_are_rejected(self):
        for old in (23,25):
            ledger=admitted();ledger.observe(event(1,24,tgid=23,parent=23,parent_start=2000000000));ledger.observe(event(3,23))
            with self.assertRaises(ValueError):ledger.observe(event(2,23,old=old))
        ledger=admitted();ledger.observe(event(1,24,tgid=23,parent=23,parent_start=2000000000))
        with self.assertRaises(ValueError):ledger.observe(event(2,23,old=24))

    def test_absorbed_old_tid_must_not_emit_an_extra_exit(self):
        ledger=admitted();ledger.observe(event(1,24,tgid=23,parent=23,parent_start=2000000000));ledger.observe(event(3,23));ledger.observe(event(2,23,old=24))
        with self.assertRaises(ValueError):ledger.observe(event(3,24,tgid=23))

    def test_threads_and_leader_can_exit_without_group_dead_inference(self):
        ledger=admitted();ledger.observe(event(1,24,tgid=23,parent=23,parent_start=2000000000));ledger.observe(event(3,23))
        with self.assertRaises(ValueError):ledger.finish()
        ledger=admitted();ledger.observe(event(1,24,tgid=23,parent=23,parent_start=2000000000));ledger.observe(event(3,23));ledger.observe(event(3,24,tgid=23));ledger.observe(event(3,22,cgroup=54))
        self.assertEqual(3,ledger.finish().exits)

    def test_guardian_exit_before_live_descendants_is_rejected(self):
        ledger=admitted();ledger.observe(event(1,24,parent=23,parent_start=2000000000));ledger.observe(event(3,23))
        with self.assertRaises(ValueError):ledger.observe(event(3,22,cgroup=54))

    def test_abort_before_G_requires_bound_leaf_exit_and_never_normal_success(self):
        ledger=GenerationLedger(BINDING,actor_cgroup_id=55,guardian_cgroup_id=54,clock_ticks=100)
        ledger.observe(event(2,22,cgroup=54));ledger.observe(event(1,23,parent=22,parent_start=1000000000,cgroup=54))
        ledger.abort();ledger.observe(event(3,23));ledger.observe(event(3,22,cgroup=54))
        with self.assertRaises(ValueError):ledger.finish()
        self.assertIsNone(ledger.result)

    def test_duplicate_exit_backward_time_and_limits_fail_closed(self):
        ledger=admitted();ledger.observe(event(1,24,parent=23,parent_start=2000000000));ledger.observe(event(3,24))
        with self.assertRaises(ValueError):ledger.observe(event(3,24))
        ledger=admitted()
        with self.assertRaises(ValueError):ledger.observe(event(2,23,time=3999999999))
        from unittest.mock import patch
        ledger=admitted()
        with patch('evals.native_bpf_generations.MAX_TASKS',2),self.assertRaises(ValueError):
            ledger.observe(event(1,24,parent=23,parent_start=2000000000))

    def test_binding_and_clock_limits_are_not_inferred(self):
        for kwargs in ({'actor_cgroup_id':54},{'clock_ticks':True},{'clock_ticks':0}):
            args={'actor_cgroup_id':55,'guardian_cgroup_id':54,'clock_ticks':100,**kwargs}
            with self.assertRaises(ValueError):GenerationLedger(BINDING,**args)
