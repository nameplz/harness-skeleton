from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from evals.native_cgroup import CgroupBinding, CleanupObservation, Namespace, ProcessIdentity, MAX_TRACKED
from evals.native_supervisor import SupervisorCleanup
from evals.native_lifecycle import lifecycle_record, verify_lifecycle


def successful_process():
    actor, guardian = ProcessIdentity(100, 200), ProcessIdentity(99, 190)
    binding = CgroupBinding('harness-eval-' + 'a' * 32 + '.service', 'b' * 32,
        Namespace('11111111-1111-4111-8111-111111111111', 1, 2), 3, 4, actor, guardian)
    observation = CleanupObservation(binding, (actor,), (), (), 0, 0, (), ())
    cleanup = SupervisorCleanup(observation, 0, 0, True, True)
    return SimpleNamespace(binding=binding, cleanup_result=cleanup, returncode=0,
        command_sha256='3'*64, environment_sha256='7'*64)


class NativeLifecycleTests(unittest.TestCase):
    bindings = {name: char * 64 for name, char in zip(
        ('invocation_sha256', 'source_sha256', 'command_sha256', 'session_sha256',
         'policy_sha256', 'turn_sha256', 'environment_sha256', 'binary_sha256'), '12345678')}

    def record(self):
        return lifecycle_record(successful_process(), self.bindings)

    def test_producer_binds_actual_admission_cleanup_and_preserves_primitive_semantics(self):
        process = successful_process()
        record = lifecycle_record(process, self.bindings)
        self.assertTrue(verify_lifecycle(record, self.bindings, returncode=0))
        self.assertEqual(record['binding'], record['cleanup']['observation']['binding'])
        self.assertEqual([{'pid': 100, 'start_ticks': 200}], record['cleanup']['observation']['observed_processes'])
        for changed in (None, replace(process.cleanup_result, observation=replace(
                process.cleanup_result.observation, binding=replace(process.binding, inode=99))),
                replace(process.cleanup_result, actor_returncode=7)):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                lifecycle_record(SimpleNamespace(**{**vars(process), 'cleanup_result': changed}), self.bindings)
        self.assertTrue(replace(process.cleanup_result, actor_returncode=7).empty_verified)

    def test_historical_replay_never_opens_live_cgroup_or_requires_current_boot(self):
        record = self.record()
        with patch('evals.native_cgroup._open_bound', side_effect=AssertionError('live cgroup')), \
                patch('evals.native_cgroup._namespace', side_effect=AssertionError('current boot')):
            self.assertTrue(verify_lifecycle(record, self.bindings, returncode=0))

    def test_all_residual_and_exit_fields_fail_closed(self):
        for key, value in (('members', [{'pid':100,'start_ticks':200}]),
                           ('remaining_generations', [{'pid':100,'start_ticks':200}]),
                           ('procs', [100]), ('threads', [100]), ('populated', 1), ('frozen', True)):
            record = self.record(); record['cleanup']['observation'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                verify_lifecycle(record, self.bindings, returncode=0)
        for key, value in (('guardian_reaped', False), ('guardian_reaped', 1),
                ('unit_gone', False), ('proxy_returncode', 1), ('actor_returncode', -9)):
            record = self.record(); record['cleanup'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                verify_lifecycle(record, self.bindings, returncode=0)
        with self.assertRaises(ValueError): verify_lifecycle(self.record(), self.bindings, returncode=True)
        with self.assertRaises(ValueError): verify_lifecycle(self.record(), self.bindings, returncode=7)

    def test_observed_generations_require_actor_sorted_unique_and_bounded(self):
        actor = {'pid':100, 'start_ticks':200}; other = {'pid':101, 'start_ticks':201}
        for values in ([], [other], [actor, actor], [other, actor],
                       [{'pid':index+100, 'start_ticks':200} for index in range(MAX_TRACKED+1)],
                       [{'pid':True, 'start_ticks':200}], [{'pid':100, 'start_ticks':-1}]):
            record = self.record(); record['cleanup']['observation']['observed_processes'] = values
            with self.subTest(values=len(values)), self.assertRaises(ValueError):
                verify_lifecycle(record, self.bindings, returncode=0)

    def test_strict_binding_shapes_types_and_hashes(self):
        for key, value in (('unit','other.service'), ('invocation_id','A'*32),
                ('device',True), ('inode',0), ('namespace',None), ('actor',{'pid':100}),
                ('guardian',{'pid':100,'start_ticks':200})):
            record=self.record();record['binding'][key]=value
            record['cleanup']['observation']['binding']=deepcopy(record['binding'])
            with self.subTest(key=key),self.assertRaises(ValueError):
                verify_lifecycle(record,self.bindings,returncode=0)
        for field in self.bindings:
            with self.subTest(field=field),self.assertRaises(ValueError):
                verify_lifecycle(self.record(),{**self.bindings,field:'f'*64},returncode=0)
        for bad in ({}, {'extra':True}, {'schema':True}, {'backend':'direct'}, {'receipt_verified':1}):
            record={**self.record(),**bad} if bad else {}
            with self.subTest(bad=bad),self.assertRaises(ValueError):
                verify_lifecycle(record,self.bindings,returncode=0)
        for value in (True, 'A'*64, None):
            with self.subTest(value=value),self.assertRaises(ValueError):
                lifecycle_record(successful_process(),{**self.bindings,'turn_sha256':value})

    def test_producer_checks_actual_launch_digests(self):
        for name in ('command_sha256','environment_sha256'):
            process=successful_process();setattr(process,name,'f'*64)
            with self.subTest(name=name),self.assertRaises(ValueError):
                lifecycle_record(process,self.bindings)
