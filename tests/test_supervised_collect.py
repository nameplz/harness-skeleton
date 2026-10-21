from tests.test_runtime_consumption import review_consumed
from contextlib import contextmanager, ExitStack
from dataclasses import replace
import json
import hashlib
import os
from pathlib import Path
import stat
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from evals.native_collect import collect_native_turn, load_native_turn, _read_native_turn
from evals.runtime_access import SUPERVISED_PROFILE
from evals.runtime_fixtures import materialize_fixture
from evals.runtime_invocation import issue_invocation, write_frozen_source
from tests import test_native_collect as direct_tests
from tests import test_supervised_session as session_tests
from tests.test_native_lifecycle import successful_process


@contextmanager
def host_profile_simulation():
    # Unit tests simulate ownership only; actual UID/cgroup qualification runs on Linux.
    with ExitStack() as stack:
        for name in ('evals.runtime_access._require_root_linux',
                     'evals.runtime_access.require_workspace',
                     'evals.runtime_access.require_private_parent',
                     'evals.runtime_access.require_private_file',
                     'evals.runtime_invocation.require_private_parent'):
            stack.enter_context(patch(name))
        yield


class SupervisedCollectTests(unittest.TestCase):
    def setUp(self):
        patched=patch('evals.native_audit_session.AuditCapture',side_effect=session_tests.FakeAuditCapture)
        patched.start();self.addCleanup(patched.stop)

    def setup_launch(self, root):
        fixture = materialize_fixture('documentation', root/'candidate', condition='baseline')
        fixture = replace(fixture, execution_profile=SUPERVISED_PROFILE)
        source = write_frozen_source(fixture, root/'source.json')
        return issue_invocation(fixture, root/'launch', source, model='test-model')

    def collect(self, root, *, cleanup_change=None):
        launch=self.setup_launch(root)
        helper=direct_tests.NativeCollectTests();command=helper.server(root)
        def launch_process(*args, **kwargs):
            process=session_tests.SupervisedSessionTests().launch(root,command)
            actual=successful_process();process.binding=actual.binding
            process.command_sha256=hashlib.sha256(json.dumps(command).encode()).hexdigest()
            process.environment_sha256=hashlib.sha256(json.dumps(kwargs['environment'],sort_keys=True).encode()).hexdigest()
            cleanup=process.cleanup
            def finish():
                cleanup()
                process.cleanup_result=actual.cleanup_result if cleanup_change is None else cleanup_change(actual.cleanup_result)
                return process.cleanup_result
            process.cleanup=finish
            return process
        with patch('evals.native_session.build_session_command',return_value=command), \
                patch('evals.native_session.trusted_supervised_binary_identity',return_value=(1,)), \
                patch('evals.native_supervisor.start_supervised',side_effect=launch_process):
            receipt=collect_native_turn(launch,binary=helper.binary(),disabled_servers=('docs',),timeout_seconds=5)
        return receipt,command

    def replay(self, receipt, command):
        with patch('evals.native_collect.build_session_command',return_value=command), \
                patch('evals.native_session.trusted_supervised_binary_identity',return_value=(1,)):
            return load_native_turn(receipt.invocation,binary=direct_tests.NativeCollectTests().binary(),disabled_servers=('docs',))

    def test_bound_turn_seals_private_actual_cleanup_and_historical_replay(self):
        with TemporaryDirectory() as temp,host_profile_simulation():
            root=Path(temp).resolve();previous=os.umask(0)
            try:receipt,command=self.collect(root)
            finally:os.umask(previous)
            self.assertEqual('completed',receipt.turn.status)
            self.assertIsNotNone(receipt.supervisor_receipt_sha256)
            self.assertFalse(receipt.process_tree_cleanup_verified)
            for path in receipt.invocation.artifact_root.iterdir():
                self.assertEqual(0o600,stat.S_IMODE(path.stat().st_mode),path.name)
            self.assertEqual(0o700,stat.S_IMODE(receipt.invocation.artifact_root.stat().st_mode))
            lifecycle=json.loads((receipt.invocation.artifact_root/'supervisor.json').read_text())
            self.assertTrue(lifecycle['receipt_verified'])
            with patch('evals.native_cgroup._open_bound',side_effect=AssertionError('live cgroup')):
                self.assertEqual(receipt,self.replay(receipt,command))

    def test_missing_mismatched_or_incomplete_final_cleanup_cannot_seal_turn(self):
        for change in (lambda result:None,lambda result:replace(result,unit_gone=False),
                lambda result:replace(result,actor_returncode=7),
                lambda result:replace(result,observation=replace(result.observation,
                    binding=replace(result.observation.binding,inode=99)))):
            with TemporaryDirectory() as temp,host_profile_simulation(),self.subTest(change=change):
                root=Path(temp).resolve()
                with self.assertRaises(ValueError):self.collect(root,cleanup_change=change)
                self.assertFalse((root/'launch/turn.json').exists())

    def test_lifecycle_artifact_tampering_rejects_without_consuming(self):
        with TemporaryDirectory() as temp,host_profile_simulation():
            root=Path(temp).resolve();receipt,command=self.collect(root)
            (root/'launch/supervisor.json').write_text('{}\n')
            with self.assertRaises(ValueError):self.replay(receipt,command)
            self.assertFalse((root/'launch/consumed.json').exists())

    def test_readonly_correctness_and_security_replay_validate_both_before_consuming(self):
        from contextlib import nullcontext
        from tests import test_native_review as review_tests
        helper=review_tests.NativeReviewTests()
        with TemporaryDirectory() as temp,host_profile_simulation(), \
                patch('evals.runtime_access.require_snapshot'), \
                patch('evals.runtime_invocation.require_snapshot'), \
                patch('evals.runtime_scope.snapshot_owner',return_value=(os.getuid(),os.getgid())), \
                patch('evals.runtime_review.actor_slot',side_effect=nullcontext), \
                patch('evals.native_session.trusted_supervised_binary_identity',return_value=(1,)):
            root=Path(temp).resolve();fixture,snapshot,source,bindings=helper.setup(root,'security-boundary')
            fixture=replace(fixture,execution_profile=SUPERVISED_PROFILE)
            # Final manifest includes the explicit execution profile.
            from evals.runtime_review import final_manifest
            bindings=replace(bindings,final_manifest_sha256=final_manifest(fixture)['sha256'])
            context=(fixture,snapshot,source,bindings)
            def launched(command,**kwargs):
                process=session_tests.SupervisedSessionTests().launch(root,command)
                actual=successful_process();process.binding=actual.binding
                process.command_sha256=hashlib.sha256(json.dumps(command).encode()).hexdigest()
                process.environment_sha256=hashlib.sha256(json.dumps(kwargs['environment'],sort_keys=True).encode()).hexdigest()
                cleanup=process.cleanup
                def finish():
                    cleanup();process.cleanup_result=actual.cleanup_result
                    return process.cleanup_result
                process.cleanup=finish
                return process
            with patch('evals.native_supervisor.start_supervised',side_effect=launched):
                a,ca=helper.review(root,context)
                b,cb=helper.review(root,context,'security',session='33333333-3333-4333-8333-333333333333')
            self.assertIsNotNone(a.supervisor_receipt_sha256);self.assertIsNotNone(b.supervisor_receipt_sha256)
            saved=(b.invocation.artifact_root/'supervisor.json').read_bytes()
            (b.invocation.artifact_root/'supervisor.json').write_bytes(b'{}\n')
            commands={'correctness':ca,'security':cb}
            with self.assertRaises(ValueError):helper.load(fixture,(a,b),commands,bindings)
            self.assertFalse(review_consumed(a.invocation))
            self.assertFalse(review_consumed(b.invocation))
            (b.invocation.artifact_root/'supervisor.json').write_bytes(saved)
            evidence=helper.load(fixture,(a,b),commands,bindings)
            self.assertEqual((('correctness','pass'),('security','pass')),evidence.reviews)

    def test_bound_transport_has_one_turn_and_only_remote_worker_callbacks(self):
        from types import SimpleNamespace
        from evals.native_session import _SessionExchange
        from evals.native_config import _ConfigExchange
        exchange=object.__new__(_SessionExchange)
        exchange.supervised=True;exchange._inspection_complete=True;exchange._turn_sent=False
        exchange.stage='turn/run'
        exchange.invocation=SimpleNamespace(session_id='session',kind='correctness',
            fixture=SimpleNamespace(remote_context=None))
        with patch.object(_ConfigExchange,'send_raw') as sent:
            for params in (None,[],True):
                with self.subTest(params=params),self.assertRaises(ValueError):
                    exchange.send_turn((json.dumps({'id':100,'method':'turn/start','params':params})+'\n').encode())
            request={'id':100,'method':'turn/start','params':{'threadId':'session'}}
            exchange.send_turn((json.dumps(request)+'\n').encode())
            with self.assertRaises(ValueError):exchange.send_turn((json.dumps(request)+'\n').encode())
            with self.assertRaises(ValueError):exchange.send_raw(b'{}\n')
            with self.assertRaises(ValueError):exchange.send_callback(b'{"id":1,"result":{}}\n')
            self.assertEqual(1,sent.call_count)
