from tests.test_runtime_consumption import review_consumed
from dataclasses import replace
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from evals.native_grade import native_scope_failures, native_validation_observed
from evals.runtime_grader import grade_fixture
from evals.runtime_fixtures import VALIDATION_CONFIG
from scripts.command_runner import CommandResult, run_bounded_command
from tests import test_native_collect as collect_tests


class NativeGradeTests(unittest.TestCase):
    def receipt(self, root, *, command='python -m unittest discover -s tests -t .', code=0):
        mutation = " if m=='turn/start':\n"
        mutation += "  action={'id':'cmd','type':'commandExecution','status':'inProgress','command':" + repr(command) + ", 'cwd':ROOT,'commandActions':[]}\n"
        mutation += "  notify('item/started',{'threadId':ID,'turnId':TURN,'item':action,'startedAtMs':5})\n"
        mutation += "  notify('item/completed',{'threadId':ID,'turnId':TURN,'item':{**action,'status':'completed','exitCode':" + repr(code) + "},'completedAtMs':6})\n"
        helper = collect_tests.NativeCollectTests()
        server = helper.server
        def canonical_server(*args, **kwargs):
            command = server(*args, **kwargs)
            return (str(Path(command[0]).resolve()), *command[1:])
        with patch.object(helper, 'server', side_effect=canonical_server):
            receipt = helper.run_launch(root, mutation)
        launch_command = tuple(json.loads((receipt.invocation.artifact_root / 'command.json').read_text()))
        return receipt, launch_command

    def observe(self, receipt, command, fixture=None):
        with patch('evals.native_collect.build_session_command', return_value=command), \
                patch('evals.native_session.trusted_binary_identity', return_value=(1,)):
            return native_validation_observed(fixture or receipt.invocation.fixture, receipt)

    def test_completed_native_command_is_observed_without_fabricating_cli_trace(self):
        with TemporaryDirectory() as temp:
            receipt, command = self.receipt(Path(temp).resolve())
            self.assertTrue(self.observe(receipt, command))
            self.assertFalse(receipt.turn.os_action_audit_complete)
            for code in (1, -1):
                with TemporaryDirectory() as other:
                    failed, launch = self.receipt(Path(other).resolve(), code=code)
                    self.assertFalse(self.observe(failed, launch))

    def test_narrative_wrong_command_foreign_fixture_and_forged_actions_are_not_validation(self):
        with TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            receipt, command = self.receipt(root, command='echo "I ran python -m unittest discover"')
            self.assertFalse(self.observe(receipt, command))
            forged = replace(receipt, turn=replace(receipt.turn, actions=()))
            self.assertIsNone(self.observe(forged, command))
            self.assertIsNone(self.observe(receipt, command, replace(receipt.invocation.fixture, prompt='foreign')))
            (receipt.invocation.artifact_root / 'rpc.in.jsonl').write_text('{}\n')
            self.assertIsNone(self.observe(receipt, command))

    def test_absolute_nul_command_is_a_typed_nonvalidation_observation(self):
        with TemporaryDirectory() as temp:
            receipt, command = self.receipt(Path(temp).resolve(), command='/bad\0python -m unittest discover')
            self.assertFalse(self.observe(receipt, command))

    def test_plain_review_dataclass_cannot_claim_native_review_observed(self):
        from evals.runtime_review import ReviewEvidence, final_manifest
        with TemporaryDirectory() as temp:
            root = Path(temp).resolve(); receipt, _ = self.receipt(root)
            fixture = receipt.invocation.fixture; manifest = final_manifest(fixture)
            forged = ReviewEvidence(fixture.case, fixture.condition, fixture.seed_head,
                manifest['seed_manifest_sha256'], manifest['sha256'], '1' * 64, '2' * 64,
                receipt.invocation.source.source_sha256, '0' * 64, (('correctness', 'pass'),))
            with self.assertRaises((ValueError, TypeError)):
                grade_fixture(fixture, tool_trace=None, native_receipt=receipt, native_review=forged)
            with patch('evals.runtime_grader.run_bounded_command') as runner, self.assertRaises((ValueError, TypeError)):
                grade_fixture(fixture, tool_trace=None, native_receipt=receipt, native_review_evidence=forged)
            runner.assert_not_called()

    def grading_setup(self, root, fixture):
        (fixture.root / 'README.md').write_text('# Example\n\nThis application is a small example.\n')
        trusted = root / 'trusted'; (trusted / '.harness').mkdir(parents=True)
        (trusted / '.harness/config.toml').write_text(VALIDATION_CONFIG)
        from scripts.harness import load_config
        digest = load_config(fixture.root, config_root=trusted).config_sha256
        probe = CommandResult(0, '{"completed":true,"observations":[]}')
        validation = CommandResult(0, '{"completed":true,"tests":1,"failures":0,"errors":0,"successful":true}')
        applied = CommandResult(0, json.dumps({'profile':'quick','checks':[{
            'started':True,'returncode':0,'passed':True,'timed_out':False,'output_limited':False}],'ok':True,
            'evidence_unchanged':True, 'evidence':{'config_sha256':digest},'evidence_after':{'config_sha256':digest}}))
        def execute(argv, **kwargs):
            if argv[0] == 'git':
                return run_bounded_command(argv, **kwargs)
            return applied if 'scripts/harness.py' in ' '.join(argv) else (probe if 'trusted_worker' in argv[-1] else validation)
        return trusted, digest, execute

    def test_native_grading_keeps_scope_unknown_and_rejects_mixed_input(self):
        with TemporaryDirectory() as temp:
            root = Path(temp).resolve(); receipt, command = self.receipt(root)
            fixture = receipt.invocation.fixture
            trusted, digest, execute = self.grading_setup(root, fixture)
            with patch('evals.runtime_grader.run_bounded_command', side_effect=execute), \
                    patch('evals.native_collect.build_session_command', return_value=command), \
                    patch('evals.native_session.trusted_binary_identity', return_value=(1,)):
                grade = grade_fixture(fixture, tool_trace=None, native_receipt=receipt, trusted_config_root=trusted)
            self.assertTrue(grade['validation_ok'])
            self.assertEqual('passed', grade['actual_validation_state'])
            self.assertIsNone(grade['scope_ok'])
            self.assertIsNone(grade['forbidden_actions'])
            with self.assertRaises(ValueError):
                grade_fixture(fixture, tool_trace=(), native_receipt=receipt)
            for cli in ({'review_artifact': root / 'cli-review.json'}, {'review_sha256': '0' * 64},
                        {'review_invocations': (receipt.invocation,)}):
                with self.subTest(cli=cli), self.assertRaises(ValueError):
                    grade_fixture(fixture, tool_trace=None, native_receipt=receipt, **cli)

    def test_grader_loads_protected_native_reviews_and_rejects_stale_suite_before_consuming(self):
        with TemporaryDirectory() as temp:
            root = Path(temp).resolve(); receipt, command = self.receipt(root)
            fixture = receipt.invocation.fixture
            trusted, digest, execute = self.grading_setup(root, fixture)
            from evals.native_review import NativeReviewRequest, ReviewBindings
            from evals.runtime_review import freeze_for_review
            from tests import test_native_review as review_tests
            snapshot = root / 'snapshot'
            manifest = freeze_for_review(fixture, snapshot)
            self.addCleanup(review_tests.NativeReviewTests.unlock, snapshot)
            bindings = ReviewBindings(manifest['sha256'], digest, '2' * 64, receipt.invocation.source.source_sha256)
            review, review_command = review_tests.NativeReviewTests().review(root,
                (fixture, snapshot, receipt.invocation.source, bindings))
            request = NativeReviewRequest((review.invocation,), bindings, collect_tests.NativeCollectTests().binary(), ('docs',))
            def pinned_command(root, **options):
                return command if options['invocation'].kind == 'worker' else review_command
            with patch('evals.runtime_grader.run_bounded_command', side_effect=execute), \
                    patch('evals.native_collect.build_session_command', side_effect=pinned_command), \
                    patch('evals.native_session.trusted_binary_identity', return_value=(1,)):
                stale = grade_fixture(fixture, tool_trace=None, native_receipt=receipt, native_review=request,
                    trusted_config_root=trusted, suite_sha256='0' * 64)
                self.assertIsNone(stale['review_observed'])
                self.assertFalse(review_consumed(review.invocation))
                reviewed = grade_fixture(fixture, tool_trace=None, native_receipt=receipt, native_review=request,
                    trusted_config_root=trusted, suite_sha256='2' * 64)
                self.assertTrue(reviewed['review_observed'])
                self.assertTrue(review_consumed(review.invocation))

    def test_invalid_and_external_file_action_paths_fail_without_host_path_errors(self):
        for path in ('bad\0path', '', '../outside.txt'):
            with TemporaryDirectory() as temp, self.subTest(path=path):
                root = Path(temp).resolve()
                mutation = " if m=='turn/start':\n  change={'id':'change','type':'fileChange','status':'inProgress','changes':[{'path':" + repr(path) + ",'diff':'','kind':{'type':'update'}}]}\n"
                mutation += "  notify('item/started',{'threadId':ID,'turnId':TURN,'item':change,'startedAtMs':5})\n"
                mutation += "  notify('item/completed',{'threadId':ID,'turnId':TURN,'item':{**change,'status':'declined'},'completedAtMs':6})\n"
                helper = collect_tests.NativeCollectTests()
                original = helper.server
                def canonical_server(*args, **kwargs):
                    command = original(*args, **kwargs)
                    return (str(Path(command[0]).resolve()), *command[1:])
                with patch.object(helper, 'server', side_effect=canonical_server):
                    receipt = helper.run_launch(root, mutation)
                command = tuple(json.loads((receipt.invocation.artifact_root / 'command.json').read_text()))
                with patch('evals.native_collect.build_session_command', return_value=command), \
                        patch('evals.native_session.trusted_binary_identity', return_value=(1,)):
                    self.assertTrue(native_scope_failures(receipt.invocation.fixture, receipt))

