from dataclasses import replace
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import sys
import unittest
from unittest.mock import patch

from evals.native_collect import collect_native_turn, load_native_turn
from evals.native_review import ReviewBindings, canonical_prompt, load_native_review_evidence
from evals.runtime_fixtures import materialize_fixture
from evals.runtime_invocation import issue_invocation, write_frozen_source
from evals.runtime_review import freeze_for_review, review_matches
from tests import test_native_collect as collect_tests

SERVER, FEATURES, ID = collect_tests.SERVER, collect_tests.FEATURES, collect_tests.ID


class NativeReviewTests(unittest.TestCase):
    def setup(self, root, case='bug-fix', condition='baseline'):
        fixture = materialize_fixture(case, root / 'candidate', condition=condition)
        snapshot = root / 'snapshot'
        manifest = freeze_for_review(fixture, snapshot)
        source = write_frozen_source(fixture, root / 'source.json')
        bindings = ReviewBindings(manifest['sha256'], '1' * 64, '2' * 64, source.source_sha256)
        self.addCleanup(self.unlock, snapshot)
        return fixture, snapshot, source, bindings

    @staticmethod
    def unlock(snapshot):
        if not snapshot.exists():
            return  # TemporaryDirectory may already have performed its own cleanup.
        for path in snapshot.rglob('*'):
            if path.is_dir():
                path.chmod(0o755)
        snapshot.chmod(0o755)

    def review(self, root, context, role='correctness', verdict_change=None, session=ID):
        fixture, snapshot, source, bindings = context
        invocation = issue_invocation(fixture, root / role, source, model='test-model', kind=role,
            execution_root=snapshot, final_manifest_sha256=bindings.final_manifest_sha256)
        expected = {**bindings.as_dict(), 'role': role, 'status': 'pass',
            'invocation_nonce': invocation.nonce, 'invocation_sha256': invocation.sha256,
            'source_manifest_sha256': source.manifest_sha256}
        verdict = {**expected, **(verdict_change or {})}
        script = root / (role + '.py')
        server = SERVER.replace('__FEATURES__', repr(FEATURES)).replace('__MUTATION__', '').replace('__TAIL__', '')
        server = server.replace("assert 'Host invocation nonce' not in p['developerInstructions']", "assert p['developerInstructions']==''")
        server = server.replace("'extends':':workspace'", "'extends':':read-only'")
        server = server.replace("'type':'workspaceWrite'", "'type':'readOnly'")
        server = server.replace(",'writableRoots':[],'excludeTmpdirEnvVar':True,'excludeSlashTmp':True", "")
        server = server.replace("'text':'done'", "'text':" + repr(json.dumps(verdict)))
        server = server.replace(ID, session)
        script.write_text(server)
        command = (sys.executable, '-I', '-B', str(script), str(snapshot), str(invocation.artifact_root))
        with patch('evals.native_session.build_session_command', return_value=command), \
                patch('evals.native_session.trusted_binary_identity', return_value=(1,)):
            receipt = collect_native_turn(invocation, binary=collect_tests.NativeCollectTests().binary(),
                disabled_servers=('docs',), review_bindings=bindings, timeout_seconds=5)
        outgoing = json.loads((invocation.artifact_root / 'rpc.out.jsonl').read_text())
        self.assertEqual(canonical_prompt(invocation, bindings), outgoing['params']['input'][0]['text'])
        self.assertFalse(json.loads(receipt.session_json)['writable'])
        return receipt, command

    def load(self, fixture, receipts, commands, bindings):
        with patch('evals.native_collect.build_session_command', side_effect=lambda root, **kw: commands[kw['invocation'].kind]), \
                patch('evals.native_session.trusted_binary_identity', return_value=(1,)):
            return load_native_review_evidence(fixture, tuple(row.invocation for row in receipts),
                binary=collect_tests.NativeCollectTests().binary(), bindings=bindings, disabled_servers=('docs',))

    def test_readonly_review_uses_host_prompt_and_is_consumed_only_once(self):
        with TemporaryDirectory() as temp:
            root = Path(temp).resolve(); context = self.setup(root)
            receipt, command = self.review(root, context)
            fixture, _, _, bindings = context
            with self.assertRaises(ValueError):
                load_native_turn(receipt.invocation, binary=collect_tests.NativeCollectTests().binary())
            evidence = self.load(fixture, (receipt,), {'correctness': command}, bindings)
            self.assertTrue(review_matches(fixture, evidence, config_sha256='1' * 64,
                suite_sha256='2' * 64, source_sha256=bindings.source_sha256))
            with self.assertRaises(ValueError):
                self.load(fixture, (receipt,), {'correctness': command}, bindings)

    def test_invalid_bindings_snapshot_and_verdict_do_not_consume(self):
        for change in ({'status': 'invented'}, {'role': 'security'}, {'invocation_nonce': '0' * 64},
                       {'config_sha256': '0' * 64}, {'suite_sha256': '0' * 64}, {'extra': True}):
            with TemporaryDirectory() as temp, self.subTest(change=change):
                root = Path(temp).resolve(); context = self.setup(root)
                receipt, command = self.review(root, context, verdict_change=change)
                with self.assertRaises(ValueError):
                    self.load(context[0], (receipt,), {'correctness': command}, context[3])
                self.assertFalse((receipt.invocation.artifact_root / 'consumed.json').exists())
        with TemporaryDirectory() as temp:
            root = Path(temp).resolve(); context = self.setup(root)
            receipt, command = self.review(root, context)
            snapshot = context[1]; snapshot.chmod(0o755)
            with self.assertRaises(ValueError):
                self.load(context[0], (receipt,), {'correctness': command}, context[3])
            self.assertFalse((receipt.invocation.artifact_root / 'consumed.json').exists())

    def test_security_requires_distinct_complete_roles_before_any_consumption(self):
        with TemporaryDirectory() as temp:
            root = Path(temp).resolve(); context = self.setup(root, 'security-boundary')
            correctness, command = self.review(root, context)
            security, other = self.review(root, context, 'security', session='33333333-3333-4333-8333-333333333333')
            commands = {'correctness': command, 'security': other}
            with self.assertRaises(ValueError):
                self.load(context[0], (correctness,), commands, context[3])
            tampered = replace(security, invocation=replace(security.invocation, native_receipt_sha256='0' * 64))
            with self.assertRaises(ValueError):
                self.load(context[0], (correctness, tampered), commands, context[3])
            self.assertFalse((correctness.invocation.artifact_root / 'consumed.json').exists())
            evidence = self.load(context[0], (correctness, security), commands, context[3])
            self.assertEqual((('correctness', 'pass'), ('security', 'pass')), evidence.reviews)

    def test_same_session_or_stale_candidate_review_is_rejected(self):
        with TemporaryDirectory() as temp:
            root = Path(temp).resolve(); context = self.setup(root, 'security-boundary')
            a, ca = self.review(root, context); b, cb = self.review(root, context, 'security')
            with self.assertRaises(ValueError):
                self.load(context[0], (a, b), {'correctness': ca, 'security': cb}, context[3])
            self.assertFalse((a.invocation.artifact_root / 'consumed.json').exists())
        with TemporaryDirectory() as temp:
            root = Path(temp).resolve(); context = self.setup(root)
            receipt, command = self.review(root, context)
            (context[0].root / 'src/dates.py').write_text('changed after review')
            with self.assertRaises(ValueError):
                self.load(context[0], (receipt,), {'correctness': command}, context[3])

    def test_canonical_review_bindings_are_finite_and_match_invocation(self):
        for bad in ('A' * 64, '0' * 63, None, 1):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                ReviewBindings(bad, '1' * 64, '2' * 64, '3' * 64)
        with TemporaryDirectory() as temp:
            root = Path(temp).resolve(); context = self.setup(root)
            fixture, snapshot, source, bindings = context
            invocation = issue_invocation(fixture, root / 'review', source, model='test-model', kind='correctness',
                execution_root=snapshot, final_manifest_sha256=bindings.final_manifest_sha256)
            for wrong in (None, replace(bindings, source_sha256='0' * 64), replace(bindings, final_manifest_sha256='0' * 64)):
                with self.subTest(wrong=wrong), self.assertRaises(ValueError):
                    canonical_prompt(invocation, wrong)
            worker = issue_invocation(fixture, root / 'worker', source, model='test-model')
            with self.assertRaises(ValueError):
                canonical_prompt(worker, bindings)

    def test_failed_and_unknown_native_verdicts_preserve_three_valued_review(self):
        for status, expected in (('fail', False), ('unknown', None)):
            with TemporaryDirectory() as temp, self.subTest(status=status):
                root = Path(temp).resolve(); context = self.setup(root)
                receipt, command = self.review(root, context, verdict_change={'status': status})
                evidence = self.load(context[0], (receipt,), {'correctness': command}, context[3])
                self.assertIs(expected, review_matches(context[0], evidence, config_sha256='1' * 64,
                    suite_sha256='2' * 64, source_sha256=context[3].source_sha256))

