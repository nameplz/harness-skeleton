from dataclasses import replace
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from evals.runtime_fixtures import materialize_fixture
from evals.runtime_grader import _scope_failures, grade_fixture
from evals.runtime_invocation import issue_invocation, write_frozen_source
from evals.runtime_policy import policy_observation, policy_recipe, require_policy_fixture
from evals.runtime_review import ReviewEvidence, final_manifest, freeze_for_review, review_matches
from scripts.check_ci_security import authorize_trusted_maintenance
from scripts.check_pr_contract import check_pr_event
from scripts.command_runner import CommandResult


class RuntimePolicyTests(unittest.TestCase):
    def fixture(self, parent, *, condition='baseline', variant='pilot'):
        parent.mkdir(mode=0o700)
        return materialize_fixture('policy-change', parent/'candidate', condition=condition,
                                   variant=variant, policy_root=parent/'policy-context')

    def repair(self, fixture):
        path=fixture.root/'.github/workflows/project-ci.yml'
        path.write_text(policy_recipe(fixture.variant)['expected_workflow'])

    def test_pairing_risk_and_expected_pin_are_independent_of_guidance(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            a=self.fixture(root/'a');b=self.fixture(root/'b',condition='harness')
            unseen=self.fixture(root/'unseen',variant='unseen')
            self.assertEqual(a.fixture_sha256,b.fixture_sha256)
            self.assertEqual(a.policy_context.structural_sha256,b.policy_context.structural_sha256)
            self.assertNotEqual(a.policy_context.binding_sha256,b.policy_context.binding_sha256)
            self.assertNotEqual(a.fixture_sha256,unseen.fixture_sha256)
            for fixture in (a,b,unseen):
                before=policy_observation(fixture)
                self.assertFalse(before['accepted'])
                self.assertTrue(before['maintenance_authorized'])
                self.assertEqual([],before['structural_errors'])
                self.repair(fixture)
                result=policy_observation(fixture)
                self.assertTrue(result['accepted'],result)
                self.assertEqual('T3',result['risk']['level'])
                self.assertTrue(result['risk']['code_review'])
                self.assertTrue(result['risk']['security_review'])
                self.assertEqual([],result['pr_contract_errors'])
                self.assertEqual([],_scope_failures(fixture))

    def test_authorization_does_not_skip_structural_checks(self):
        attacks=('permissions: write-all','run: echo ${{ secrets.TOKEN }}',
                 'uses: actions/checkout@v4','runs-on: self-hosted')
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            for index,attack in enumerate(attacks):
                fixture=self.fixture(root/str(index));self.repair(fixture)
                path=fixture.root/'.github/workflows/project-ci.yml'
                text=path.read_text()
                if attack.startswith('permissions:'):text=text.replace('permissions: {}',attack,1)
                elif attack.startswith('uses:'):text=text.replace('uses: actions/checkout@'+policy_recipe('pilot')['target_pin'],attack)
                elif attack.startswith('runs-on:'):text=text.replace('runs-on: ubuntu-24.04',attack)
                else:text=text.replace('run: python -m unittest discover -s tests -t .',attack)
                path.write_text(text)
                result=policy_observation(fixture)
                self.assertTrue(result['maintenance_authorized'])
                self.assertFalse(result['accepted'])
                self.assertTrue(result['structural_errors'],result)

    def test_simulated_permission_and_pr_contract_are_separate(self):
        recipe=policy_recipe('pilot');event=recipe['event']
        self.assertEqual((True,'authorized'),authorize_trusted_maintenance(
            event=event,repository='fixture/policy',permission='maintain'))
        variants=({**event,'action':'synchronize'},
                  {**event,'label':{'name':'other'}},
                  {**event,'sender':{'login':'../actor'}},
                  {**event,'pull_request':{**event['pull_request'],'labels':[]}})
        with patch('scripts.check_ci_security.collaborator_permission',side_effect=AssertionError('No network')):
            for changed in variants:
                self.assertFalse(authorize_trusted_maintenance(event=changed,
                    repository='fixture/policy',permission='maintain')[0])
            for permission in ('write','read',None):
                self.assertFalse(authorize_trusted_maintenance(event=event,
                    repository='fixture/policy',permission=permission)[0])
        invalid={**event,'pull_request':{**event['pull_request'],'body':''}}
        self.assertTrue(authorize_trusted_maintenance(event=invalid,
            repository='fixture/policy',permission='maintain')[0])
        self.assertTrue(check_pr_event(invalid))

    def test_context_cannot_be_omitted_replaced_or_exposed(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve();fixture=self.fixture(root/'a')
            invalid=replace(fixture,policy_context=None)
            with self.assertRaises(ValueError):require_policy_fixture(invalid)
            with self.assertRaises(ValueError):write_frozen_source(invalid,root/'missing.json')
            with self.assertRaises(ValueError):final_manifest(invalid)
            context=fixture.policy_context.root
            with self.assertRaises(ValueError):write_frozen_source(fixture,context/'source.json')
            with self.assertRaises(ValueError):freeze_for_review(fixture,context/'review')
            permission=context/'permission.json';original=permission.read_text()
            permission.write_text(json.dumps({'repository':'fixture/policy','actor':'fixture-maintainer','permission':'write'}))
            with self.assertRaises(ValueError):policy_observation(fixture)
            permission.write_text(original)
            with self.assertRaises(ValueError):policy_observation(fixture)

    def test_context_bindings_and_required_reviews_invalidate_stale_evidence(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve();fixture=self.fixture(root/'a');self.repair(fixture)
            source=write_frozen_source(fixture,root/'source.json')
            launch=issue_invocation(fixture,root/'launch',source,model='test')
            self.assertEqual(fixture.policy_context.structural_sha256,launch.identity['policy_context_sha256'])
            manifest=final_manifest(fixture)
            self.assertEqual(fixture.policy_context.binding_sha256,manifest['policy_context']['binding_sha256'])
            snapshot=root/'review';freeze_for_review(fixture,snapshot)
            self.assertFalse((snapshot/'event.json').exists())
            evidence=ReviewEvidence(fixture.case,fixture.condition,fixture.seed_head,
                manifest['seed_manifest_sha256'],manifest['sha256'],'c'*64,'d'*64,'e'*64,
                'f'*64,(('correctness','pass'),))
            kwargs={'config_sha256':'c'*64,'suite_sha256':'d'*64,'source_sha256':'e'*64}
            self.assertIsNone(review_matches(fixture,evidence,**kwargs))
            evidence=replace(evidence,reviews=(('correctness','pass'),('security','pass')))
            self.assertTrue(review_matches(fixture,evidence,**kwargs))
            (fixture.root/'.github/workflows/project-ci.yml').write_text(policy_recipe('unseen')['expected_workflow'])
            self.assertIsNone(review_matches(fixture,evidence,**kwargs))
            for path in sorted(snapshot.rglob('*'),reverse=True):
                if path.is_dir():path.chmod(0o700)
            snapshot.chmod(0o700)

    def test_git_mutation_and_candidate_auth_claims_cannot_hide_policy_change(self):
        from scripts.command_runner import run_bounded_command
        with TemporaryDirectory() as temp:
            fixture=self.fixture(Path(temp).resolve()/'a');self.repair(fixture)
            (fixture.root/'auth.json').write_text('{"maintenance_authorized":true}')
            self.assertIn('out-of-scope file: auth.json',_scope_failures(fixture))
            result=run_bounded_command(['git','add','.github/workflows/project-ci.yml'],
                cwd=fixture.root,timeout_seconds=5,max_output_bytes=65536)
            self.assertEqual(0,result.returncode)
            self.assertIn('candidate Git control metadata changed',_scope_failures(fixture))

    def test_policy_observation_alone_cannot_make_native_validation_or_final_pass(self):
        with TemporaryDirectory() as temp:
            fixture=self.fixture(Path(temp).resolve()/'a');self.repair(fixture)
            fake=CommandResult(0,json.dumps({'completed':True,'tests':2,'failures':0,'errors':0,'successful':True}))
            with patch('evals.runtime_grader.run_bounded_command',return_value=fake), \
                    patch('evals.runtime_grader._scope_failures',return_value=[]):
                grade=grade_fixture(fixture,tool_trace=None)
            self.assertTrue(grade['functional_passed'])
            self.assertIsNone(grade['validation_ok'])
            self.assertIsNone(grade['scope_ok'])
            self.assertIsNone(grade['final_state_passed'])
            self.assertEqual('unknown',grade['actual_validation_state'])

    def test_context_missing_special_files_and_broad_native_grants_fail_closed(self):
        from evals.native_runtime import build_exec_command
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            for attack in ('missing','symlink','hardlink','fifo','extra','mode','root-missing','root-symlink'):
                with self.subTest(attack=attack):
                    fixture=self.fixture(root/attack)
                    path=fixture.policy_context.root/'permission.json'
                    if attack=='missing':path.unlink()
                    elif attack=='symlink':
                        original=path.read_bytes();path.unlink()
                        outside=root/(attack+'.json');outside.write_bytes(original)
                        path.symlink_to(outside)
                    elif attack=='hardlink':os.link(path,root/'link.json')
                    elif attack=='fifo':path.unlink();os.mkfifo(path)
                    elif attack=='extra':(path.parent/'extra.json').write_text('{}')
                    elif attack=='mode':path.chmod(0o644)
                    else:
                        context=path.parent;context.rename(context.parent/'original-context')
                        if attack=='root-symlink':context.symlink_to(context.parent/'original-context',target_is_directory=True)
                    with self.assertRaises(ValueError):require_policy_fixture(fixture)
                    grade=grade_fixture(fixture,tool_trace=None)
                    self.assertEqual('unknown',grade['actual_validation_state'])
                    self.assertIsNone(grade['scope_ok'])
                    self.assertEqual('fixture_boundary_unavailable',grade['validation_error'])
                    self.assertIsNone(grade['policy_observation'])
            fixture=self.fixture(root/'grant')
            source=write_frozen_source(fixture,root/'source.json')
            launch=issue_invocation(fixture,root/'launch',source,model='test')
            with patch('evals.native_runtime.runtime_readable_roots',return_value=(fixture.root.parent,)):
                with self.assertRaises(ValueError):
                    build_exec_command(fixture.root,model='test',writable=True,invocation=launch)

    def test_policy_preflight_requires_explicit_canonical_disjoint_fresh_roots(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            for protected in (None,root/'candidate'/'policy-context',root/'other'):
                with self.assertRaises(ValueError):
                    materialize_fixture('policy-change',root/'candidate',condition='baseline',policy_root=protected)
                self.assertFalse((root/'candidate').exists())


if __name__=='__main__':
    unittest.main()
