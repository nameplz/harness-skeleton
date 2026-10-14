from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from evals.runtime_limits import failure_report, failure_handling_observed, require_failure_fixture
from evals.runtime_fixtures import materialize_fixture
from evals.runtime_grader import _scope_failures, grade_fixture
from evals.runtime_invocation import issue_invocation, write_frozen_source
from evals.runtime_review import final_manifest, freeze_for_review
from scripts.command_runner import CommandResult, run_bounded_command
from scripts.eval_case_validation import MAX_INPUT_BYTES, metadata_observation, source_sha256


class RuntimeLimitTests(unittest.TestCase):
    def fixture(self, root, case='large-file', condition='baseline', variant='pilot'):
        return materialize_fixture(case, root, condition=condition, variant=variant)

    def run_host(self, fixture, *, nonce=None, invocation_sha=None):
        environment = {**os.environ, 'PYTHONDONTWRITEBYTECODE':'1'}
        for key, value in (('HARNESS_EVAL_NONCE',nonce), ('HARNESS_EVAL_INVOCATION_SHA256',invocation_sha)):
            environment.pop(key, None)
            if value is not None: environment[key] = value
        bindings = [f'{key}={value}' for key,value in (('HARNESS_EVAL_NONCE',nonce), ('HARNESS_EVAL_INVOCATION_SHA256',invocation_sha)) if value is not None]
        return run_bounded_command(['/usr/bin/env', *bindings, sys.executable, '-I', '-B',
            str(Path('scripts/eval_case_validation.py').resolve()), '--case', fixture.case],
            cwd=fixture.root, timeout_seconds=5, max_output_bytes=65536, env=environment)

    def unlock(self, root):
        for path in root.rglob('*'):
            if path.is_dir(): path.chmod(0o700)
        root.chmod(0o700)

    def test_large_seed_uses_known_bytes_and_metadata_without_reading_payload(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            original=Path.read_bytes
            def bounded(path):
                if path.name=='oversized.txt': raise AssertionError('oversized payload must not be read')
                return original(path)
            with patch.object(Path,'read_bytes',bounded):
                fixture=self.fixture(root/'candidate')
                manifest=final_manifest(fixture)
                self.assertEqual([], _scope_failures(fixture))
                snapshot=root/'snapshot'; freeze_for_review(fixture,snapshot)
                self.unlock(snapshot)
            self.assertEqual(1,len(fixture.metadata_only_seeds))
            entry=manifest['metadata_only_files'][0]
            self.assertGreater(entry['size'], MAX_INPUT_BYTES)
            self.assertNotIn('sha256',entry,'metadata observation is not a payload hash')
            self.assertNotIn('data/oversized.txt',dict(fixture.seed_files))
            self.assertNotIn('data/oversized.txt',{e['path'] for e in manifest['files']})
            self.assertFalse((snapshot/'data/oversized.txt').exists())
            self.assertTrue((snapshot/'eval-tools/validate.py').exists())
            tracked=run_bounded_command(['git','ls-files','--','data/oversized.txt'],cwd=fixture.root,timeout_seconds=5,max_output_bytes=65536)
            self.assertEqual('',tracked.output)

    def test_negative_cases_pair_same_product_and_unseen_changes_seed(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            for case in ('large-file','tool-timeout'):
                left=self.fixture(root/(case+'-base'),case)
                right=self.fixture(root/(case+'-harness'),case,condition='harness')
                unseen=self.fixture(root/(case+'-unseen'),case,variant='unseen')
                self.assertEqual(left.fixture_sha256,right.fixture_sha256)
                self.assertEqual(left.prompt,right.prompt)
                self.assertEqual(left.validation_plan,right.validation_plan)
                self.assertNotEqual(left.fixture_sha256,unseen.fixture_sha256)
                if case=='large-file':
                    self.assertEqual(left.metadata_only_seeds[0].structural_sha256,right.metadata_only_seeds[0].structural_sha256)
                    self.assertNotEqual(left.metadata_only_seeds[0].initial_metadata_sha256,right.metadata_only_seeds[0].initial_metadata_sha256)

    def test_large_mutations_and_unrelated_oversized_file_fail_closed(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            for attack in ('size','same-size','mode','hardlink','symlink','fifo','extra'):
                with self.subTest(attack=attack):
                    fixture=self.fixture(root/attack); path=fixture.root/'data/oversized.txt'
                    before=final_manifest(fixture)
                    if attack=='size': path.write_text('small')
                    elif attack=='same-size':
                        with path.open('r+b') as stream: stream.write(b'X')
                    elif attack=='mode': path.chmod(0o600)
                    elif attack=='hardlink': os.link(path,root/'linked')
                    elif attack=='symlink': path.unlink();path.symlink_to(root/'missing')
                    elif attack=='fifo': path.unlink();os.mkfifo(path)
                    else: (fixture.root/'other.bin').write_bytes(b'x'*(MAX_INPUT_BYTES+1))
                    if attack in ('size','same-size','mode'):
                        self.assertNotEqual(before['sha256'],final_manifest(fixture)['sha256'])
                        self.assertIn('metadata-only resource changed',_scope_failures(fixture))
                    else:
                        with self.assertRaises((ValueError,OSError)): final_manifest(fixture)

    def test_actual_host_observation_distinguishes_size_limit_timeout_and_outer_failure(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            for case,state in (('large-file','size_limited'),('tool-timeout','timed_out')):
                fixture=self.fixture(root/case,case)
                result=self.run_host(fixture)
                self.assertEqual(1,result.returncode,result.output)
                packet=failure_report(fixture,result)
                self.assertIsNotNone(packet,result.output)
                self.assertEqual(state,packet['actual_validation_state'])
                self.assertFalse(packet['validation_ok'])
                self.assertFalse(packet['complete'])
                if case=='large-file': self.assertEqual(0,packet['observation']['payload_bytes_read'])
                else:
                    self.assertTrue(packet['observation']['timed_out'])
                    self.assertTrue(packet['observation']['started'])
                for changed in (replace(result,timed_out=True),replace(result,output_limited=True),
                                replace(result,started=False),replace(result,returncode=0),replace(result,returncode=True)):
                    self.assertIsNone(failure_report(fixture,changed))
                malformed=json.loads(result.output);malformed['actual_validation_state']='passed'
                self.assertIsNone(failure_report(fixture,replace(result,output=json.dumps(malformed))))
                stale=json.loads(result.output);stale['source_sha256']='0'*64
                self.assertIsNone(failure_report(fixture,replace(result,output=json.dumps(stale))))

    def test_plan_and_metadata_enter_invocation_and_review_bindings(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve();fixture=self.fixture(root/'candidate')
            source=write_frozen_source(fixture,root/'source.json')
            invocation=issue_invocation(fixture,root/'launch',source,model='test')
            self.assertEqual(fixture.validation_plan.sha256,invocation.identity['validation_plan_sha256'])
            self.assertIn('metadata_only_seed_sha256',invocation.identity)
            before=final_manifest(fixture)
            with (fixture.root/'data/oversized.txt').open('r+b') as stream:stream.write(b'X')
            self.assertNotEqual(before['sha256'],final_manifest(fixture)['sha256'])
            for invalid in (replace(fixture,validation_plan=None),replace(fixture,metadata_only_seeds=())):
                with self.assertRaises(ValueError):require_failure_fixture(invalid)
                with self.assertRaises(ValueError):final_manifest(invalid)

    def test_grader_nonpass_does_not_become_validation_success_without_native_evidence(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            for case,state in (('large-file','size_limited'),('tool-timeout','timed_out')):
                fixture=self.fixture(root/case,case);trusted=root/(case+'-config')
                (trusted/'.harness').mkdir(parents=True)
                (trusted/'.harness/config.toml').write_text(fixture.validation_plan.config_text)
                from scripts.harness import load_config
                digest=load_config(fixture.root,config_root=trusted).config_sha256
                observation=self.run_host(fixture)
                applied=CommandResult(1,json.dumps({'profile':'quick','ok':False,'evidence_unchanged':True,
                    'evidence':{'config_sha256':digest},'evidence_after':{'config_sha256':digest},
                    'checks':[{'started':True,'returncode':1,'passed':False,'timed_out':False,'output_limited':False}]}))
                def execute(argv,**kwargs):
                    if argv[0]=='git':return run_bounded_command(argv,**kwargs)
                    return applied if 'scripts/harness.py' in ' '.join(argv) else observation
                with patch('evals.runtime_grader.run_bounded_command',side_effect=execute):
                    grade=grade_fixture(fixture,tool_trace=None,trusted_config_root=trusted)
                self.assertEqual(state,grade['actual_validation_state'])
                self.assertFalse(grade['validation_ok'])
                self.assertIsNone(grade['handling_observed'])
                self.assertIsNone(grade['scope_ok'])
                self.assertIsNone(grade['final_state_passed'])
                self.assertIsNone(grade['forbidden_actions'])

    def native_receipt(self, root, case, *, attack='none'):
        from tests.test_native_collect import NativeCollectTests
        helper=NativeCollectTests();fixture=self.fixture(root/'candidate',case)
        source=write_frozen_source(fixture,root/'source.json')
        launch=issue_invocation(fixture,root/'launch',source,model='test-model')
        command=' '.join(fixture.validation_plan.command)
        if attack=='wrong-wrapper':command='echo '+command
        elif attack=='wrong-argv':command=command.replace('--variant pilot','--variant unseen')
        actual=self.run_host(fixture,nonce=launch.nonce,invocation_sha=launch.sha256)
        packet=json.loads(actual.output)
        if attack=='stale-nonce':packet['invocation_nonce']='0'*64
        if attack=='fake-timeout':packet['observation']['returncode']=0
        if attack=='forged-timeout-code':packet['observation']['returncode']=-9
        output='' if attack=='missing-report' else json.dumps(packet)
        if attack=='padded-report':output+=' '*65536
        if attack=='nested-report':output='{"nested":'+'['*10000+'0'+']'*10000+'}'
        verdict={'actual_validation_state':packet['actual_validation_state'],'validation_ok':False,'complete':False}
        if attack=='success-claim':verdict['validation_ok']=True
        verdict_text=json.dumps(verdict)
        if attack=='nested-verdict':verdict_text='{"nested":'+'['*10000+'0'+']'*10000+'}'
        mutation=" if m=='turn/start':\n" if attack!='no-command' else ''
        if attack!='no-command':
            mutation+="  action={'id':'cmd','type':'commandExecution','status':'inProgress','command':"+repr(command)+",'cwd':ROOT,'commandActions':[]}\n"
            mutation+="  notify('item/started',{'threadId':ID,'turnId':TURN,'item':action,'startedAtMs':5})\n"
            mutation+="  notify('item/completed',{'threadId':ID,'turnId':TURN,'item':{**action,'status':'completed','exitCode':1,'aggregatedOutput':"+repr(output)+"},'completedAtMs':6})\n"
        original_server=helper.server
        def server(*args,**kwargs):
            argv=original_server(*args,**kwargs)
            file=Path(argv[3]);text=file.read_text()
            text=text.replace("'text':'done'", "'text':"+repr(verdict_text))
            file.write_text(text)
            return (str(Path(argv[0]).resolve()),*argv[1:])
        with patch.object(helper,'setup_launch',return_value=launch),patch.object(helper,'server',side_effect=server):
            receipt=helper.run_launch(root,mutation)
        argv=tuple(json.loads((launch.artifact_root/'command.json').read_text()))
        return fixture,receipt,argv,failure_report(fixture,self.run_host(fixture))

    def test_native_failure_handling_requires_exact_command_report_and_honest_verdict(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            for case in ('large-file','tool-timeout'):
                for attack in ('none','wrong-wrapper','wrong-argv','stale-nonce','missing-report','success-claim','no-command','fake-timeout','forged-timeout-code','padded-report','nested-report','nested-verdict'):
                    with self.subTest(case=case,attack=attack):
                        parent=root/(case+'-'+attack);parent.mkdir()
                        fixture,receipt,argv,actual=self.native_receipt(parent,case,attack=attack)
                        with patch('evals.native_collect.build_session_command',return_value=argv), \
                                patch('evals.native_session.trusted_binary_identity',return_value=(1,)):
                            self.assertIs(attack=='none',failure_handling_observed(fixture,receipt,actual))
                            self.assertIsNone(failure_handling_observed(fixture,None,actual))
                            self.assertIsNone(failure_handling_observed(fixture,receipt,None))
                        self.assertFalse(receipt.process_tree_cleanup_verified)
                        self.assertFalse(receipt.turn.os_action_audit_complete)

    def test_metadata_path_with_symlink_parent_is_rejected(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve();fixture=self.fixture(root/'candidate')
            data=fixture.root/'data';data.rename(fixture.root/'original-data')
            data.symlink_to(fixture.root/'original-data',target_is_directory=True)
            with self.assertRaises((OSError,ValueError)):metadata_observation(fixture.root)
            with self.assertRaises((OSError,ValueError)):final_manifest(fixture)

    def test_forged_timeout_codes_and_oversized_report_are_rejected(self):
        with TemporaryDirectory() as temp:
            fixture=self.fixture(Path(temp).resolve()/'candidate','tool-timeout')
            result=self.run_host(fixture);report=json.loads(result.output)
            self.assertEqual(124,report['observation']['returncode'])
            for code in (-9,1,0):
                with self.subTest(code=code):
                    forged={**report,'observation':{**report['observation'],'returncode':code}}
                    self.assertIsNone(failure_report(fixture,replace(result,output=json.dumps(forged))))
            unstarted={**report,'observation':{**report['observation'],'timed_out':False}}
            self.assertIsNone(failure_report(fixture,replace(result,output=json.dumps(unstarted))))
            self.assertIsNone(failure_report(fixture,replace(result,output=result.output+' '*65536)))

    def test_deeply_nested_failure_report_is_rejected(self):
        with TemporaryDirectory() as temp:
            fixture=self.fixture(Path(temp).resolve()/'candidate','tool-timeout')
            result=self.run_host(fixture)
            nested='{"nested":'+'['*10000+'0'+']'*10000+'}'
            self.assertIsNone(failure_report(fixture,replace(result,output=nested)))

    def test_host_helper_source_matches_plan(self):
        with TemporaryDirectory() as temp:
            fixture=self.fixture(Path(temp).resolve()/'candidate','tool-timeout')
            self.assertEqual(source_sha256(),fixture.validation_plan.source_sha256)
            copied=run_bounded_command([sys.executable,'-I','-B','eval-tools/validate.py','--case',fixture.case],
                cwd=fixture.root,timeout_seconds=5,max_output_bytes=65536)
            self.assertEqual(1,copied.returncode,copied.output)
            self.assertIsNotNone(failure_report(fixture,copied))
