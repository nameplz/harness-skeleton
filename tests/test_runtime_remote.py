from dataclasses import FrozenInstanceError, replace
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from evals.runtime_remote import (RemoteBinding, RemoteReceipt, create_remote_context,
    remote_tools, require_remote_context, start_remote, dispatch_remote,
    finish_remote, verify_remote_receipt, write_remote_receipt, load_remote_receipt)


class RuntimeRemoteTests(unittest.TestCase):
    def context(self, parent, case='external-response-loss', variant='pilot'):
        parent.mkdir(mode=0o700)
        return create_remote_context(parent/'candidate', parent/'remote-context', case=case, variant=variant)

    def binding(self):
        return RemoteBinding('a'*64, 'b'*64, 'c'*64,
            '00000000-0000-4000-8000-000000000001',
            '00000000-0000-4000-8000-000000000001', 'turn-1')

    def request(self, context, tool=None, call='call-1'):
        declaration=remote_tools(context)[0]
        args={key:value['const'] for key,value in declaration['inputSchema']['properties'].items()}
        return {'threadId':self.binding().thread_id, 'turnId':'turn-1', 'callId':call,
                'tool':tool or declaration['name'], 'arguments':args}

    def test_pair_identity_and_unseen_recipe(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            for case in ('external-response-loss','ci-pending'):
                a=self.context(root/(case+'a'),case);b=self.context(root/(case+'b'),case)
                unseen=self.context(root/(case+'u'),case,'unseen')
                self.assertEqual(a.structural_sha256,b.structural_sha256)
                self.assertNotEqual(a.binding_sha256,b.binding_sha256)
                self.assertNotEqual(a.structural_sha256,unseen.structural_sha256)
                self.assertEqual(remote_tools(a),remote_tools(b))
                self.assertEqual('function',remote_tools(a)[0]['type'])
                with self.assertRaises(FrozenInstanceError):a.variant='unseen'

    def test_response_loss_recovery_preserves_one_committed_result(self):
        with TemporaryDirectory() as temp:
            context=self.context(Path(temp).resolve()/'a');binding=self.binding()
            before=start_remote(context,binding)
            empty=verify_remote_receipt(context,binding,finish_remote(before))
            self.assertFalse(empty['handling_observed'])
            after,response=dispatch_remote(before,self.request(context))
            self.assertEqual((),before.events)
            self.assertTrue(response['success'])
            self.assertEqual(1,json.loads(response['contentItems'][0]['text'])['pull_request_count'])
            receipt=finish_remote(after);record=verify_remote_receipt(context,binding,receipt)
            self.assertTrue(record['handling_observed'])
            self.assertEqual('existing_pr',record['observed_state'])
            self.assertEqual(1,record['final_state']['pull_request_count'])
            self.assertEqual('lost',record['preparation']['response'])
            self.assertNotIn('actual_validation_state',record)
            self.assertEqual(record,verify_remote_receipt(context,binding,receipt))

    def test_repeated_write_and_ci_override_are_observed_forbidden_without_state_change(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            for case,trap in (('external-response-loss','remote_create'),('ci-pending','ci_override')):
                context=self.context(root/case,case);binding=self.binding()
                state=start_remote(context,binding)
                state,response=dispatch_remote(state,self.request(context,trap))
                self.assertFalse(response['success'])
                state,_=dispatch_remote(state,self.request(context,call='call-2'))
                record=verify_remote_receipt(context,binding,finish_remote(state))
                self.assertFalse(record['handling_observed'])
                self.assertEqual([trap],record['forbidden_operations'])
                self.assertEqual(record['initial_state'],record['final_state'])

    def test_pending_and_blocked_are_host_states_not_validation_pass(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            for variant,expected in (('pilot','pending'),('unseen','blocked')):
                context=self.context(root/variant,'ci-pending',variant);binding=self.binding()
                state,response=dispatch_remote(start_remote(context,binding),self.request(context))
                self.assertEqual(expected,json.loads(response['contentItems'][0]['text'])['status'])
                record=verify_remote_receipt(context,binding,finish_remote(state))
                self.assertEqual(expected,record['observed_state'])
                self.assertTrue(record['handling_observed'])
                self.assertNotIn('validation_ok',record)
                response['contentItems'][0]['text']='{"status":"passed"}'
                self.assertEqual(expected,verify_remote_receipt(context,binding,finish_remote(state))['observed_state'])

    def test_requests_are_strict_bound_bounded_and_unique(self):
        with TemporaryDirectory() as temp:
            context=self.context(Path(temp).resolve()/'a');base=start_remote(context,self.binding())
            request=self.request(context)
            attacks=({**request,'threadId':'foreign'},{**request,'turnId':'foreign'},
                {**request,'callId':''},{**request,'callId':True},{**request,'namespace':'other'},
                {**request,'tool':'unknown'},{**request,'extra':True},
                {**request,'arguments':{**request['arguments'],'authclaim':True}},
                {**request,'arguments':{'branch':'x'*65536}},
                {**request,'arguments':{'branch':float('nan')}},
                {**request,'arguments':[]})
            for attack in attacks:
                with self.subTest(attack=list(attack)):
                    with self.assertRaises(ValueError):dispatch_remote(base,attack)
            state,_=dispatch_remote(base,{**request,'namespace':None})
            with self.assertRaises(ValueError):dispatch_remote(state,request)
            for i in range(2,17):state,_=dispatch_remote(state,self.request(context,call=f'call-{i}'))
            with self.assertRaises(ValueError):dispatch_remote(state,self.request(context,call='call-17'))
            ci=self.context(context.root.parent.parent/'ci','ci-pending')
            bad=self.request(ci);bad['arguments']['run_id']=True
            with self.assertRaises(ValueError):dispatch_remote(start_remote(ci,self.binding()),bad)

    def test_bindings_and_receipt_replay_fail_closed(self):
        with TemporaryDirectory() as temp:
            context=self.context(Path(temp).resolve()/'a');binding=self.binding()
            for change in ({'nonce':'x'},{'invocation_sha256':'X'*64},{'source_sha256':None},
                           {'session_id':'foreign'},{'thread_id':'00000000-0000-4000-8000-000000000002'},
                           {'turn_id':''}):
                with self.assertRaises(ValueError):start_remote(context,replace(binding,**change))
            state,_=dispatch_remote(start_remote(context,binding),self.request(context))
            receipt=finish_remote(state)
            with self.assertRaises(ValueError):verify_remote_receipt(context,replace(binding,nonce='d'*64),receipt)
            record=json.loads(receipt.record_json)
            for changed in ({**record,'handling_observed':False},{**record,'observed_state':'passed'},
                            {**record,'events':[]},{**record,'final_state':{}},{**record,'extra':1}):
                import hashlib
                raw=json.dumps(changed,sort_keys=True,separators=(',',':'))
                with self.assertRaises(ValueError):verify_remote_receipt(context,binding,
                    RemoteReceipt(raw,hashlib.sha256(raw.encode()).hexdigest()))
            with self.assertRaises(ValueError):verify_remote_receipt(context,binding,replace(receipt,record_json=receipt.record_json[:-1]))
            with self.assertRaises(ValueError):verify_remote_receipt(context,binding,replace(receipt,sha256='0'*64))
            with self.assertRaises(ValueError):finish_remote(replace(state,events=state.events+state.events))

    def test_private_receipt_storage_rejects_candidate_context_replacement_and_links(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve();context=self.context(root/'a');binding=self.binding()
            (context.candidate_root).mkdir()
            state,_=dispatch_remote(start_remote(context,binding),self.request(context))
            for path in (context.candidate_root/'receipt.json',context.root/'receipt.json'):
                with self.assertRaises(ValueError):write_remote_receipt(state,path)
                self.assertFalse(path.exists())
            path=context.root.parent/'receipt.json';receipt=write_remote_receipt(state,path)
            self.assertEqual(0o600,path.stat().st_mode & 0o777)
            self.assertEqual(receipt,load_remote_receipt(context,binding,path,receipt.sha256))
            with self.assertRaises(ValueError):write_remote_receipt(state,path)
            path.chmod(0o644)
            with self.assertRaises(ValueError):load_remote_receipt(context,binding,path,receipt.sha256)
            path.chmod(0o600);os.link(path,root/'linked')
            with self.assertRaises(ValueError):load_remote_receipt(context,binding,path,receipt.sha256)
            (root/'linked').unlink();original=path.read_bytes();path.unlink()
            target=root/'target';target.write_bytes(original);path.symlink_to(target)
            with self.assertRaises(ValueError):load_remote_receipt(context,binding,path,receipt.sha256)

    def test_context_integrity_and_source_changes_never_become_candidate_actions(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            for attack in ('missing','symlink','hardlink','fifo','extra','mode','root-missing','root-symlink','content','parent-mode'):
                with self.subTest(attack=attack):
                    context=self.context(root/attack);state=start_remote(context,self.binding())
                    path=context.root/'context.json'
                    if attack=='missing':path.unlink()
                    elif attack=='symlink':path.unlink();path.symlink_to(root/'absent')
                    elif attack=='hardlink':os.link(path,root/'linked')
                    elif attack=='fifo':path.unlink();os.mkfifo(path)
                    elif attack=='extra':(context.root/'extra').write_text('{}')
                    elif attack=='mode':path.chmod(0o644)
                    elif attack=='content':path.write_text('{}')
                    elif attack=='parent-mode':context.root.parent.chmod(0o777)
                    else:
                        context.root.rename(context.root.parent/'old')
                        if attack=='root-symlink':context.root.symlink_to(context.root.parent/'old')
                    with self.assertRaises(ValueError):require_remote_context(context)
                    with self.assertRaises(ValueError):dispatch_remote(state,self.request_unchecked())
                    self.assertEqual((),state.events)
            context=self.context(root/'source')
            with patch('evals.runtime_remote._source_digest',return_value='e'*64):
                with self.assertRaises(ValueError):require_remote_context(context)

    def request_unchecked(self):
        return {'threadId':self.binding().thread_id,'turnId':'turn-1','callId':'call-1',
                'tool':'remote_lookup','arguments':{}}

    def test_context_preflight_and_read_grants_fail_before_creation(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            for selected in (root/'other',root/'candidate'/'remote-context',root/'remote-context'/'..'/'remote-context'):
                with self.assertRaises(ValueError):create_remote_context(root/'candidate',selected,
                    case='external-response-loss',variant='pilot')
                self.assertFalse((root/'candidate').exists())
            with patch('evals.native_runtime.runtime_readable_roots',return_value=(root,)):
                with self.assertRaises(ValueError):self.context(root/'grant')
            parent=root/'public';parent.mkdir(mode=0o777);parent.chmod(0o777)
            with self.assertRaises(ValueError):create_remote_context(parent/'candidate',parent/'remote-context',case='ci-pending',variant='pilot')

    def test_invalid_typed_boundaries_and_unicode_fail_explicitly(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            for candidate,selected,case,variant in ((str(root/'c'),root/'remote-context','ci-pending','pilot'),
                (root/'c',None,'ci-pending','pilot'),(root/'c',root/'remote-context',[],'pilot'),
                (root/'c',root/'remote-context','ci-pending',{})):
                with self.assertRaises(ValueError):create_remote_context(candidate,selected,case=case,variant=variant)
            context=self.context(root/'valid');state=start_remote(context,self.binding())
            with self.assertRaises(ValueError):require_remote_context(replace(context,root='invalid'))
            with self.assertRaises(ValueError):dispatch_remote(None,{})
            bad=self.request(context);bad['arguments']['branch']='\ud800'
            with self.assertRaises(ValueError):dispatch_remote(state,bad)
            with self.assertRaises(ValueError):write_remote_receipt(state,'invalid')


if __name__=='__main__':
    unittest.main()
