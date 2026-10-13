from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
import hashlib
import json
import os
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

from evals.native_config import BinaryPin, FEATURES, _ConfigExchange
from evals.native_collect import collect_native_turn, load_native_turn
from evals.runtime_fixtures import materialize_fixture
from evals.runtime_invocation import issue_invocation, write_frozen_source

ID = "11111111-1111-4111-8111-111111111111"
TURN = "22222222-2222-4222-8222-222222222222"


SERVER = '''import json,sys
ROOT=sys.argv[1]
ARTIFACT=sys.argv[2]
ID="11111111-1111-4111-8111-111111111111"
TURN="22222222-2222-4222-8222-222222222222"
FEATURES=__FEATURES__
from pathlib import Path
assert (Path(ARTIFACT)/'command.json').exists()
def notify(method,params):print(json.dumps({'method':method,'params':params,'emittedAtMs':3}),flush=True)
for line in sys.stdin:
 r=json.loads(line)
 if 'id' not in r:continue
 m=r['method'];p=r['params']
 if m=='initialize':v={}
 elif m=='config/read':
  s={'name':{'type':'sessionFlags'},'version':'1'}
  v={'config':{'mcp_servers':{'docs':{'enabled':False}},'features':{k:False for k in FEATURES}},'layers':[{**s,'config':{}}],'origins':{'features':s,'mcp_servers':s}}
 elif m=='configRequirements/read':v={'requirements':None}
 elif m=='permissionProfile/list':v={'data':[{'id':'harness-eval','allowed':True}],'nextCursor':None}
 elif m=='thread/start':
  assert 'Host invocation nonce' not in p['developerInstructions']
  v={'thread':{'id':ID,'sessionId':ID,'ephemeral':True,'environments':p['environments']},'model':p['model'],'cwd':ROOT,'runtimeWorkspaceRoots':[ROOT],'instructionSources':[],'activePermissionProfile':{'id':'harness-eval','extends':':workspace'},'approvalPolicy':'never','approvalsReviewer':'user','sandbox':{'type':'workspaceWrite','networkAccess':False,'writableRoots':[],'excludeTmpdirEnvVar':True,'excludeSlashTmp':True}}
  notify('thread/started',{'thread':{'id':ID,'sessionId':ID}})
 elif m=='mcpServerStatus/list':v={'data':[{'name':'docs','runtimeStatus':'disabled','authStatus':'unsupported','tools':{},'resources':[],'resourceTemplates':[]}],'nextCursor':None}
 elif m=='turn/start':
  assert (Path(ARTIFACT)/'session.json').exists()
  t={'id':TURN,'status':'inProgress','items':[]}
  notify('thread/status/changed',{'threadId':ID,'status':{'type':'active','activeFlags':[]}})
  notify('turn/started',{'threadId':ID,'turn':t})
  v={'turn':t}
 else:raise RuntimeError('bad method')

__MUTATION__
 print(json.dumps({'id':r['id'],'result':v}),flush=True)
 if m=='turn/start':
  user={'id':'u1','type':'userMessage','clientId':p['clientUserMessageId'],'content':p['input']}
  for method,timestamp in [('item/started','startedAtMs'),('item/completed','completedAtMs')]:notify(method,{'threadId':ID,'turnId':TURN,'item':user,timestamp:5})
  item={'id':'a1','type':'agentMessage','text':'done','phase':'final_answer'}
  for method,timestamp in [('item/started','startedAtMs'),('item/completed','completedAtMs')]:notify(method,{'threadId':ID,'turnId':TURN,'item':item,timestamp:6})
  notify('account/updated',{'authMode':'chatgpt','planType':'pro'})
  notify('account/rateLimits/updated',{'rateLimits':{'planType':'pro','primary':{'usedPercent':10},'credits':{'hasCredits':False,'unlimited':False,'balance':'SENSITIVE'}}})
  notify('turn/completed',{'threadId':ID,'turn':{**t,'status':'completed','items':[item],'itemsView':'summary'}})
  notify('thread/status/changed',{'threadId':ID,'status':{'type':'idle'}})
__TAIL__
'''

class NativeCollectTests(unittest.TestCase):
    def binary(self):
        path = Path(sys.executable).resolve()
        return BinaryPin(path, hashlib.sha256(path.read_bytes()).hexdigest())

    def setup_launch(self, root):
        fixture = materialize_fixture('documentation', root / 'candidate', condition='baseline')
        source = write_frozen_source(fixture, root / 'source.json')
        return issue_invocation(fixture, root / 'launch', source, model='test-model')

    def server(self, root, mutation='', tail=''):
        script=root/'server.py'
        script.write_text(SERVER.replace('__FEATURES__',repr(FEATURES)).replace('__MUTATION__',mutation).replace('__TAIL__',tail))
        return (sys.executable,'-I','-B',str(script),str((root/'candidate').resolve()),str((root/'launch').resolve()))

    def run_launch(self, root, mutation='', tail='', **limits):
        launch=self.setup_launch(root);command=self.server(root,mutation,tail)
        with patch('evals.native_session.build_session_command',return_value=command), \
                patch('evals.native_session.trusted_binary_identity',return_value=(1,)):
            return collect_native_turn(launch,binary=self.binary(),disabled_servers=('docs',),timeout_seconds=5,**limits)

    def test_same_process_claim_response_events_and_telemetry_are_bound(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve();r=self.run_launch(root)
            self.assertEqual('completed',r.turn.status)
            self.assertEqual(('done',),r.turn.assistant_messages)
            self.assertEqual(0,r.returncode)
            self.assertEqual(ID,r.invocation.session_id)
            self.assertTrue((root/'launch/native-policy.json').exists())
            raw=(root/'launch/rpc.in.jsonl').read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(),r.rpc_in_sha256)
            self.assertIn(b'"emittedAtMs": 3',raw)
            self.assertNotIn(b'SENSITIVE',raw)
            command=tuple(json.loads((root/'launch/command.json').read_text()))
            with patch('evals.native_collect.build_session_command',return_value=command), \
                    patch('evals.native_session.trusted_binary_identity',return_value=(1,)):
                self.assertEqual(r,load_native_turn(r.invocation,binary=self.binary(),disabled_servers=('docs',)))
                with self.assertRaises(ValueError):load_native_turn(r.invocation,binary=self.binary(),disabled_servers=('docs',))

    def test_wrong_response_identity_unknown_timestamp_and_replay_fail(self):
        for mutation in (" if m=='turn/start':r['id']=999\n", " if m=='turn/start':v['turn']['id']='other'\n"):
            with TemporaryDirectory() as temp,self.subTest(mutation=mutation),self.assertRaises(ValueError):self.run_launch(Path(temp).resolve(),mutation)
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve();r=self.run_launch(root)
            with self.assertRaises(ValueError):collect_native_turn(r.invocation,binary=self.binary(),disabled_servers=('docs',))

    def test_tampered_original_bytes_or_policy_are_rejected(self):
        for name in ('rpc.in.jsonl','rpc.out.jsonl','native-policy.json','turn.json'):
            with TemporaryDirectory() as temp,self.subTest(name=name):
                root=Path(temp).resolve();r=self.run_launch(root);(root/'launch'/name).write_text('{}\n')
                with self.assertRaises(ValueError):load_native_turn(r.invocation,binary=self.binary(),disabled_servers=('docs',))

    def test_late_unknown_activity_and_malformed_envelopes_invalidate_receipt(self):
        cases = (
            (" if m=='turn/start':notify('model/rerouted',{'threadId':ID})", ''),
            (" if m=='turn/start':print('{\"id\":100,\"id\":100,\"result\":{}}',flush=True)", ''),
            (" if m=='turn/start':print(json.dumps({'id':7,'method':'item/commandExecution/requestApproval','params':{}}),flush=True)", ''),
            ('', "  notify('item/agentMessage/delta',{'threadId':ID,'turnId':TURN,'itemId':'a1','delta':'late'})"),
            ('', "  notify('account/rateLimits/updated',{'rateLimits':{'credits':{'hasCredits':False,'unlimited':'bad'}}})"),
            ('', "  notify('thread/status/changed',{'threadId':'other','status':{'type':'idle'}})"),
        )
        for mutation,tail in cases:
            with TemporaryDirectory() as temp,self.subTest(mutation=mutation,tail=tail):
                root=Path(temp).resolve()
                with self.assertRaises(ValueError):self.run_launch(root,mutation,tail)
                self.assertFalse((root/'launch/turn.json').exists())

    def test_native_limits_and_missing_external_receipt_binding_fail_closed(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            with self.assertRaises(ValueError):self.run_launch(root,max_output_bytes=1)
            self.assertFalse((root/'launch/turn.json').exists())
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve();receipt=self.run_launch(root)
            with self.assertRaises(ValueError):
                load_native_turn(replace(receipt.invocation,native_receipt_sha256=None),binary=self.binary(),disabled_servers=('docs',))

    def test_unexpected_native_instruction_sources_fail_before_turn(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve();launch=self.setup_launch(root);command=self.server(root)
            with patch('evals.native_session.build_session_command',return_value=command), \
                    patch('evals.native_session._instructions',return_value=(('a'*64,'b'*64),)), \
                    patch('evals.native_session.trusted_binary_identity',return_value=(1,)), self.assertRaises(ValueError):
                collect_native_turn(launch,binary=self.binary(),disabled_servers=('docs',))
            self.assertFalse((root/'launch/rpc.out.jsonl').exists())

    def test_account_telemetry_records_only_method_and_count(self):
        with TemporaryDirectory() as temp:
            receipt=self.run_launch(Path(temp).resolve())
            self.assertEqual((('account/rateLimits/updated',1),('account/updated',1)),receipt.telemetry)
            self.assertFalse(receipt.process_tree_cleanup_verified)

    def test_mutable_native_installation_is_rejected_before_claim_or_spawn(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve();launch=self.setup_launch(root)
            with patch('evals.native_session.subprocess.Popen') as spawn,self.assertRaises(ValueError):
                collect_native_turn(launch,binary=self.binary(),disabled_servers=('docs',))
            self.assertEqual(0,spawn.call_count)
            self.assertFalse((root/'launch/command.json').exists())

    def test_approved_instruction_sources_are_bound_at_collection_and_loading(self):
        expected=(('a'*64,'b'*64),)
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            with patch('evals.native_session._instructions',return_value=expected):
                receipt=self.run_launch(root,instruction_sources=expected)
            command=tuple(json.loads((root/'launch/command.json').read_text()))
            with patch('evals.native_collect.build_session_command',return_value=command), \
                    patch('evals.native_session.trusted_binary_identity',return_value=(1,)):
                with self.assertRaises(ValueError):
                    load_native_turn(receipt.invocation,binary=self.binary(),disabled_servers=('docs',))
                self.assertFalse((root/'launch/consumed.json').exists())
                self.assertEqual(receipt,load_native_turn(receipt.invocation,binary=self.binary(),disabled_servers=('docs',),instruction_sources=expected))

    def test_claim_is_consumed_before_failed_spawn(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve();launch=self.setup_launch(root)
            with patch('evals.native_session.subprocess.Popen',side_effect=PermissionError(13,'hidden')), \
                    patch('evals.native_session.trusted_binary_identity',return_value=(1,)):
                with self.assertRaises(ValueError):collect_native_turn(launch,binary=self.binary(),disabled_servers=('docs',))
            self.assertTrue((root/'launch/command.json').exists())
            with self.assertRaises(ValueError):collect_native_turn(launch,binary=self.binary(),disabled_servers=('docs',))

    def test_stdin_write_timeout_is_bounded(self):
        process=subprocess.Popen([sys.executable,'-I','-c','import time;time.sleep(3)'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,bufsize=0,start_new_session=True)
        os.set_blocking(process.stdin.fileno(),False)
        while True:
            try:os.write(process.stdin.fileno(),b'x'*65536)
            except BlockingIOError:break
        exchange=_ConfigExchange(process,time.monotonic()+0.1,1048576)
        try:
            with self.assertRaises(ValueError):exchange.send({'bounded':'request'})
        finally:
            process.kill();process.wait();exchange.selector.close()
            for stream in (process.stdin,process.stdout,process.stderr):stream.close()
