from dataclasses import asdict
from pathlib import Path
from tempfile import TemporaryDirectory
import hashlib
import json
import sys
import unittest
from unittest.mock import patch

from evals.native_config import BinaryPin, FEATURES
from evals.native_session import NativeSessionError, build_session_command, inspect_native_session


class NativeSessionTests(unittest.TestCase):
    def _binary(self):
        path = Path(sys.executable).resolve()
        with path.open('rb') as stream:
            return BinaryPin(path, hashlib.file_digest(stream, 'sha256').hexdigest())

    def _server(self, root, mutation=''):
        script = root / 'fake-server.py'
        script.write_text('''import json, sys
ROOT = sys.argv[1]
ID = '11111111-1111-4111-8111-111111111111'
FEATURES = ''' + repr(FEATURES) + '''
pending = False
for line in sys.stdin:
    request = json.loads(line)
    if 'id' not in request: continue
    method = request['method']; params = request['params']
    if method == 'initialize':
        result = {'userAgent': 'codex/0.162.1'}
        print(json.dumps({'method':'account/updated','params':{'authMode':'chatgpt','planType':'pro'}}),flush=True)
    elif method == 'config/read':
        source = {'name':{'type':'sessionFlags'},'version':'v1'}
        result = {'config':{'mcp_servers':{'docs':{'enabled':False}},'features':{key:False for key in FEATURES}},
            'layers':[{**source,'config':{}}], 'origins':{'mcp_servers':source,'features':source}}
    elif method == 'configRequirements/read': result = {'requirements':None}
    elif method == 'permissionProfile/list': result = {'data':[{'id':'harness-eval','allowed':True,'description':'SENTINEL'}],'nextCursor':None}
    elif method == 'thread/start':
        assert params['environments'] == [{'environmentId':'local','cwd':ROOT,'runtimeWorkspaceRoots':[ROOT]}]
        assert params['dynamicTools'] == [] and params['selectedCapabilityRoots'] == []
        result = {'thread':{'id':ID,'sessionId':ID,'ephemeral':True,'environments':params['environments']},
            'model':params['model'],'cwd':ROOT,'runtimeWorkspaceRoots':[ROOT],'instructionSources':[],
            'activePermissionProfile':{'id':'harness-eval','extends':':read-only'},
            'approvalPolicy':'never','approvalsReviewer':'user','sandbox':{'type':'readOnly','networkAccess':False}}
        pending = True
    elif method == 'mcpServerStatus/list':
        assert params == {'threadId':ID,'serverName':'docs','detail':'full','cursor':None,'limit':1}
        result = {'data':[{'name':'docs','runtimeStatus':'disabled','authStatus':'unsupported',
            'tools':{},'resources':[],'resourceTemplates':[],'httpOrigin':'https://SENTINEL.invalid/token'}],'nextCursor':None}
    else: raise RuntimeError('unapproved method')
''' + mutation + '''
    print(json.dumps({'id':request['id'],'result':result}),flush=True)
    if pending:
        print(json.dumps({'method':'thread/started','params':{'thread':{'id':ID,'sessionId':ID}}}),flush=True)
        pending = False
''')
        return (sys.executable, '-I', '-B', str(script), str(root.resolve()))

    def _inspect(self, root, mutation=''):
        with patch('evals.native_session.build_session_command', return_value=self._server(root, mutation)):
            return inspect_native_session(root, binary=self._binary(), model='gpt-6.1-sol', disabled_servers=('docs',))

    def test_command_selects_local_profile_and_synthetic_tool_environment(self):
        with TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            command = build_session_command(root, binary=self._binary(), disabled_servers=('docs',), writable=False)
            self.assertEqual(str(self._binary().path), command[0])
            self.assertIn('mcp_servers.docs.enabled=false', command)
            self.assertIn('permissions.harness-eval.extends=":read-only"', command)
            self.assertTrue(any(value.startswith('shell_environment_policy.set=') and str(root / '.eval-home') in value for value in command))
            self.assertEqual(('app-server', '--listen', 'stdio://'), command[-3:])

    def test_same_thread_named_inventory_and_local_environment_are_observed(self):
        with TemporaryDirectory() as temp:
            result = self._inspect(Path(temp))
            self.assertEqual('11111111-1111-4111-8111-111111111111', result.session.thread_id)
            self.assertEqual(result.session.thread_id, result.session.session_id)
            self.assertEqual(('local',), result.session.environment_ids)
            self.assertEqual(('docs',), tuple(value.name for value in result.session.mcp))
            self.assertTrue(result.session.mcp[0].http_origin_present)
            self.assertEqual(0, result.returncode)
            self.assertNotIn('SENTINEL', json.dumps(asdict(result)))
            self.assertNotIn('pro', result.auth_modes)

    def test_invalid_roots_profile_environment_or_guidance_stop_before_mcp(self):
        changes = (
            "result['runtimeWorkspaceRoots']=[]",
            "result['activePermissionProfile']['id']='other'",
            "result['activePermissionProfile']['extends']=':full-access'",
            "result['thread']['environments']=[]",
            "result['thread']['environments'][0]['environmentId']='remote'",
            "result['instructionSources']=[ROOT+'/AGENTS.md']",
            "result['sandbox']['networkAccess']=True",
            "result['sandbox']['writableRoots']=[ROOT]",
            "result['sandbox']['excludeTmpdirEnvVar']=False",
            "result['sandbox']['excludeSlashTmp']=False",
            "result['sandbox']['unexpectedCapability']=True",
            "result['model']='other'",
        )
        for change in changes:
            with TemporaryDirectory() as temp, self.subTest(change=change):
                with self.assertRaises(NativeSessionError) as caught:
                    self._inspect(Path(temp), "    if method == 'thread/start': " + change + '\n')
                self.assertEqual('thread/start', caught.exception.failure.failure_stage)
                self.assertNotIn('SENTINEL', str(caught.exception))

    def test_missing_or_enabled_config_and_unclassified_warning_are_rejected(self):
        changes = (
            "result['config']['mcp_servers']['docs']['enabled']=True",
            "result['config']['mcp_servers']['other']={'enabled':False}",
            "result['config']['features']['plugins']=True",
            "result.pop('layers')",
            "result.pop('origins')",
            "result['layers']=[]",
            "result['origins']={}",
            "result['origins']['features']={'name':{'type':'user','file':'/SENTINEL/config.toml'},'version':'v1'}",
        )
        for change in changes:
            with TemporaryDirectory() as temp, self.subTest(change=change), self.assertRaises(NativeSessionError):
                self._inspect(Path(temp), "    if method == 'config/read': " + change + '\n')
        with TemporaryDirectory() as temp, self.assertRaises(NativeSessionError):
            self._inspect(Path(temp), "    print(json.dumps({'method':'configWarning','params':{'summary':'SENTINEL unknown'}}),flush=True)\n")

    def test_managed_requirements_and_disallowed_profile_fail_closed(self):
        for mutation in (
            "    if method == 'configRequirements/read': result['requirements']={}\n",
            "    if method == 'permissionProfile/list': result['data'][0]['allowed']=False\n",
            "    if method == 'permissionProfile/list': result['nextCursor']='SENTINEL'\n",
        ):
            with TemporaryDirectory() as temp, self.subTest(mutation=mutation), self.assertRaises(NativeSessionError):
                self._inspect(Path(temp), mutation)

    def test_active_missing_or_malformed_mcp_status_is_rejected(self):
        for change in (
            "result['data'][0]['runtimeStatus']='connected'",
            "result['data'][0].pop('runtimeStatus')",
            "result['data'][0]['authStatus']='oAuth'",
            "result['data'][0]['tools']={'unsafe':{}}",
            "result['data'][0]['resources']=[{}]",
            "result['data'][0]['resourceTemplates']=None",
            "result['data'][0]['toolsError']='SENTINEL'",
            "result['data'][0]['name']='other'",
            "result['nextCursor']='SENTINEL'",
        ):
            with TemporaryDirectory() as temp, self.subTest(change=change), self.assertRaises(NativeSessionError):
                self._inspect(Path(temp), "    if method == 'mcpServerStatus/list': " + change + '\n')

    def test_unknown_server_requests_and_late_mcp_events_are_rejected(self):
        notifications = (
            {'id':99,'method':'account/chatgptAuthTokens/refresh','params':{}},
            {'method':'mcpServer/startupStatus/updated','params':{}},
            {'method':'thread/started','params':{'thread':{'id':'22222222-2222-4222-8222-222222222222'}}},
        )
        for message in notifications:
            with TemporaryDirectory() as temp, self.subTest(message=message), self.assertRaises(NativeSessionError):
                self._inspect(Path(temp), "    if method == 'mcpServerStatus/list': print(" + repr(json.dumps(message)) + ",flush=True)\n")

    def test_bad_auth_notification_and_spawn_failure_preserve_safe_error_metadata(self):
        with TemporaryDirectory() as temp, self.assertRaises(NativeSessionError):
            self._inspect(Path(temp), "    print(json.dumps({'method':'account/updated','params':{'authMode':'SENTINEL','planType':None}}),flush=True)\n")
        with TemporaryDirectory() as temp, patch('evals.native_session.subprocess.Popen', side_effect=PermissionError(13, 'SENTINEL')):
            with self.assertRaises(NativeSessionError) as caught:
                inspect_native_session(Path(temp), binary=self._binary(), model='gpt-6.1-sol')
            self.assertEqual('spawn', caught.exception.failure.failure_stage)
            self.assertEqual(13, caught.exception.failure.original_errno)
            self.assertNotIn('SENTINEL', str(caught.exception))

    def test_instruction_source_is_hashed_without_logging_content_or_path(self):
        with TemporaryDirectory() as temp, TemporaryDirectory() as external:
            path = Path(external).resolve() / 'AGENTS.md'
            path.write_text('SENTINEL common host instructions')
            mutation = "    if method == 'thread/start': result['instructionSources']=[" + repr(str(path)) + "]\n"
            result = self._inspect(Path(temp), mutation)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), result.session.instruction_sources[0][1])
            self.assertNotIn(str(path), json.dumps(asdict(result)))
            self.assertNotIn('SENTINEL', json.dumps(asdict(result)))

    def test_timeout_and_output_limit_have_typed_failure_and_cleanup(self):
        for mutation, options, reason in (
            ("    if method == 'thread/start': __import__('time').sleep(2)\n", {'timeout_seconds':0.2}, 'timeout'),
            ("    print('x'*8192, file=sys.stderr, flush=True)\n", {'max_output_bytes':4096}, 'output_limit'),
        ):
            with TemporaryDirectory() as temp, self.subTest(reason=reason):
                root = Path(temp)
                with patch('evals.native_session.build_session_command', return_value=self._server(root, mutation)):
                    with self.assertRaises(NativeSessionError) as caught:
                        inspect_native_session(root, binary=self._binary(), model='gpt-6.1-sol', disabled_servers=('docs',), **options)
                self.assertEqual(reason, caught.exception.failure.reason)
                self.assertIsNotNone(caught.exception.failure.returncode)
