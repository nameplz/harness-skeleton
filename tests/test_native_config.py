from pathlib import Path
from tempfile import TemporaryDirectory
import json
import hashlib
import sys
import unittest
from unittest.mock import patch

from evals.native_config import BinaryPin, ConfigInspectionError, build_config_command, inspect_native_config, project_config, project_warning


class NativeConfigTests(unittest.TestCase):
    def _binary(self):
        path = Path(sys.executable).resolve()
        with path.open('rb') as stream:
            return BinaryPin(path, hashlib.file_digest(stream, 'sha256').hexdigest())

    def test_binary_mismatch_prevents_process_start(self):
        with TemporaryDirectory() as temp, patch('evals.native_config.subprocess.Popen') as spawn:
            with self.assertRaises(ValueError):
                inspect_native_config(Path(temp), binary=BinaryPin(Path(sys.executable).resolve(), '0' * 64))
            spawn.assert_not_called()

    def test_spawn_failures_preserve_safe_metadata(self):
        for error in (PermissionError(13, 'SENTINEL'), FileNotFoundError(2, 'SENTINEL')):
            with TemporaryDirectory() as temp, self.subTest(error=type(error).__name__), \
                    patch('evals.native_config.subprocess.Popen', side_effect=error), \
                    patch('evals.native_config._terminate_process_group') as cleanup:
                with self.assertRaises(ConfigInspectionError) as caught:
                    inspect_native_config(Path(temp), binary=self._binary())
                failure = caught.exception.failure
                self.assertEqual('spawn', failure.failure_stage)
                self.assertEqual('spawn_error', failure.reason)
                self.assertEqual(type(error).__name__, failure.original_error_type)
                self.assertEqual(error.errno, failure.original_errno)
                self.assertIsNone(failure.returncode)
                self.assertIsNone(failure.cleanup_error_type)
                self.assertNotIn('SENTINEL', str(caught.exception))
                cleanup.assert_not_called()

    def test_disable_overrides_are_explicit_and_reject_unsafe_names(self):
        with TemporaryDirectory() as temp:
            command = build_config_command(Path(temp), binary=self._binary(), disabled_servers=('docs', 'known-server'))
            self.assertEqual(str(Path(sys.executable).resolve()), command[0])
            self.assertIn('mcp_servers.docs.enabled=false', command)
            self.assertIn('mcp_servers.known-server.enabled=false', command)
            self.assertIn('projects={' + json.dumps(str(Path(temp).resolve())) + '={trust_level="untrusted"}}', command)
            for names in (('docs', 'docs'), ('unsafe.name',), ('',), 'docs'):
                with self.subTest(names=names), self.assertRaises(ValueError):
                    build_config_command(Path(temp), binary=self._binary(), disabled_servers=names)

    def test_projection_keeps_only_names_and_booleans(self):
        reply = {'config': {'mcp_servers': {'docs': {
            'enabled': False, 'url': 'https://secret.invalid/token', 'env': {'TOKEN': 'SENTINEL'}}},
            'features': {'apps': False, 'plugins': False}, 'developer_instructions': 'SENTINEL'},
            'origins': {'mcp_servers': {'name': {'type': 'user', 'file': '/SENTINEL/config.toml'}, 'version': 'v1'}}}
        projected = project_config(reply)
        self.assertEqual((('docs', False),), projected.servers)
        self.assertNotIn('SENTINEL', repr(projected))
        self.assertNotIn('secret.invalid', repr(projected))
        self.assertTrue(projected.catalog_reported)
        self.assertFalse(project_config({'config': {}, 'origins': {}}).catalog_reported)

    def test_invalid_configuration_is_rejected_without_echoing_values(self):
        for config in ({'mcp_servers': []}, {'mcp_servers': {'docs': {'enabled': 'SENTINEL'}}},
                       {'mcp_servers': {'SENTINEL.invalid': {}}}, {'features': {'apps': 1}}):
            with self.subTest(config=config), self.assertRaises(ValueError) as caught:
                project_config({'config': config, 'origins': {}})
            self.assertNotIn('SENTINEL', str(caught.exception))

    def test_layer_and_setting_origins_are_sanitized_and_ordered(self):
        user = {'name': {'type': 'user', 'file': '/SENTINEL/config.toml'}, 'version': 'SENTINEL'}
        session = {'name': {'type': 'sessionFlags'}, 'version': 'v2'}
        reply = {'config': {'mcp_servers': {'docs': {'enabled': False}}, 'features': {'apps': False}},
                 'origins': {'features.apps': session, 'mcp_servers': user, 'unrelated': user},
                 'layers': [{**user, 'config': {'secret': 'SENTINEL'}},
                            {**session, 'config': {'features': {'apps': False}}}]}
        result = project_config(reply)
        self.assertEqual(('user', 'sessionFlags'), tuple(layer.source.source_type for layer in result.layers))
        origins = dict(result.origins)
        self.assertEqual('sessionFlags', origins['features.apps'].source_type)
        self.assertEqual('user', origins['mcp_servers.docs.enabled'].source_type)
        self.assertNotIn('unrelated', origins)
        self.assertNotIn('SENTINEL', repr(result))
        self.assertIsNone(project_config({'config': {}}).layers)

    def test_malformed_layers_and_origins_fail_closed(self):
        metadata = {'name': {'type': 'sessionFlags'}, 'version': 'v1'}
        for extra in ({'layers': {}}, {'layers': [{**metadata, 'config': { }, 'disabledReason': 1}]},
                      {'layers': [{'name': {'type': 'unknown'}, 'version': 'v1', 'config': {}}]},
                      {'origins': []}, {'origins': {'features.apps': {'name': [], 'version': 'v1'}}}):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                project_config({'config': {'features': {'apps': False}}, **extra})

    def test_warnings_are_classified_without_exposing_payloads(self):
        warnings = (
            ('Invalid configuration; using defaults.', 'invalid_configuration'),
            ('Error parsing rules; custom rules not applied.', 'rules_not_applied'),
            ('Project-local config, hooks, and exec policies are disabled in the following folders '
             'until the project is trusted, but skills still load.\n    1. /SENTINEL/.codex\n       untrusted\n',
             'project_configuration_disabled'),
            ('SENTINEL unknown diagnostic', 'unclassified'),
        )
        for summary, category in warnings:
            with self.subTest(category=category):
                warning = project_warning({'summary': summary})
                self.assertEqual(category, warning.category)
                self.assertNotIn('SENTINEL', repr(warning))
        warning = project_warning({'summary': warnings[2][0], 'details': 'SENTINEL'})
        self.assertEqual('unclassified', warning.category)
        for payload in ({'summary': 1}, {'summary': 'text', 'details': []},
                        {'summary': 'text', 'range': {'start': {'line': True, 'column': 0}, 'end': {'line': 1, 'column': 1}}}):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                project_warning(payload)

    def test_pinned_native_features_are_explicitly_disabled_in_command(self):
        root=Path.cwd()
        command=build_config_command(root,binary=self._binary())
        for name in ('goals','remote_control','network_proxy','auth_elicitation','js_repl','tool_suggest','memories'):
            self.assertIn('features.'+name+'=false',command)
        projected=project_config({'config':{'features':{'goals':False,'remote_control':False,'network_proxy':False}}})
        self.assertFalse(dict(projected.features)['goals'])

    def test_unknown_feature_keys_fail_closed(self):
        for enabled in (True, False):
            with self.subTest(enabled=enabled), self.assertRaises(ValueError):
                project_config({'config': {'features': {'future_remote_exec': enabled}}})

    def test_active_or_malformed_remote_control_fails_closed(self):
        for params in ({'status': 'connected', 'installationId': 'id', 'serverName': 'name'},
                       {'status': 'connecting', 'installationId': 'id', 'serverName': 'name'},
                       {'status': 'errored', 'installationId': 'id', 'serverName': 'name'},
                       {'status': 'disabled'}, {'secret': 'SENTINEL'}):
            with TemporaryDirectory() as temp, self.subTest(params=params):
                root=Path(temp)
                argv=self._server(root,"    print(json.dumps({'method':'remoteControl/status/changed','params':"+repr(params)+"}),flush=True)\n")
                with patch('evals.native_config.build_config_command',return_value=argv),self.assertRaises(ValueError):
                    inspect_native_config(root,binary=self._binary())

    def _server(self, root, behavior):
        script = root / 'server.py'
        script.write_text('''import json, sys, time
for line in sys.stdin:
    request = json.loads(line)
    if 'id' not in request: continue
    if request['method'] == 'initialize':
        result = {'userAgent': 'codex/0.162.1'}
    elif request['method'] == 'config/read':
        result = {'config': {'mcp_servers': {}, 'features': {'apps': False, 'plugins': False}, 'secret': 'SENTINEL'}, 'origins': {}}
    elif request['method'] == 'configRequirements/read':
        result = {'requirements': None}
    else: raise RuntimeError('unexpected method')
''' + behavior + '''
    print(json.dumps({'id': request['id'], 'result': result}), flush=True)
''')
        return (sys.executable, '-I', '-B', str(script))

    def test_model_free_exchange_returns_sanitized_receipt(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            argv = self._server(root, "    print('SENTINEL', file=sys.stderr, flush=True)\n")
            with patch('evals.native_config.build_config_command', return_value=argv):
                result = inspect_native_config(root, binary=self._binary(), disabled_servers=('docs',))
            self.assertEqual((), result.config.servers)
            self.assertFalse(result.requirements_present)
            self.assertEqual(0, result.returncode)
            self.assertNotIn('SENTINEL', repr(result))
            self.assertGreater(result.stderr_bytes, 0)
            self.assertEqual(self._binary().sha256, result.binary_sha256)
            self.assertEqual(('docs',), result.requested_disabled_servers)

    def test_known_notification_is_projected_without_its_payload(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            argv = self._server(root, "    print(json.dumps({'method': 'remoteControl/status/changed', 'params': {'status':'disabled','installationId':'SENTINEL','serverName':'SENTINEL'}}), flush=True)\n")
            with patch('evals.native_config.build_config_command', return_value=argv):
                result = inspect_native_config(root, binary=self._binary())
            self.assertEqual(('remoteControl/status/changed',), result.notification_methods)
            self.assertNotIn('SENTINEL', repr(result))

    def test_config_warning_is_collected_during_exchange_and_shutdown(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            behavior = "    print(json.dumps({'method': 'configWarning', 'params': {'summary': 'SENTINEL unknown warning'}}), flush=True)\n"
            argv = self._server(root, behavior)
            script = root / 'server.py'
            script.write_text(script.read_text() + "print(json.dumps({'method': 'configWarning', 'params': {'summary': 'late SENTINEL'}}), flush=True)\n")
            with patch('evals.native_config.build_config_command', return_value=argv):
                result = inspect_native_config(root, binary=self._binary())
            self.assertEqual(4, len(result.warnings))
            self.assertTrue(all(warning.category == 'unclassified' for warning in result.warnings))
            self.assertIn('configWarning', result.notification_methods)
            self.assertNotIn('SENTINEL', repr(result))

    def test_binary_recheck_failure_rejects_completed_exchange(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            argv = self._server(root, '')
            with patch('evals.native_config.build_config_command', return_value=argv), \
                    patch('evals.native_config.verify_binary', side_effect=[None, ValueError('SENTINEL')]) as verify:
                with self.assertRaises(ConfigInspectionError) as caught:
                    inspect_native_config(root, binary=self._binary())
            self.assertEqual(2, verify.call_count)
            self.assertEqual('binary recheck', caught.exception.failure.failure_stage)
            self.assertNotIn('SENTINEL', str(caught.exception))

    def test_timeout_limit_invalid_reply_and_server_requests_fail_closed(self):
        behaviors = (
            ('    time.sleep(2)\n', {'timeout_seconds': 0.1}),
            ("    print('x' * 10000, flush=True)\n", {'max_output_bytes': 1000}),
            ("    print('SENTINEL not JSON', flush=True)\n", {}),
            ("    print(json.dumps({'id': 99, 'method': 'item/commandExecution/requestApproval', 'params': {'status':'disabled','installationId':'SENTINEL','serverName':'SENTINEL'}}), flush=True)\n", {}),
            ("    print(json.dumps({'method': 'mcpServer/startupStatus/updated', 'params': {'status':'disabled','installationId':'SENTINEL','serverName':'SENTINEL'}}), flush=True)\n", {}),
            ("    print(json.dumps({'id': request['id'], 'error': {'message': 'SENTINEL'}}), flush=True)\n", {}),
            ("    if request['method'] == 'configRequirements/read': result = {'requirements': {'featureRequirements': []}}\n", {}),
            ("    print(json.dumps({'method': 'unrecognized/notify', 'params': {'status':'disabled','installationId':'SENTINEL','serverName':'SENTINEL'}}), flush=True)\n", {}),
        )
        with TemporaryDirectory() as temp:
            root = Path(temp)
            for behavior, limits in behaviors:
                argv = self._server(root, behavior)
                with self.subTest(behavior=behavior), patch('evals.native_config.build_config_command', return_value=argv):
                    with self.assertRaises(ValueError) as caught:
                        inspect_native_config(root, binary=self._binary(), **limits)
                    self.assertNotIn('SENTINEL', str(caught.exception))

    def test_cleanup_failure_preserves_primary_failure_and_closes_streams(self):
        from scripts.command_runner import _terminate_process_group
        stopped = []
        def failed_cleanup(process):
            _terminate_process_group(process)
            stopped.append(process)
            raise cleanup_error
        with TemporaryDirectory() as temp:
            root = Path(temp)
            argv = self._server(root, "    print('invalid JSON', flush=True)\n")
            for cleanup_error in (PermissionError(1, 'SENTINEL'), RuntimeError('SENTINEL')):
                with self.subTest(error=type(cleanup_error).__name__), \
                        patch('evals.native_config.build_config_command', return_value=argv), \
                        patch('evals.native_config._terminate_process_group', side_effect=failed_cleanup):
                    with self.assertRaises(ValueError) as caught:
                        inspect_native_config(root, binary=self._binary())
                self.assertEqual('ValueError', caught.exception.failure.original_error_type)
                self.assertEqual(type(cleanup_error).__name__, caught.exception.failure.cleanup_error_type)
                self.assertEqual(getattr(cleanup_error, 'errno', None), caught.exception.failure.cleanup_errno)
                self.assertNotIn('SENTINEL', str(caught.exception))
                self.assertTrue(all(stream.closed for stream in (stopped[-1].stdin, stopped[-1].stdout, stopped[-1].stderr)))


if __name__ == '__main__':
    unittest.main()
