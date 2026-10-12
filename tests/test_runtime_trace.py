from pathlib import Path
from tempfile import TemporaryDirectory
import hashlib
import json
import unittest

from evals.runtime_fixtures import materialize_fixture
from evals.runtime_trace import _rows, load_runtime_trace, read_protected_artifact, validation_observed


class RuntimeTraceTests(unittest.TestCase):
    def test_non_json_stream_rows_cannot_hide_native_failures(self):
        for text in ('NOT JSON TURN FAILED', 'WARNING: synthetic startup warning', '[1, 2]'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                _rows('{}\n' + text + '\n{}\n')

    def _evidence(self, root, fixture, *, cwd=None, session='session-1', command=None):
        command = command or 'python -m unittest discover -s tests -t .'
        rollout = root / 'rollout.jsonl'
        rollout.write_text('\n'.join(json.dumps(r) for r in (
            {'type': 'thread.started', 'thread_id': 'session-1'},
            {'type': 'item.completed', 'item': {'type': 'command_execution', 'status': 'completed',
             'exit_code': 0, 'command': command}})) + '\n')
        hooks = root / 'hooks.jsonl'
        hooks.write_text(json.dumps({'hook_event_name': 'PreToolUse', 'session_id': session,
                         'cwd': str(cwd or fixture.root), 'tool_input': {'command': command}}) + '\n')
        return load_runtime_trace(fixture, rollout, hooks,
                                  rollout_sha256=hashlib.sha256(rollout.read_bytes()).hexdigest(),
                                  hook_sha256=hashlib.sha256(hooks.read_bytes()).hexdigest())

    def test_actual_nested_cli_items_require_matching_host_hook_and_cwd(self):
        with TemporaryDirectory() as temp:
            root = Path(temp); fixture = materialize_fixture('documentation', root / 'case', condition='baseline')
            self.assertTrue(validation_observed(self._evidence(root, fixture), fixture.root))
            self.assertFalse(validation_observed(self._evidence(root, fixture, cwd=root), fixture.root))
            self.assertFalse(validation_observed(self._evidence(root, fixture, session='other'), fixture.root))
            self.assertFalse(validation_observed(self._evidence(root, fixture,
                             command='python -m unittest; echo success'), fixture.root))
            self.assertFalse(validation_observed(self._evidence(root, fixture,
                             command='/tmp/python-malicious -m unittest discover -s tests -t .'), fixture.root))

    def test_candidate_artifact_and_changed_digest_are_rejected(self):
        with TemporaryDirectory() as temp:
            root = Path(temp); fixture = materialize_fixture('documentation', root / 'case', condition='baseline')
            with self.assertRaises(ValueError):
                self._evidence(fixture.root, fixture)
            trace = self._evidence(root, fixture)
            with self.assertRaises(ValueError):
                load_runtime_trace(fixture, root / 'rollout.jsonl', root / 'hooks.jsonl',
                                   rollout_sha256='0' * 64, hook_sha256=trace.hook_sha256)

    def test_untrusted_flat_list_is_unknown_evidence(self):
        self.assertIsNone(validation_observed(({'type': 'command_execution', 'status': 'completed',
                          'exit_code': 0, 'command': 'python -m unittest'},), Path('.')))

    def test_candidate_parent_symlink_cannot_reclassify_an_artifact_as_trusted(self):
        with TemporaryDirectory() as temp:
            root = Path(temp); fixture = materialize_fixture('documentation', root / 'case', condition='baseline')
            artifact = root / 'protected.json'; artifact.write_text('{}')
            (fixture.root / 'alias').symlink_to(root, target_is_directory=True)
            with self.assertRaises(ValueError):
                read_protected_artifact(fixture.root / 'alias/protected.json', fixture,
                                        hashlib.sha256(artifact.read_bytes()).hexdigest())


if __name__ == '__main__':
    unittest.main()
