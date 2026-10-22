import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from evals.runtime_fixtures import materialize_fixture
from evals.native_runtime import build_exec_command, worker_prompt
from evals.runtime_invocation import bind_session, claim_launch, consume_invocation, issue_invocation, load_frozen_source, write_frozen_source


class InvocationTests(unittest.TestCase):
    def test_source_hashes_ignore_nested_task_notes_but_keep_harness_files(self):
        from evals.runtime_invocation import source_file_hashes
        with TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            for relative in ('.harness/config.toml', '.harness/task-template.md',
                             '.harness/tasks/issue-1-evaluation.md'):
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(relative)
            with patch('evals.runtime_invocation.PROJECT_ROOT', root):
                hashes = source_file_hashes()
            self.assertEqual({'.harness/config.toml', '.harness/task-template.md'}, set(hashes))

    def test_source_hashes_reject_a_directory_at_a_matched_source_path(self):
        from evals.runtime_invocation import source_file_hashes
        for relative in ('evals/broken.py', '.harness/config.toml'):
            with self.subTest(relative=relative), TemporaryDirectory() as temp:
                root = Path(temp).resolve()
                (root / relative).mkdir(parents=True)
                with patch('evals.runtime_invocation.PROJECT_ROOT', root), self.assertRaises(ValueError):
                    source_file_hashes()

    def test_bpf_c_source_changes_are_part_of_frozen_identity(self):
        from evals.runtime_invocation import source_file_hashes
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve();path=root/'evals/bpf/lifecycle.bpf.c'
            path.parent.mkdir(parents=True);path.write_text('trusted source')
            with patch('evals.runtime_invocation.PROJECT_ROOT',root):
                before=source_file_hashes()
                self.assertIn('evals/bpf/lifecycle.bpf.c',before)
                path.write_text('changed source')
                self.assertNotEqual(before,source_file_hashes())

    def test_frozen_source_digest_and_file_changes_fail_before_issue(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            fixture = materialize_fixture('documentation', root / 'candidate', condition='baseline')
            source = write_frozen_source(fixture, root / 'source.json')
            self.assertEqual(source, load_frozen_source(fixture, source.path, source.manifest_sha256))
            with self.assertRaises(ValueError):
                load_frozen_source(fixture, source.path, '0' * 64)
            with patch('evals.runtime_invocation.source_file_hashes', return_value={'unexpected.py': '0' * 64}):
                with self.assertRaises(ValueError):
                    issue_invocation(fixture, root / 'launch', source, model='test-model')
            self.assertFalse((root / 'launch').exists())

    def test_fresh_nonce_unique_directory_session_and_single_consumption(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            fixture = materialize_fixture('documentation', root / 'candidate', condition='baseline')
            source = write_frozen_source(fixture, root / 'source.json')
            first = issue_invocation(fixture, root / 'first', source, model='test-model')
            second = issue_invocation(fixture, root / 'second', source, model='test-model')
            self.assertNotEqual(first.nonce, second.nonce)
            self.assertNotEqual(first.sha256, second.sha256)
            with self.assertRaises(ValueError):
                issue_invocation(fixture, root / 'first', source, model='test-model')
            with self.assertRaises(ValueError):
                issue_invocation(fixture, fixture.root / 'owned', source, model='test-model')
            with self.assertRaises(ValueError):
                bind_session(first, 'malformed-session')
            first = claim_launch(first, (*build_exec_command(fixture.root, model='test-model', writable=True,
                                                            invocation=first), worker_prompt(first)))
            bound = bind_session(first, '00000000-0000-0000-0000-000000000001')
            self.assertEqual(first.sha256, bound.sha256)
            consume_invocation(fixture, bound)
            with self.assertRaises(ValueError):
                consume_invocation(fixture, bound)
            with self.assertRaises(ValueError):
                bind_session(bound, '00000000-0000-0000-0000-000000000002')

    def test_launch_is_claimed_once_before_session_binding(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            fixture = materialize_fixture('documentation', root / 'candidate', condition='baseline')
            source = write_frozen_source(fixture, root / 'source.json')
            invocation = issue_invocation(fixture, root / 'launch', source, model='test-model')
            with self.assertRaises(ValueError):
                bind_session(invocation, '00000000-0000-0000-0000-000000000001')
            command = (*build_exec_command(fixture.root, model='test-model', writable=True,
                                           invocation=invocation), worker_prompt(invocation))
            for bad in (('codex', 'exec', 'unbound'), (*command[:-1], 'wrong prompt')):
                with self.assertRaises(ValueError):
                    claim_launch(invocation, bad)
            claimed = claim_launch(invocation, command)
            with self.assertRaises(ValueError):
                claim_launch(invocation, command)
            (invocation.artifact_root / 'command.json').write_text('[]')
            with self.assertRaises(ValueError):
                bind_session(claimed, '00000000-0000-0000-0000-000000000001')

    def test_candidate_cannot_supply_source_manifest(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            fixture = materialize_fixture('documentation', root / 'candidate', condition='baseline')
            source = write_frozen_source(fixture, root / 'source.json')
            candidate = fixture.root / 'source.json'
            candidate.write_bytes(source.path.read_bytes())
            with self.assertRaises(ValueError):
                load_frozen_source(fixture, candidate, hashlib.sha256(candidate.read_bytes()).hexdigest())

    def test_source_manifest_rejects_missing_added_or_changed_entries(self):
        import json
        with TemporaryDirectory() as temp:
            root = Path(temp)
            fixture = materialize_fixture('documentation', root / 'candidate', condition='baseline')
            source = write_frozen_source(fixture, root / 'source.json')
            original = json.loads(source.path.read_text())
            first = next(iter(original['files_sha256']))
            variants = (
                {key: value for key, value in original['files_sha256'].items() if key != first},
                {**original['files_sha256'], 'added.py': '0' * 64},
                {**original['files_sha256'], first: '0' * 64},
            )
            for index, files in enumerate(variants):
                bad = root / f'bad-{index}.json'
                bad.write_text(json.dumps({'schema': 1, 'files_sha256': files}))
                with self.assertRaises(ValueError):
                    load_frozen_source(fixture, bad, hashlib.sha256(bad.read_bytes()).hexdigest())
            alias = root / 'alias.json'; alias.symlink_to(source.path)
            with self.assertRaises(ValueError):
                load_frozen_source(fixture, alias, source.manifest_sha256)


if __name__ == '__main__':
    unittest.main()
