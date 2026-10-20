from pathlib import Path
from dataclasses import replace
import os
import hashlib
import json
from tempfile import TemporaryDirectory
import unittest

from evals.runtime_fixtures import materialize_fixture
from evals.runtime_grader import _scope_failures
from evals.runtime_invocation import issue_invocation,write_frozen_source,verify_invocation
from evals.runtime_review import final_manifest,freeze_for_review,load_review_evidence
from evals.native_review import ReviewBindings,verify_review_snapshot
from evals.runtime_scope import metadata_failures,tree_metadata,is_git,verify_snapshot_metadata


class RuntimeScopeTests(unittest.TestCase):
    def test_allowed_file_content_permission_changes_are_separate(self):
        with TemporaryDirectory() as temp:
            fixture=materialize_fixture('documentation',Path(temp)/'candidate',condition='baseline')
            path=fixture.root/'README.md'
            path.write_text(path.read_text().replace('applicatio','application'))
            self.assertEqual([],_scope_failures(fixture))
            path.chmod(0o666)
            self.assertTrue(any('metadata' in value for value in _scope_failures(fixture)))

    def test_existing_directory_modes_and_empty_new_directory_are_in_scope(self):
        with TemporaryDirectory() as temp:
            fixture=materialize_fixture('documentation',Path(temp)/'candidate',condition='baseline')
            directory=fixture.root/'tests';mode=directory.stat().st_mode&0o777
            directory.chmod(0o777)
            self.assertTrue(any('metadata' in value for value in _scope_failures(fixture)))
            directory.chmod(mode)
            (fixture.root/'empty').mkdir(mode=0o777)
            self.assertIn('out-of-scope directory: empty',_scope_failures(fixture))

    def test_owner_only_seed_and_atomic_content_replacement_remain_supported(self):
        with TemporaryDirectory() as temp:
            previous=os.umask(0o077)
            try:
                fixture=materialize_fixture('documentation',Path(temp)/'candidate',condition='baseline')
                path=fixture.root/'README.md'
                self.assertEqual(0o600,path.stat().st_mode&0o777)
                replacement=fixture.root/'replacement'
                replacement.write_text(path.read_text().replace('applicatio','application'))
                replacement.replace(path)
                self.assertEqual([],_scope_failures(fixture))
            finally:os.umask(previous)

    def test_new_test_ancestors_are_allowed_but_unused_directories_are_not(self):
        with TemporaryDirectory() as temp:
            fixture=materialize_fixture('bug-fix',Path(temp)/'candidate',condition='baseline')
            directory=fixture.root/'tests/regressions';directory.mkdir(mode=0o700)
            (directory/'test_new.py').write_text('import unittest\n')
            self.assertEqual([],_scope_failures(fixture))
            (directory/'unused').mkdir()
            self.assertIn('out-of-scope directory: tests/regressions/unused',_scope_failures(fixture))

    def test_owner_group_type_links_and_missing_metadata_are_independent(self):
        with TemporaryDirectory() as temp:
            fixture=materialize_fixture('documentation',Path(temp)/'candidate',condition='baseline')
            original=fixture.seed_metadata
            for changes in ({'uid':original[-1].uid+1},{'gid':original[-1].gid+1},
                            {'kind':'directory'},{'links':2}):
                changed=tuple(row._replace(**changes) if row.path=='README.md' else row for row in original)
                with self.subTest(changes=changes):
                    self.assertIn('scope metadata changed: README.md',metadata_failures(fixture,[list(row) for row in changed]))
            self.assertIn('scope metadata baseline unavailable',metadata_failures(replace(fixture,seed_metadata=()),[]))

    def test_metadata_changes_invalidate_invocations_and_final_manifest(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            fixture=materialize_fixture('documentation',root/'candidate',condition='baseline')
            source=write_frozen_source(fixture,root/'source.json')
            invocation=issue_invocation(fixture,root/'launch',source,model='test-model')
            changed=replace(fixture,seed_metadata=tuple(row._replace(mode=row.mode ^ 0o040)
                if row.path=='README.md' else row for row in fixture.seed_metadata))
            altered=replace(invocation,fixture=changed)
            self.assertNotEqual(invocation.identity['seed_manifest_sha256'],altered.identity['seed_manifest_sha256'])
            with self.assertRaises(ValueError):verify_invocation(changed,altered)
            before=final_manifest(fixture)
            directory=fixture.root/'tests'
            directory.chmod((directory.stat().st_mode&0o777)^0o040)
            self.assertNotEqual(before['sha256'],final_manifest(fixture)['sha256'])

    def test_snapshot_preserves_empty_directories_and_rejects_metadata_tampering(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            fixture=materialize_fixture('documentation',root/'candidate',condition='baseline')
            (fixture.root/'empty').mkdir()
            fixture=replace(fixture,seed_metadata=tuple(row for row in tree_metadata(fixture.root) if not is_git(row.path)))
            snapshot=root/'snapshot'
            try:
                manifest=freeze_for_review(fixture,snapshot)
                self.assertTrue((snapshot/'empty').is_dir())
                verify_snapshot_metadata(fixture,snapshot,manifest)
                (snapshot/'empty').chmod(0o545)
                with self.assertRaisesRegex(ValueError,'metadata'):
                    verify_snapshot_metadata(fixture,snapshot,manifest)
            finally:
                if snapshot.exists():
                    for directory,_,_ in os.walk(snapshot):Path(directory).chmod(0o700)

    def test_both_review_paths_reject_directory_metadata_without_consumption(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            fixture=materialize_fixture('documentation',root/'candidate',condition='baseline')
            snapshot=root/'snapshot'
            try:
                manifest=freeze_for_review(fixture,snapshot)
                source=write_frozen_source(fixture,root/'source.json')
                bindings=ReviewBindings(manifest['sha256'],'1'*64,'2'*64,source.source_sha256)
                invocation=issue_invocation(fixture,root/'review',source,model='test-model',kind='correctness',
                    execution_root=snapshot,final_manifest_sha256=manifest['sha256'])
                verify_review_snapshot(invocation,bindings)
                envelope={'schema':1,'manifest':manifest,'snapshot_root':str(snapshot),
                    'config_sha256':'1'*64,'suite_sha256':'2'*64,'source_sha256':source.source_sha256,'reviews':[]}
                raw=json.dumps(envelope).encode();artifact=root/'review.json';artifact.write_bytes(raw)
                (snapshot/'tests').chmod(0o545)
                with self.assertRaisesRegex(ValueError,'metadata'):
                    verify_review_snapshot(invocation,bindings)
                with self.assertRaisesRegex(ValueError,'metadata'):
                    load_review_evidence(fixture,artifact,hashlib.sha256(raw).hexdigest(),expected_invocations=(invocation,))
                self.assertFalse((invocation.artifact_root/'consumed.json').exists())
            finally:
                if snapshot.exists():
                    for directory,_,_ in os.walk(snapshot):Path(directory).chmod(0o700)

    def test_protected_git_empty_directory_and_mode_changes_are_rejected(self):
        with TemporaryDirectory() as temp:
            fixture=materialize_fixture('dirty-workspace',Path(temp)/'candidate',condition='baseline')
            self.assertEqual([],_scope_failures(fixture))
            (fixture.root/'.git/unrequested').mkdir()
            self.assertIn('candidate Git control entry metadata changed',_scope_failures(fixture))
            (fixture.root/'.git/unrequested').rmdir()
            path=fixture.root/'.git/config';path.chmod((path.stat().st_mode&0o777)^0o040)
            self.assertIn('candidate Git control entry metadata changed',_scope_failures(fixture))
