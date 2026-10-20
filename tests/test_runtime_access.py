from dataclasses import replace
from contextlib import nullcontext, contextmanager
import os
import stat
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from evals.runtime_access import (
    DIRECT_PROFILE, SUPERVISED_PROFILE, actor_permissions, require_profile,
    require_private_parent, require_private_file, handoff_workspace, write_host_file,
    _root_chain, require_workspace, require_snapshot,
    preflight_workspace,
    actor_slot,
    snapshot_file_mode,
)
from evals.runtime_fixtures import materialize_fixture
from evals.runtime_invocation import issue_invocation, verify_invocation, write_frozen_source
from evals.runtime_review import final_manifest, freeze_for_review, read_candidate_file
from scripts.eval_case_validation import metadata_observation


class RuntimeAccessTests(unittest.TestCase):
    def test_profile_is_explicit_and_linux_root_is_required_before_creation(self):
        self.assertFalse(require_profile(DIRECT_PROFILE))
        for value in (None, True, 'unknown', ['direct']):
            with self.subTest(profile=value), self.assertRaises(ValueError):
                require_profile(value)
        with TemporaryDirectory() as temp, patch('evals.runtime_access._require_root_linux',
                side_effect=ValueError('requires root')):
            root = Path(temp).resolve() / 'candidate'
            with self.assertRaises(ValueError):
                materialize_fixture('documentation', root, condition='baseline',
                                    execution_profile=SUPERVISED_PROFILE)
            self.assertEqual([], list(root.parent.iterdir()))

    def test_direct_default_and_profile_identity_cannot_be_replayed(self):
        with TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            fixture = materialize_fixture('documentation', root / 'candidate', condition='baseline')
            self.assertEqual(DIRECT_PROFILE, fixture.execution_profile)
            source = write_frozen_source(fixture, root / 'source.json')
            invocation = issue_invocation(fixture, root / 'launch', source, model='test-model')
            self.assertEqual(DIRECT_PROFILE, invocation.identity['execution_profile'])
            self.assertEqual(DIRECT_PROFILE, final_manifest(fixture)['execution_profile'])
            changed = replace(fixture, execution_profile=SUPERVISED_PROFILE)
            self.assertNotEqual(invocation.sha256, replace(invocation, fixture=changed).sha256)
            with patch('evals.runtime_access.require_workspace'), \
                    patch('evals.runtime_access._require_root_linux'), self.assertRaises(ValueError):
                verify_invocation(changed, replace(invocation, fixture=changed))

    def test_actor_permissions_use_owner_group_other_without_root_access(self):
        for uid, gid, mode, expected in ((0, 0, 0o700, 0), (0, 2000, 0o710, 1),
                (0, 2000, 0o440, 4), (2000, 2000, 0o750, 7), (0, 0, 0o755, 5)):
            with self.subTest(uid=uid, gid=gid, mode=mode):
                self.assertEqual(expected, actor_permissions(SimpleNamespace(
                    st_uid=uid, st_gid=gid, st_mode=mode)))

    def test_snapshot_mode_projection_preserves_direct_and_exposes_supervised_readonly(self):
        with patch('evals.runtime_access._require_root_linux'):
            for mode, direct, supervised in ((0o600,0o400,0o444), (0o700,0o500,0o555),
                    (0o640,0o440,0o444), (0o755,0o555,0o555)):
                with self.subTest(mode=mode):
                    self.assertEqual(direct,snapshot_file_mode(mode,DIRECT_PROFILE))
                    self.assertEqual(supervised,snapshot_file_mode(mode,SUPERVISED_PROFILE))
            for value in (True,-1,'600',0o4755,0o2755,0o1755):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    snapshot_file_mode(value,SUPERVISED_PROFILE)

    def test_private_files_and_parents_reject_public_modes_and_replacements(self):
        metadata = SimpleNamespace(st_uid=0, st_gid=0, st_mode=0o40700, st_nlink=2)
        with patch('evals.runtime_access._root_chain', return_value=(metadata,)):
            require_private_parent(Path('/srv/private'))
        for changes in ({'st_uid':2000}, {'st_mode':0o40710}, {'st_mode':0o40770}):
            row = SimpleNamespace(**{**vars(metadata), **changes})
            with self.subTest(changes=changes), \
                    patch('evals.runtime_access._root_chain', return_value=(row,)), \
                    self.assertRaises(ValueError):
                require_private_parent(Path('/srv/private'))
        regular = SimpleNamespace(st_uid=0, st_gid=0, st_mode=0o100600, st_nlink=1)
        for changes in ({}, {'st_uid':2000}, {'st_mode':0o100644}, {'st_nlink':2}, {'st_mode':0o120600}):
            row = SimpleNamespace(**{**vars(regular), **changes})
            with self.subTest(changes=changes), patch('evals.runtime_access.require_private_parent'), \
                    patch.object(Path, 'lstat', return_value=row):
                if changes:
                    with self.assertRaises(ValueError): require_private_file(Path('/srv/private/file'))
                else:
                    require_private_file(Path('/srv/private/file'))

    def test_handoff_rejects_linked_or_special_entries_before_any_chown(self):
        with TemporaryDirectory() as temp, patch('evals.runtime_access.require_private_parent'), \
                patch('evals.runtime_access.os.chown') as chown:
            root = Path(temp).resolve() / 'candidate'; root.mkdir()
            original = root / 'file'; original.write_text('seed')
            alias = root / 'alias'
            for kind in ('symlink', 'hardlink', 'fifo'):
                with self.subTest(kind=kind):
                    if kind == 'symlink': alias.symlink_to(original)
                    elif kind == 'hardlink': os.link(original, alias)
                    else: os.mkfifo(alias)
                    with self.assertRaises(ValueError): handoff_workspace(root)
                    alias.unlink()
            chown.assert_not_called()

    def test_metadata_only_owner_is_explicit_and_not_inferred_from_candidate(self):
        with TemporaryDirectory() as temp:
            root = Path(temp).resolve(); (root / 'data').mkdir()
            (root / 'data/oversized.txt').write_bytes(b'payload')
            expected = metadata_observation(root)
            self.assertEqual(expected, metadata_observation(root, expected_uid=os.getuid()))
            with self.assertRaises(ValueError): metadata_observation(root, expected_uid=os.getuid()+1)
            for value in (True, -1, '2000'):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    metadata_observation(root, expected_uid=value)

    def test_invalid_root_profile_identity_is_rejected_before_artifact_or_process_writes(self):
        from evals.native_collect import collect_native_turn, load_native_turn
        from evals.native_session import native_session
        from evals.runtime_grader import grade_fixture
        from evals.runtime_invocation import claim_launch, claim_native_launch
        with TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            fixture = materialize_fixture('documentation', root / 'candidate', condition='baseline')
            source = write_frozen_source(fixture, root / 'source.json')
            invocation = issue_invocation(fixture, root / 'launch', source, model='test-model')
            fixture = replace(fixture, execution_profile=SUPERVISED_PROFILE)
            invocation = replace(invocation, fixture=fixture)
            before = tuple(invocation.artifact_root.iterdir())
            def session():
                with native_session(fixture.root, binary=None, model='test-model', invocation=invocation): pass
            calls = (lambda: collect_native_turn(invocation, binary=None),
                     lambda: load_native_turn(invocation, binary=None), session,
                     lambda: grade_fixture(fixture, tool_trace=None),
                     lambda: claim_launch(invocation, ('forbidden',)),
                     lambda: claim_native_launch(invocation, ('forbidden',), binary=None, disabled_servers=()))
            with patch('evals.runtime_access._require_root_linux'), \
                    patch('evals.native_session.subprocess.Popen') as spawn:
                for call in calls:
                    with self.subTest(call=call), self.assertRaises(ValueError):
                        call()
            self.assertEqual(before, tuple(invocation.artifact_root.iterdir()))
            spawn.assert_not_called()

    def test_protected_writer_is_exclusive_and_private_even_with_umask_zero(self):
        with TemporaryDirectory() as temp, patch('evals.runtime_access._require_root_linux'), \
                patch('evals.runtime_access.require_private_parent'), \
                patch('evals.runtime_access.require_private_file'):
            path = Path(temp).resolve() / 'record'
            previous = os.umask(0)
            try:
                write_host_file(path, b'protected', SUPERVISED_PROFILE)
            finally:
                os.umask(previous)
            self.assertEqual(0o600, path.stat().st_mode & 0o777)
            with self.assertRaises(FileExistsError):
                write_host_file(path, b'replacement', SUPERVISED_PROFILE)
            self.assertEqual(b'protected', path.read_bytes())

    def test_ancestry_rejects_noncanonical_actor_owned_and_writable_directories(self):
        directory = SimpleNamespace(st_uid=0, st_gid=2000, st_mode=0o40755)
        with patch('evals.runtime_access._require_root_linux'), \
                patch.object(Path, 'resolve', lambda path, **kwargs: path):
            with patch.object(Path, 'lstat', return_value=directory):
                self.assertEqual(3, len(_root_chain(Path('/srv/private'))))
                for path in (Path('relative'), Path('/srv/../private'), Path('/srv/*'), Path('/srv/line\nbreak')):
                    with self.subTest(path=path), self.assertRaises(ValueError): _root_chain(path)
            for change in ({'st_uid':2000}, {'st_mode':0o40775}, {'st_mode':0o120755}):
                row = SimpleNamespace(**{**vars(directory), **change})
                with self.subTest(change=change), patch.object(Path, 'lstat', return_value=row), \
                        self.assertRaises(ValueError): _root_chain(Path('/srv/private'))

    def test_workspace_requires_actor_ownership_and_readonly_snapshot_requires_root(self):
        parent = SimpleNamespace(st_uid=0, st_gid=2000, st_mode=0o40710)
        actor = SimpleNamespace(st_uid=2000, st_gid=2000, st_mode=0o40755)
        with patch('evals.runtime_access._root_chain', return_value=(parent,)), \
                patch.object(Path, 'resolve', lambda path, **kwargs: path):
            with patch.object(Path, 'lstat', return_value=actor):
                require_workspace(Path('/srv/candidate'))
                with self.assertRaises(ValueError): require_workspace(Path('/srv/candidate'), writable=False)
            snapshot = SimpleNamespace(st_uid=0, st_gid=2000, st_mode=0o40555)
            with patch.object(Path, 'lstat', return_value=snapshot):
                require_workspace(Path('/srv/review'), writable=False)
                with self.assertRaises(ValueError): require_workspace(Path('/srv/review'))
            for special in (0o4000, 0o2000, 0o1000):
                row = SimpleNamespace(**{**vars(snapshot), 'st_mode':snapshot.st_mode | special})
                with self.subTest(special=special), patch.object(Path, 'lstat', return_value=row), \
                        self.assertRaises(ValueError):
                    require_workspace(Path('/srv/review'), writable=False)
            with patch.object(Path, 'lstat', return_value=SimpleNamespace(**{**vars(actor), 'st_mode':0o120755})), \
                    self.assertRaises(ValueError): require_workspace(Path('/srv/candidate'))
        with patch('evals.runtime_access._root_chain', return_value=(
                SimpleNamespace(st_uid=0, st_gid=0, st_mode=0o40700),)), self.assertRaises(ValueError):
            require_workspace(Path('/srv/candidate'))

    def test_snapshot_rejects_writable_unreadable_and_linked_entries(self):
        with TemporaryDirectory() as temp, patch('evals.runtime_access.require_workspace'):
            root = Path(temp).resolve(); path = root / 'file'; path.write_text('review')
            valid = SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFREG | 0o444)
            for change in ({}, {'st_mode':stat.S_IFREG | 0o644}, {'st_mode':stat.S_IFREG | 0o400},
                           {'st_uid':2000}, {'st_mode':stat.S_IFLNK | 0o777},
                           {'st_mode':stat.S_IFREG | 0o4555},
                           {'st_mode':stat.S_IFREG | 0o2555},
                           {'st_mode':stat.S_IFDIR | 0o1555}):
                row = SimpleNamespace(**{**vars(valid), **change})
                tree = ((root, SimpleNamespace(st_uid=0,st_gid=0,st_mode=stat.S_IFDIR|0o555)),(path,row))
                with self.subTest(change=change), patch('evals.runtime_access.bounded_tree',return_value=tree):
                    if change:
                        with self.assertRaises(ValueError): require_snapshot(root)
                    else: require_snapshot(root)

    def test_special_candidate_modes_are_rejected_before_creating_review_snapshot(self):
        with TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            fixture = materialize_fixture('documentation', root/'candidate', condition='baseline')
            candidate = fixture.root/'special'
            candidate.write_bytes(b'benign metadata-only test; never executed')
            original_lstat = Path.lstat
            for mode in (0o4755, 0o2755, 0o1755):
                def metadata(path, *args, **kwargs):
                    actual = original_lstat(path, *args, **kwargs)
                    return SimpleNamespace(**{**{key:getattr(actual,key) for key in dir(actual)
                        if key.startswith('st_')}, 'st_mode':stat.S_IFREG | mode}) if path == candidate else actual
                snapshot = root/('review-'+str(mode))
                with patch.object(Path, 'lstat', metadata):
                    for operation in (lambda:read_candidate_file(candidate),
                                      lambda:freeze_for_review(fixture, snapshot)):
                        with self.subTest(mode=oct(mode), operation=operation), \
                                self.assertRaisesRegex(ValueError, 'special'):
                            operation()
                self.assertFalse(snapshot.exists())

    def test_supervised_snapshot_stays_private_until_sealed_under_actor_lock(self):
        with TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            fixture = materialize_fixture('documentation', root/'candidate', condition='baseline')
            for name,mode in (('owner-private',0o600), ('owner-script',0o700)):
                file = fixture.root/name
                file.write_bytes(b'benign review content')
                file.chmod(mode)
            fixture = replace(fixture, execution_profile=SUPERVISED_PROFILE)
            snapshot = root/'review'
            active = []; private_reads = []; writes = []
            @contextmanager
            def guard():
                active.append(True)
                try: yield
                finally: active.pop()
            original_read = read_candidate_file
            original_open = os.open
            def read(path):
                self.assertTrue(active)
                if snapshot.exists():
                    self.assertEqual(0o700, stat.S_IMODE(snapshot.stat().st_mode))
                    private_reads.append(path)
                return original_read(path)
            def open_file(path, flags, *args, **kwargs):
                if Path(path).is_relative_to(snapshot):
                    self.assertTrue(active)
                    self.assertEqual(0o700, stat.S_IMODE(snapshot.stat().st_mode))
                    self.assertTrue(flags & os.O_EXCL and flags & os.O_NOFOLLOW)
                    writes.append(path)
                return original_open(path, flags, *args, **kwargs)
            previous = os.umask(0)
            try:
                with patch('evals.runtime_access._require_root_linux'), \
                        patch('evals.runtime_access.require_workspace'), \
                        patch('evals.runtime_review.require_readable_parent'), \
                        patch('evals.runtime_review.require_snapshot'), \
                        patch('evals.runtime_review.snapshot_owner',return_value=(os.getuid(),os.getgid())), \
                        patch('evals.runtime_scope.snapshot_owner',return_value=(os.getuid(),os.getgid())), \
                        patch('evals.runtime_review.actor_slot', return_value=guard(), create=True), \
                        patch('evals.runtime_review.read_candidate_file', side_effect=read), \
                        patch('evals.runtime_review.os.open', side_effect=open_file):
                    manifest = freeze_for_review(fixture, snapshot)
                self.assertTrue(private_reads)
                self.assertEqual(len(manifest['files']), len(writes))
                self.assertEqual(0o555, stat.S_IMODE(snapshot.stat().st_mode))
                for entry in manifest['files']:
                    path = snapshot/entry['path']
                    self.assertEqual((fixture.root/entry['path']).read_bytes(),path.read_bytes())
                    expected_mode = 0o555 if entry['mode'] & 0o111 else 0o444
                    self.assertEqual(expected_mode,stat.S_IMODE(path.stat().st_mode))
                self.assertEqual(0o600, next(row['mode'] for row in manifest['files'] if row['path']=='owner-private'))
                self.assertEqual(0o700, next(row['mode'] for row in manifest['files'] if row['path']=='owner-script'))
            finally:
                os.umask(previous)
                if snapshot.exists():
                    for directory, _, _ in os.walk(snapshot): Path(directory).chmod(0o700)

    def test_preparation_requires_fresh_root_and_traversable_ancestors(self):
        traversable = SimpleNamespace(st_uid=0, st_gid=0, st_mode=0o40755)
        private = SimpleNamespace(st_uid=0, st_gid=0, st_mode=0o40700)
        with TemporaryDirectory() as temp, patch('evals.runtime_access.require_private_parent'):
            root = Path(temp).resolve() / 'candidate'
            with patch('evals.runtime_access._root_chain', return_value=(private,traversable)):
                preflight_workspace(root)
                root.mkdir()
                with self.assertRaises(ValueError): preflight_workspace(root)
                root.rmdir()
                with self.assertRaises(ValueError): preflight_workspace(root.parent / '*')
            with patch('evals.runtime_access._root_chain', return_value=(private,private)), \
                    self.assertRaisesRegex(ValueError, 'traverse'):
                preflight_workspace(root)

    def test_oversized_or_overfull_seed_is_rejected_before_ownership_changes(self):
        with TemporaryDirectory() as temp, patch('evals.runtime_access.require_private_parent'), \
                patch('evals.runtime_access.os.chown') as chown:
            root = Path(temp).resolve() / 'candidate'; root.mkdir()
            (root / 'one').write_bytes(b'ab'); (root / 'two').write_bytes(b'cd')
            for name,limit in (('MAX_ENTRIES',2), ('MAX_TREE_BYTES',1)):
                with self.subTest(bound=name), patch('evals.runtime_access.'+name, limit), \
                        self.assertRaisesRegex(ValueError, 'bounds'):
                    handoff_workspace(root)
            chown.assert_not_called()

    def test_actor_slot_checks_uid_before_after_and_preserves_cleanup_failures(self):
        with patch('evals.runtime_access._require_root_linux'), \
                patch('evals.native_supervisor._lock', side_effect=lambda:nullcontext()) as lock:
            with patch('evals.native_supervisor._idle_actor_uid') as idle:
                with actor_slot(): pass
                self.assertEqual(2,idle.call_count)
            with patch('evals.native_supervisor._idle_actor_uid',side_effect=[None,ValueError('residual')]):
                with self.assertRaises(BaseExceptionGroup) as raised:
                    with actor_slot(): raise KeyboardInterrupt()
                self.assertIsInstance(raised.exception.exceptions[0],KeyboardInterrupt)
                self.assertIsInstance(raised.exception.exceptions[1],ValueError)
            with patch('evals.native_supervisor._idle_actor_uid',side_effect=ValueError('busy')), \
                    self.assertRaisesRegex(ValueError,'busy'):
                with actor_slot(): self.fail('busy actor was admitted')
            self.assertEqual(3,lock.call_count)
