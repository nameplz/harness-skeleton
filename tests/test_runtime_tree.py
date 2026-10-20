from contextlib import contextmanager
import os
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

from evals import runtime_review
from evals.runtime_access import bounded_tree
from evals.runtime_access import SUPERVISED_PROFILE
from evals.runtime_fixtures import materialize_fixture
from evals.runtime_trace import open_no_symlink


class RuntimeTreeTests(unittest.TestCase):
    def test_empty_directories_depth_paths_and_bytes_are_bounded(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            (root/'empty').mkdir(); (root/'empty/deep').mkdir()
            (root/'data').write_bytes(b'1234')
            self.assertEqual(4,len(bounded_tree(root)))
            for name,limit in (('MAX_ENTRIES',3), ('MAX_TREE_DEPTH',1),
                               ('MAX_PATH_BYTES',2), ('MAX_TREE_BYTES',3)):
                with self.subTest(bound=name), patch('evals.runtime_access.'+name,limit), \
                        self.assertRaisesRegex(ValueError,'bounds'):
                    bounded_tree(root)

    def test_manifest_bounds_empty_directories_and_rejects_directory_symlinks(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            for n in range(4): (root/str(n)).mkdir()
            with patch('evals.runtime_access.MAX_ENTRIES',4), self.assertRaisesRegex(ValueError,'bounds'):
                runtime_review._scan(root)
            (root/'link').symlink_to(root/'0',target_is_directory=True)
            with self.assertRaises(ValueError): bounded_tree(root)

    def test_fifo_replacement_is_rejected_before_any_content_read(self):
        with TemporaryDirectory() as temp:
            path=Path(temp).resolve()/'file'; path.write_bytes(b'regular')
            fdopen=os.fdopen; reads=[]
            def replace_file(selected):
                selected.unlink();os.mkfifo(selected)
                return os.open(selected,os.O_RDONLY|os.O_NONBLOCK)
            @contextmanager
            def tracking(fd,*args,**kwargs):
                with fdopen(fd,*args,**kwargs) as stream:
                    proxy=Mock(wraps=stream);reads.append(proxy.read)
                    yield proxy
            with patch('evals.runtime_review.open_no_symlink',side_effect=replace_file), \
                    patch('evals.runtime_review.os.fdopen',side_effect=tracking), self.assertRaises(ValueError):
                runtime_review.read_candidate_file(path)
            self.assertTrue(reads)
            reads[0].assert_not_called()

    def test_hardlink_added_between_stat_and_open_is_rejected(self):
        with TemporaryDirectory() as temp:
            path=Path(temp).resolve()/'file';path.write_bytes(b'regular')
            def add_link(selected):
                os.link(selected,selected.with_name('alias'))
                return open_no_symlink(selected)
            with patch('evals.runtime_review.open_no_symlink',side_effect=add_link), \
                    self.assertRaises(ValueError):
                runtime_review.read_candidate_file(path)

    def test_artifact_final_open_is_nonblocking(self):
        with TemporaryDirectory() as temp:
            path=Path(temp).resolve()/'file';path.write_bytes(b'content')
            original=os.open;flags=[]
            def record(selected,value,*args,**kwargs):
                if selected==path.name: flags.append(value)
                return original(selected,value,*args,**kwargs)
            with patch('evals.runtime_trace.os.open',side_effect=record):
                os.close(open_no_symlink(path))
            self.assertEqual(1,len(flags));self.assertTrue(flags[0]&os.O_NONBLOCK)

    def test_supervised_public_candidate_scans_reject_busy_actor_before_traversal(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve()
            fixture=replace(materialize_fixture('documentation',root/'candidate',condition='baseline'),
                            execution_profile=SUPERVISED_PROFILE)
            with patch('evals.runtime_access._require_root_linux'), \
                    patch('evals.runtime_review.actor_slot',side_effect=ValueError('busy actor')), \
                    patch('evals.runtime_review._scan') as scan:
                for call in (lambda:runtime_review.final_manifest(fixture),
                        lambda:runtime_review.git_control_manifest(fixture.root,execution_profile=SUPERVISED_PROFILE),
                        lambda:runtime_review.freeze_for_review(fixture,root/'snapshot')):
                    with self.subTest(call=call),self.assertRaisesRegex(ValueError,'busy actor'): call()
                scan.assert_not_called()
            self.assertFalse((root/'snapshot').exists())
