from dataclasses import replace
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from evals.runtime_consumption import consume_reviews
from evals.runtime_fixtures import materialize_fixture
from evals.runtime_invocation import issue_invocation, write_frozen_source, bind_session, _claim_command
from evals.runtime_review import freeze_for_review


def review_consumed(launch) -> bool:
    path=launch.source.path.parent/'.review-consumption.json'
    return path.exists() and launch.sha256 in json.loads(path.read_text())['consumed']


class ReviewConsumptionTests(unittest.TestCase):
    def setup(self, root):
        fixture=materialize_fixture('security-boundary',root/'candidate',condition='baseline')
        snapshot=root/'snapshot';manifest=freeze_for_review(fixture,snapshot)
        source=write_frozen_source(fixture,root/'source.json')
        launches=[]
        for index,role in enumerate(('correctness','security'),1):
            launch=issue_invocation(fixture,root/role,source,model='test-model',kind=role,
                execution_root=snapshot,final_manifest_sha256=manifest['sha256'])
            launch=_claim_command(launch,('/usr/bin/false',))
            launches.append(bind_session(launch,f'00000000-0000-4000-8000-{index:012d}'))
        return fixture,tuple(launches)

    def ledger(self,root):
        return json.loads((root/'.review-consumption.json').read_text())['consumed']

    def test_group_is_one_atomic_authority_and_duplicate_or_partial_reuse_fails(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve();fixture,launches=self.setup(root)
            consume_reviews(fixture,launches,review_digest='a'*64,kind='native')
            records=self.ledger(root)
            self.assertEqual({row.sha256 for row in launches},set(records))
            self.assertEqual(1,len(set(records.values())))
            self.assertTrue(all(not (row.artifact_root/'consumed.json').exists() for row in launches))
            self.assertEqual(0o600,(root/'.review-consumption.json').stat().st_mode&0o777)
            with self.assertRaises(ValueError):consume_reviews(fixture,launches,review_digest='a'*64,kind='native')
            with self.assertRaises(ValueError):consume_reviews(fixture,launches[:1],review_digest='a'*64,kind='native')

    @unittest.skipUnless(hasattr(os,'fork'),'POSIX review transaction')
    def test_real_termination_before_or_after_rename_leaves_none_or_all_consumed(self):
        for after in (False,True):
            with TemporaryDirectory() as temp,self.subTest(after=after):
                root=Path(temp).resolve();fixture,launches=self.setup(root)
                original=os.replace;pid=os.fork()
                if pid==0:
                    def terminate(source,target,**kwargs):
                        if after:original(source,target,**kwargs)
                        os._exit(77)
                    try:
                        with patch('evals.runtime_consumption.os.replace',side_effect=terminate):
                            consume_reviews(fixture,launches,review_digest='a'*64,kind='native')
                    except BaseException:os._exit(98)
                    os._exit(99)
                _,status=os.waitpid(pid,0);self.assertEqual(77,os.waitstatus_to_exitcode(status))
                if after:
                    self.assertEqual({row.sha256 for row in launches},set(self.ledger(root)))
                    with self.assertRaises(ValueError):consume_reviews(fixture,launches,review_digest='a'*64,kind='native')
                else:
                    self.assertFalse((root/'.review-consumption.json').exists())
                    consume_reviews(fixture,launches,review_digest='a'*64,kind='native')
                    self.assertEqual({row.sha256 for row in launches},set(self.ledger(root)))

    @unittest.skipUnless(hasattr(os,'fork'),'POSIX review transaction')
    def test_concurrent_consumers_have_exactly_one_success(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve();fixture,launches=self.setup(root)
            read,write=os.pipe();children=[]
            for _ in range(2):
                pid=os.fork()
                if pid==0:
                    os.close(write);os.read(read,1);os.close(read)
                    try:consume_reviews(fixture,launches,review_digest='a'*64,kind='native')
                    except ValueError:os._exit(17)
                    except BaseException as error:
                        __import__('traceback').print_exc();os._exit(98)
                    os._exit(0)
                children.append(pid)
            os.close(read);os.write(write,b'GG');os.close(write)
            statuses=[os.waitstatus_to_exitcode(os.waitpid(pid,0)[1]) for pid in children]
            self.assertEqual([0,17],sorted(statuses))
            self.assertEqual({row.sha256 for row in launches},set(self.ledger(root)))

    def test_unsafe_or_malformed_ledger_and_legacy_consumption_fail_closed(self):
        for raw,mode in ((b'{}',0o600),(b'{"schema":true,"consumed":{}}',0o600),
                (b'{"schema":1,"consumed":{}}',0o644),
                (b'{"schema":1,"consumed":{"bad":"bad"}}',0o600)):
            with TemporaryDirectory() as temp,self.subTest(raw=raw,mode=mode):
                root=Path(temp).resolve();fixture,launches=self.setup(root)
                path=root/'.review-consumption.json';path.write_bytes(raw);path.chmod(mode)
                with self.assertRaises(ValueError):consume_reviews(fixture,launches,review_digest='a'*64,kind='native')
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve();fixture,launches=self.setup(root)
            (launches[1].artifact_root/'consumed.json').write_text('{}')
            with self.assertRaises(ValueError):consume_reviews(fixture,launches,review_digest='a'*64,kind='native')
            self.assertFalse((root/'.review-consumption.json').exists())

    def test_source_anchor_cannot_be_relocated_to_bypass_consumption(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve();fixture,launches=self.setup(root)
            consume_reviews(fixture,launches,review_digest='a'*64,kind='native')
            other=root/'alternate';other.mkdir(mode=0o700)
            copy=other/'source.json';copy.write_bytes(launches[0].source.path.read_bytes())
            relocated=tuple(replace(row,source=replace(row.source,path=copy)) for row in launches)
            with self.assertRaises(ValueError):
                consume_reviews(fixture,relocated,review_digest='b'*64,kind='native')
            self.assertFalse((other/'.review-consumption.json').exists())

    def test_authority_rejects_links_unknown_fields_duplicates_and_bounds(self):
        records=(b'{"schema":1,"consumed":{},"extra":true}',
                 b'{"schema":1,"schema":1,"consumed":{}}',
                 json.dumps({'schema':1,'consumed':{f'{index:064x}':'a'*64 for index in range(4097)}}).encode(),
                 b' '*1048577)
        for raw in records:
            with TemporaryDirectory() as temp,self.subTest(size=len(raw)):
                root=Path(temp).resolve();fixture,launches=self.setup(root)
                path=root/'.review-consumption.json';path.write_bytes(raw);path.chmod(0o600)
                with self.assertRaises(ValueError):consume_reviews(fixture,launches,review_digest='a'*64,kind='native')
        for kind in ('symlink','hardlink','directory'):
            with TemporaryDirectory() as temp,self.subTest(kind=kind):
                root=Path(temp).resolve();fixture,launches=self.setup(root)
                target=root/'outside';target.write_text('{"schema":1,"consumed":{}}');target.chmod(0o600)
                path=root/'.review-consumption.json'
                if kind=='symlink':path.symlink_to(target)
                elif kind=='hardlink':os.link(target,path)
                else:path.mkdir(mode=0o700)
                with self.assertRaises(ValueError):consume_reviews(fixture,launches,review_digest='a'*64,kind='native')

    def test_distinct_fresh_group_allowed_but_old_role_cannot_join_new_group(self):
        with TemporaryDirectory() as temp:
            root=Path(temp).resolve();fixture,launches=self.setup(root)
            consume_reviews(fixture,launches,review_digest='a'*64,kind='native')
            newer=[]
            for index,row in enumerate(launches,3):
                launch=issue_invocation(fixture,root/(row.kind+'-new'),row.source,model='test-model',kind=row.kind,
                    execution_root=row.execution_root,final_manifest_sha256=row.final_manifest_sha256)
                newer.append(bind_session(_claim_command(launch,('/usr/bin/false',)),
                    f'00000000-0000-4000-8000-{index:012d}'))
            with self.assertRaises(ValueError):
                consume_reviews(fixture,(launches[0],newer[1]),review_digest='b'*64,kind='native')
            self.assertEqual(2,len(self.ledger(root)))
            consume_reviews(fixture,tuple(newer),review_digest='b'*64,kind='native')
            self.assertEqual(4,len(self.ledger(root)))

    def test_stale_temporary_is_bounded_recovered_and_unsafe_entry_is_preserved(self):
        for mode in (0o600,0o644):
            with TemporaryDirectory() as temp,self.subTest(mode=mode):
                root=Path(temp).resolve();fixture,launches=self.setup(root)
                stale=root/'.review-consumption.tmp';stale.write_bytes(b'interrupted write');stale.chmod(mode)
                if mode==0o600:
                    consume_reviews(fixture,launches,review_digest='a'*64,kind='native')
                    self.assertFalse(stale.exists())
                    self.assertEqual(2,len(self.ledger(root)))
                else:
                    with self.assertRaises(ValueError):consume_reviews(fixture,launches,review_digest='a'*64,kind='native')
                    self.assertEqual(b'interrupted write',stale.read_bytes())
                    self.assertFalse((root/'.review-consumption.json').exists())
