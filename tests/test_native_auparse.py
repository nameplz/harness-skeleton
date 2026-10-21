import hashlib
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from evals.native_auparse import AuditDecoder
from evals import native_auparse
from evals import native_audit_library
from tests.test_native_audit_events import KEY, message


class Function:
    def __init__(self, call): self.call = call
    def __call__(self, *args): return self.call(*args)


class FakeAuparse:
    """Cursor ABI double; actual pinned C implementation is qualified on Linux."""
    def __init__(self):
        self.callback = None
        self.records = []
        self.record = self.field = 0
        self.key = KEY
        self.fed = []
        self.destroyed = False
        self.feed_result = self.flush_result = self.buffered = 0
        self.callback_kind = 0
        self.init_result = 1
        self.value_reads = []
        self.interpreted_reads = []
        methods = {
            'init': lambda *args: self.init_result,
            'destroy': self.destroy,
            'set_escape_mode': lambda *args: setattr(self, 'escape', args[1]),
            'add_callback': lambda au, cb, *rest: setattr(self, 'callback', cb),
            'feed': self.feed, 'flush_feed': self.flush,
            'feed_has_data': lambda au: self.buffered,
            'get_time': lambda au: self.key.seconds,
            'get_milli': lambda au: self.key.milli,
            'get_serial': lambda au: self.key.serial,
            'get_num_records': lambda au: len(self.records),
            'first_record': lambda au: self.first_record(),
            'next_record': lambda au: self.next_record(),
            'get_type': lambda au: self.records[self.record][0],
            'first_field': lambda au: self.first_field(),
            'next_field': lambda au: self.next_field(),
            'get_field_name': lambda au: self.current()[0],
            'get_field_str': lambda au: self.read(False),
            'interpret_field': lambda au: self.read(True),
        }
        for name, call in methods.items(): setattr(self, 'auparse_' + name, Function(call))

    def destroy(self, au): self.destroyed = True
    def first_record(self): self.record = 0; return 1 if self.records else 0
    def next_record(self): self.record += 1; return int(self.record < len(self.records))
    def first_field(self): self.field = 0; return int(bool(self.records[self.record][1]))
    def next_field(self): self.field += 1; return int(self.field < len(self.records[self.record][1]))
    def current(self): return self.records[self.record][1][self.field]
    def read(self, interpreted):
        (self.interpreted_reads if interpreted else self.value_reads).append(self.current()[0])
        return self.current()[1]
    def feed(self, au, data, size):
        assert size == len(data)
        self.fed.append(data)
        return self.feed_result
    def flush(self, au):
        if self.records: self.callback(au, self.callback_kind, None)
        return self.flush_result


def syscall_fields(**changes):
    fields = dict(arch=b'c00000b7', syscall=b'56', success=b'no', exit=b'-13',
        a0=b'ffffffffffffff9c', a1=b'123', a2=b'0', a3=b'0', items=b'0',
        pid=b'2001', ppid=b'2000', uid=b'2000', gid=b'2000', euid=b'2000',
        suid=b'2000', fsuid=b'2000', egid=b'2000', sgid=b'2000', fsgid=b'2000')
    return [(name.encode(), value) for name, value in {**fields, **changes}.items()]


class NativeAuparseTests(unittest.TestCase):
    def decoder(self, fake, **kwargs):
        with patch('evals.native_auparse._library', return_value=fake):
            return AuditDecoder(key=b'k'*32, **kwargs)

    def syscall(self, fake, **changes):
        fake.records = [(1300, syscall_fields(**changes))]
        decoder = self.decoder(fake)
        decoder.consume(message(1300)); decoder.consume(message(1320))
        return decoder

    def test_bpf_hyphenated_program_id_is_numeric_and_both_fields_are_required(self):
        for fields in ([(b'prog-id',b'23'),(b'op',b'LOAD')],[],[(b'prog-id',b'23')],
                       [(b'prog-id',b'23'),(b'op',b'unknown')]):
            fake=FakeAuparse();fake.records=[(1334,fields)]
            with self.decoder(fake) as decoder:
                decoder.consume(message(1334))
                if len(fields)==2 and fields[-1][1]==b'LOAD':
                    self.assertEqual(1,decoder.finish().events)
                    self.assertIn(b'prog-id',fake.value_reads)
                else:
                    with self.assertRaises(ValueError):decoder.finish()

    def test_service_nested_fields_keep_outcome_and_skip_comm(self):
        for result in (b'success',b'failed',b'unknown'):
            fake=FakeAuparse();fake.records=[(1130,[(b'pid',b'1'),(b'uid',b'0'),
                (b'auid',b'4294967295'),(b'ses',b'4294967295'),(b'unit',b'owned'),
                (b'comm',b'private-canary'),(b'res',result)])]
            with self.decoder(fake) as decoder:
                decoder.consume(message(1130))
                if result==b'unknown':
                    with self.assertRaises(ValueError):decoder.finish()
                else:self.assertEqual(1,decoder.finish().events)
            self.assertNotIn(b'comm',fake.value_reads)

    def test_dense_same_second_stream_flushes_callbacks_before_pending_bound(self):
        from dataclasses import replace
        import re
        class Buffered(FakeAuparse):
            def __init__(self):super().__init__();self.queue=[]
            def feed(self,au,data,size):
                serial=int(re.search(rb':([0-9]+)\):',data).group(1))
                self.queue.append(replace(KEY,serial=serial))
                return 0
            def flush(self,au):
                for key in self.queue:
                    self.key=key;self.records=[(1300,syscall_fields())]
                    self.callback(au,self.callback_kind,None)
                self.queue=[];self.records=[]
                return 0
        fake=Buffered()
        with self.decoder(fake) as decoder:
            for serial in range(1,4201):
                key=replace(KEY,serial=serial)
                decoder.consume(message(1300,key));decoder.consume(message(1320,key))
            result=decoder.finish()
        self.assertEqual((4200,8400),(result.events,result.frames))
        fake=Buffered()
        with self.decoder(fake) as decoder:
            for serial in range(1,131):decoder.consume(message(1300,replace(KEY,serial=serial)))
            with self.assertRaises(ValueError):decoder.finish()  # Flush cannot invent missing EOE.

    def test_pinned_feed_abi_and_raw_escape_mode(self):
        fake = FakeAuparse()
        with self.syscall(fake) as decoder:
            result = decoder.finish()
        self.assertTrue(fake.destroyed)
        self.assertEqual(0, fake.escape)
        self.assertEqual(1, len(fake.fed))
        self.assertTrue(fake.fed[0].startswith(b'type=SYSCALL msg=audit('))
        self.assertEqual(1, result.events)

    def test_private_argv_proctitle_comm_values_are_never_read(self):
        fake = FakeAuparse()
        fake.records = [(1300, syscall_fields(comm=b'private-canary', exe=b'/private-canary')),
                        (1309, [(b'a0', b'private-canary')]),
                        (1327, [(b'proctitle', b'private-canary')])]
        with self.decoder(fake) as decoder:
            for kind in (1300, 1309, 1327, 1320): decoder.consume(message(kind))
            result = decoder.finish()
        self.assertNotIn(b'comm', fake.value_reads)
        self.assertNotIn(b'proctitle', fake.value_reads + fake.interpreted_reads)
        self.assertEqual(1, fake.value_reads.count(b'a0'))  # syscall numeric argument only
        self.assertEqual([b'exe'], fake.interpreted_reads)
        self.assertNotIn('private-canary', str(result.projection()))

    def test_numeric_fields_are_strict_and_callback_failure_latches(self):
        for changes in ({'pid': b'-1'}, {'arch': b'0x123'}, {'syscall': b'+56'},
                        {'exit': b'private-canary'}, {'items': b'65'},
                        {'success': b'1'}, {'a0': b'f'*17}, {'pid': b'2'*32}):
            fake = FakeAuparse()
            with self.syscall(fake, **changes) as decoder:
                with self.subTest(changes=changes), self.assertRaises(ValueError) as caught:
                    decoder.finish()
                self.assertNotIn('private-canary', str(caught.exception))
                with self.assertRaises(ValueError): decoder.consume(message(1300))
            self.assertTrue(fake.destroyed)

    def test_duplicate_missing_fields_and_wrong_callback_kind_are_rejected(self):
        for change in ('duplicate', 'missing', 'kind'):
            fake = FakeAuparse(); decoder = self.syscall(fake)
            if change == 'duplicate': fake.records[0][1].append((b'pid', b'2001'))
            if change == 'missing': fake.records[0][1].pop()
            if change == 'kind': fake.callback_kind = 1
            with decoder, self.assertRaises(ValueError): decoder.finish()

    def test_kernel_task_exit_can_omit_both_return_fields_without_inventing_success(self):
        for keep in (set(), {'success'}, {'exit'}):
            fake = FakeAuparse(); seen = []
            fake.records = [(1300, [(n, v) for n, v in syscall_fields()
                                    if n.decode() not in {'success', 'exit'} - keep])]
            with self.decoder(fake, on_event=seen.append) as decoder:
                decoder.consume(message(1300)); decoder.consume(message(1320))
                if keep:
                    with self.assertRaises(ValueError): decoder.finish()
                else:
                    self.assertEqual(1, decoder.finish().events)
                    values = dict(seen[0].records[0].values)
                    self.assertNotIn('success', values)
                    self.assertNotIn('exit', values)

    def test_empty_or_partial_config_change_cannot_complete_without_eoe(self):
        for fields in ([], [(b'op', b'add_rule'), (b'res', b'1')],
                       [(b'op', b'add_rule'), (b'list', b'4')],
                       [(b'op', b'set'), (b'audit_enabled', b'0'), (b'res', b'1')]):
            fake = FakeAuparse(); fake.records = [(1305, fields)]
            with self.decoder(fake) as decoder:
                decoder.consume(message(1305))
                with self.assertRaises(ValueError): decoder.finish()

    def test_complete_config_rule_and_status_forms_preserve_optional_uid_absence(self):
        for fields in ([(b'op', b'add_rule'), (b'list', b'4'), (b'res', b'1')],
                       [(b'op', b'set'), (b'audit_enabled', b'0'), (b'old', b'1'), (b'res', b'1')]):
            fake = FakeAuparse(); fake.records = [(1305, fields)]; seen = []
            with self.decoder(fake, on_event=seen.append) as decoder:
                decoder.consume(message(1305)); self.assertEqual(1, decoder.finish().events)
            self.assertNotIn('uid', dict(seen[0].records[0].values))

    def test_fields_for_paths_cwd_and_sockaddr_remain_ephemeral(self):
        fake = FakeAuparse(); seen = []
        fake.records = [(1300, syscall_fields(items=b'1')),
            (1302, [(b'item', b'0'), (b'name', b'/private-canary'), (b'nametype', b'NORMAL')]),
            (1307, [(b'cwd', b'/private-canary')]), (1306, [(b'saddr', b'02000050')])]
        with self.decoder(fake, on_event=seen.append) as decoder:
            for kind in (1300, 1302, 1307, 1306, 1320): decoder.consume(message(kind))
            result = decoder.finish()
        self.assertEqual(b'/private-canary', dict(seen[0].records[1].values)['name'])
        self.assertEqual(bytes.fromhex('02000050'), dict(seen[0].records[3].values)['saddr'])
        self.assertNotIn('private-canary', repr(seen))
        self.assertNotIn('private-canary', str(result.projection()))

    def test_kernel_mmap_and_openat2_use_signed_fd_prefixed_hex_and_octal(self):
        fake = FakeAuparse(); seen = []
        fake.records = [(1300, syscall_fields()),
                        (1323, [(b'fd', b'-1'), (b'flags', b'0x22')]),
                        (1337, [(b'oflag', b'0100002'), (b'mode', b'0640'), (b'resolve', b'0x8')])]
        with self.decoder(fake, on_event=seen.append) as decoder:
            for kind in (1300, 1323, 1337, 1320): decoder.consume(message(kind))
            decoder.finish()
        self.assertEqual({'fd': -1, 'flags': 0x22}, dict(seen[0].records[1].values))
        self.assertEqual({'oflag': 0o100002, 'mode': 0o640, 'resolve': 8}, dict(seen[0].records[2].values))

    def test_feed_flush_buffer_and_initialization_failures_never_pass(self):
        for mode in ('feed', 'flush', 'buffer', 'init'):
            fake = FakeAuparse()
            if mode == 'init':
                fake.init_result = 0
                with self.assertRaises(ValueError): self.decoder(fake)
                continue
            decoder = self.syscall(fake)
            with decoder, self.assertRaises(ValueError):
                if mode == 'feed':
                    fake.feed_result = -1; decoder.consume(message(1300, key=type(KEY)(1, 123, 11)))
                else:
                    if mode == 'flush': fake.flush_result = -1
                    else: fake.buffered = 1
                    decoder.finish()

    def test_base_exception_from_consumer_is_raised_after_c_callback_returns(self):
        fake = FakeAuparse()
        def consumer(event): raise KeyboardInterrupt()
        fake.records = [(1300, syscall_fields())]
        with self.decoder(fake, on_event=consumer) as decoder:
            decoder.consume(message(1300)); decoder.consume(message(1320))
            with self.assertRaises(KeyboardInterrupt): decoder.finish()
        self.assertTrue(fake.destroyed)

    def test_close_is_idempotent_and_closed_decoder_is_unavailable(self):
        fake = FakeAuparse(); decoder = self.decoder(fake)
        decoder.close(); decoder.close()
        with self.assertRaises(ValueError): decoder.consume(message(1300))
        with self.assertRaises(ValueError): decoder.finish()

    def test_library_loader_pins_root_regular_bytes_before_loading_open_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / 'parser.so'; path.write_bytes(b'pinned')
            metadata = SimpleNamespace(st_mode=stat.S_IFREG|0o444, st_uid=0, st_size=6, st_dev=1, st_ino=2)
            loader = Mock(return_value='loaded'); calls = []
            def load(name, **kwargs):
                calls.append(int(name.rsplit('/', 1)[1])); return loader(name, **kwargs)
            with patch.object(native_auparse, 'LIBRARY', path), \
                    patch.object(native_auparse, 'LIBRARY_SHA256', hashlib.sha256(b'pinned').hexdigest()), \
                    patch('evals.native_cgroup._require_root_linux'), \
                    patch('evals.runtime_access._root_chain'), \
                    patch.dict(native_audit_library._loaded, {}, clear=True), \
                    patch.object(native_audit_library.platform, 'machine', return_value='aarch64'), \
                    patch.object(native_audit_library.os, 'fstat', return_value=metadata), \
                    patch.object(native_audit_library.C, 'CDLL', side_effect=load):
                self.assertEqual('loaded', native_auparse._library())
                self.assertEqual('loaded', native_auparse._library())
                with patch.object(native_auparse, 'LIBRARY_SHA256', '0'*64), self.assertRaises(ValueError):
                    native_auparse._library()
                with patch.object(native_audit_library.os, 'fstat', return_value=SimpleNamespace(
                        st_mode=stat.S_IFREG|0o666, st_uid=0, st_size=6)), self.assertRaises(ValueError):
                    native_auparse._library()
                with patch.object(native_audit_library.platform, 'machine', return_value='x86_64'), self.assertRaises(ValueError):
                    native_auparse._library()
                for library, fd, identity in native_audit_library._loaded.values():os.close(fd)
                native_audit_library._loaded.clear()
            self.assertEqual(1, len(calls))
            with self.assertRaises(OSError): os.fstat(calls[0])
