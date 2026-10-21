from dataclasses import replace
import os
import struct
import unittest
from unittest.mock import Mock, patch

from evals.native_audit_capture import AuditCapture
from evals.native_audit_control import AuditStatus, ControlReceipt, STATUS, GET, SET, ADD_RULE, DEL_RULE, LIST_RULES
from evals.native_audit_events import AuditSummary
from evals.native_audit_rule import build_rule
from evals.native_audit_wire import HEADER
from tests.test_native_audit_control import status_payload
from tests.test_native_audit_rule import FakeAuditLibrary, KEY


class FakeKernel:
    def __init__(self):
        self.status=AuditStatus.decode(status_payload())
        self.rules=()
        self.operations=[]
        self.channels=[]
        self.fail_after=None
        self.actor_idle=True
        self.listener=None
        self.replacement_count=1

    def channel(self):
        kernel=self
        class Channel:
            def __init__(self):
                self.receipts=();self.closed=False;self.incoming=[]
            def __enter__(self):kernel.channels.append(self);return self
            def __exit__(self,*args):self.close()
            def close(self):self.closed=True
            def fileno(self):return 99
            def recvmsg(self):
                if self.incoming:return self.incoming.pop(0),[],0,(0,0)
                raise BlockingIOError()
            def request(self,kind,payload=b'',pump=None):
                if pump:pump()
                kernel.operations.append((kind,payload))
                if kind==GET:answer=(kernel.status.encode(),)
                elif kind==LIST_RULES:answer=kernel.rules
                elif kind==ADD_RULE:kernel.rules=(*kernel.rules,payload);answer=()
                elif kind==DEL_RULE:kernel.rules=tuple(r for r in kernel.rules if r!=payload);answer=()
                elif kind==SET:
                    values=STATUS.unpack(payload);mask=values[0]
                    field,index={1:('enabled',1),4:('pid',3),16:('backlog_limit',5)}[mask]
                    if field=='pid':
                        if values[index]:kernel.listener=self
                        elif kernel.listener:
                            kernel.listener.incoming.extend([HEADER.pack(20,1329,0,0,0)+
                                struct.pack('=i',os.getpid())]*kernel.replacement_count)
                    kernel.status=replace(kernel.status,**{field:values[index]});answer=()
                else:raise AssertionError('unexpected operation')
                if kernel.fail_after==kind:
                    kernel.fail_after=None;raise TimeoutError('lost response')
                self.receipts=(*self.receipts,ControlReceipt(kind,len(kernel.operations),88,'a'*64,1,36))
                return answer
        return Channel()


class FakeDecoder:
    def __init__(self,*args,**kwargs):self.closed=False;self.failure=False
    def consume(self,message):
        if self.failure:raise ValueError('parser failure')
    def finish(self):
        if self.failure:raise ValueError('parser failure')
        return AuditSummary(1,3,100,((1300,1),),'a'*64,'b'*64)
    def close(self):self.closed=True


class AuditCaptureTests(unittest.TestCase):
    def setUp(self):
        self.kernel=FakeKernel();self.lock=Mock();self.decoder=FakeDecoder()
        with patch('evals.native_audit_rule._library',return_value=FakeAuditLibrary()):
            self.rule=build_rule(KEY)
        patches=(patch('evals.native_audit_capture._require_root_linux'),
            patch('evals.native_audit_capture._lock',return_value=self.lock),
            patch('evals.native_audit_capture._idle_actor_uid',side_effect=self.idle),
            patch('evals.native_audit_capture.AuditChannel',side_effect=lambda **options:self.kernel.channel()),
            patch('evals.native_audit_capture.build_rule',return_value=self.rule),
            patch('evals.native_audit_capture.AuditDecoder',return_value=self.decoder),
            patch('evals.native_audit_capture.select.select',return_value=([],[],[])))
        for item in patches:item.start();self.addCleanup(item.stop)

    def idle(self):
        if not self.kernel.actor_idle:raise ValueError('dedicated UID active')

    def test_exact_rule_single_uid_lock_and_full_pristine_restore(self):
        baseline=self.kernel.status;capture=AuditCapture()
        with capture:
            self.assertTrue(capture.ready)
            self.assertEqual((self.rule.payload,),self.kernel.rules)
            self.assertEqual((1,os.getpid(),8192),(self.kernel.status.enabled,self.kernel.status.pid,
                                                self.kernel.status.backlog_limit))
            self.lock.close.assert_not_called()
        self.assertTrue(capture.restored)
        self.assertEqual(baseline,self.kernel.status)
        self.assertEqual((),self.kernel.rules)
        self.assertEqual(self.rule.sha256,capture.result.rule_sha256)
        self.assertEqual(1,capture.result.replacement_notifications)
        self.assertTrue(self.decoder.closed)
        self.assertTrue(all(channel.closed for channel in self.kernel.channels))
        self.lock.close.assert_called_once()

    def test_nonpristine_or_active_uid_baseline_never_mutates_kernel(self):
        for change in ('pid','rules','actor','panic'):
            self.kernel=FakeKernel()
            if change=='pid':self.kernel.status=replace(self.kernel.status,pid=1234)
            if change=='panic':self.kernel.status=replace(self.kernel.status,failure=2)
            if change=='rules':self.kernel.rules=(b'foreign',)
            if change=='actor':self.kernel.actor_idle=False
            with self.subTest(change=change),self.assertRaises(ValueError):
                with AuditCapture():pass
            self.assertFalse(any(kind in (SET,ADD_RULE,DEL_RULE) for kind,_ in self.kernel.operations))

    def test_add_response_loss_uses_fresh_authoritative_lookup_then_rolls_back_exact_rule(self):
        self.kernel.fail_after=ADD_RULE;capture=AuditCapture()
        with self.assertRaises(TimeoutError):capture.__enter__()
        self.assertTrue(capture.restored)
        self.assertEqual((),self.kernel.rules)
        self.assertTrue(self.kernel.status.pristine)
        self.assertEqual(1,sum(kind==ADD_RULE for kind,_ in self.kernel.operations))
        self.assertEqual([(DEL_RULE,self.rule.payload)],[(k,p) for k,p in self.kernel.operations if k==DEL_RULE])

    def test_listener_registration_response_loss_restores_pid_without_retrying_registration(self):
        self.kernel.fail_after=SET;capture=AuditCapture()
        with self.assertRaises(TimeoutError):capture.__enter__()
        self.assertTrue(capture.restored)
        self.assertTrue(self.kernel.status.pristine)
        registrations=[p for k,p in self.kernel.operations if k==SET and STATUS.unpack(p)[3]==os.getpid()]
        self.assertEqual(1,len(registrations))

    def test_delete_response_loss_restores_kernel_but_does_not_accept_complete_capture(self):
        capture=AuditCapture();capture.__enter__();self.kernel.fail_after=DEL_RULE
        with self.assertRaises(TimeoutError):capture.close()
        self.assertTrue(capture.restored)
        self.assertIsNone(capture.result)
        self.assertEqual((),self.kernel.rules)

    def test_missing_rule_or_baseline_status_before_cleanup_blocks_result(self):
        for change in ('rule', 'enabled', 'backlog_limit'):
            self.kernel=FakeKernel();capture=AuditCapture();capture.__enter__()
            if change=='rule':self.kernel.rules=()
            else:self.kernel.status=replace(self.kernel.status,**{change:getattr(capture._baseline,change)})
            with self.subTest(change=change),self.assertRaises(BaseException):capture.close()
            self.assertTrue(capture.restored)
            self.assertIsNone(capture.result)

    def test_delete_before_effect_loss_reconciles_exact_rule_then_preserves_error(self):
        capture=AuditCapture();capture.__enter__()
        original=capture._control;failed=[]
        def control(kind,payload=b''):
            if kind==DEL_RULE and not failed:
                failed.append(kind);raise TimeoutError('before-effect response loss')
            return original(kind,payload)
        capture._control=control
        with self.assertRaises(TimeoutError):capture.close()
        self.assertEqual([DEL_RULE],failed)
        self.assertEqual((),self.kernel.rules)
        self.assertTrue(capture.restored)
        self.assertIsNone(capture.result)

    def test_repeated_delete_failure_is_bounded_and_explicit(self):
        capture=AuditCapture();capture.__enter__()
        original=capture._control;attempts=[]
        def control(kind,payload=b''):
            if kind==DEL_RULE:
                attempts.append(kind);raise TimeoutError('before-effect response loss')
            return original(kind,payload)
        capture._control=control
        with self.assertRaises(BaseException):capture.close()
        self.assertEqual(2,len(attempts))
        self.assertEqual((self.rule.payload,),self.kernel.rules)
        self.assertFalse(capture.restored)
        self.assertIsNone(capture.result)

    def test_active_actor_blocks_all_teardown_and_retains_resources_until_idle(self):
        capture=AuditCapture();capture.__enter__();self.kernel.actor_idle=False
        before=len(self.kernel.operations)
        with self.assertRaises(ValueError):capture.close()
        self.assertEqual(before,len(self.kernel.operations))
        self.lock.close.assert_not_called()
        self.assertFalse(self.decoder.closed)
        self.assertFalse(capture._listener.closed)
        self.assertIsNone(capture.result)
        self.kernel.actor_idle=True;capture.close()
        self.assertTrue(capture.restored)
        self.lock.close.assert_called_once()
        self.assertIsNone(capture.result)

    def test_foreign_state_retains_lock_and_listener_until_authoritative_recovery(self):
        capture=AuditCapture();capture.__enter__();self.kernel.rules+=(b'foreign',)
        with self.assertRaises(BaseException):capture.close()
        self.lock.close.assert_not_called()
        self.assertFalse(self.decoder.closed)
        self.assertFalse(capture._listener.closed)
        self.assertFalse(capture._closed)
        self.assertIsNone(capture.result)
        # A foreign controller restores its own settings; capture never deletes them.
        self.kernel.rules=();self.kernel.status=capture._baseline
        capture.close()
        self.assertTrue(capture.restored)
        self.lock.close.assert_called_once()
        self.assertIsNone(capture.result)

    def test_wire_integrity_failure_is_latched_while_cleanup_can_still_drain(self):
        capture=AuditCapture();capture.__enter__()
        packets=[(b'private-canary',[],0,(0,0))]
        original=capture._listener.recvmsg
        def receive():
            if packets:return packets.pop()
            return original()
        capture._listener.recvmsg=receive
        with self.assertRaises(ValueError) as caught:capture.drain()
        self.assertNotIn('private-canary',str(caught.exception))
        with self.assertRaises(ValueError):capture.close()
        self.assertTrue(capture.restored)
        self.assertIsNone(capture.result)

    def test_receive_enobufs_is_integrity_failure_even_after_socket_recovers(self):
        capture=AuditCapture();capture.__enter__();failures=[OSError(105,'buffer overflow')]
        original=capture._listener.recvmsg
        def receive():
            if failures:raise failures.pop()
            return original()
        capture._listener.recvmsg=receive
        with self.assertRaises(OSError):capture.drain()
        with self.assertRaises(ValueError):capture.close()
        self.assertTrue(capture.restored)
        self.assertIsNone(capture.result)

    def test_parser_failure_does_not_prevent_kernel_restore_or_produce_a_result(self):
        capture=AuditCapture();capture.__enter__();self.decoder.failure=True
        with self.assertRaises(ValueError):capture.close()
        self.assertTrue(capture.restored)
        self.assertIsNone(capture.result)
        self.assertTrue(self.kernel.status.pristine)
        self.assertTrue(self.decoder.closed)

    def test_foreign_rule_is_preserved_and_global_disable_is_not_attempted(self):
        capture=AuditCapture();capture.__enter__();self.kernel.rules+= (b'foreign',)
        before=len(self.kernel.operations)
        with self.assertRaises(BaseException):capture.close()
        self.assertFalse(capture.restored)
        self.assertEqual((b'foreign',),self.kernel.rules)
        self.assertFalse(any(k==SET for k,p in self.kernel.operations[before:]))

    def test_foreign_listener_is_preserved_without_status_takeover(self):
        capture=AuditCapture();capture.__enter__();self.kernel.status=replace(self.kernel.status,pid=1234)
        before=len(self.kernel.operations)
        with self.assertRaises(BaseException):capture.close()
        self.assertEqual(1234,self.kernel.status.pid)
        self.assertFalse(capture.restored)
        self.assertFalse(any(k==SET for k,p in self.kernel.operations[before:]))

    def test_unsolicited_replacement_notification_is_not_mistaken_for_owned_teardown(self):
        capture=AuditCapture();capture.__enter__()
        capture._listener.incoming.append(HEADER.pack(20,1329,0,0,0)+struct.pack('=i',os.getpid()))
        with self.assertRaises(ValueError):capture.drain()
        with self.assertRaises(BaseException):capture.close()
        self.assertTrue(capture.restored)
        self.assertIsNone(capture.result)

    def test_missing_or_duplicate_owned_replacement_probe_blocks_result(self):
        for count in (0,2):
            self.kernel=FakeKernel();self.kernel.replacement_count=count
            capture=AuditCapture();capture.__enter__()
            with self.subTest(count=count),self.assertRaises(BaseException):capture.close()
            self.assertTrue(capture.restored)
            self.assertIsNone(capture.result)

    def test_loss_counter_is_never_reset_and_cannot_claim_restoration(self):
        capture=AuditCapture();capture.__enter__();self.kernel.status=replace(self.kernel.status,lost=1)
        with self.assertRaises(BaseException):capture.close()
        self.assertEqual(1,self.kernel.status.lost)
        self.assertFalse(capture.restored)
        self.assertFalse(any(k==SET and STATUS.unpack(p)[0] not in (1,4,16)
                             for k,p in self.kernel.operations))

    def test_body_error_after_complete_events_cannot_leave_capture_result(self):
        capture=AuditCapture()
        with self.assertRaisesRegex(RuntimeError,'body operation failed'):
            with capture:
                self.assertIsNotNone(self.decoder.finish())
                raise RuntimeError('body operation failed')
        self.assertTrue(capture.restored)
        self.assertIsNone(capture.result)
        self.lock.close.assert_called_once()

    def test_body_interrupt_is_preserved_and_cleanup_error_is_grouped(self):
        capture=AuditCapture()
        with self.assertRaises(KeyboardInterrupt):
            with capture:raise KeyboardInterrupt()
        self.assertTrue(capture.restored)
        self.assertIsNone(capture.result)
        capture=AuditCapture()
        with self.assertRaises(BaseExceptionGroup) as caught:
            with capture:
                self.kernel.status=replace(self.kernel.status,lost=1)
                raise KeyboardInterrupt()
        self.assertTrue(any(isinstance(error,KeyboardInterrupt) for error in caught.exception.exceptions))


    def test_resource_close_failure_retains_retry_without_repeating_kernel_teardown(self):
        capture=AuditCapture();capture.__enter__()
        self.lock.close.side_effect=[OSError(5,'close failed'),None]
        with self.assertRaises(OSError):capture.close()
        self.assertTrue(capture.restored)
        self.assertFalse(capture._closed)
        self.assertIsNone(capture.result)
        operations=len(self.kernel.operations)
        capture.close()
        self.assertTrue(capture._closed)
        self.assertEqual(operations,len(self.kernel.operations))
        self.assertIsNone(capture.result)
