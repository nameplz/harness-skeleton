from dataclasses import replace
import itertools
import struct
import unittest
from unittest.mock import Mock, patch

from evals.native_audit_control import AuditRequest, AuditReplies, AuditStatus, AuditChannel
from evals.native_audit_wire import HEADER


def frame(kind, body=b'', *, seq=1, port=0, flags=0):
    return HEADER.pack(16+len(body), kind, flags, seq, port)+body


def ack(request, *, error=0, echo=None, flags=256):
    return frame(2, struct.pack('=i', error)+(request.packet[:16] if echo is None else echo),
                 seq=request.sequence, port=request.port_id, flags=flags)


def status_payload(**changes):
    values = dict(mask=0, enabled=0, failure=1, pid=0, rate_limit=0, backlog_limit=64,
        lost=0, backlog=0, feature_bitmap=0x3f, backlog_wait_time=60000,
        backlog_wait_time_actual=0)
    return struct.pack('=11I', *{**values, **changes}.values())


class AuditControlProtocolTests(unittest.TestCase):
    def request(self, kind=1000, payload=b''):
        return AuditRequest(kind, payload, 1, 88)

    def test_status_roundtrip_is_fixed_abi_and_pristine_preserves_all_fields(self):
        status = AuditStatus.decode(status_payload())
        self.assertTrue(status.pristine)
        self.assertEqual(64, status.backlog_limit)
        self.assertEqual(status_payload(), status.encode())
        for changes in ({'enabled':1}, {'pid':99}, {'lost':1}, {'backlog':1}, {'rate_limit':1}):
            self.assertFalse(AuditStatus.decode(status_payload(**changes)).pristine)
        for body in (b'', b'\0'*40, status_payload()+b'\0', status_payload(enabled=3), status_payload(mask=1)):
            with self.assertRaises(ValueError): AuditStatus.decode(body)

    def test_kernel_panic_failure_mode_is_not_an_admissible_pristine_baseline(self):
        self.assertFalse(AuditStatus.decode(status_payload(failure=2)).pristine)

    def test_request_has_exact_identity_and_bounded_allowed_command_surface(self):
        request = self.request()
        self.assertEqual(HEADER.pack(16,1000,5,1,88), request.packet)
        self.assertNotIn('private-canary', repr(self.request(1011,b'private-canary')))
        for changes in ({'kind':1002}, {'kind':True}, {'sequence':0}, {'sequence':True},
                        {'port_id':0}, {'port_id':2**32}, {'payload':'x'}, {'payload':b'x'*4097}):
            with self.subTest(changes=tuple(changes)), self.assertRaises(ValueError):
                replace(request, **changes).packet

    def test_success_ack_requires_capped_header_echo_and_no_extra_tlvs(self):
        request = self.request(1001, b'\0'*44)
        replies = AuditReplies(request)
        self.assertTrue(replies.consume(ack(request)))
        self.assertEqual((), replies.answers)
        for packet in (ack(request, flags=0), ack(request, flags=768),
                       ack(request, echo=b'\0'*16), ack(request)+b'\0'*4,
                       frame(2,b'\0'*4+request.packet[:16]+b'private-canary',port=88,flags=256)):
            with self.subTest(size=len(packet)), self.assertRaises(ValueError):
                AuditReplies(request).consume(packet)

    def test_failed_ack_does_not_expose_kernel_text_and_echo_is_still_required(self):
        request = self.request()
        with self.assertRaises(OSError) as caught:
            AuditReplies(request).consume(ack(request,error=-1))
        self.assertEqual(1, caught.exception.errno)
        self.assertNotIn('private-canary', str(caught.exception))
        with self.assertRaises(ValueError):
            AuditReplies(request).consume(ack(request,error=-1,echo=b'x'*16))

    def test_get_requires_one_status_and_ack_in_either_order(self):
        request = self.request(); data = frame(1000,status_payload())
        for packets in ((ack(request),data),(data,ack(request))):
            replies=AuditReplies(request)
            self.assertFalse(replies.consume(packets[0]))
            self.assertTrue(replies.consume(packets[1]))
            self.assertEqual((status_payload(),),replies.answers)

    def test_empty_multipart_list_requires_done_and_ack(self):
        request=self.request(1013); replies=AuditReplies(request)
        self.assertFalse(replies.consume(frame(3,flags=2)))
        self.assertTrue(replies.consume(ack(request)))
        self.assertEqual((),replies.answers)
        for body in (b'bad',struct.pack('=i',-1),b'\0'*8):
            with self.assertRaises(ValueError):
                AuditReplies(request).consume(frame(3,body,flags=2))

    def test_multipart_order_duplicates_and_response_identity_fail_closed(self):
        request=self.request(1013)
        replies=AuditReplies(request)
        self.assertFalse(replies.consume(ack(request)))
        self.assertFalse(replies.consume(frame(1013,b'private-canary',flags=2)))
        self.assertTrue(replies.consume(frame(3,flags=2)))
        self.assertNotIn('private-canary',repr(replies))
        for packet in (ack(request),frame(3,flags=2),frame(1013,b'x',flags=2)):
            with self.assertRaises(ValueError): replies.consume(packet)
        for packet in (frame(1013,b'x',seq=2,flags=2),frame(1013,b'x',port=88,flags=2),
                       frame(1013,b'x'),frame(1000,status_payload()),frame(3)):
            with self.assertRaises(ValueError): AuditReplies(request).consume(packet)

    def test_extra_reply_in_same_packet_and_latched_failure_are_not_silently_ignored(self):
        request=self.request(1001,b'\0'*44); replies=AuditReplies(request)
        with self.assertRaises(ValueError): replies.consume(ack(request)+ack(request))
        with self.assertRaises(ValueError): replies.consume(ack(request))

    def test_response_byte_and_record_count_bounds_cover_multipart_lists(self):
        request=self.request(1013); replies=AuditReplies(request)
        for _ in range(64): self.assertFalse(replies.consume(frame(1013,b'x',flags=2)))
        with self.assertRaises(ValueError): replies.consume(frame(1013,b'x',flags=2))
        replies=AuditReplies(request)
        with self.assertRaises(ValueError): replies.consume(frame(1013,b'x'*65500,flags=2))


class FakeSocket:
    def __init__(self, respond):
        self.respond = respond
        self.sent = []
        self.rows = []
        self.closed = False
        self.metadata = ((0, 0), 0, [])

    def getsockname(self): return (88, 0)
    def fileno(self): return 88
    def close(self): self.closed = True
    def sendto(self, raw, address):
        assert address == (0, 0)
        self.sent.append(raw)
        self.rows.extend(self.respond(raw))
        return len(raw)
    def recvmsg(self, *args):
        address, flags, ancillary = self.metadata
        if not self.rows: raise BlockingIOError()
        return self.rows.pop(0), ancillary, flags, address


def respond(raw):
    size, kind, flags, sequence, port = HEADER.unpack_from(raw)
    request = AuditRequest(kind, raw[16:], sequence, port)
    result = [ack(request)]
    if kind == 1000: result.append(frame(1000,status_payload(),seq=sequence))
    if kind == 1013: result.append(frame(3,seq=sequence,flags=2))
    return result


class AuditChannelTests(unittest.TestCase):
    def setUp(self):
        sequence_patch=patch('evals.native_audit_control._sequences',itertools.count(1))
        sequence_patch.start();self.addCleanup(sequence_patch.stop)

    def channel(self, sock):
        with patch('evals.native_audit_control._open_socket',return_value=sock):
            return AuditChannel()

    def test_live_wrapper_passes_actual_recv_metadata_and_fixed_capped_ack_contract(self):
        sock=FakeSocket(respond); pumps=[]
        with self.channel(sock) as channel, patch('evals.native_audit_control.select.select',
                side_effect=lambda *args: ([sock],[],[])):
            self.assertEqual((status_payload(),),channel.request(1000,pump=lambda:pumps.append(1)))
            self.assertEqual((),channel.request(1013))
            self.assertEqual([1,2],[HEADER.unpack_from(raw)[3] for raw in sock.sent])
            self.assertTrue(pumps)
            self.assertEqual(2,len(channel.receipts))
            self.assertEqual(1000,channel.receipts[0].kind)
            self.assertEqual(64,len(channel.receipts[0].request_sha256))
        self.assertTrue(sock.closed)

    def test_wrong_actual_origin_or_truncation_latches_failure_and_disables_reuse(self):
        for metadata in (((1,0),0,[]),((0,0),32,[]),((0,0),0,[(1,40,b'\1\0\0\0')])):
            sock=FakeSocket(respond);sock.metadata=metadata
            with self.channel(sock) as channel, patch('evals.native_audit_control.select.select',
                    return_value=([sock],[],[])):
                with self.assertRaises(ValueError):channel.request(1000)
                with self.assertRaises(ValueError):channel.request(1000)
                self.assertEqual((),channel.receipts)
            self.assertTrue(sock.closed)

    def test_no_reply_times_out_without_repeating_mutation(self):
        sock=FakeSocket(lambda raw:[])
        with self.channel(sock) as channel, patch('evals.native_audit_control.time.monotonic',
                side_effect=[0,0,4]), patch('evals.native_audit_control.select.select',return_value=([],[],[])):
            with self.assertRaises(TimeoutError):channel.request(1001,b'\0'*44)
            self.assertEqual(1,len(sock.sent))
        self.assertTrue(sock.closed)

    def test_pump_interrupt_and_closed_channel_do_not_start_another_request(self):
        sock=FakeSocket(respond)
        with self.channel(sock) as channel:
            def interrupt():raise KeyboardInterrupt()
            with self.assertRaises(KeyboardInterrupt):channel.request(1000,pump=interrupt)
            with self.assertRaises(ValueError):channel.request(1000)
        with self.assertRaises(ValueError):channel.request(1000)

    def test_fresh_channels_do_not_reuse_sequence_after_socket_port_reuse(self):
        sockets=[FakeSocket(respond),FakeSocket(respond)]
        for sock in sockets:
            with self.channel(sock) as channel, patch('evals.native_audit_control.select.select',
                    return_value=([sock],[],[])):
                channel.request(1000)
        self.assertEqual([1,2],[HEADER.unpack_from(s.sent[0])[3] for s in sockets])


class AuditSocketBufferTests(unittest.TestCase):
    def test_event_socket_requires_effective_bounded_buffer_without_global_changes(self):
        import socket
        from evals.native_audit_control import _open_socket
        for effective in (64*1024*1024,425984):
            stream=Mock();stream.getsockopt.return_value=effective
            with patch('evals.native_cgroup._require_root_linux'), \
                    patch('evals.native_audit_control.socket.AF_NETLINK',16,create=True), \
                    patch('evals.native_audit_control.socket.SOCK_CLOEXEC',0x80000,create=True), \
                    patch('evals.native_audit_control.socket.socket',return_value=stream):
                if effective==425984:
                    with self.assertRaises(ValueError):_open_socket(events=True)
                    stream.close.assert_called_once()
                else:self.assertIs(stream,_open_socket(events=True))
            stream.setsockopt.assert_any_call(socket.SOL_SOCKET,33,32*1024*1024)

    def test_listener_mode_rejects_non_boolean_before_opening_socket(self):
        with patch('evals.native_audit_control._open_socket') as opened:
            for mode in (1,None,'yes'):
                with self.assertRaises(ValueError):AuditChannel(events=mode)
        opened.assert_not_called()
