import socket
import struct
import unittest

from evals.native_audit_wire import decode_control, decode_event, decode_replace


def frame(kind, payload, *, sequence=7, port=88, flags=0, legacy=False):
    return struct.pack('=IHHII', len(payload) + (0 if legacy else 16),
                       kind, flags, sequence, port) + payload


class NativeAuditWireTests(unittest.TestCase):
    def test_replace_notification_uses_standard_length_and_exact_current_pid(self):
        packet=frame(1329,struct.pack('=i',1234),sequence=0,port=0)
        self.assertIsNone(decode_replace(packet,expected_pid=1234))
        for raw in (packet[:-1],packet+b'\0',frame(1329,struct.pack('=i',1235),sequence=0,port=0),
                    frame(1329,struct.pack('=i',1234),sequence=1,port=0),
                    frame(1329,struct.pack('=i',1234),sequence=0,port=0,flags=2),
                    frame(1329,struct.pack('=i',1234),sequence=0,port=0,legacy=True)):
            with self.assertRaises(ValueError):decode_replace(raw,expected_pid=1234)
        with self.assertRaises(ValueError):decode_replace(packet,expected_pid=True)
        with self.assertRaises(ValueError):decode_replace(packet,expected_pid=1234,address=(1,0))
    def test_legacy_unicast_length_is_payload_only_even_below_header_size(self):
        raw = frame(1320, b'audit:', sequence=0, port=0, legacy=True)
        message = decode_event(raw)
        self.assertEqual((1320, 0, b'audit:'), (message.kind, message.sequence, message.payload))
        self.assertNotIn('audit:', repr(message))

    def test_event_decoder_rejects_standard_length_and_concatenated_messages(self):
        raw = frame(1300, b'payload', sequence=0, port=0, legacy=True)
        for packet in (frame(1300, b'payload', sequence=0, port=0), raw + raw, raw[:-1]):
            with self.subTest(packet=packet), self.assertRaises(ValueError):
                decode_event(packet)

    def test_event_identity_and_unsupported_envelope_fail_closed(self):
        for changes in ({'kind': 1000}, {'kind': 3000}, {'sequence': 1},
                        {'port': 88}, {'flags': 2}, {'payload': b''}):
            values = {'kind': 1300, 'payload': b'payload', 'sequence': 0,
                      'port': 0, 'flags': 0, 'legacy': True}
            values.update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                decode_event(frame(**values))

    def test_control_replies_use_standard_lengths_and_bound_request_identity(self):
        first = frame(2, b'\0' * 20, flags=256)
        second = frame(1000, b'\0' * 44, port=0)
        messages = decode_control(first + second, sequence=7, port_id=88)
        self.assertEqual((2, 1000), tuple(message.kind for message in messages))
        self.assertEqual(b'\0' * 44, messages[1].payload)
        for changes in ({'sequence': 8}, {'port_id': 89}, {'sequence': True},
                        {'sequence': 0}, {'port_id': -1}, {'port_id': False}):
            values = {'sequence': 7, 'port_id': 88, **changes}
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                decode_control(first, **values)

    def test_control_alignment_accepts_final_unpadded_record_but_rejects_junk(self):
        one = frame(1013, b'a', port=0, flags=2)
        two = frame(3, b'', port=0, flags=2)
        self.assertEqual(2, len(decode_control(one + b'\0' * 3 + two, sequence=7, port_id=88)))
        self.assertEqual(1, len(decode_control(one, sequence=7, port_id=88)))
        self.assertEqual(1, len(decode_control(one + b'\0' * 3, sequence=7, port_id=88)))
        for raw in (one + b'\0', one + b'bad', one + b'\0' * 4,
                    frame(999, b''), frame(1300, b'a'), frame(3, b'', flags=4),
                    frame(1000, b'\0' * 44), frame(2, b'\0' * 20, port=0),
                    frame(1000, b'\0' * 44, port=0, flags=512)):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                decode_control(raw, sequence=7, port_id=88)

    def test_short_and_invalid_headers_raise_value_errors_without_raw_data(self):
        raw = frame(1300, b'sensitive-canary', sequence=0, port=0, legacy=True)
        for prefix in range(len(raw)):
            with self.subTest(prefix=prefix), self.assertRaises(ValueError) as caught:
                decode_event(raw[:prefix])
            self.assertNotIn('sensitive-canary', str(caught.exception))
        for size in (0, 1, 15, 65537):
            packet = struct.pack('=IHHII', size, 2, 0, 7, 88)
            with self.subTest(size=size), self.assertRaises(ValueError):
                decode_control(packet, sequence=7, port_id=88)

    def test_socket_origin_truncation_and_overflow_are_not_accepted(self):
        raw = frame(1320, b'x', sequence=0, port=0, legacy=True)
        for changes in ({'address': (1, 0)}, {'address': (0, 1)},
                        {'address': (False, 0)}, {'flags': socket.MSG_TRUNC},
                        {'flags': socket.MSG_CTRUNC}, {'flags': True},
                        {'ancillary': ((socket.SOL_SOCKET, 40, struct.pack('=I', 1)),)},
                        {'ancillary': ((socket.SOL_SOCKET, 40, b''),)},
                        {'ancillary': ((socket.SOL_SOCKET, 1, b'\0' * 4),)},
                        {'ancillary': ((socket.SOL_SOCKET, 40, b'\0' * 4),) * 2}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                decode_event(raw, **changes)
        self.assertEqual(1320, decode_event(raw,
            ancillary=((socket.SOL_SOCKET, 40, b'\0' * 4),)).kind)
        with self.assertRaises(ValueError):
            decode_control(frame(3, b''), sequence=7, port_id=88, address=(1, 0))

    def test_input_and_message_counts_are_bounded_before_decoding(self):
        for raw in ('data', b'', b'x' * 65537):
            with self.subTest(raw_type=type(raw)), self.assertRaises(ValueError):
                decode_event(raw)
            with self.assertRaises(ValueError):
                decode_control(raw, sequence=7, port_id=88)
        with self.assertRaises(ValueError):
            decode_control(frame(3, b'', port=0) * 65, sequence=7, port_id=88)
        with self.assertRaises(ValueError):
            decode_event(frame(1300, b'x' * 8971, sequence=0, port=0, legacy=True))

    def test_actual_recvmsg_ancillary_lists_are_accepted_without_mutation(self):
        raw = frame(1320, b'x', sequence=0, port=0, legacy=True)
        self.assertEqual(1320, decode_event(raw, ancillary=[]).kind)
        ancillary = [(socket.SOL_SOCKET, 40, b'\0' * 4)]
        self.assertEqual(1320, decode_event(raw, ancillary=ancillary).kind)
        self.assertEqual([(socket.SOL_SOCKET, 40, b'\0' * 4)], ancillary)
        self.assertEqual(3, decode_control(frame(3, b'', port=0),
            sequence=7, port_id=88, ancillary=[])[0].kind)
        with self.assertRaises(ValueError):
            decode_event(raw, ancillary=ancillary * 2)

    def test_extended_ack_flags_preserve_opaque_payload_for_caller_semantics(self):
        payload = b'\0' * 20 + b'sensitive-ack-tlv'
        for flags in (512, 768):
            with self.subTest(flags=flags):
                message, = decode_control(frame(2, payload, flags=flags), sequence=7, port_id=88)
                self.assertEqual(payload, message.payload)
                self.assertEqual(flags, message.flags)
                self.assertNotIn('sensitive-ack-tlv', repr(message))
        with self.assertRaises(ValueError):
            decode_control(frame(2, payload, flags=516), sequence=7, port_id=88)
