"""Pure synthetic codec tests with independent byte assembly and HMAC math."""
import hashlib
import socket
import struct
import unittest

import switchlab.radius as codec
from switchlab.radius import RadiusError


# Synthetic test material is generated in memory, never loaded from fixtures.
SECRET = bytes(range(1, 25))
STAMP = 0x65010203
BASE = ((33, b"proxy-a\x00"), (24, b"state\xff\x00"),
        (55, STAMP.to_bytes(4, "big")), (33, b"proxy-b"),
        (25, b"class-a\xff"), (25, b"class-b\x00"), (31, b"02-AA-BB-CC-DD-EE"))
ACCT = ((25, b"class-a\xff"), (44, b"segment-7"), (25, b"class-b\x00"),
        (32, b"lab-nas"), (33, b"accounting-proxy"))


def wire_attributes(attributes):
    # Independent test oracle: do not call the owner's encoder/parser.
    return b"".join(bytes([kind, len(value) + 2]) + value for kind, value in attributes)


def manual_hmac_md5(key, message):
    # RFC2104 equation, independent of hmac.digest used by the implementation.
    if len(key) > 64:
        key = hashlib.md5(key).digest()
    key = key.ljust(64, b"\x00")
    inner = hashlib.md5(bytes(x ^ 0x36 for x in key) + message).digest()
    return hashlib.md5(bytes(x ^ 0x5c for x in key) + inner).digest()


def signed_request(code, identifier, attributes, *, ma=True, secret=SECRET):
    """Independent RFC5176/RFC2866 assembly, not a codec round trip."""
    values = tuple(attributes) + (((80, bytes(16)),) if ma else ())
    body = wire_attributes(values)
    header = bytes([code, identifier]) + (20 + len(body)).to_bytes(2, "big")
    if ma:
        body = body[:-16] + manual_hmac_md5(secret, header + bytes(16) + body)
    request_md5 = hashlib.md5(header + bytes(16) + body + secret).digest()
    return header + request_md5 + body


def signed_response(request, code, attributes=(), *, ma=False, identifier=None, secret=SECRET):
    values = tuple(attributes) + (((80, bytes(16)),) if ma else ())
    body = wire_attributes(values)
    identifier = request[1] if identifier is None else identifier
    header = bytes([code, identifier]) + (20 + len(body)).to_bytes(2, "big")
    if ma:
        body = body[:-16] + manual_hmac_md5(secret, header + request[4:20] + body)
    response_md5 = hashlib.md5(header + request[4:20] + body + secret).digest()
    return header + response_md5 + body


def independent_attributes(packet):
    length = int.from_bytes(packet[2:4], "big")
    values = []
    position = 20
    while position < length:
        n = packet[position + 1]
        values.append((packet[position], packet[position + 2:position + n]))
        position += n
    return tuple(values)


def replace_byte(packet, position):
    position %= len(packet)
    return packet[:position] + bytes([packet[position] ^ 1]) + packet[position + 1:]


def resign_md5(packet, secret=SECRET):
    return packet[:4] + hashlib.md5(packet[:4] + bytes(16) + packet[20:] + secret).digest() + packet[20:]


class CodecTests(unittest.TestCase):
    def reason(self, expected, operation, *args, **kwargs):
        with self.assertRaises(RadiusError) as caught:
            operation(*args, **kwargs)
        self.assertEqual(str(caught.exception), expected)
        self.assertNotIn("class-a", str(caught.exception))
        self.assertNotIn("state", repr(caught.exception) if expected != "ambiguous_state" else "")

    def dynamic(self, attributes=BASE, *, code=43, identifier=7, ma=True):
        return signed_request(code, identifier, attributes, ma=ma)

    def accounting(self, *, identifier=19, attributes=ACCT, status=1):
        return signed_request(4, identifier, (*attributes, (40, status.to_bytes(4, "big"))), ma=False)

    def test_manual_hmac_rfc2202_vector(self):
        self.assertEqual(manual_hmac_md5(bytes([0x0b]) * 16, b"Hi There").hex(),
                         "9294727a3638bb1c13f48ef8158bfc9d")

    def test_manual_hmac_long_key_rfc2202_vector(self):
        self.assertEqual(manual_hmac_md5(bytes([0xaa]) * 80,
                         b"Test Using Larger Than Block-Size Key - Hash Key First").hex(),
                         "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd")

    def test_dynamic_fixed_vector(self):
        packet = self.dynamic()
        self.assertEqual(packet.hex(), DAS_VECTOR)
        parsed = codec.verify_dynamic_request(bytes.fromhex(DAS_VECTOR), SECRET)
        self.assertEqual(parsed.attributes, (*BASE, (80, packet[-16:])))
        self.assertEqual((parsed.code, parsed.identifier, parsed.timestamp, parsed.length),
                         (43, 7, STAMP, len(packet)))
        self.assertEqual(parsed.authenticator, packet[4:20])
        self.assertEqual(parsed.packet, packet)

    def test_dynamic_both_request_codes(self):
        for code in (40, 43):
            with self.subTest(code=code):
                packet = self.dynamic(code=code)
                self.assertEqual(codec.verify_dynamic_request(packet, SECRET).code, code)

    def test_dynamic_padding_ignored(self):
        packet = self.dynamic()
        padded = packet + b"\x50\x00\x37\xff" + bytes(4000)
        parsed = codec.verify_dynamic_request(padded, SECRET)
        self.assertEqual(parsed.packet, packet)
        self.assertEqual(parsed.length, len(packet))
        self.assertEqual(parsed.attributes, codec.verify_dynamic_request(packet, SECRET).attributes)

    def test_dynamic_ma_in_middle(self):
        packet = self.dynamic()
        attrs = list(independent_attributes(packet))
        attrs.insert(2, attrs.pop())
        unsigned = signed_request(43, 7, [(k, bytes(16) if k == 80 else v) for k,v in attrs], ma=False)
        # HMAC with both authenticator and the moved MA value zeroed.
        position = 20 + len(wire_attributes(attrs[:2])) + 2
        ma = manual_hmac_md5(SECRET, unsigned[:4] + bytes(16) + unsigned[20:])
        moved = resign_md5(unsigned[:position] + ma + unsigned[position + 16:])
        self.assertEqual(codec.verify_dynamic_request(moved, SECRET).attributes[2], (80, ma))

    def test_dynamic_missing_ma(self):
        self.reason("missing_message_authenticator", codec.verify_dynamic_request,
                    self.dynamic(ma=False), SECRET)

    def test_dynamic_duplicate_ma(self):
        self.reason("invalid_message_authenticator", codec.verify_dynamic_request,
                    self.dynamic((*BASE, (80, bytes(16)))), SECRET)

    def test_dynamic_short_ma(self):
        self.reason("invalid_message_authenticator", codec.verify_dynamic_request,
                    self.dynamic((*BASE, (80, bytes(15))), ma=False), SECRET)

    def test_dynamic_long_ma(self):
        self.reason("invalid_message_authenticator", codec.verify_dynamic_request,
                    self.dynamic((*BASE, (80, bytes(17))), ma=False), SECRET)

    def test_dynamic_zero_length_ma_value(self):
        self.reason("invalid_message_authenticator", codec.verify_dynamic_request,
                    self.dynamic((*BASE, (80, b"")), ma=False), SECRET)

    def test_dynamic_bad_request_authenticator(self):
        self.reason("invalid_request_authenticator", codec.verify_dynamic_request,
                    replace_byte(self.dynamic(), 4), SECRET)

    def test_dynamic_bad_ma_with_valid_request_authenticator(self):
        self.reason("invalid_message_authenticator", codec.verify_dynamic_request,
                    resign_md5(replace_byte(self.dynamic(), -1)), SECRET)

    def test_dynamic_wrong_secret(self):
        self.reason("invalid_request_authenticator", codec.verify_dynamic_request,
                    self.dynamic(), SECRET + b"x")

    def test_dynamic_changed_identifier(self):
        self.reason("invalid_request_authenticator", codec.verify_dynamic_request,
                    replace_byte(self.dynamic(), 1), SECRET)

    def test_dynamic_changed_code_to_other_request(self):
        packet = self.dynamic()
        self.reason("invalid_request_authenticator", codec.verify_dynamic_request,
                    bytes([40]) + packet[1:], SECRET)

    def test_dynamic_access_ordering_is_invalid(self):
        packet = self.dynamic()
        # Incorrect Access rule: HMAC incorporates the request authenticator.
        wrong_ma = manual_hmac_md5(SECRET, packet[:-16] + bytes(16))
        self.reason("invalid_message_authenticator", codec.verify_dynamic_request,
                    resign_md5(packet[:-16] + wrong_ma), SECRET)

    def test_dynamic_request_md5_must_include_inserted_ma(self):
        packet = self.dynamic()
        wrong_md5 = hashlib.md5(packet[:4] + bytes(16) + packet[20:-16] + bytes(16) + SECRET).digest()
        self.reason("invalid_request_authenticator", codec.verify_dynamic_request,
                    packet[:4] + wrong_md5 + packet[20:], SECRET)

    def test_dynamic_missing_timestamp(self):
        self.reason("missing_event_timestamp", codec.verify_dynamic_request,
                    self.dynamic(tuple(item for item in BASE if item[0] != 55)), SECRET)

    def test_dynamic_duplicate_timestamp(self):
        self.reason("invalid_event_timestamp", codec.verify_dynamic_request,
                    self.dynamic((*BASE, (55, STAMP.to_bytes(4, "big")))), SECRET)

    def test_dynamic_short_timestamp(self):
        self.reason("invalid_event_timestamp", codec.verify_dynamic_request,
                    self.dynamic(tuple((k, b"abc" if k == 55 else v) for k,v in BASE)), SECRET)

    def test_dynamic_long_timestamp(self):
        self.reason("invalid_event_timestamp", codec.verify_dynamic_request,
                    self.dynamic(tuple((k, b"abcde" if k == 55 else v) for k,v in BASE)), SECRET)

    def test_dynamic_no_time_window_gating(self):
        for timestamp in (0, 1, 0xffffffff):
            with self.subTest(timestamp=timestamp):
                values = tuple((k, timestamp.to_bytes(4, "big") if k == 55 else v) for k,v in BASE)
                self.assertEqual(codec.verify_dynamic_request(self.dynamic(values), SECRET).timestamp,
                                 timestamp)

    def test_dynamic_semantics_deferred(self):
        # NAS selector lengths, duplicate State, unsupported controls, and kind0
        # are authenticated raw attributes, not codec matching decisions.
        values = (*BASE, (4, b"bad"), (24, b"second"), (11, b"filter"), (0, b""))
        packet = self.dynamic(values)
        self.assertEqual(codec.verify_dynamic_request(packet, SECRET).attributes[:-1], values)

    def test_dynamic_no_selector_requirement_in_codec(self):
        values = ((55, STAMP.to_bytes(4, "big")),)
        self.assertEqual(codec.verify_dynamic_request(self.dynamic(values), SECRET).attributes[:-1], values)

    def test_dynamic_hidden_repr(self):
        parsed = codec.verify_dynamic_request(self.dynamic(), SECRET)
        self.assertNotIn("state", repr(parsed))
        self.assertNotIn("proxy", repr(parsed))
        self.assertNotIn(str(STAMP), repr(parsed))

    def test_dynamic_response_vectors_and_math(self):
        for code, response_code, error in ((40, 41, None), (40, 42, 503), (43, 44, None), (43, 45, 407)):
            with self.subTest(code=code, response=response_code):
                request = self.dynamic(code=code)
                parsed = codec.verify_dynamic_request(request, SECRET)
                values = tuple((k,v) for k,v in BASE if k == 33 or (k == 24 and code == 43))
                if error is not None:
                    values += ((101, error.to_bytes(4, "big")),)
                expected = signed_response(request, response_code, values, ma=True)
                actual = codec.dynamic_response(parsed, response_code, SECRET, error_cause=error)
                self.assertEqual(actual, expected)
                self.assertEqual(actual.hex(), RESPONSE_VECTORS[response_code])
                self.assertEqual(actual[1], request[1])
                self.assertEqual(int.from_bytes(actual[2:4], "big"), len(actual))
                self.assertEqual(independent_attributes(actual)[:-1], values)
                self.assertEqual(actual[-16:], manual_hmac_md5(SECRET,
                    actual[:4] + request[4:20] + actual[20:-16] + bytes(16)))
                self.assertEqual(actual[4:20], hashlib.md5(
                    actual[:4] + request[4:20] + actual[20:] + SECRET).digest())

    def test_dynamic_response_unchanged_by_request_padding(self):
        packet = self.dynamic()
        first = codec.verify_dynamic_request(packet, SECRET)
        padded = codec.verify_dynamic_request(packet + b"\x00padding", SECRET)
        self.assertEqual(codec.dynamic_response(first, 44, SECRET), codec.dynamic_response(padded, 44, SECRET))

    def test_dynamic_response_empty_echo(self):
        request = self.dynamic(((55, STAMP.to_bytes(4, "big")),))
        response = codec.dynamic_response(codec.verify_dynamic_request(request, SECRET), 44, SECRET)
        self.assertEqual(response, signed_response(request, 44, ma=True))

    def test_dynamic_response_repeated_proxy_and_state_order(self):
        values = ((33, b"z"), (24, b"opaque\xff"), (33, b"a"),
                  (33, b"z"), (55, STAMP.to_bytes(4, "big")))
        parsed = codec.verify_dynamic_request(self.dynamic(values), SECRET)
        response = codec.dynamic_response(parsed, 45, SECRET, error_cause=404)
        self.assertEqual(independent_attributes(response)[:4], values[:4])

    def test_dynamic_response_mismatch_negatives(self):
        parsed = codec.verify_dynamic_request(self.dynamic(), SECRET)
        actual = codec.dynamic_response(parsed, 44, SECRET)
        other_request = self.dynamic(identifier=8)
        attrs = independent_attributes(actual)[:-1]
        self.assertNotEqual(actual, signed_response(other_request, 44, attrs, ma=True))
        self.assertNotEqual(actual, signed_response(parsed.packet, 45, attrs, ma=True))
        self.assertNotEqual(actual, signed_response(parsed.packet, 44, attrs, ma=True, secret=SECRET+b"x"))

    def test_dynamic_response_invalid_request_type(self):
        self.reason("invalid_dynamic_response", codec.dynamic_response, self.dynamic(), 44, SECRET)

    def test_dynamic_response_error_cause_bounds(self):
        parsed = codec.verify_dynamic_request(self.dynamic(), SECRET)
        for value in (-1, 0x100000000, True, "407", 407.0):
            with self.subTest(value_type=type(value).__name__):
                self.reason("invalid_error_cause", codec.dynamic_response,
                            parsed, 45, SECRET, error_cause=value)

    def test_dynamic_response_identifier_boundaries(self):
        for identifier in (0, 255):
            with self.subTest(identifier=identifier):
                packet = self.dynamic(identifier=identifier)
                parsed = codec.verify_dynamic_request(packet, SECRET)
                self.assertEqual(codec.dynamic_response(parsed, 44, SECRET)[1], identifier)

    def test_dynamic_response_budget(self):
        # A valid max-length request can need more space when Error-Cause is added.
        proxies = tuple((33, bytes(253)) for _ in range(15)) + ((33, bytes(225)),)
        packet = self.dynamic((*proxies, (55, STAMP.to_bytes(4, "big"))))
        self.assertEqual(len(packet), 4096)
        parsed = codec.verify_dynamic_request(packet, SECRET)
        self.assertLessEqual(len(codec.dynamic_response(parsed, 44, SECRET)), 4096)
        self.assertLessEqual(len(codec.dynamic_response(parsed, 45, SECRET, error_cause=503)), 4096)

    def test_accounting_fixed_vector(self):
        expected = self.accounting()
        self.assertEqual(expected.hex(), ACCOUNTING_VECTOR)
        actual = codec.accounting_request(19, 1, ACCT, SECRET)
        self.assertEqual(actual, bytes.fromhex(ACCOUNTING_VECTOR))
        self.assertEqual(actual[4:20], hashlib.md5(actual[:4] + bytes(16) + actual[20:] + SECRET).digest())
        self.assertNotEqual(actual[4:20], bytes(16))
        self.assertEqual(independent_attributes(actual), (*ACCT, (40, bytes([0,0,0,1]))))

    def test_accounting_status_types(self):
        for status in (1, 2, 3, 7, 8):
            with self.subTest(status=status):
                actual = codec.accounting_request(0, status, ACCT, SECRET)
                self.assertEqual(actual, self.accounting(identifier=0, status=status))

    def test_accounting_invalid_status_types(self):
        for value in (0, -1, 4, 6, 9, 0x100000000, True, "1", 1.0, None):
            with self.subTest(value_type=type(value).__name__):
                self.reason("invalid_accounting_status", codec.accounting_request, 1, value, ACCT, SECRET)

    def test_accounting_identifier_bounds(self):
        for value in (-1, 256, True, "1", 1.0, None):
            with self.subTest(value_type=type(value).__name__):
                self.reason("invalid_request", codec.accounting_request, value, 1, ACCT, SECRET)
        for value in (0, 255):
            self.assertEqual(codec.accounting_request(value, 1, ACCT, SECRET)[1], value)

    def test_accounting_ordered_opaque_class(self):
        values = ((25, b"a\x00\xff"), (44, b"id"), (25, b"b"), (25, b"a\x00\xff"))
        actual = codec.accounting_request(19, 2, values, SECRET)
        self.assertEqual(independent_attributes(actual)[:-1], values)

    def test_accounting_no_ma_generated(self):
        actual = codec.accounting_request(1, 7, (), SECRET)
        self.assertNotIn(80, [kind for kind,_ in independent_attributes(actual)])

    def test_accounting_reserved_ma_and_status(self):
        for kind in (2, 3, 18, 24, 40, 60, 79, 80):
            with self.subTest(kind=kind):
                self.reason("reserved_accounting_attribute", codec.accounting_request,
                            1, 1, ((kind, bytes(16)),), SECRET)

    def test_accounting_valid_response_without_ma(self):
        request = self.accounting()
        response = signed_response(request, 5, ((33, b"accounting-proxy"),))
        self.assertEqual(response.hex(), ACCOUNTING_RESPONSE_VECTOR)
        parsed = codec.verify_accounting(request, response, SECRET)
        self.assertEqual(parsed.packet, response)
        self.assertEqual(parsed.attributes, ((33, b"accounting-proxy"),))
        self.assertEqual(parsed.code, 5)
        self.assertEqual(parsed.identifier, request[1])

    def test_accounting_empty_response(self):
        request = self.accounting()
        response = signed_response(request, 5)
        parsed = codec.verify_accounting(request, response, SECRET)
        self.assertEqual(parsed.attributes, ())
        self.assertEqual(parsed.length, 20)

    def test_accounting_padding_ignored_on_both(self):
        request = self.accounting()
        response = signed_response(request, 5)
        parsed = codec.verify_accounting(request + b"padding", response + b"\x50\x00padding", SECRET)
        self.assertEqual(parsed.packet, response)
        self.assertEqual(parsed.length, 20)

    def test_accounting_response_opaque_order_preserved(self):
        request = self.accounting()
        values = ((26, b"opaque-a"), (33, b"proxy-a"), (26, b"opaque-b"), (33, b"proxy-b"))
        parsed = codec.verify_accounting(request, signed_response(request, 5, values), SECRET)
        self.assertEqual(parsed.attributes, values)

    def test_accounting_bad_response_authenticator(self):
        request = self.accounting()
        self.reason("invalid_response_authenticator", codec.verify_accounting,
                    request, replace_byte(signed_response(request, 5), 4), SECRET)

    def test_accounting_bad_response_identifier(self):
        request = self.accounting()
        self.reason("uncorrelated_response", codec.verify_accounting,
                    request, signed_response(request, 5, identifier=20), SECRET)

    def test_accounting_wrong_request_response_mismatch(self):
        request = self.accounting()
        other = self.accounting(status=2)
        self.reason("invalid_response_authenticator", codec.verify_accounting,
                    request, signed_response(other, 5), SECRET)

    def test_accounting_bad_request_authenticator(self):
        request = replace_byte(self.accounting(), 4)
        self.reason("invalid_request_authenticator", codec.verify_accounting,
                    request, signed_response(request, 5), SECRET)

    def test_accounting_response_attr_tamper(self):
        request = self.accounting()
        response = signed_response(request, 5, ((33, b"proxy"),))
        self.reason("invalid_response_authenticator", codec.verify_accounting,
                    request, replace_byte(response, len(response)-1), SECRET)

    def test_accounting_request_padding_not_part_of_response_math(self):
        request = self.accounting()
        wrong = bytes([5, request[1], 0, 20])
        response = wrong + hashlib.md5(wrong + request[4:20] + b"padding" + SECRET).digest()
        self.reason("invalid_response_authenticator", codec.verify_accounting,
                    request + b"padding", response, SECRET)

    def test_accounting_bad_request_code(self):
        request = signed_request(1, 19, ACCT, ma=False)
        self.reason("uncorrelated_response", codec.verify_accounting,
                    request, signed_response(request, 5), SECRET)

    def test_accounting_response_hidden_repr(self):
        request = self.accounting()
        parsed = codec.verify_accounting(request, signed_response(request, 5, ((33,b"proxy-private"),)), SECRET)
        self.assertNotIn("proxy-private", repr(parsed))

    def test_accounting_verify_rejects_request_eap_or_ma(self):
        for kind in (79, 80):
            with self.subTest(kind=kind):
                request = self.accounting(attributes=(*ACCT, (kind, bytes(16))))
                self.reason("reserved_accounting_attribute", codec.verify_accounting,
                            request, signed_response(request, 5), SECRET)

    def test_accounting_exact_4096_encoding_rejected(self):
        attributes = tuple((25, bytes(253)) for _ in range(15)) + ((25, bytes(243)),)
        self.assertEqual(len(self.accounting(attributes=attributes)), 4096)
        self.reason("packet_budget", codec.accounting_request, 19, 1, attributes, SECRET)

    def test_accounting_declared_4096_request_rejected(self):
        attributes = tuple((25, bytes(253)) for _ in range(15)) + ((25, bytes(243)),)
        request = self.accounting(attributes=attributes)
        self.assertEqual(len(request), 4096)
        self.reason("invalid_packet_length", codec.verify_accounting,
                    request, signed_response(request, 5), SECRET)

    def test_accounting_declared_4096_response_rejected(self):
        request = self.accounting()
        attributes = tuple((33, bytes(253)) for _ in range(15)) + ((33, bytes(249)),)
        response = signed_response(request, 5, attributes)
        self.assertEqual(len(response), 4096)
        self.reason("invalid_packet_length", codec.verify_accounting, request, response, SECRET)

    def test_accounting_4095_response_plus_padding_allowed(self):
        request = self.accounting()
        attributes = tuple((33, bytes(253)) for _ in range(15)) + ((33, bytes(248)),)
        response = signed_response(request, 5, attributes)
        self.assertEqual(len(response), 4095)
        parsed = codec.verify_accounting(request, response + bytes(30), SECRET)
        self.assertEqual(parsed.packet, response)
        self.assertEqual(parsed.attributes, attributes)

    def test_accounting_wrong_secret(self):
        request = self.accounting()
        self.reason("invalid_request_authenticator", codec.verify_accounting,
                    request, signed_response(request, 5), SECRET + b"x")

    def test_accounting_response_using_zero_request_authenticator_fails(self):
        request = self.accounting()
        # Incorrect accounting response: using zeros instead of request MD5.
        header = bytes([5, request[1], 0, 20])
        response = header + hashlib.md5(header + bytes(16) + SECRET).digest()
        self.reason("invalid_response_authenticator", codec.verify_accounting, request, response, SECRET)

    def test_dynamic_zero_timestamp_value_length(self):
        values = tuple((k, b"" if k == 55 else v) for k,v in BASE)
        self.reason("invalid_event_timestamp", codec.verify_dynamic_request, self.dynamic(values), SECRET)

    def test_accounting_response_extra_attributes_are_opaque(self):
        request = self.accounting()
        # Nonstandard 80 is not an Accounting Message-Authenticator protocol.
        values = ((80, bytes(16)), (18, b"opaque-reply"), (80, b"short"),
                  (79, b"not-eap"), (33, b"proxy"), (80, bytes(17)))
        response = signed_response(request, 5, values)
        parsed = codec.verify_accounting(request, response, SECRET)
        self.assertEqual(parsed.packet, response)
        self.assertEqual(parsed.attributes, values)
        self.assertNotIn("opaque-reply", repr(parsed))
        self.assertNotIn("not-eap", repr(parsed))

    def test_accounting_response_extra_attribute_tamper_fails(self):
        request = self.accounting()
        response = signed_response(request, 5, ((80, bytes(16)),))
        self.reason("invalid_response_authenticator", codec.verify_accounting,
                    request, replace_byte(response, -1), SECRET)

    def test_accounting_response_ma_hmac_is_not_a_substitute_for_response_md5(self):
        request = self.accounting()
        response = signed_response(request, 5, ma=True)
        # This creates an Access-style HMAC, which is still only opaque bytes.
        parsed = codec.verify_accounting(request, response, SECRET)
        self.assertEqual(parsed.attributes, ((80, response[-16:]),))
        self.reason("invalid_response_authenticator", codec.verify_accounting,
                    request, replace_byte(response, 4), SECRET)

    def test_accounting_response_malformed_nonstandard_ma_tlv_fails(self):
        request = self.accounting()
        header = bytes([5, request[1], 0, 22])
        body = bytes([80, 1])
        response = header + hashlib.md5(header + request[4:20] + body + SECRET).digest() + body
        self.reason("invalid_attribute_length", codec.verify_accounting, request, response, SECRET)

    def test_packet_input_types(self):
        request = self.accounting()
        for value in (None, "private-packet", bytearray(request)):
            with self.subTest(value_type=type(value).__name__):
                self.reason("invalid_packet", codec.verify_dynamic_request, value, SECRET)
                self.reason("invalid_packet", codec.verify_accounting, request, value, SECRET)

    def test_invalid_secret_types(self):
        request = self.accounting()
        self.reason("invalid_shared_secret", codec.verify_dynamic_request, self.dynamic(), "private")
        self.reason("invalid_shared_secret", codec.verify_accounting, request, signed_response(request,5), "private")
        self.reason("invalid_shared_secret", codec.accounting_request, 1, 1, (), "private")

    def test_accounting_attribute_validation(self):
        for values in (None, iter(ACCT), ((256,b"a"),), ((True,b"a"),), ((1,"private"),),
                       ((1,b"x"*254),), ((1,),), ((1,b"a",b"b"),), ((1,b""),)*2039):
            with self.subTest(value_type=type(values).__name__):
                self.reason("invalid_attribute", codec.accounting_request, 1, 1, values, SECRET)

    def test_accounting_packet_budget(self):
        maximum = tuple((25, bytes(253)) for _ in range(15)) + ((25, bytes(242)),)
        actual = codec.accounting_request(1, 1, maximum, SECRET)
        self.assertEqual(len(actual), 4095)
        self.assertEqual(int.from_bytes(actual[2:4], "big"), 4095)
        self.reason("packet_budget", codec.accounting_request, 1, 1, (*maximum,(25,b"x")), SECRET)


# Distinct unittest methods preserve exact executed counts for each negative.
def dynamic_bad_code_test(code):
    def check(self):
        self.reason("invalid_dynamic_code", codec.verify_dynamic_request,
                    self.dynamic(code=code), SECRET)
    return check

for _code in (0, 1, 4, 5, 12, 41, 42, 44, 45, 255):
    setattr(CodecTests, "test_dynamic_invalid_code_" + str(_code), dynamic_bad_code_test(_code))


def response_bad_code_test(code):
    def check(self):
        request = self.accounting()
        self.reason("uncorrelated_response", codec.verify_accounting,
                    request, signed_response(request, code), SECRET)
    return check

for _code in (0, 1, 2, 3, 4, 11, 12, 40, 41, 42, 43, 44, 45, 255):
    setattr(CodecTests, "test_accounting_invalid_response_code_" + str(_code), response_bad_code_test(_code))


def dynamic_response_bad_pair_test(request_code, response_code):
    def check(self):
        parsed = codec.verify_dynamic_request(self.dynamic(code=request_code), SECRET)
        self.reason("invalid_dynamic_response", codec.dynamic_response, parsed, response_code, SECRET)
    return check

for _request, _response in ((40,44), (40,45), (43,41), (43,42), (43,12), (43,True), (43,"44")):
    setattr(CodecTests, "test_dynamic_bad_response_pair_" + str(_request) + "_" + str(_response),
            dynamic_response_bad_pair_test(_request, _response))


def malformed_length_test(mutation, reason):
    def check(self):
        self.reason(reason, codec.verify_dynamic_request, mutation(self.dynamic()), SECRET)
        request = self.accounting()
        self.reason(reason, codec.verify_accounting, request, mutation(signed_response(request, 5)), SECRET)
    return check

for _name, _mutation, _reason in (
    ("short_header", lambda p: p[:19], "short_packet"),
    ("below_minimum", lambda p: p[:2] + bytes([0,19]) + p[4:], "invalid_packet_length"),
    ("above_maximum", lambda p: p[:2] + bytes([16,1]) + p[4:] + bytes(4097), "invalid_packet_length"),
    ("truncated", lambda p: p[:2] + (len(p)+1).to_bytes(2,"big") + p[4:], "invalid_packet_length"),
    ("one_attribute_octet", lambda p: p[:2] + bytes([0,21]) + p[4:20] + b"\x01", "invalid_attribute_length"),
    ("zero_attribute_length", lambda p: p[:2] + bytes([0,22]) + p[4:20] + b"\x01\x00", "invalid_attribute_length"),
    ("one_attribute_length", lambda p: p[:2] + bytes([0,22]) + p[4:20] + b"\x01\x01", "invalid_attribute_length"),
    ("attribute_overrun", lambda p: p[:2] + bytes([0,22]) + p[4:20] + b"\x01\x03", "invalid_attribute_length"),
):
    setattr(CodecTests, "test_malformed_" + _name, malformed_length_test(_mutation, _reason))


# Filled from the independent byte equations before exercising the candidate.
DAS_VECTOR = "2b07006fa2a0d8de786543dff0412db239de7924210a70726f78792d610018097374617465ff00370665010203210970726f78792d62190a636c6173732d61ff190a636c6173732d62001f1330322d41412d42422d43432d44442d454550121a80c9926aa633c256b493274956da9b"
ACCOUNTING_VECTOR = "04130054c2319ba30dc0ab125fd13e99f796f05c190a636c6173732d61ff2c0b7365676d656e742d37190a636c6173732d620020096c61622d6e617321126163636f756e74696e672d70726f7879280600000001"
ACCOUNTING_RESPONSE_VECTOR = "05130026195af29d6cdba84216c6fa9e00b61eca21126163636f756e74696e672d70726f7879"
RESPONSE_VECTORS = {41: '2907003955ca7e373c0afd3db0857365b4449131210a70726f78792d6100210970726f78792d625012a429071e2dd340c62a6c0a6c7ec0ec42', 42: '2a07003f76bde2f5081f1d610e27ccbe8e36418e210a70726f78792d6100210970726f78792d626506000001f750123ce03df80dc4f6cc34aa49b0d4620733', 44: '2c07004203de677e3bf731336500b4742f37f4aa210a70726f78792d610018097374617465ff00210970726f78792d625012e8bf4e417c9c3a36928519ebdc8c2a98', 45: '2d070048d60605f02fc75de5e3e0a2c510a544bb210a70726f78792d610018097374617465ff00210970726f78792d6265060000019750125985ba01bd94395741ed9a6020147ea1'}
