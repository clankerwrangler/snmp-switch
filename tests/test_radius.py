import hashlib
import hmac
import struct
from types import SimpleNamespace

import pytest

from switchlab.radius import AccessResult, RadiusError, authorization, encode_attributes, mab_request, packet_attributes, verify_access


SECRET = b"synthetic-test-secret-only"
PEER = ("192.0.2.1", 1812)


def reply(request, values=(), code=2, ma=True):
    body = encode_attributes([*values, *(((80, bytes(16)),) if ma else ())])
    head = bytes((code, request[1])) + struct.pack("!H", 20 + len(body)) + request[4:20]
    if ma:
        body = body[:-16] + hmac.digest(SECRET, head + body, "md5")
    return head[:4] + hashlib.md5(head + body + SECRET).digest() + body


def request():
    return mab_request(5, b"021122aabbcc", [(1, b"021122aabbcc"), (6, struct.pack("!I", 10))], SECRET)


def test_mab_pap_and_request_ma_are_real_and_separate_from_eap():
    packet = request()
    _, values = packet_attributes(packet)
    assert not any(kind == 79 for kind, _ in values)
    assert len([v for k, v in values if k == 80]) == 1
    assert hmac.compare_digest(packet[-16:], hmac.digest(SECRET, packet[:-16] + bytes(16), "md5"))
    encrypted = next(v for k, v in values if k == 2)
    mask = hashlib.md5(SECRET + packet[4:20]).digest()
    assert bytes(a ^ b for a, b in zip(encrypted, mask)) == b"021122aabbcc" + bytes(4)
    assert b"021122aabbcc" not in encrypted
    assert packet != request()


@pytest.mark.parametrize("code,eap_code", [(2, 4), (3, 3)])
def test_authenticated_nas_code_is_not_peer_eap_code(code, eap_code):
    req = request()
    result = verify_access(req, reply(req, [(79, bytes((eap_code, 0, 0, 4)))], code), SECRET, PEER)
    assert result.code == code


def test_ordered_repeated_values_and_padding():
    req = request()
    values = [(25, b"one"), (24, b"opaque"), (25, b"two")]
    wire = reply(req, values)
    result = verify_access(req, wire + b"ignored padding", SECRET, PEER)
    assert result.attributes[:-1] == tuple(values)
    assert result.request_authenticator == req[4:20]
    assert b"opaque" not in repr(result).encode()


@pytest.mark.parametrize("fault", ["missing", "short", "long", "duplicate", "bad-ma", "bad-response", "identifier", "old-request", "eap-length"])
def test_invalid_packet_cannot_become_access_result(fault):
    req = request()
    if fault == "missing":wire = reply(req, ma=False)
    elif fault in ("short", "long", "duplicate"):
        wire = reply(req, [(80, bytes({"short": 15, "long": 17, "duplicate": 16}[fault]))])
    elif fault == "eap-length":wire = reply(req, [(79, b"\x04\x00\x00\x08")])
    else:
        wire = bytearray(reply(req))
        if fault == "bad-ma":wire[-1] ^= 1
        elif fault == "bad-response":wire[4] ^= 1
        elif fault == "identifier":wire[1] ^= 1
        elif fault == "old-request":req = request()
        wire = bytes(wire)
    with pytest.raises(RadiusError):verify_access(req, wire, SECRET, PEER)


def policy(values, forbidden=()):
    return authorization(AccessResult(2, tuple(values), PEER, bytes(16)), SimpleNamespace(pvid=1, forbidden=forbidden), {1, 20})


def vlan(tag=0, vid=b"20"):
    return [(64, bytes((tag, 0, 0, 13))), (65, bytes((tag, 0, 0, 6))), (81, bytes((tag,)) + vid)]


def test_policy_distinguishes_baseline_and_explicit_and_preserves_zero():
    assert (policy([]).vid, policy([]).source) == (1, "port-default")
    result = policy(vlan(2) + [(25, b"a"), (25, b"b"), (27, bytes(4)), (28, struct.pack("!I", 60)), (29, struct.pack("!I", 1))])
    assert (result.vid, result.source, result.session_timeout, result.idle_timeout, result.termination_action) == (20, "radius", 0, 60, 1)
    assert result.classes == (b"a", b"b")


@pytest.mark.parametrize("values", [vlan()[:-1], vlan()+vlan(), vlan()+vlan(2), vlan(vid=b"4095"), vlan(vid=b"name"), [(11,b"filter")], [(6,struct.pack("!I",17))], [(29,struct.pack("!I",2))]])
def test_unusable_policy_is_not_accept_fallback(values):
    with pytest.raises(RadiusError):policy(values)


def test_forbidden_explicit_vlan_is_rejected_without_saved_membership_change():
    with pytest.raises(RadiusError):policy(vlan(), [20])


@pytest.mark.parametrize("kind", [7,13,8,9,10,22,23,11,12,14,15,16,19,20,34,35,36,37,38,39,62,63,88,96,97,98,99,100,66,67,69,82,90,91])
def test_recognized_unavailable_control_never_becomes_unrestricted_access(kind):
    with pytest.raises(RadiusError, match="unsupported_access_control"):
        policy([(kind, b"requested-control")])


def test_duplicate_service_type_even_if_equal_is_invalid():
    with pytest.raises(RadiusError):policy([(6, struct.pack("!I", 2)), (6, struct.pack("!I", 2))])
    for service in (8, 10, 17):
        with pytest.raises(RadiusError):policy([(6, struct.pack("!I", service))])


def vendor(*subtypes):
    return struct.pack("!I",311) + b"".join(bytes((subtype,20))+b"\x80\x01"+bytes(16) for subtype in subtypes)


def test_native_mppe_key_envelope_is_private_not_an_extra_grant_floor():
    result = policy(vlan()+[(26,vendor(16)),(26,vendor(17))])
    assert result.vid == 20
    assert "vendor" not in vars(result) and not any(isinstance(v,bytes) and vendor(16) in v for v in vars(result).values())
    assert policy([(26,vendor(16,17))]).source == "port-default"


@pytest.mark.parametrize("value", [b"",struct.pack("!I",311),struct.pack("!I",999)+b"\x10\x02",vendor(16,99),vendor(99,17),struct.pack("!I",311)+b"\x10\x01",struct.pack("!I",311)+b"\x10\x20"+bytes(3),vendor(16)+b"\x11"])
def test_malformed_unknown_and_mixed_vendor_policy_cannot_hide_after_valid_prefix(value):
    with pytest.raises(RadiusError):policy(vlan()+[(26,value)])


@pytest.mark.parametrize("kind", [24,25])
def test_empty_opaque_values_are_invalid(kind):
    with pytest.raises(RadiusError):policy([(kind,b"")])


def test_informational_metadata_is_not_a_filter_or_public_configuration():
    value = policy([(1,b"identity"),(18,b"private text"),(33,b"opaque proxy"),(77,b"Ethernet"),(25,b"opaque class")])
    assert value.vid == 1 and value.classes == (b"opaque class",)
