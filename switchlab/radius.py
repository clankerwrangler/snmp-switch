from __future__ import annotations

import asyncio
import hashlib
import hmac
import secrets
import struct
from dataclasses import dataclass, field, replace


class RadiusError(ValueError):
    """A fixed, nonsecret protocol or policy reason."""


@dataclass(frozen=True, repr=False)
class AccessResult:
    code: int
    attributes: tuple[tuple[int, bytes], ...] = field(repr=False)
    peer: tuple[str, int]
    request_authenticator: bytes = field(repr=False)
    peer_result: int = 0
    tls_errors: int = 0


@dataclass(frozen=True, repr=False)
class NasIdentity:
    identifier: bytes = field(repr=False)
    ipv4: bytes | None = None


def resolve_nas_identity(cfg):
    import ipaddress
    value = cfg.radius.nas_identifier if cfg.radius.nas_identifier is not None else cfg.switch.name
    try:
        encoded = value.encode("utf-8")
    except UnicodeError:
        raise RadiusError("nas_identifier_override_required") from None
    if not 1 <= len(encoded) <= 253:
        raise RadiusError("nas_identifier_override_required")
    advertised = ipaddress.IPv4Address(cfg.radius.nas_ip_address).packed if cfg.radius.nas_ip_address is not None else None
    return NasIdentity(encoded, advertised)


@dataclass(frozen=True, repr=False)
class Authorization:
    vid: int
    source: str
    session_timeout: int | None = None
    idle_timeout: int | None = None
    termination_action: int = 0
    classes: tuple[bytes, ...] = field(default=(), repr=False)
    state: bytes | None = field(default=None, repr=False)
    interim_seconds: int | None = None
    accounting_warning: str | None = None
    username: bytes | None = field(default=None, repr=False)


def packet_attributes(packet: bytes):
    if len(packet) < 20:
        raise RadiusError("short_packet")
    size = int.from_bytes(packet[2:4], "big")
    if not 20 <= size <= 4096 or size > len(packet):
        raise RadiusError("invalid_packet_length")
    # RFC 2865/5176: UDP padding is not part of the authenticated packet.
    packet = packet[:size]
    values = []
    position = 20
    while position < size:
        if position + 2 > size or packet[position + 1] < 2:
            raise RadiusError("invalid_attribute_length")
        end = position + packet[position + 1]
        if end > size:
            raise RadiusError("invalid_attribute_length")
        values.append((packet[position], packet[position + 2:end]))
        position = end
    return packet, tuple(values)


def encode_attributes(values):
    encoded = bytearray()
    for kind, value in values:
        if type(kind) is not int or not 1 <= kind <= 255 or not isinstance(value, bytes) or len(value) > 253:
            raise RadiusError("invalid_attribute")
        encoded.extend(bytes((kind, len(value) + 2)) + value)
    if len(encoded) > 4076:
        raise RadiusError("packet_budget")
    return bytes(encoded)


def _message_authenticator(packet):
    zeroed = bytearray(packet)
    found = None
    position = 20
    while position < len(packet):
        length = packet[position + 1]
        if packet[position] == 80:
            if found is not None or length != 18:
                raise RadiusError("invalid_message_authenticator")
            found = bytes(packet[position + 2:position + 18])
            zeroed[position + 2:position + 18] = bytes(16)
        position += length
    if found is None:
        raise RadiusError("missing_message_authenticator")
    return zeroed, found


def verify_access(request: bytes, response: bytes, secret: bytes, peer: tuple[str, int]):
    request, _ = packet_attributes(request)
    response, values = packet_attributes(response)
    if request[0] != 1 or response[0] not in (2, 3, 11) or response[1] != request[1]:
        raise RadiusError("uncorrelated_response")
    zeroed, actual_ma = _message_authenticator(response)
    zeroed[4:20] = request[4:20]
    if not hmac.compare_digest(hmac.digest(secret, zeroed, "md5"), actual_ma):
        raise RadiusError("invalid_message_authenticator")
    expected = hashlib.md5(response[:4] + request[4:20] + response[20:] + secret).digest()
    if not hmac.compare_digest(expected, response[4:20]):
        raise RadiusError("invalid_response_authenticator")
    eap = bytearray()
    seen = ended = False
    for kind, value in values:
        if kind == 79:
            if ended:
                raise RadiusError("nonconsecutive_eap_fragments")
            eap.extend(value)
            seen = True
        elif seen:
            ended = True
    if seen and (len(eap) < 4 or int.from_bytes(eap[2:4], "big") != len(eap) or
                 eap[0] not in (1, 2, 3, 4) or
                 (len(eap) < 5 if eap[0] in (1, 2) else len(eap) != 4)):
        raise RadiusError("malformed_eap")
    # The authenticated RADIUS code, not EAP/MPPE/exit success, owns the NAS result.
    return AccessResult(response[0], values, peer, request[4:20])


def mab_request(identifier, password: bytes, attributes, secret: bytes):
    if type(identifier) is not int or not 0 <= identifier <= 255 or not 1 <= len(password) <= 128:
        raise RadiusError("invalid_request")
    if any(kind in (2, 79, 80) for kind, _ in attributes):
        raise RadiusError("reserved_request_attribute")
    authenticator = secrets.token_bytes(16)
    padded = password + bytes((-len(password)) % 16)
    encrypted = bytearray()
    previous = authenticator
    for offset in range(0, len(padded), 16):
        mask = hashlib.md5(secret + previous).digest()
        previous = bytes(a ^ b for a, b in zip(padded[offset:offset + 16], mask))
        encrypted.extend(previous)
    body = encode_attributes([*attributes, (2, bytes(encrypted)), (80, bytes(16))])
    request = struct.pack("!BBH", 1, identifier, 20 + len(body)) + authenticator + body
    return request[:-16] + hmac.digest(secret, request, "md5")


# Recognized controls this Ethernet simulator cannot apply (RFC 2865/3580).
# Informational/opaque attributes are not all filters. Unknown vendor semantics
# are handled separately by the deliberately narrow native-key exception.
UNSUPPORTED_ACCESS_CONTROLS = frozenset({
    7, 13,                          # Non-Ethernet framing/compression.
    8, 9, 10, 22, 23,               # IP/IPX assignment and routing.
    11, 12,                        # Filters and per-session MTU enforcement.
    14, 15, 16, 19, 20,             # Login, callback, and redirection.
    34, 35, 36, 37, 38, 39, 62, 63, # LAT, AppleTalk, and multilink services.
    88, 96, 97, 98, 99, 100,        # Address pools and IPv6 services.
    66, 67, 69, 82, 90, 91,         # Non-VLAN tunnel endpoints/credentials.
})
# 1/18/33/77: identity/information/protocol metadata, never configuration or
# public diagnostic text. 79/80: transport. 85: accounting, not access policy.


def authorization(result: AccessResult, port, vlans):
    if result.code != 2:
        raise RadiusError("not_access_accept")
    groups = {}
    controls = {}
    classes = []
    state = None
    service_seen = False
    for kind, value in result.attributes:
        if kind in UNSUPPORTED_ACCESS_CONTROLS:
            raise RadiusError("unsupported_access_control")
        if kind == 6:
            if service_seen or len(value) != 4 or int.from_bytes(value, "big") != 2:
                raise RadiusError("unsupported_service")
            service_seen = True
        elif kind == 26:
            # Only the native peer consumes these opaque key bytes. They never
            # enter Authorization, Runtime, snapshots, or diagnostics.
            if len(value) < 6 or int.from_bytes(value[:4], "big") != 311:
                raise RadiusError("unsupported_vendor")
            position = 4
            while position < len(value):
                if position + 2 > len(value) or value[position + 1] < 2:
                    raise RadiusError("malformed_vendor")
                end = position + value[position + 1]
                if end > len(value):
                    raise RadiusError("malformed_vendor")
                if value[position] not in (16, 17):
                    raise RadiusError("unsupported_vendor")
                position = end
        elif kind in (64, 65, 81):
            if kind in (64, 65):
                if len(value) != 4 or value[0] > 31:
                    raise RadiusError("malformed_tunnel")
                tag, decoded = value[0], int.from_bytes(value[1:], "big")
            else:
                if not value:
                    raise RadiusError("malformed_tunnel")
                tag = value[0] if value[0] <= 31 else 0
                decoded = value[1:] if value[0] <= 31 else value
            group = groups.setdefault(tag, {})
            if kind in group:
                raise RadiusError("ambiguous_tunnel")
            group[kind] = decoded
        elif kind in (27, 28, 29):
            if kind in controls or len(value) != 4:
                raise RadiusError("invalid_session_control")
            controls[kind] = int.from_bytes(value, "big")
            if kind == 29 and controls[kind] not in (0, 1):
                raise RadiusError("unsupported_termination_action")
        elif kind == 25:
            if not value:
                raise RadiusError("invalid_class")
            classes.append(value)
        elif kind == 24:
            if not value or state is not None:
                raise RadiusError("ambiguous_state")
            state = value
    vid, source = port.pvid, "port-default"
    if groups:
        if len(groups) != 1:
            raise RadiusError("ambiguous_tunnel")
        group = next(iter(groups.values()))
        if set(group) != {64, 65, 81} or group[64] != 13 or group[65] != 6:
            raise RadiusError("unsupported_tunnel")
        raw = group[81]
        if not raw or not raw.isdigit():
            raise RadiusError("invalid_vlan")
        vid, source = int(raw), "radius"
    if not 1 <= vid <= 4094 or vid not in vlans or vid in port.forbidden:
        raise RadiusError("unusable_vlan")
    intervals = [value for kind,value in result.attributes if kind == 85]
    interval = None
    warning = None
    if intervals:
        if len(intervals) == 1 and len(intervals[0]) == 4 and int.from_bytes(intervals[0], "big") >= 60:
            interval = int.from_bytes(intervals[0], "big")
        else:
            warning = "invalid-server-interim-interval"
    names = [value for kind,value in result.attributes if kind == 1]
    username = names[0] if len(names) == 1 and names[0] else None
    return Authorization(vid, source, controls.get(27), controls.get(28), controls.get(29, 0), tuple(classes), state,
                         interval, warning, username)


@dataclass(frozen=True, repr=False)
class NativeObservation:
    result: AccessResult | None = field(repr=False)
    peer_result: int
    tls_errors: int
    eap_frames: int
    challenges: int
    timed_out: bool
    preparation_failed: bool
    invalid_replies: int = 0
    unanswered_retries: int = 0


class _NativeDecoder:
    """One bounded frame/packet owner; only finish() releases a NAS decision."""
    header = struct.Struct("!4sBBHII")

    def __init__(self, peer, secret, source_address=None, on_response=None):
        self.peer, self.secret, self.source_address = peer, secret, source_address
        self.on_response = on_response
        self.buffer = bytearray()
        self.total = 0
        self.sequence = 1
        self.requests, self.consumed, self.transmissions = {}, set(), {}
        self.local = self.result = self.terminal = None
        self.frames = self.challenges = self.invalid_replies = 0
        self.eap_events = []
        self.failed = False
        self.ended = False

    def feed(self, data):
        if self.failed or self.ended:
            raise RadiusError("native_failed_channel")
        try:
            self._feed(data)
        except BaseException:
            self.failed = True
            raise

    def _feed(self, data):
        self.total += len(data)
        if self.total > 1048576:
            raise RadiusError("native_channel_size")
        self.buffer.extend(data)
        while len(self.buffer) >= self.header.size:
            magic, kind, flags, reserved, size, sequence = self.header.unpack_from(self.buffer)
            if (self.terminal is not None or magic != b"SLR1" or flags or reserved or
                    sequence != self.sequence or sequence > 512 or size > 8176):
                raise RadiusError("native_frame_header")
            if len(self.buffer) < self.header.size + size:
                return
            payload = bytes(self.buffer[self.header.size:self.header.size + size])
            del self.buffer[:self.header.size + size]
            self.sequence += 1
            self._frame(kind, payload)

    def _frame(self, kind, payload):
        import ipaddress
        if kind in (1, 2):
            if len(payload) < 84 or payload[0] not in (4, 6) or any(payload[1:4]) or any(payload[60:64]):
                raise RadiusError("native_packet_metadata")
            width = 4 if payload[0] == 4 else 16
            remote = (str(ipaddress.ip_address(payload[8:8+width])), int.from_bytes(payload[4:6], "big"))
            local = (str(ipaddress.ip_address(payload[24:24+width])), int.from_bytes(payload[6:8], "big"))
            if (remote != self.peer or not local[1] or
                    (self.source_address is not None and local[0] != self.source_address) or
                    (self.local is not None and local != self.local)):
                raise RadiusError("native_peer_mismatch")
            self.local = local
            if width == 4 and (any(payload[12:24]) or any(payload[28:40])):
                raise RadiusError("native_address_padding")
            packet, _ = packet_attributes(payload[64:])
            if len(packet) != len(payload) - 64 or len(packet) != int.from_bytes(payload[56:60], "big"):
                raise RadiusError("native_packet_size")
            key = (packet[1], payload[40:56])
            if kind == 1:
                if self.result is not None or packet[0] != 1 or key[1] != packet[4:20] or key in self.consumed:
                    raise RadiusError("native_request_record")
                zeroed, authenticator = _message_authenticator(packet)
                if not hmac.compare_digest(authenticator, hmac.digest(self.secret, zeroed, "md5")):
                    raise RadiusError("native_request_integrity")
                if key in self.requests and self.requests[key] != packet:
                    raise RadiusError("native_request_reuse")
                self.requests[key] = packet
                self.transmissions[key] = self.transmissions.get(key, 0) + 1
            else:
                if key not in self.requests or key in self.consumed or self.result is not None:
                    raise RadiusError("native_uncorrelated_response")
                received = verify_access(self.requests[key], packet, self.secret, self.peer)
                self.consumed.add(key)
                if received.code == 11:
                    self.challenges += 1
                else:
                    self.result = received
                if self.on_response is not None:
                    self.on_response()
        elif kind == 3:
            if (len(payload) != 16 or payload[0] not in (1, 2) or payload[1] not in (1, 2, 3) or
                    payload[2] > 4 or any(payload[14:])):
                raise RadiusError("native_eap_event")
            self.frames += 1
            self.eap_events.append(payload)
        elif kind in (4, 5, 6):
            if len(payload) != 4:
                raise RadiusError("native_numeric_event")
            number = int.from_bytes(payload, "big")
            if (kind == 5 and number not in (1, 2, 3)) or (kind == 6 and number != 1):
                raise RadiusError("native_numeric_value")
            if kind == 6:
                self.invalid_replies += 1
        elif kind == 7:
            if len(payload) != 32:
                raise RadiusError("native_terminal_size")
            self.terminal = struct.unpack("!8I", payload)
            if (any(self.terminal[i] not in (0, 1) for i in (0, 1, 2, 7)) or
                    self.terminal[6] not in (0, 1, 2, 3) or self.terminal[3] > 2147483647 or self.terminal[4] > 2147483647):
                raise RadiusError("native_terminal_value")
        else:
            raise RadiusError("native_unknown_frame")

    def finish(self):
        if self.failed or self.ended:
            raise RadiusError("native_failed_channel")
        self.ended = True
        if not self.total or self.buffer:
            raise RadiusError("native_partial_or_empty_channel")
        if self.terminal is None:
            raise RadiusError("native_missing_terminal")
        code = self.result.code if self.result else None
        if self.terminal[0] != (code == 2) or self.terminal[1] != (code == 3):
            raise RadiusError("native_terminal_disagreement")
        result = self.result
        if result is not None:
            result = AccessResult(result.code, result.attributes, result.peer, result.request_authenticator, self.terminal[6], self.terminal[5])
        unanswered = max((count for key,count in self.transmissions.items() if key not in self.consumed), default=0)
        return NativeObservation(result, self.terminal[6], self.terminal[5], self.frames, self.challenges,
            bool(self.terminal[2]), bool(self.terminal[7]), self.invalid_replies, unanswered)


def native_observation(stream: bytes, peer, secret: bytes, source_address=None):
    decoder = _NativeDecoder(peer, secret, source_address)
    decoder.feed(stream)
    return decoder.finish()


def safe_access_summary(result):
    """Public typed facts from an authenticated reply, never effective defaults."""
    names = {6:"Service-Type",64:"Tunnel-Type",65:"Tunnel-Medium-Type",81:"Tunnel-Private-Group-ID",
             27:"Session-Timeout",28:"Idle-Timeout",29:"Termination-Action",85:"Acct-Interim-Interval"}
    hidden = {1:"User-Name",24:"State",25:"Class",26:"Vendor-Specific",33:"Proxy-State",79:"EAP-Message",80:"Message-Authenticator"}
    values = {}
    for kind,value in result.attributes:values.setdefault(kind,[]).append(value)
    decoded = []
    for kind,name in names.items():
        items = values.get(kind,[])
        item = dict(name=name,status="absent" if not items else "invalid")
        if len(items) == 1:
            raw = items[0]
            value = None
            if kind == 81:
                text = raw[1:] if raw and raw[0] <= 31 else raw
                if text and all(48 <= byte <= 57 for byte in text):
                    numeric = int(text)
                    if 1 <= numeric <= 4094:value = numeric
            elif kind in (64,65):
                if len(raw)==4 and raw[0] <= 31:value = int.from_bytes(raw[1:],"big")
            elif len(raw)==4:
                value = int.from_bytes(raw,"big")
                if (kind==29 and value not in (0,1)) or (kind==85 and value<60):value = None
            if value is not None:item.update(status="present",value=value)
        decoded.append(item)
    omitted = [dict(name=hidden.get(kind,f"Attribute {kind}"),count=len(items))
               for kind,items in sorted(values.items()) if kind not in names]
    return dict(nas_code=result.code,attributes=decoded,omitted=omitted)


def station_id(address, settings):
    value = address.replace(":", "")
    if settings.station_case == "upper":
        value = value.upper()
    return settings.station_separator.join(value[i:i+2] for i in range(0, 12, 2))


def access_attributes(settings, port, address, session_id, state=None, *, nas_identity):
    """NAS-Port is the bridge port, not the PAE/IF-MIB interface index."""
    import ipaddress
    values = [(5, struct.pack("!I", port.bridge_port)), (61, struct.pack("!I", 15)),
              (87, port.name.encode()), (31, station_id(address, settings).encode()),
              (44, session_id.encode())]
    if not isinstance(nas_identity, NasIdentity) or not 1 <= len(nas_identity.identifier) <= 253:
        raise RadiusError("nas_identifier_override_required")
    values.append((32, nas_identity.identifier))
    if nas_identity.ipv4 is not None:
        if len(nas_identity.ipv4) != 4:
            raise RadiusError("invalid_advertised_ipv4")
        values.append((4, nas_identity.ipv4))
    if state is not None:
        values.append((24, state))
    encode_attributes(values)
    return tuple(values)


def eap_capability(executable="/usr/local/bin/eapol_test"):
    """Match the installed helper to its build receipt, without private inputs."""
    import json
    import os
    import sys
    from pathlib import Path
    if not sys.platform.startswith("linux"):
        return {"available": False, "reason": "eap_platform_unsupported"}
    binary = Path(executable)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        return {"available": False, "reason": "eap_helper_missing"}
    try:
        receipt = binary.with_name(binary.name + ".switchlab.json")
        if receipt.stat().st_size > 16384 or not 0 < binary.stat().st_size <= 16777216:
            raise ValueError()
        manifest = json.loads(receipt.read_text())
        if (manifest.get("interface") != "SLR1" or manifest.get("upstream") != "2.12" or
                manifest.get("security_fix") != "aa02cfa569477f67f3915c8b9a83d1a7ca93693d" or
                manifest.get("managed_patch_sha256") != "226721ea0081ce5b8459d1ed629ccc6a59588cfba1588a2b38d526a60faebd29" or
                manifest.get("binary_sha256") != hashlib.sha256(binary.read_bytes()).hexdigest()):
            raise ValueError()
    except (OSError, ValueError, TypeError, AttributeError):
        return {"available": False, "reason": "eap_helper_incompatible"}
    return {"available": True, "reason": None, "upstream": "2.12", "interface": "SLR1"}


async def native_exchange(settings, server, profile, port, address, session_id, *, nas_identity, state=None, on_response=None, on_eap_events=None,
                          executable="/usr/local/bin/eapol_test", temporary_parent=None):
    """One owned EAP exchange. Cancellation reaps it; only a complete channel returns.

    Call outside Engine/SNMP locks. The Engine separately validates its captured
    attempt before consuming the observation. Private files never enter argv or
    environment as values; diagnostic output has no result/authorization role.
    """
    import asyncio
    import os
    import signal
    import tempfile
    from pathlib import Path

    attributes = access_attributes(settings, port, address, session_id, state, nas_identity=nas_identity)
    capability = eap_capability(executable)
    if not capability["available"]:
        raise RadiusError(capability["reason"])
    process = transport = pipe_file = None
    reader_fd = writer_fd = None
    with tempfile.TemporaryDirectory(prefix="switchlab-radius-", dir=temporary_parent) as directory:
        root = Path(directory)
        def write(name, value):
            path = root / name
            with path.open("xb") as output:
                os.chmod(path, 0o600)
                output.write(value)
            return path
        def text(value):
            return value.encode().hex()
        trust = settings.materials[profile.trust_id]
        ca = write("ca.pem", trust.certificate.encode())
        config = ["network={", "key_mgmt=IEEE8021X", "eap=" + profile.method.upper(),
                  "identity=" + text(profile.username if profile.method == "peap" else profile.identity),
                  "ca_cert=" + text(str(ca)), "domain_match=" + text(profile.server_name),
                  'phase1="tls_disable_tlsv1_0=1 tls_disable_tlsv1_1=1 tls_disable_tlsv1_3=1"',
                  "fragment_size=1024", "eapol_flags=0"]
        if profile.method == "peap":
            config += ["anonymous_identity=" + text(profile.identity), "password=" + text(profile.password),
                       'phase2="auth=MSCHAPV2"']
        else:
            identity = settings.materials[profile.client_identity_id]
            certificate = write("client.pem", identity.certificate.encode())
            key = write("client.key", identity.private_key.encode())
            config += ["client_cert=" + text(str(certificate)), "private_key=" + text(str(key))]
            if identity.key_password:
                config.append("private_key_passwd=" + text(identity.key_password))
        config += ["}", ""]
        config_path = write("network.conf", "\n".join(config).encode())
        secret = server.secret.encode()
        secret_path = write("secret", secret)
        attribute_path = write("attributes", b"".join(str(k).encode() + b":x:" + v.hex().encode() + b"\n" for k,v in attributes))
        try:
            reader_fd, writer_fd = os.pipe()
            pipe_file = os.fdopen(reader_fd, "rb", buffering=0)
            reader_fd = None
            reader = asyncio.StreamReader(limit=16384)
            transport, _ = await asyncio.get_running_loop().connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), pipe_file)
            command = [executable, "-c", str(config_path), "-a", server.address, "-p", str(server.port),
                       "-F", str(secret_path), "-G", str(attribute_path), "-M", address,
                       "-t", str(settings.exchange_timeout_seconds), "-r", "0", "-B", str(writer_fd),
                       "-b", str(settings.response_timeout_seconds), "-q", str(settings.attempts)]
            if server.source_address:
                command += ["-A", server.source_address]
            process = await asyncio.create_subprocess_exec(*command, stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
                pass_fds=(writer_fd,), start_new_session=True, umask=0o077,
                env={"PATH":"/usr/local/bin:/usr/bin:/bin", "LANG":"C.UTF-8", "LC_ALL":"C.UTF-8"})
            os.close(writer_fd)
            writer_fd = None
            decoder = _NativeDecoder((server.address, server.port), secret, server.source_address, on_response)
            async with asyncio.timeout(settings.exchange_timeout_seconds + 3):
                while block := await reader.read(8192):
                    decoder.feed(block)
                    if decoder.eap_events:
                        events, decoder.eap_events = tuple(decoder.eap_events), []
                        if on_eap_events is not None:
                            await on_eap_events(events)
                await process.wait()
            # Exit status / MPPE / peer success do not authorize or override NAS type.
            return decoder.finish()
        except TimeoutError:
            raise RadiusError("native_deadline") from None
        except OSError:
            raise RadiusError("native_unavailable") from None
        finally:
            if writer_fd is not None:
                os.close(writer_fd)
            if transport is not None:
                transport.close()
            elif pipe_file is not None:
                pipe_file.close()
            if reader_fd is not None:
                os.close(reader_fd)
            if process is not None and process.returncode is None:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    await asyncio.wait_for(process.wait(), 1)
                except TimeoutError:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    await process.wait()


def mab_username(address, settings):
    value = address.replace(":", "")
    if settings.mab_case == "upper":
        value = value.upper()
    return settings.mab_separator.join(value[i:i+2] for i in range(0, 12, 2)).encode()


async def mab_exchange(settings, server, profile, port, address, session_id, *, nas_identity, state=None, on_response=None, on_eap_events=None):
    """One connected UDP request with bounded retries; no EAP helper dependency."""
    import asyncio
    import ipaddress
    import socket
    values = list(access_attributes(settings, port, address, session_id, state, nas_identity=nas_identity))
    username = mab_username(address, settings)
    values += [(1, username), (6, struct.pack("!I", 10))]
    try:
        secret = server.secret.encode("utf-8")
    except UnicodeError:
        raise RadiusError("invalid_shared_secret") from None
    request = mab_request(secrets.randbelow(256), username, values, secret)
    family = socket.AF_INET6 if ipaddress.ip_address(server.address).version == 6 else socket.AF_INET
    loop = asyncio.get_running_loop()
    invalid, received_bytes = 0, 0
    stage = "socket"
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as udp:
            udp.setblocking(False)
            stage = "bind"
            udp.bind((server.source_address or ("::" if family == socket.AF_INET6 else "0.0.0.0"), 0))
            stage = "connect"
            await loop.sock_connect(udp, (server.address, server.port))
            for _ in range(settings.attempts):
                stage = "send"
                sent = await loop.sock_sendto(udp, request, (server.address, server.port))
                if sent != len(request):
                    raise RadiusError("access_send_failed")
                try:
                    async with asyncio.timeout(settings.response_timeout_seconds):
                        while True:
                            stage = "receive"
                            response = await loop.sock_recv(udp, 4097)
                            received_bytes += len(response)
                            if received_bytes > 1048576 or invalid >= 512:
                                raise RadiusError("access_packet_budget")
                            try:
                                result = verify_access(request, response, secret, (server.address, server.port))
                            except RadiusError:
                                invalid += 1
                                continue
                            if on_response is not None:
                                on_response()
                            stage = "close"
                            return NativeObservation(result, 0, 0, 0, int(result.code == 11), False, False, invalid)
                except TimeoutError:
                    continue
            stage = "close"
    except OSError as error:
        import errno
        # Fixed categories only: OS messages can contain addresses or private text.
        category = {
            errno.EADDRNOTAVAIL: "address_not_available",
            errno.EAFNOSUPPORT: "address_family_not_supported",
            errno.ENETUNREACH: "unreachable", errno.EHOSTUNREACH: "unreachable",
            errno.ECONNREFUSED: "refused",
            errno.EACCES: "permission_denied", errno.EPERM: "permission_denied",
        }.get(error.errno, "failed")
        raise RadiusError(f"access_transport_{stage}_{category}") from None
    return NativeObservation(None, 0, 0, 0, 0, True, False, invalid, settings.attempts)


@dataclass(frozen=True, repr=False)
class _RadiusPacket:
    packet: bytes = field(repr=False)
    attributes: tuple[tuple[int, bytes], ...] = field(repr=False)

    @property
    def code(self):
        return self.packet[0]

    @property
    def identifier(self):
        return self.packet[1]

    @property
    def authenticator(self):
        return self.packet[4:20]

    @property
    def length(self):
        return len(self.packet)


@dataclass(frozen=True, repr=False)
class _DynamicRequest(_RadiusPacket):
    timestamp: int


def _codec_packet(packet):
    if not isinstance(packet, bytes):
        raise RadiusError("invalid_packet")
    return packet_attributes(packet)


def _codec_secret(secret):
    # Secret content/selection belongs to the captured configuration owner.
    if not isinstance(secret, bytes):
        raise RadiusError("invalid_shared_secret")


def _codec_attributes(attributes):
    # Existing Engine callers use finite sequences, not streaming iterators.
    if not isinstance(attributes, (tuple, list)) or len(attributes) > 2038:
        raise RadiusError("invalid_attribute")
    try:
        body = encode_attributes(attributes)
    except RadiusError:
        raise
    except (TypeError, ValueError):
        raise RadiusError("invalid_attribute") from None
    return tuple((kind, value) for kind, value in attributes), body


def verify_dynamic_request(packet: bytes, secret: bytes):
    """Verify only DAS structure/integrity; return real Event-Timestamp unchanged.

    This does not select a trusted peer or check time, selectors, or policy.
    The caller must silently discard RadiusError, not issue an informative NAK.
    """
    _codec_secret(secret)
    packet, attributes = _codec_packet(packet)
    if packet[0] not in (40, 43):
        raise RadiusError("invalid_dynamic_code")
    zeroed, actual_ma = _message_authenticator(packet)
    # RFC5176 sections 2.3 and 3.4: MA is inserted before the request MD5.
    expected = hashlib.md5(packet[:4] + bytes(16) + packet[20:] + secret).digest()
    if not hmac.compare_digest(expected, packet[4:20]):
        raise RadiusError("invalid_request_authenticator")
    zeroed[4:20] = bytes(16)
    if not hmac.compare_digest(hmac.digest(secret, zeroed, "md5"), actual_ma):
        raise RadiusError("invalid_message_authenticator")
    timestamps = [value for kind, value in attributes if kind == 55]
    if not timestamps:
        raise RadiusError("missing_event_timestamp")
    if len(timestamps) != 1 or len(timestamps[0]) != 4:
        raise RadiusError("invalid_event_timestamp")
    return _DynamicRequest(packet, attributes, int.from_bytes(timestamps[0], "big"))


def dynamic_response(request: _DynamicRequest, response_code: int, secret: bytes,
                     *, error_cause: int | None = None):
    """Encode a caller-decided ACK/NAK, without claiming committed effects.

    Only pass a result from verify_dynamic_request after the Engine's gates.
    Semantic invalidity and unsupported-attribute decisions belong to Engine.
    """
    _codec_secret(secret)
    if (not isinstance(request, _DynamicRequest) or
            type(response_code) is not int or
            (request.code, response_code) not in ((40, 41), (40, 42), (43, 44), (43, 45))):
        raise RadiusError("invalid_dynamic_response")
    if error_cause is not None and (
            type(error_cause) is not int or not 0 <= error_cause <= 0xffffffff):
        raise RadiusError("invalid_error_cause")
    # Preserve proxy order and opaque CoA State without interpreting either.
    states = [value for kind, value in request.attributes if kind == 24]
    malformed_state = len(states) > 1 or any(not value for value in states)
    # Root-selected normalization: malformed CoA State produces NAK404 without
    # any State echo; a valid singleton still echoes on unrelated errors.
    omit_state = request.code == 43 and response_code == 45 and error_cause == 404 and malformed_state
    values = [(kind, value) for kind, value in request.attributes
              if kind == 33 or (kind == 24 and request.code == 43 and not omit_state)]
    if error_cause is not None:
        values.append((101, struct.pack("!I", error_cause)))
    body = encode_attributes([*values, (80, bytes(16))])
    header = struct.pack("!BBH", response_code, request.identifier, 20 + len(body))
    response = header + request.authenticator + body
    # RFC5176 section 3.4: response MA uses the original request authenticator.
    response = response[:-16] + hmac.digest(secret, response, "md5")
    authenticator = hashlib.md5(response + secret).digest()
    return response[:4] + authenticator + response[20:]


def accounting_request(identifier: int, status_type: int, attributes, secret: bytes):
    """Encode RFC2866 accounting; generation is not delivery or acknowledgment.

    The caller supplies identity and status-appropriate accounting fields.
    RFC2866 section 3 gives a 4095-octet accounting maximum, unlike DAS.
    RFC2869 section 5.19 forbids EAP-Message and MA in Accounting-Request.
    """
    _codec_secret(secret)
    if type(identifier) is not int or not 0 <= identifier <= 255:
        raise RadiusError("invalid_request")
    if type(status_type) is not int or status_type not in (1, 2, 3, 7, 8):
        raise RadiusError("invalid_accounting_status")
    values, _ = _codec_attributes(attributes)
    # RFC2866 sections 4.1/5.13 and RFC2869 section 5.19; 40 is added here.
    if any(kind in (2, 3, 18, 24, 40, 60, 79, 80) for kind, _ in values):
        raise RadiusError("reserved_accounting_attribute")
    body = encode_attributes([*values, (40, struct.pack("!I", status_type))])
    if len(body) + 20 > 4095:
        raise RadiusError("packet_budget")
    header = struct.pack("!BBH", 4, identifier, 20 + len(body))
    authenticator = hashlib.md5(header + bytes(16) + body + secret).digest()
    return header + authenticator + body


def verify_accounting(request: bytes, response: bytes, secret: bytes):
    """Validate conventional accounting correlation and MD5 authenticators.

    The caller retains peer, outstanding-request, and current-generation gates.
    Extra response attributes, including nonstandard 80, remain opaque and
    private. No accounting HMAC recipe is inferred from Access or DAS.
    """
    _codec_secret(secret)
    request, request_values = _codec_packet(request)
    response, values = _codec_packet(response)
    # RFC2866 section 3: enforce the accounting-specific declared Length.
    if len(request) > 4095 or len(response) > 4095:
        raise RadiusError("invalid_packet_length")
    if request[0] != 4 or response[0] != 5 or response[1] != request[1]:
        raise RadiusError("uncorrelated_response")
    if any(kind in (79, 80) for kind, _ in request_values):
        raise RadiusError("reserved_accounting_attribute")
    expected_request = hashlib.md5(request[:4] + bytes(16) + request[20:] + secret).digest()
    if not hmac.compare_digest(expected_request, request[4:20]):
        raise RadiusError("invalid_request_authenticator")
    expected_response = hashlib.md5(response[:4] + request[4:20] + response[20:] + secret).digest()
    if not hmac.compare_digest(expected_response, response[4:20]):
        raise RadiusError("invalid_response_authenticator")
    # The selected accounting profile authenticates all bytes with response
    # MD5, but never applies or interprets extra response attributes.
    return _RadiusPacket(response, values)


async def accounting_delivery(record, targets, *, ready, elapsed, remaining, on_event):
    import asyncio
    import base64
    attributes = tuple((kind, base64.b64decode(value, validate=True)) for kind,value in record["attributes"])
    loop = asyncio.get_running_loop()
    policy = record["delivery_policy"]
    if not ready() or remaining() <= 0:return None
    try:
        async with asyncio.timeout(remaining()):
            return await _deliver_accounting_targets(record, targets, attributes, loop, policy, ready, elapsed, remaining, on_event)
    except TimeoutError:
        return None


async def _deliver_accounting_targets(record, targets, attributes, loop, policy, ready, elapsed, remaining, on_event):
    import asyncio
    import ipaddress
    import socket
    for captured in record["targets"]:
        target = targets[captured["id"]]
        family = socket.AF_INET6 if ipaddress.ip_address(target.address).version == 6 else socket.AF_INET
        if not ready() or remaining() <= 0:return None
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as udp:
                udp.setblocking(False)
                udp.bind((target.source_address or ("::" if family == socket.AF_INET6 else "0.0.0.0"), 0))
                await loop.sock_connect(udp, (target.address, target.port))
                identifier, prior_delay, request = secrets.randbelow(256), None, None
                for attempt in range(policy["attempts"]):
                    if not ready() or remaining() <= 0:return None
                    delay = int(elapsed())
                    if delay != prior_delay:
                        identifier = (identifier+1) % 256
                        request = accounting_request(identifier, record["status_type"], (*attributes, (41,delay.to_bytes(4,"big"))), target.secret.encode())
                        prior_delay = delay
                    await on_event("attempting", target.id)
                    if not ready() or remaining() <= 0:return None
                    sent = await loop.sock_sendto(udp, request, (target.address, target.port))
                    if sent != len(request):raise RadiusError("accounting_send_failed")
                    await on_event("sent", target.id)
                    try:
                        async with asyncio.timeout(min(policy["response_timeout_seconds"],remaining())):
                            invalid = 0
                            while True:
                                response = await loop.sock_recv(udp, 4096)
                                if not ready() or remaining() <= 0:return None
                                try:verify_accounting(request, response, target.secret.encode())
                                except RadiusError:
                                    invalid += 1
                                    if invalid > 512:break
                                    continue
                                return True, target.id
                    except (TimeoutError, OSError):pass
                    await on_event("no-valid-response", target.id)
                    if attempt+1 < policy["attempts"]:
                        await asyncio.sleep(min(30,policy["retry_backoff_seconds"]*(attempt+1),remaining()))
        except OSError:
            await on_event("transport-unavailable", target.id)
            continue
    return False, None


@dataclass(frozen=True, repr=False)
class _DynamicSessionProposal:
    key: tuple[str, str]
    session_id: str
    grant_generation: str
    policy: Authorization | None
    lease_deadline_ms: int | None
    idle_deadline_ms: int | None


@dataclass(frozen=True, repr=False)
class _DynamicPlan:
    error_cause: int | None
    sessions: tuple[_DynamicSessionProposal, ...] = ()
    omit_state_echo: bool = False


def plan_dynamic_request(request: _DynamicRequest, runtime) -> _DynamicPlan:
    """Plan against one current Runtime; never mutate or advance it.

    The caller supplies a verified request only after current trust/replay gates.
    Precedence: malformed CoA State404; unsupported401; service405; duplicate
    singleton NAS/session/control404; missing selectors/triple402; invalid
    values407; no captured NAS identity403 (empty Runtime503);
    no session503; forbidden VLAN501. Attribute order never selects the error.
    A NAK always has an empty proposal tuple. The Engine owns the full-PDU-like
    commit, freshness checks, deadline processing, persistence, and reply.
    """
    from .models import mac as canonical_mac
    if not isinstance(request, _DynamicRequest) or request.code not in (40, 43):
        raise RadiusError("invalid_dynamic_request")
    values = {}
    for kind, value in request.attributes:
        values.setdefault(kind, []).append(value)
    coa = request.code == 43
    states = values.get(24, [])
    if coa and (len(states) > 1 or any(not value for value in states)):
        return _DynamicPlan(404, omit_state_echo=True)
    selectors = {1, 5, 31, 44, 87}
    allowed = selectors | {4, 32, 33, 55, 80}
    if coa:
        allowed |= {6, 24, 27, 28, 29, 64, 65, 81}
    if set(values) - allowed:
        return _DynamicPlan(401)
    if coa and 6 in values:
        return _DynamicPlan(405)
    if any(len(values.get(kind, [])) > 1 for kind in selectors | {4, 32, 27, 28, 29}):
        return _DynamicPlan(404)
    tunnels = set(values) & {64, 65, 81}
    if not set(values) & selectors or (tunnels and tunnels != {64, 65, 81}):
        return _DynamicPlan(402)

    # Strings are exact opaque bytes. Only Calling-Station-Id is normalized.
    if (any(len(value) != 4 for kind in (4, 5, 27, 28, 29) for value in values.get(kind, [])) or
            any(not value for kind in (1, 32, 44, 87) for value in values.get(kind, []))):
        return _DynamicPlan(407)
    try:
        addresses = tuple(canonical_mac(value.decode("ascii")) for value in values.get(31, []))
    except (UnicodeError, ValueError):
        return _DynamicPlan(407)
    controls = {kind: int.from_bytes(values[kind][0], "big") for kind in (27, 28, 29) if kind in values}
    if 29 in controls and controls[29] not in (0, 1):
        return _DynamicPlan(407)
    vid = None
    if tunnels:
        if any(len(values[kind]) != 1 for kind in (64, 65, 81)):
            return _DynamicPlan(407)
        tt, medium, group = (values[kind][0] for kind in (64, 65, 81))
        if (len(tt) != 4 or len(medium) != 4 or tt[0] > 31 or medium[0] > 31 or
                int.from_bytes(tt[1:], "big") != 13 or int.from_bytes(medium[1:], "big") != 6 or not group):
            return _DynamicPlan(407)
        group_tag, group_value = (group[0], group[1:]) if group[0] <= 31 else (0, group)
        if tt[0] != medium[0] or tt[0] != group_tag or not group_value.isdigit():
            return _DynamicPlan(407)
        vid = int(group_value)
        if not 1 <= vid <= 4094 or vid not in runtime.cfg.vlans:
            return _DynamicPlan(407)

    # NAS identity is captured on each grant; current configuration is not
    # evidence about that session. All supplied NAS fields conjoin per session.
    candidates = sorted(runtime.radius_sessions.items())
    if not candidates:
        return _DynamicPlan(503)
    if 4 in values or 32 in values:
        candidates = [(key, session) for key, session in candidates
                      if session.nas_identity is not None
                      and all(value == session.nas_identity.ipv4 for value in values.get(4, []))
                      and all(value == session.nas_identity.identifier for value in values.get(32, []))]
        if not candidates:
            return _DynamicPlan(403)

    # Root-selected shared-service selectors name its authenticated owner,
    # never an arbitrary dependent from Runtime.session, inventory, or FDB.
    selected = []
    for key, session in candidates:
        port = runtime.cfg.ports[session.port_id]
        if (any(int.from_bytes(value, "big") != port.bridge_port for value in values.get(5, [])) or
                any(value != port.name.encode("utf-8") for value in values.get(87, [])) or
                any(value != session.id.encode("utf-8") for value in values.get(44, [])) or
                any(value != session.user_name for value in values.get(1, [])) or
                any(address != session.mac for address in addresses)):
            continue
        selected.append((key, session))
    if not selected:
        return _DynamicPlan(503)
    if vid is not None and any(vid in runtime.cfg.ports[session.port_id].forbidden for _, session in selected):
        return _DynamicPlan(501)

    proposals = []
    for key, session in selected:
        if not coa:
            proposals.append(_DynamicSessionProposal(key, session.id, session.grant_generation, None, None, None))
            continue
        changes = {}
        if vid is not None:
            changes.update(vid=vid, source="radius")
        for kind, name in ((27, "session_timeout"), (28, "idle_timeout"), (29, "termination_action")):
            if kind in controls:
                changes[name] = controls[kind]
        if states:
            changes["state"] = states[0]
        policy = replace(session.policy, **changes)
        lease = runtime.sim_ms + controls[27] * 1000 if 27 in controls else session.lease_deadline_ms
        candidate = replace(session, policy=policy, lease_deadline_ms=lease)
        idle, _, _ = runtime.session_deadlines(candidate)
        proposals.append(_DynamicSessionProposal(key, session.id, session.grant_generation, policy, lease, idle))
    return _DynamicPlan(None, tuple(proposals))


class DynamicListener(asyncio.DatagramProtocol):
    def __init__(self, engine, binding):
        self.engine, self.binding, self.transport = engine, binding, None
    def connection_made(self, transport):self.transport = transport
    def connection_lost(self, exc):self.transport = None
    def error_received(self, exc):self.engine.dynamic_drop("transport-error")
    def datagram_received(self, data, address):self.engine.receive_dynamic(self, data, address)
