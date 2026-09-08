"""Real BER/security/cache boundaries through an in-memory dispatcher, without UDP."""
import asyncio
import copy
from contextlib import contextmanager
import socket
from unittest.mock import patch

import pytest
from pyasn1.codec.ber import encoder, decoder
from pysnmp.carrier.base import AbstractTransportDispatcher
from pysnmp.entity import config, engine as snmp_engine
from pysnmp.proto.api import v2c
from pysnmp.proto import rfc1902 as a, error

from switchlab.snmp_lifetime import InboundLifetime, UnsupportedLifetime

DOMAIN = (1, 3, 6, 1, 6, 1, 1)
PEER = ("127.0.0.1", 40000)
TARGET = ("127.0.0.1", 1161)
AGENT_ID = bytes.fromhex("80000000047363726174636841")
MANAGER_ID = bytes.fromhex("8000000004736372617463684d")


@pytest.fixture(autouse=True)
def no_network():
    original = socket.socket
    attempts = []
    def guarded(family=socket.AF_INET, *args, **kwargs):
        if family in (socket.AF_INET, socket.AF_INET6):
            attempts.append(family)
            raise AssertionError("Network sockets are prohibited in lifetime tests")
        return original(family, *args, **kwargs)
    with patch("socket.socket", guarded):
        yield
    assert not attempts


class Sink(AbstractTransportDispatcher):
    def __init__(self):
        super().__init__()
        self.sent = []
        self.attempts = 0
        self.failure = None
    def send_message(self, message, domain, address):
        self.attempts += 1
        if self.failure == "before":
            raise RuntimeError("Injected transport failure")
        self.sent.append((bytes(message), domain, address))
        if self.failure == "after":
            raise RuntimeError("Injected uncertain delivery")


def make_engine(ident):
    # Match application construction; do not use PySNMP's optional temp files.
    snmp = snmp_engine.SnmpEngine(maxMessageSize=65507)
    identity, boots = snmp.get_mib_builder().import_symbols(
        "__SNMP-FRAMEWORK-MIB", "snmpEngineID", "snmpEngineBoots")
    identity.syntax = identity.syntax.clone(ident)
    boots.syntax = boots.syntax.clone(1)
    snmp.snmpEngineID = identity.syntax
    sink = Sink()
    snmp.register_transport_dispatcher(sink)
    return snmp, sink


def request(identifier=-2147483648):
    pdu = v2c.SetRequestPDU()
    v2c.apiPDU.set_defaults(pdu)
    v2c.apiPDU.set_request_id(pdu, identifier)
    v2c.apiPDU.set_varbinds(pdu, [((1, 3, 6, 1, 2, 1, 2, 2, 1, 7, 101), a.Integer32(2))])
    return pdu


def receive(snmp, message, address=PEER):
    snmp.message_dispatcher.receive_message(snmp, DOMAIN, address, message)


def user(snmp, level, security_engine=None):
    config.add_v3_user(snmp, "lifetime-probe",
        authProtocol=config.USM_AUTH_HMAC192_SHA256 if level > 1 else config.USM_AUTH_NONE,
        authKey="synthetic-auth-passphrase" if level > 1 else None,
        privProtocol=config.USM_PRIV_CFB128_AES if level == 3 else config.USM_PRIV_NONE,
        privKey="synthetic-priv-passphrase" if level == 3 else None,
        securityEngineId=security_engine)


class Exchange:
    def __init__(self, level):
        self.level = level
        self.agent, self.sink = make_engine(AGENT_ID)
        self.tickets, self.requests, self.returned = [], [], []
        self.owner = InboundLifetime(self.agent, lambda: self.tickets)
        self.agent.message_dispatcher.register_context_engine_id(self.agent.snmpEngineID,
            (v2c.SetRequestPDU.tagSet,), self.capture)
        self.manager = self.msink = None
        if level:
            self.manager, self.msink = make_engine(MANAGER_ID)
            user(self.agent, level)
            user(self.manager, level, a.OctetString(AGENT_ID))
            for _ in range(3):
                self.send_request()
                if self.requests:
                    captured = self.requests.pop()
                    self.respond(captured)
                    self.decode()
                    break
                assert self.sink.sent, "Missing public discovery/timeliness response"
                while self.sink.sent:
                    receive(self.manager, self.sink.sent.pop(0)[0], TARGET)
            assert not self.requests
        else:
            config.add_v1_system(self.agent, "probe", "synthetic-community", securityName="probe")
        self.mp = self.agent.message_processing_subsystems[3 if level else 1]
        self.security = self.agent.security_models[3 if level else 2]
        self.mp_pops, self.sec_pops, self.pre_admission_sec_pops = [], [], []
        self.admitted_security = set()
        old_mp = self.mp._cache.pop_by_state_reference
        old_sec = self.security._cache.pop
        def mp_pop(ref):
            self.mp_pops.append(ref)
            return old_mp(ref)
        def sec_pop(ref):
            key = (ref, id(self.security._cache._Cache__cache_entries.get(ref)))
            if key in self.admitted_security:
                self.admitted_security.remove(key)
                self.sec_pops.append(ref)
            else:
                # USM replaces a provisional state before admission (3414 step
                # 3.2.11). Count it separately from the captured response state.
                self.pre_admission_sec_pops.append(ref)
            return old_sec(ref)
        self.mp._cache.pop_by_state_reference = mp_pop
        self.security._cache.pop = sec_pop
        self.sink.attempts = 0

    def capture(self, *args):
        # The application must capture ephemeral authenticated metadata here.
        incoming = self.agent.observer.get_execution_context("rfc3412.receiveMessage:request")
        assert incoming["transportAddress"] == PEER
        ticket = self.owner.capture(int(args[1]), args[10])
        self.tickets.append(ticket)
        if hasattr(self, "admitted_security"):
            self.admitted_security.add((ticket.security_reference, id(ticket.security_record)))
        self.requests.append((ticket, args))

    def send_request(self, identifier=-2147483648):
        pdu = request(identifier)
        if self.level:
            self.manager.message_dispatcher.send_pdu(self.manager, DOMAIN, TARGET, 3, 3,
                a.OctetString("lifetime-probe"), self.level, None, b"", 1, pdu, True, 100,
                lambda *args: self.returned.append(args))
            assert len(self.msink.sent) == 1
            receive(self.agent, self.msink.sent.pop(0)[0])
        else:
            msg = v2c.Message()
            v2c.apiMessage.set_defaults(msg)
            v2c.apiMessage.set_community(msg, "synthetic-community")
            v2c.apiMessage.set_pdu(msg, pdu)
            receive(self.agent, encoder.encode(msg))

    def fresh(self):
        self.send_request()
        assert len(self.requests) == 1
        captured = self.requests.pop()
        assert self.owner.ready(captured[0])
        with pytest.raises(KeyError):
            self.agent.observer.get_execution_context("rfc3412.receiveMessage:request")
        return captured

    def send_response(self, captured, status=0, index=0, empty=False, info=None):
        ticket, args = captured
        response = v2c.apiPDU.get_response(args[8])
        v2c.apiPDU.set_error_status(response, status)
        v2c.apiPDU.set_error_index(response, index)
        v2c.apiPDU.set_varbinds(response, [] if empty else v2c.apiPDU.get_varbinds(args[8]))
        self.agent.message_dispatcher.return_response_pdu(*args[:8], response, *args[9:], info or {})

    def respond(self, captured, **kwargs):
        return self.owner.complete(captured[0], lambda: self.send_response(captured, **kwargs))

    def decode(self):
        assert len(self.sink.sent) == 1
        wire = self.sink.sent.pop(0)[0]
        if self.level:
            before = len(self.returned)
            receive(self.manager, wire, TARGET)
            assert len(self.returned) == before + 1
            assert self.returned[-1][9] is None
            return self.returned[-1][8]
        return v2c.apiMessage.get_pdu(decoder.decode(wire, asn1Spec=v2c.Message())[0])

    def ticks(self, count):
        # Use the registered public timer, not a second timer or private clock edit.
        for _ in range(count):
            self.clock = getattr(self, "clock", 0) + 1
            self.sink.handle_timer_tick(float(self.clock))

    def expire(self):
        self.ticks(610)

    def empty(self):
        assert not self.mp._cache._Cache__stateReferenceIndex
        assert self.security._cache.is_empty()

    def close(self):
        self.owner.close()
        self.empty()
        self.agent.close_dispatcher()
        if self.manager:
            self.manager.close_dispatcher()


@pytest.fixture(params=[0, 1, 2, 3], ids=["v2c", "v3-noauth", "v3-auth", "v3-priv"])
def exchange(request):
    instance = Exchange(request.param)
    try:
        yield instance
    finally:
        instance.close()


def terminal(ticket):
    assert ticket.phase == "terminal"
    assert ticket.owner is ticket.mp is ticket.mp_record is None
    assert ticket.security is ticket.security_record is None


async def test_delayed_response_error_and_toobig(exchange):
    x = exchange
    for status, index, empty in [(0, 0, False), (6, 1, False), (16, 0, False), (1, 0, True)]:
        captured = x.fresh()
        before = len(x.mp_pops), len(x.sec_pops), x.sink.attempts
        await asyncio.sleep(0)
        assert x.respond(captured, status=status, index=index, empty=empty)
        response = x.decode()
        assert int(v2c.apiPDU.get_request_id(response)) == -2147483648
        assert int(v2c.apiPDU.get_error_status(response)) == status
        assert int(v2c.apiPDU.get_error_index(response)) == index
        assert len(v2c.apiPDU.get_varbinds(response)) == (0 if empty else 1)
        assert (len(x.mp_pops), len(x.sec_pops), x.sink.attempts) == tuple(v + 1 for v in before)
        assert not x.respond(captured)
        assert not x.owner.discard(captured[0])
        terminal(captured[0])
        x.empty()


@pytest.mark.parametrize("reason", ["cancel", "overload", "revoke", "close", "reboot", "expiry", "cancel-expiry", "expiry-cancel"])
async def test_terminal_paths_never_respond_or_apply(exchange, reason):
    x = exchange
    captured = x.fresh()
    if reason in ("close", "reboot"):
        x.owner.close()
        x.owner.close()
        x.agent.close_dispatcher()
    elif reason.startswith("expiry"):
        x.expire()
        x.owner.discard(captured[0], "cancel")
    else:
        x.owner.discard(captured[0], reason)
        if reason == "cancel-expiry":
            x.expire()
    await asyncio.sleep(0)
    effects = []
    assert not x.owner.complete(captured[0], lambda: effects.append("changed"))
    assert not effects and not x.sink.sent and x.sink.attempts == 0
    assert len(x.mp_pops) == len(x.sec_pops) == 1
    terminal(captured[0])
    x.empty()


@contextmanager
def fail_at(x, stage):
    if stage == "before-mp":
        with patch.object(x.mp, "prepare_response_message", side_effect=RuntimeError("Injected before MP take")):
            yield
    elif stage == "after-mp":
        with patch.object(x.security, "generate_response_message", side_effect=RuntimeError("Injected before security take")):
            yield
    elif stage == "after-security":
        original = x.security.generate_response_message
        def fail(*args, **kwargs):
            original(*args, **kwargs)
            raise RuntimeError("Injected after security take")
        with patch.object(x.security, "generate_response_message", fail):
            yield
    elif stage == "encode":
        with patch.object(encoder, "encode", side_effect=RuntimeError("Injected BER encode failure")):
            yield
    elif stage == "size":
        original = x.mp.prepare_response_message
        def fail(*args, **kwargs):
            domain, address, _ = original(*args, **kwargs)
            return domain, address, b"x" * 65508
        with patch.object(x.mp, "prepare_response_message", fail):
            yield
    else:
        x.sink.failure = "before" if stage == "send" else "after"
        try:
            yield
        finally:
            x.sink.failure = None


@pytest.mark.parametrize("stage", ["before-mp", "after-mp", "after-security", "encode", "size", "send", "uncertain-send"])
def test_response_failures_cleanup_once_without_undoing_commit(exchange, stage, engine, store):
    x = exchange
    captured = x.fresh()
    candidate = copy.deepcopy(engine.state)
    candidate.cfg.switch.name = "Committed before response"
    candidate.configuration_revision += 1
    candidate.revision += 1
    commits = []
    def commit_and_respond():
        # Existing synchronous storage boundary; asynchronous SET integration is
        # tested separately. A successful transaction is not a delivery promise.
        store.commit(candidate, {})
        engine.state = candidate
        commits.append(1)
        x.send_response(captured)
    with fail_at(x, stage), pytest.raises((RuntimeError, error.StatusInformation)):
        x.owner.complete(captured[0], commit_and_respond)
    assert store.load().switch.name == "Committed before response"
    assert engine.state is candidate and commits == [1]
    assert not x.owner.complete(captured[0], commit_and_respond)
    assert len(x.mp_pops) == len(x.sec_pops) == 1
    assert x.sink.attempts == (1 if stage in ("send", "uncertain-send") else 0)
    assert len(x.sink.sent) == (1 if stage == "uncertain-send" else 0)
    terminal(captured[0])
    x.empty()


def test_rolled_back_storage_failure_can_respond_once(exchange, engine, store):
    x = exchange
    store.commit(engine.state, {})
    before = store.load().model_dump(), engine.snapshot(), store.events(), store.last_event
    captured = x.fresh()
    candidate = copy.deepcopy(engine.state)
    candidate.cfg.switch.name = "Must roll back"
    original = store.put
    def fail(key, value):
        original(key, value)
        if key == "outbox":
            raise RuntimeError("Injected transaction failure")
    def operation():
        with patch.object(store, "put", fail), pytest.raises(RuntimeError):
            store.commit(candidate, {})
        x.send_response(captured, status=14, index=1)
    assert x.owner.complete(captured[0], operation)
    assert (store.load().model_dump(), engine.snapshot(), store.events(), store.last_event) == before
    assert int(v2c.apiPDU.get_error_status(x.decode())) == 14
    assert len(x.mp_pops) == len(x.sec_pops) == 1
    x.empty()


@pytest.mark.parametrize("reason", ["cancel", "expiry", "revoke", "close"])
@pytest.mark.parametrize("foreign", [False, True], ids=["missing-security", "foreign-security"])
def test_queued_security_loss_reports_and_preserves_foreign(exchange, reason, foreign):
    x = exchange
    a_ticket, a_args = x.fresh()
    old_sec_ref = a_ticket.security_reference
    # Inject unexpected loss using the public owner release, not dictionary edits.
    x.security.release_state_information(old_sec_ref)
    b = None
    if foreign:
        # A real receive allocates B at the reused numeric security reference.
        with patch.object(x.security._cache, "_Cache__state_reference", lambda: old_sec_ref):
            b = x.fresh()
        # Model the independently taken B MP record. B's exact security state
        # remains owned by its ticket, not by A or the close-drain of A's MP row.
        x.mp._cache.pop_by_state_reference(b[0].reference)
        x.tickets.remove(b[0])
        foreign_record = b[0].security_record
    before = len(x.sec_pops)
    if reason == "expiry":
        x.expire()
    elif reason == "close":
        x.owner.close()
    else:
        x.owner.discard(a_ticket, reason)
    assert x.owner.error == "inbound_response_ownership_lost"
    assert len(x.sec_pops) == before
    assert not x.sink.sent and x.sink.attempts == 0
    terminal(a_ticket)
    if b:
        assert x.security._cache._Cache__cache_entries[old_sec_ref] is foreign_record
        x.owner.discard(b[0])
    x.empty()


@pytest.mark.parametrize("first", ["cancel", "complete", "expiry"])
def test_numeric_reference_reuse_cannot_revive_terminal_ticket(exchange, first):
    x = exchange
    a = x.fresh()
    old_mp_ref, old_sec_ref = a[0].reference, a[0].security_reference
    if first == "complete":
        x.respond(a)
        x.decode()
    elif first == "expiry":
        x.expire()
    else:
        x.owner.discard(a[0])
    with patch.object(x.mp._cache, "new_state_reference", lambda: old_mp_ref), \
         patch.object(x.security._cache, "_Cache__state_reference", lambda: old_sec_ref):
        b = x.fresh()
    before = len(x.mp_pops), len(x.sec_pops), x.sink.attempts
    assert not x.respond(a)
    assert not x.owner.discard(a[0])
    assert x.owner.ready(b[0])
    assert (len(x.mp_pops), len(x.sec_pops), x.sink.attempts) == before
    assert x.respond(b)
    x.decode()
    assert len(x.mp_pops) == len(x.sec_pops) == 2
    x.empty()


def test_other_engine_cannot_claim_or_discard_ticket(exchange):
    x = exchange
    other, sink = make_engine(MANAGER_ID)
    owner = InboundLifetime(other)
    try:
        captured = x.fresh()
        assert not owner.ready(captured[0])
        assert not owner.discard(captured[0])
        assert not owner.complete(captured[0], lambda: pytest.fail("Wrong engine effect"))
        assert x.owner.ready(captured[0])
        x.respond(captured)
        x.decode()
    finally:
        owner.close()
        other.close_dispatcher()


def test_real_prepare_status_branch_does_not_double_pop(exchange):
    x = exchange
    captured = x.fresh()
    # v2c rejects nonempty status information after MP take. v3 detects a
    # Report for a response-class PDU and publicly releases security first.
    info = {"oid": (1, 3, 6, 1, 6, 3, 11, 2, 1, 1, 0), "val": a.Counter32(1)}
    with pytest.raises(error.StatusInformation):
        x.respond(captured, info=info)
    assert len(x.mp_pops) == len(x.sec_pops) == 1
    assert not x.sink.sent
    x.empty()


@pytest.mark.parametrize("reason", ["cancel", "expiry", "close"])
def test_inbound_retirement_preserves_outgoing_requests_and_traps(exchange, reason):
    x = exchange
    captured = x.fresh()
    if reason == "expiry":
        x.ticks(590)
    # Create real outgoing confirmed-request state at a later deadline. Leave
    # it pending: the inbound finalizer must not use its sendPduHandle indexes.
    outgoing = request(2147483647)
    x.agent.message_dispatcher.send_pdu(x.agent, DOMAIN, TARGET,
        3 if x.level else 1, 3 if x.level else 2,
        a.OctetString("lifetime-probe" if x.level else "probe"), x.level or 1,
        None, b"", 1, outgoing, True, 10000, lambda *args: None)
    assert x.sink.sent
    x.sink.sent.clear()
    cache = x.mp._cache
    before = tuple((ref, id(row)) for ref, row in cache._Cache__msgIdIndex.items()), dict(cache._Cache__sendPduHandleIdx)
    assert before[0] and before[1]
    if reason == "expiry":
        x.ticks(20)
    elif reason == "close":
        x.owner.close()
    else:
        x.owner.discard(captured[0])
    assert not x.sink.sent
    assert (tuple((ref, id(row)) for ref, row in cache._Cache__msgIdIndex.items()), dict(cache._Cache__sendPduHandleIdx)) == before
    terminal(captured[0])
    x.empty()
    # Unconfirmed notification serialization still uses the original public
    # path and engine identity even after inbound admission has closed.
    trap = v2c.SNMPv2TrapPDU()
    v2c.apiTrapPDU.set_defaults(trap)
    v2c.apiPDU.set_varbinds(trap, [((1, 3, 6, 1, 2, 1, 1, 3, 0), a.TimeTicks(10)),
        ((1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0), a.ObjectIdentifier((1, 3, 6, 1, 6, 3, 1, 1, 5, 1)))])
    x.agent.message_dispatcher.send_pdu(x.agent, DOMAIN, TARGET,
        3 if x.level else 1, 3 if x.level else 2,
        a.OctetString("lifetime-probe" if x.level else "probe"), x.level or 1,
        None, b"", 1, trap, False)
    assert len(x.sink.sent) == 1
    if x.level:
        traps = []
        x.manager.message_dispatcher.register_context_engine_id(b"", (v2c.SNMPv2TrapPDU.tagSet,), lambda *args: traps.append(args[8]))
        receive(x.manager, x.sink.sent.pop(0)[0], TARGET)
        assert len(traps) == 1 and traps[0].tagSet == trap.tagSet
    else:
        out = decoder.decode(x.sink.sent.pop(0)[0], asn1Spec=v2c.Message())[0]
        assert v2c.apiMessage.get_pdu(out).tagSet == trap.tagSet
    assert (tuple((ref, id(row)) for ref, row in cache._Cache__msgIdIndex.items()), dict(cache._Cache__sendPduHandleIdx)) == before


def test_live_mp_reference_replacement_does_not_authorize_old_ticket(exchange):
    x = exchange
    a = x.fresh()
    ref = a[0].reference
    # A loses only its MP record through the owner API; its captured security
    # state still needs finalization. B is an actual new receive at the same ID.
    x.mp._cache.pop_by_state_reference(ref)
    with patch.object(x.mp._cache, "new_state_reference", lambda: ref):
        b = x.fresh()
    b_record, b_security = b[0].mp_record, b[0].security_record
    assert not x.owner.ready(a[0])
    assert x.owner.error == "inbound_response_ownership_lost"
    assert x.mp._cache._Cache__stateReferenceIndex[ref] is b_record
    assert x.security._cache._Cache__cache_entries[b[0].security_reference] is b_security
    assert not x.respond(a)
    assert x.respond(b)
    x.decode()
    assert len(x.mp_pops) == len(x.sec_pops) == 2
    x.empty()


@pytest.mark.parametrize("mismatch", ["version", "source", "cache-method", "push-method", "mp-method", "security-method", "active-record"])
def test_unsupported_layout_does_not_install_partial_hooks(mismatch):
    snmp, sink = make_engine(AGENT_ID)
    mp = snmp.message_processing_subsystems[1]
    originals = [(m._cache.expire_caches, m._cache.push_by_state_reference) for m in snmp.message_processing_subsystems.values()]
    captured = []
    config.add_v1_system(snmp, "probe", "synthetic-community", securityName="probe")
    snmp.message_dispatcher.register_context_engine_id(snmp.snmpEngineID, (v2c.SetRequestPDU.tagSet,), lambda *args: captured.append(args))
    msg = v2c.Message()
    v2c.apiMessage.set_defaults(msg)
    v2c.apiMessage.set_community(msg, "synthetic-community")
    v2c.apiMessage.set_pdu(msg, request())
    if mismatch == "version":
        change = patch("switchlab.snmp_lifetime.version", return_value="7.1.30")
    elif mismatch == "source":
        change = patch("switchlab.snmp_lifetime.PINNED_SOURCES", {"proto/mpmod/cache.py": "0" * 64})
    elif mismatch == "cache-method":
        change = patch.object(mp._cache, "pop_by_state_reference", lambda ref: None)
    elif mismatch == "push-method":
        change = patch.object(mp._cache, "push_by_state_reference", lambda *args, **kwargs: None)
    elif mismatch == "mp-method":
        change = patch.object(mp, "prepare_response_message", lambda *args: None)
    elif mismatch == "security-method":
        change = patch.object(snmp.security_models[2], "release_state_information", lambda ref: None)
    else:
        receive(snmp, encoder.encode(msg))
        change = patch("switchlab.snmp_lifetime.version", return_value="7.1.29")
    try:
        with change, pytest.raises(UnsupportedLifetime):
            InboundLifetime(snmp)
        assert [(m._cache.expire_caches, m._cache.push_by_state_reference) for m in snmp.message_processing_subsystems.values()] == originals
        if not captured:
            receive(snmp, encoder.encode(msg))
        # Unsupported replacement has not damaged the existing public path.
        args = captured.pop()
        response = v2c.apiPDU.get_response(args[8])
        snmp.message_dispatcher.return_response_pdu(*args[:8], response, *args[9:], {})
        assert len(sink.sent) == 1 and snmp.security_models[2]._cache.is_empty()
    finally:
        snmp.close_dispatcher()


@pytest.mark.parametrize("supported", [True, False])
async def test_adapter_initialization_keeps_existing_read_path(engine, store, supported):
    from switchlab.snmp import SnmpAdapter, wire_name
    adapter = SnmpAdapter(engine, store)
    credential = await engine.execute("credential-save", {"label": "Reader", "community": "synthetic-community", "polling": {"enabled": True}})
    cid = credential["id"]
    with patch("switchlab.snmp_lifetime.version", return_value="7.1.29" if supported else "unsupported"):
        adapter._initialize()
    sink = Sink()
    adapter.snmp.register_transport_dispatcher(sink)
    try:
        assert (adapter.inbound is not None) == supported
        assert adapter.set_error == (None if supported else "unsupported_pysnmp_lifetime")
        # Emulate an established binding without creating a network transport.
        adapter.listening = True
        engine.state.cfg.snmp.enabled = True
        engine.state.cfg.switch.identity.sys_object_id = "1.3.6.1.4.1.32473.1"
        config.add_v1_system(adapter.snmp, wire_name(cid), "synthetic-community", securityName=wire_name(cid))
        for kind in (v2c.GetRequestPDU, v2c.GetNextRequestPDU, v2c.GetBulkRequestPDU):
            pdu = kind()
            if kind is v2c.GetBulkRequestPDU:
                v2c.apiBulkPDU.set_defaults(pdu)
                v2c.apiBulkPDU.set_non_repeaters(pdu, 0)
                v2c.apiBulkPDU.set_max_repetitions(pdu, 2)
            else:
                v2c.apiPDU.set_defaults(pdu)
            v2c.apiPDU.set_varbinds(pdu, [((1, 3, 6, 1, 2, 1, 1, 1, 0), a.Null(""))])
            msg = v2c.Message()
            v2c.apiMessage.set_defaults(msg)
            v2c.apiMessage.set_community(msg, "synthetic-community")
            v2c.apiMessage.set_pdu(msg, pdu)
            receive(adapter.snmp, encoder.encode(msg))
            assert len(sink.sent) == 1
            result = v2c.apiMessage.get_pdu(decoder.decode(sink.sent.pop(0)[0], asn1Spec=v2c.Message())[0])
            assert int(v2c.apiPDU.get_error_status(result)) == 0
            assert v2c.apiPDU.get_varbinds(result)
        assert adapter.snmp.security_models[2]._cache.is_empty()
    finally:
        adapter.close()


def test_guard_specific_import_failure_keeps_adapter_importable():
    import subprocess
    import sys
    # A fresh interpreter exercises the optional helper's first import, not an
    # already-imported module with a mocked version. No network is opened.
    script = r"""
import builtins
import socket
original_import = builtins.__import__
original_socket = socket.socket
attempts = []
class guarded_socket(original_socket):
    def __new__(cls, family=socket.AF_INET, *args, **kwargs):
        if family in (socket.AF_INET, socket.AF_INET6):
            attempts.append(family)
            raise AssertionError("Network socket prohibited")
        return super().__new__(cls, family, *args, **kwargs)
def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
    if name == "pysnmp.proto.mpmod" and (globals or {}).get("__name__") == "switchlab.snmp_lifetime":
        raise ImportError("Synthetic unsupported private layout")
    return original_import(name, globals, locals, fromlist, level)
socket.socket = guarded_socket
builtins.__import__ = guarded_import
from cryptography.fernet import Fernet
from switchlab.snmp import SnmpAdapter
from switchlab.engine import Engine
from switchlab.models import initial_configuration
from switchlab.storage import Store
store = Store(":memory:", Fernet.generate_key())
adapter = SnmpAdapter(Engine(initial_configuration(4), store), store)
try:
    adapter._initialize()
    assert adapter.inbound is None
    assert adapter.set_error == "unsupported_pysnmp_lifetime"
    assert adapter.responder is not None and adapter.originator is not None
    assert not attempts
finally:
    adapter.close()
    store.close()
print("optional_import_failure_preserves_adapter=passed network_socket_attempts=0")
"""
    result = subprocess.run([sys.executable, "-B", "-c", script], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "optional_import_failure_preserves_adapter=passed network_socket_attempts=0" in result.stdout


@pytest.mark.parametrize("level", [0, 1, 2, 3])
@pytest.mark.parametrize("trigger", ["expiry", "close"])
def test_unadmitted_original_security_association(level, trigger):
    x = Exchange(level)
    collected = []
    dispatcher = x.agent.message_dispatcher
    dispatcher.unregister_context_engine_id(x.agent.snmpEngineID, (v2c.SetRequestPDU.tagSet,))
    dispatcher.register_context_engine_id(x.agent.snmpEngineID, (v2c.SetRequestPDU.tagSet,), lambda *args: collected.append(args))
    try:
        # A reaches the genuine inbound MP cache but is not admitted to a ticket.
        x.send_request()
        a_args = collected.pop()
        a_ref = a_args[10]
        a_record = x.mp._cache._Cache__stateReferenceIndex[a_ref]
        sec_ref = a_record[0]["securityStateReference"]
        old_security = x.security._cache._Cache__cache_entries[sec_ref]
        x.security.release_state_information(sec_ref)
        # B is a real receive with the ordinary allocator replaced for one
        # bounded reuse fixture. No production dictionary is seeded or cleared.
        with patch.object(x.security._cache, "_Cache__state_reference", lambda: sec_ref):
            x.send_request()
        b_args = collected.pop()
        b_record = x.mp._cache._Cache__stateReferenceIndex[b_args[10]]
        foreign = x.security._cache._Cache__cache_entries[sec_ref]
        assert foreign is not old_security
        # Fault injection: B's independent MP owner has taken its response row,
        # leaving security completion pending. Closing A must not complete B.
        taken = x.mp._cache.pop_by_state_reference(b_args[10])
        assert taken is b_record[0]
        foreign_pops = []
        original = x.security._cache.pop
        def observe(ref):
            if x.security._cache._Cache__cache_entries.get(ref) is foreign:
                foreign_pops.append(ref)
            return original(ref)
        with patch.object(x.security._cache, "pop", observe):
            if trigger == "expiry":
                x.expire()
            else:
                x.owner.close()
        preserved = x.security._cache._Cache__cache_entries.get(sec_ref) is foreign
        print(f"level={level} trigger={trigger} B_security_preserved={preserved} B_security_pops={len(foreign_pops)} sends={x.sink.attempts} A_MP_present={a_ref in x.mp._cache._Cache__stateReferenceIndex}", flush=True)
        assert preserved and not foreign_pops, "Unadmitted A cleanup released B's exact security record"
        assert x.sink.attempts == 0
    finally:
        # Retire B through its public owner only if the reproduction preserved it.
        if 'foreign' in locals() and x.security._cache._Cache__cache_entries.get(sec_ref) is foreign:
            x.security.release_state_information(sec_ref)
        x.close()


@contextmanager
def raw_admission(x):
    """Capture public callback arguments without creating application tickets."""
    collected = []
    dispatcher = x.agent.message_dispatcher
    tags = (v2c.SetRequestPDU.tagSet,)
    dispatcher.unregister_context_engine_id(x.agent.snmpEngineID, tags)
    dispatcher.register_context_engine_id(x.agent.snmpEngineID, tags, lambda *args: collected.append(args))
    try:
        yield collected
    finally:
        dispatcher.unregister_context_engine_id(x.agent.snmpEngineID, tags)
        dispatcher.register_context_engine_id(x.agent.snmpEngineID, tags, x.capture)


@contextmanager
def entry_fault(x, fault):
    from switchlab import snmp_lifetime as lifetime
    from pysnmp.proto.mpmod.cache import Cache
    cache = x.mp._cache
    push = cache.push_by_state_reference
    witness_type = lifetime.SecurityWitness
    if fault == "missing-at-insert":
        def missing(ref, **params):
            x.security.release_state_information(params["securityStateReference"])
            push(ref, **params)
        fixture = patch.object(cache, "push_by_state_reference", missing)
    elif fault == "missing-witness":
        # One genuine receive uses the unchanged stock insertion owner, omitting
        # the integration's metadata. No cache dictionary is edited or seeded.
        fixture = patch.object(cache, "push_by_state_reference", Cache.push_by_state_reference.__get__(cache))
    elif fault in ("foreign-lifetime", "foreign-security", "wrong-witness-type"):
        def foreign(owner, security, record):
            if fault == "wrong-witness-type":
                return object()
            return witness_type(object() if fault == "foreign-lifetime" else owner,
                x.agent.security_models[1] if fault == "foreign-security" else security, record)
        fixture = patch.object(lifetime, "SecurityWitness", foreign)
    else:
        yield
        return
    with fixture:
        yield


@pytest.mark.parametrize("route", ["admit", "expiry", "close"])
@pytest.mark.parametrize("fault", ["none", "lost", "reused", "missing-at-insert", "missing-witness", "foreign-lifetime", "foreign-security", "wrong-witness-type"])
async def test_entry_witness_survives_delayed_admission(exchange, route, fault):
    x = exchange
    remaining = None
    with raw_admission(x) as collected:
        with entry_fault(x, fault):
            x.send_request()
        args = collected.pop()
        ref = args[10]
        params = x.mp._cache._Cache__stateReferenceIndex[ref][0]
        sec_ref = params["securityStateReference"]
        remaining = x.security._cache._Cache__cache_entries.get(sec_ref)
        if fault in ("lost", "reused"):
            x.security.release_state_information(sec_ref)
            remaining = None
        if fault in ("reused", "missing-at-insert"):
            with patch.object(x.security._cache, "_Cache__state_reference", lambda: sec_ref):
                x.send_request()
            b_args = collected.pop()
            remaining = x.security._cache._Cache__cache_entries[sec_ref]
            x.mp._cache.pop_by_state_reference(b_args[10])
        pops, effects = [], []
        original = x.security._cache.pop
        def pop(ref):
            if remaining is not None and x.security._cache._Cache__cache_entries.get(ref) is remaining:
                pops.append(ref)
            return original(ref)
        try:
            await asyncio.sleep(0)
            with patch.object(x.security._cache, "pop", pop):
                if route == "admit":
                    ticket = x.owner.capture(int(args[1]), ref)
                    def operation():
                        effects.append(1)
                        x.send_response((ticket, args))
                    assert x.owner.complete(ticket, operation) == (fault == "none")
                    terminal(ticket)
                elif route == "expiry":
                    x.expire()
                else:
                    x.owner.close()
            assert ref not in x.mp._cache._Cache__stateReferenceIndex
            if fault == "none":
                assert x.owner.error is None and len(pops) == 1
                if route == "admit":
                    assert int(v2c.apiPDU.get_error_status(x.decode())) == 0
                    assert effects == [1]
                else:
                    assert not effects and x.sink.attempts == 0
            else:
                assert x.owner.error == "inbound_response_ownership_lost"
                assert not pops and not effects and x.sink.attempts == 0
                assert x.security._cache._Cache__cache_entries.get(sec_ref) is remaining
        finally:
            # The fixture knows this independent security owner; the integration
            # intentionally does not invent ownership when its witness is absent.
            if remaining is not None and x.security._cache._Cache__cache_entries.get(sec_ref) is remaining:
                x.security.release_state_information(sec_ref)


@pytest.mark.parametrize("trigger", ["expiry", "close"])
@pytest.mark.parametrize("fault", ["missing-witness", "foreign-lifetime"])
def test_exceptional_row_does_not_abort_other_rows_or_outbound_timer(exchange, trigger, fault):
    x = exchange
    with raw_admission(x) as collected:
        with entry_fault(x, fault):
            x.send_request()
        bad = collected.pop()
        params = x.mp._cache._Cache__stateReferenceIndex[bad[10]][0]
        bad_sec_ref = params["securityStateReference"]
        unknown = x.security._cache._Cache__cache_entries[bad_sec_ref]
        x.send_request()
        good = collected.pop()
        good_params = x.mp._cache._Cache__stateReferenceIndex[good[10]][0]
        good_sec_ref = good_params["securityStateReference"]
        x.agent.message_dispatcher.send_pdu(x.agent, DOMAIN, TARGET,
            3 if x.level else 1, 3 if x.level else 2,
            a.OctetString("lifetime-probe" if x.level else "probe"), x.level or 1,
            None, b"", 1, request(127), True, 10000, lambda *args: None)
        cache = x.mp._cache
        assert cache._Cache__msgIdIndex
        handles = dict(cache._Cache__sendPduHandleIdx)
        x.sink.sent.clear()
        attempts = x.sink.attempts
        try:
            if trigger == "close":
                x.owner.close()
                assert cache._Cache__msgIdIndex
            x.expire()
            assert not cache._Cache__stateReferenceIndex
            assert x.security._cache._Cache__cache_entries.get(bad_sec_ref) is unknown
            assert good_sec_ref not in x.security._cache._Cache__cache_entries
            assert x.owner.error == "inbound_response_ownership_lost"
            assert not x.sink.sent and x.sink.attempts == attempts
            assert not cache._Cache__msgIdIndex
            # The stock MP expiration method owns these indexes. In this pin it
            # leaves the send-handle mapping; the inbound helper does not change it.
            assert cache._Cache__sendPduHandleIdx == handles
        finally:
            if x.security._cache._Cache__cache_entries.get(bad_sec_ref) is unknown:
                x.security.release_state_information(bad_sec_ref)


def test_witness_is_immutable_opaque_and_not_in_wire_data(exchange):
    from dataclasses import FrozenInstanceError
    from switchlab.snmp_lifetime import SECURITY_WITNESS, SecurityWitness
    x = exchange
    captured = x.fresh()
    ticket = captured[0]
    params = ticket.mp_record[0]
    witness = params[SECURITY_WITNESS]
    assert type(witness) is SecurityWitness
    assert witness.lifetime is x.owner and witness.security is x.security
    assert witness.record is ticket.security_record
    assert witness != SecurityWitness(witness.lifetime, witness.security, witness.record)
    with pytest.raises(FrozenInstanceError):
        witness.record = None
    rendered = repr(params) + str(params)
    for hidden in ("usmUserAuthKeyLocalized", "usmUserPrivKeyLocalized", "communityName",
                   "synthetic-community", "synthetic-auth-passphrase", "synthetic-priv-passphrase"):
        assert hidden not in rendered, "Opaque witness exposed synthetic security content"
    assert "record=" not in repr(witness) and "security=" not in str(witness)
    assert x.respond(captured)
    wire = x.sink.sent[0][0]
    assert SECURITY_WITNESS.encode() not in wire and b"SecurityWitness" not in wire
    x.decode()
    x.empty()


@pytest.mark.parametrize("level", [1, 2, 3])
def test_real_discovery_report_entry_keeps_public_security_pipeline(level):
    from switchlab.snmp_lifetime import SECURITY_WITNESS, SecurityWitness
    agent, sink = make_engine(AGENT_ID)
    manager, msink = make_engine(MANAGER_ID)
    owner = InboundLifetime(agent)
    entries, captured, returned = [], [], []
    mp = agent.message_processing_subsystems[3]
    security = agent.security_models[3]
    push, mp_pop, sec_pop = mp._cache.push_by_state_reference, mp._cache.pop_by_state_reference, security._cache.pop
    def observe_push(ref, **params):
        push(stateReference=ref, **params)
        row = mp._cache._Cache__stateReferenceIndex[ref]
        witness = row[0][SECURITY_WITNESS]
        assert type(witness) is SecurityWitness and witness.lifetime is owner
        assert witness.security is security
        assert witness.record is security._cache._Cache__cache_entries[params["securityStateReference"]]
        assert "usmUserAuthKeyLocalized" not in repr(row)
        assert "usmUserPrivKeyLocalized" not in str(row)
        entries.append({"mp": row, "security": witness.record, "report": params["securityName"] is None,
                        "mp_pops": 0, "security_pops": 0})
    def observe_mp_pop(ref):
        row = mp._cache._Cache__stateReferenceIndex.get(ref)
        for entry in entries:
            if entry["mp"] is row:
                entry["mp_pops"] += 1
        return mp_pop(ref)
    def observe_sec_pop(ref):
        row = security._cache._Cache__cache_entries.get(ref)
        for entry in entries:
            if entry["security"] is row:
                entry["security_pops"] += 1
        return sec_pop(ref)
    mp._cache.push_by_state_reference = observe_push
    mp._cache.pop_by_state_reference = observe_mp_pop
    security._cache.pop = observe_sec_pop
    def capture(*args):
        incoming = agent.observer.get_execution_context("rfc3412.receiveMessage:request")
        assert SECURITY_WITNESS not in incoming
        captured.append(args)
    agent.message_dispatcher.register_context_engine_id(agent.snmpEngineID, (v2c.SetRequestPDU.tagSet,), capture)
    user(agent, level)
    user(manager, level, a.OctetString(AGENT_ID))
    try:
        for _ in range(3):
            manager.message_dispatcher.send_pdu(manager, DOMAIN, TARGET, 3, 3,
                a.OctetString("lifetime-probe"), level, None, b"", 1, request(), True, 100,
                lambda *args: returned.append(args))
            assert len(msink.sent) == 1
            receive(agent, msink.sent.pop(0)[0])
            if captured:
                break
            assert sink.sent, "Expected a real discovery/timeliness report"
            while sink.sent:
                wire = sink.sent.pop(0)[0]
                assert SECURITY_WITNESS.encode() not in wire
                receive(manager, wire, TARGET)
        assert len(captured) == 1
        assert any(e["report"] for e in entries)
        assert any(not e["report"] for e in entries)
        args = captured.pop()
        ticket = owner.capture(3, args[10])
        response = v2c.apiPDU.get_response(args[8])
        assert owner.complete(ticket, lambda: agent.message_dispatcher.return_response_pdu(
            *args[:8], response, *args[9:], {}))
        assert len(sink.sent) == 1
        receive(manager, sink.sent.pop(0)[0], TARGET)
        assert returned[-1][8] is not None and returned[-1][9] is None
        assert all(e["mp_pops"] == e["security_pops"] == 1 for e in entries)
        assert not mp._cache._Cache__stateReferenceIndex and security._cache.is_empty()
    finally:
        owner.close()
        agent.close_dispatcher()
        manager.close_dispatcher()


class ApplicationExchange:
    """Existing application responder with its transport replaced by an in-memory sink."""
    def __init__(self, app_engine, store, level):
        from switchlab.snmp import SnmpAdapter
        self.engine, self.level = app_engine, level
        self.adapter = SnmpAdapter(app_engine, store)
        self.adapter._initialize()
        self.agent = self.adapter.snmp
        self.sink = Sink()
        self.agent.register_transport_dispatcher(self.sink)
        # This flag represents only the test sink: no UDP transport or bind call.
        self.adapter.listening = True
        self.adapter.binding = (app_engine.state.cfg.snmp.host, app_engine.state.cfg.snmp.port)
        self.adapter.cold_sent = True
        self.returned = []
        self.manager = self.msink = None
        if level:
            self.manager, self.msink = make_engine(MANAGER_ID)
            user(self.manager, level, a.OctetString(self.adapter.engine_id))

    async def start(self):
        await self.adapter._reconcile()
        if self.level:
            for _ in range(3):
                discovery = request()
                v2c.apiPDU.set_varbinds(discovery, [])
                self.send(discovery)
                if self.adapter.pending_sets:
                    await self.settle()
                    self.decode()
                    break
                assert self.sink.sent, "Expected genuine v3 discovery/report output"
                while self.sink.sent:
                    receive(self.manager, self.sink.sent.pop(0)[0], TARGET)
            else:
                raise AssertionError("v3 SET discovery did not complete")
        self.sink.attempts = 0
        return self

    def send(self, pdu, peer=PEER, community="synthetic-community", context_name=b"", security_level=None):
        if self.level:
            self.manager.message_dispatcher.send_pdu(self.manager, DOMAIN, TARGET, 3, 3,
                a.OctetString("lifetime-probe"), security_level or self.level, None, context_name,
                1, pdu, True, 100, lambda *args: self.returned.append(args))
            assert len(self.msink.sent) == 1
            receive(self.agent, self.msink.sent.pop(0)[0], peer)
        else:
            msg = v2c.Message()
            v2c.apiMessage.set_defaults(msg)
            v2c.apiMessage.set_community(msg, community)
            v2c.apiMessage.set_pdu(msg, pdu)
            receive(self.agent, encoder.encode(msg), peer)

    async def settle(self):
        pending = [r.task for r in self.adapter.pending_sets.values() if r.task]
        await asyncio.gather(*pending, return_exceptions=True)
        await asyncio.sleep(0)
        assert not self.adapter.pending_sets

    def decode(self):
        assert len(self.sink.sent) == 1
        wire = self.sink.sent.pop(0)[0]
        if self.level:
            before = len(self.returned)
            receive(self.manager, wire, TARGET)
            assert len(self.returned) == before + 1
            assert self.returned[-1][9] is None
            return self.returned[-1][8]
        return v2c.apiMessage.get_pdu(decoder.decode(wire, asn1Spec=v2c.Message())[0])

    def empty(self):
        for model in (1, 3):
            assert not self.agent.message_processing_subsystems[model]._cache._Cache__stateReferenceIndex
        for model in (2, 3):
            assert self.agent.security_models[model]._cache.is_empty()

    def expire(self):
        for tick in range(1, 612):
            self.sink.handle_timer_tick(float(tick))

    async def close(self):
        self.adapter.close()
        await self.settle()
        self.empty()
        if self.manager:
            self.manager.close_dispatcher()


@pytest.fixture(params=[0, 1, 2, 3], ids=["app-v2c", "app-v3-noauth", "app-v3-auth", "app-v3-priv"])
async def app_exchange(engine, store, request):
    level = request.param
    await engine.execute("switch-edit", {"identity": {"sys_object_id": "1.3.6.1.4.1.32473.1"}})
    await engine.execute("snmp-settings", {"enabled": True})
    fields = {"label": "Synthetic application SET", "polling": {"enabled": True},
              "writing": {"enabled": True, "view_id": "all"}}
    if level:
        fields.update(version="3", username="lifetime-probe",
            security_level={1: "noAuthNoPriv", 2: "authNoPriv", 3: "authPriv"}[level],
            auth_key="synthetic-auth-passphrase" if level > 1 else None,
            priv_key="synthetic-priv-passphrase" if level == 3 else None)
    else:
        fields["community"] = "synthetic-community"
    cid = (await engine.execute("credential-save", fields))["id"]
    instance = ApplicationExchange(engine, store, level)
    instance.credential_id = cid
    try:
        yield await instance.start()
    finally:
        await instance.close()


async def test_application_set_real_dispatcher_atomic_echo_and_cleanup(app_exchange):
    x = app_exchange
    pdu = request(-2147483648)
    before = x.engine.state
    x.send(pdu)
    pending = next(iter(x.adapter.pending_sets.values()))
    assert x.engine.state is before
    await x.settle()
    response = x.decode()
    assert int(v2c.apiPDU.get_request_id(response)) == -2147483648
    assert int(v2c.apiPDU.get_error_status(response)) == 0
    assert int(v2c.apiPDU.get_error_index(response)) == 0
    assert encoder.encode(v2c.apiPDU.get_varbinds(response)[0][1]) == encoder.encode(v2c.apiPDU.get_varbinds(pdu)[0][1])
    assert x.engine.state.revision == before.revision + 1
    assert not next(iter(x.engine.state.cfg.ports.values())).admin_up
    terminal(pending.ticket)
    x.empty()


async def configure_application(x, action, payload):
    async with x.adapter.io_lock:
        result = await x.engine.execute(action, payload)
        await x.adapter._reconcile()
        return result


def three_bindings(bad=None):
    from switchlab.mib import oid
    pdu = request(2147483647)
    bindings = [(oid("1.3.6.1.2.1.2.2.1.7.102"), a.Integer32(1)),
                (oid("1.3.6.1.2.1.2.2.1.7.101"), a.Integer32(2)),
                (oid("1.3.6.1.2.1.17.7.1.4.3.1.1.1"), a.OctetString(b"Committed"))]
    if bad:
        bindings[1] = bad
    v2c.apiPDU.set_varbinds(pdu, bindings)
    return pdu


@pytest.mark.parametrize("permission,status,index", [("readonly", 16, 0), ("excluded", 6, 1), ("wrongtype", 7, 2)])
async def test_application_set_denials_keep_original_echo_and_state(app_exchange, permission, status, index):
    from switchlab.mib import oid
    x = app_exchange
    fields = {"writing": {"enabled": False}} if permission == "readonly" else {
        "writing": {"view_id": "interfaces"}} if permission == "excluded" else {}
    if permission == "excluded":
        await configure_application(x, "view-save", {"id": "interfaces", "name": "Read", "includes": ["1.3.6.1.2.1.1"]})
    await configure_application(x, "credential-save", {"id": x.credential_id, **fields})
    pdu = three_bindings((oid("1.3.6.1.2.1.2.2.1.7.101"), a.OctetString(b"bad")) if permission == "wrongtype" else None)
    before = x.engine.state
    persisted = x.engine.store.get("configuration")
    x.send(pdu)
    await x.settle()
    response = x.decode()
    assert (int(v2c.apiPDU.get_error_status(response)), int(v2c.apiPDU.get_error_index(response))) == (status, index)
    assert int(v2c.apiPDU.get_request_id(response)) == 2147483647
    for (rn, rv), (qn, qv) in zip(v2c.apiPDU.get_varbinds(response), v2c.apiPDU.get_varbinds(pdu)):
        assert rn == qn and encoder.encode(rv) == encoder.encode(qv)
    assert x.engine.state is before and x.engine.store.get("configuration") == persisted
    x.empty()


@pytest.mark.parametrize("permission", ["readonly", "excluded"])
async def test_application_set_actual_budget_precedes_normal_denial(app_exchange, permission):
    from switchlab.mib import oid
    x = app_exchange
    fields = {"writing": {"enabled": False}} if permission == "readonly" else {"writing": {"view_id": "interfaces"}}
    await configure_application(x, "credential-save", {"id": x.credential_id, **fields})
    pdu = three_bindings()
    # These accepted input sizes cross the actual production scoped-response
    # budget (v2c) or RFC-minimum peer budget (v3), without changing local65507.
    length = {0: 65400, 1: 320, 2: 296, 3: 288}[x.level]
    v2c.apiPDU.set_varbinds(pdu, [(oid("1.3.6.1.2.1.17.7.1.4.3.1.1.1"), a.OctetString(b"x" * length)),
                                (oid("1.3.6.1.2.1.2.2.1.7.101"), a.Integer32(2))])
    if x.level:
        maximum = x.manager.get_mib_builder().import_symbols("__SNMP-FRAMEWORK-MIB", "snmpEngineMaxMessageSize")[0]
        maximum.syntax = maximum.syntax.clone(484)
    before = x.engine.state
    x.send(pdu)
    pending = next(iter(x.adapter.pending_sets.values()))
    assert len(pending.whole_message) <= (484 if x.level else 65507)
    await x.settle()
    wire = x.sink.sent[0][0]
    assert len(wire) <= (484 if x.level else 65507)
    response = x.decode()
    assert (int(v2c.apiPDU.get_error_status(response)), int(v2c.apiPDU.get_error_index(response))) == (1, 0)
    assert v2c.apiPDU.get_varbinds(response) == []
    assert x.engine.state is before
    x.empty()


@pytest.mark.parametrize("change", ["writer-off", "credential-aba", "write-view-aba", "same-view", "read-view", "expiry", "close", "reboot"])
async def test_application_set_waiting_current_generation_and_ready_claim(app_exchange, change):
    x = app_exchange
    await configure_application(x, "view-save", {"id": "write", "name": "SET", "includes": ["1.3.6.1.2.1"]})
    await configure_application(x, "credential-save", {"id": x.credential_id,
        "polling": {"view_id": "interfaces"}, "writing": {"view_id": "write"}})
    second = await configure_application(x, "credential-save", {"label": "Second writer", "community": "synthetic-second",
        "writing": {"enabled": True, "view_id": "write"}})
    other = second["id"]
    generation = dict(x.engine.state.credential_generations)
    saved_view = x.engine.state.cfg.views["write"].model_dump()
    async with x.adapter.io_lock:
        x.send(request())
        pending = next(iter(x.adapter.pending_sets.values()))
        await asyncio.sleep(0)
        assert pending.ticket.phase == "queued"
        if change == "writer-off":
            await x.engine.execute("credential-save", {"id": x.credential_id, "writing": {"enabled": False}})
        elif change == "credential-aba":
            await x.engine.execute("credential-save", {"id": x.credential_id, "enabled": False})
            await x.engine.execute("credential-save", {"id": x.credential_id, "enabled": True})
        elif change == "write-view-aba":
            await x.engine.execute("view-save", {**saved_view, "includes": ["1.3.6.1.2.1.47"]})
            await x.engine.execute("view-save", saved_view)
            assert x.engine.state.credential_generations[other] != generation[other]
        elif change == "same-view":
            await x.engine.execute("view-save", saved_view)
            assert x.engine.state.credential_generations == generation
        elif change == "read-view":
            await x.engine.execute("view-save", {"id": "interfaces", "name": "Read", "includes": ["1.3.6.1.2.1.1"]})
            assert x.engine.state.credential_generations == generation
        elif change == "expiry":
            x.expire()
        elif change == "close":
            x.adapter.close()
        elif change == "reboot":
            await x.engine.execute("reboot")
            x.adapter.close()
        if change not in ("close", "reboot"):
            await x.adapter._reconcile()
        after_change = x.engine.state
    await x.settle()
    if change in ("same-view", "read-view"):
        assert int(v2c.apiPDU.get_error_status(x.decode())) == 0
        assert x.engine.state.revision == after_change.revision + 1
    else:
        assert x.engine.state is after_change and not x.sink.sent
        assert next(iter(x.engine.state.cfg.ports.values())).admin_up
    terminal(pending.ticket)
    x.empty()


async def test_application_set_source_filter_drop_and_optional_empty_filter(app_exchange):
    x = app_exchange
    await configure_application(x, "credential-save", {"id": x.credential_id,
        "writing": {"networks": ["192.0.2.0/24"]}})
    before = x.engine.state
    x.send(request())
    await x.settle()
    assert x.engine.state is before and not x.sink.sent
    x.empty()
    await configure_application(x, "credential-save", {"id": x.credential_id, "writing": {"networks": []}})
    x.send(request())
    await x.settle()
    assert int(v2c.apiPDU.get_error_status(x.decode())) == 0
    x.empty()


async def test_application_set_bounded_overload_does_not_apply(app_exchange, monkeypatch):
    import switchlab.snmp as adapter_module
    x = app_exchange
    monkeypatch.setattr(adapter_module, "MAX_PENDING_SETS", 1)
    before = x.engine.state
    async with x.adapter.io_lock:
        x.send(request(1))
        pending = next(iter(x.adapter.pending_sets.values()))
        x.send(request(2))
        assert len(x.adapter.pending_sets) == 1 and x.engine.state is before and not x.sink.sent
    await x.settle()
    assert int(v2c.apiPDU.get_request_id(x.decode())) == 1
    assert x.engine.state.revision == before.revision + 1
    terminal(pending.ticket)
    x.empty()


async def test_application_write_only_retains_listener_without_polling_grant(app_exchange):
    x = app_exchange
    await configure_application(x, "credential-save", {"id": x.credential_id, "polling": {"enabled": False}})
    status = x.adapter.status()
    assert status["listener_ready"] and status["writing_ready"] and not status["ready"]
    assert status["reason"] == "credentials_required"
    pdu = v2c.GetRequestPDU()
    v2c.apiPDU.set_defaults(pdu)
    v2c.apiPDU.set_varbinds(pdu, [((1, 3, 6, 1, 2, 1, 2, 2, 1, 7, 101), a.Null())])
    x.send(pdu)
    assert not x.sink.sent
    x.expire()
    x.empty()
    x.send(request())
    await x.settle()
    assert int(v2c.apiPDU.get_error_status(x.decode())) == 0
    await configure_application(x, "credential-save", {"id": x.credential_id, "writing": {"enabled": False}})
    assert not x.adapter.listening and not x.adapter.status()["writing_ready"]


@pytest.mark.parametrize("delivery", ["before", "after"])
async def test_application_set_commit_survives_failed_delivery(app_exchange, delivery):
    x = app_exchange
    before = x.engine.state
    x.sink.failure = delivery
    x.send(three_bindings())
    pending = next(iter(x.adapter.pending_sets.values()))
    await x.settle()
    assert x.engine.state.revision == before.revision + 1
    assert x.engine.store.load() == x.engine.state.cfg
    assert x.engine.state.cfg.vlans[1].name == "Committed" and x.engine.idempotency == {}
    assert x.adapter.set_error == "set_delivery_failed"
    assert x.sink.attempts == 1 and len(x.sink.sent) == (delivery == "after")
    assert not x.adapter.inbound.complete(pending.ticket, lambda: pytest.fail("Repeated effect"))
    x.sink.sent.clear()
    x.empty()


class TransactionFault:
    def __init__(self, connection, stage):
        self.connection, self.stage = connection, stage
        self.commit_calls = self.rollback_calls = 0
    def __getattr__(self, name):
        return getattr(self.connection, name)
    def commit(self):
        import sqlite3
        self.commit_calls += 1
        if self.stage == "commit-after":
            self.connection.commit()
        elif self.stage == "commit-rolled-back":
            self.connection.rollback()
        raise sqlite3.OperationalError("Synthetic COMMIT failure")
    def rollback(self):
        import sqlite3
        self.rollback_calls += 1
        if self.stage == "rollback":
            raise sqlite3.OperationalError("Synthetic rollback failure")
        self.connection.rollback()


@pytest.mark.parametrize("stage,status,index", [("mid-write", 14, 2), ("commit-before", 14, 2),
                                                 ("rollback", 15, 0), ("commit-after", None, None),
                                                 ("commit-rolled-back", None, None)])
async def test_application_set_storage_commit_rollback_and_unknown_outcomes(app_exchange, monkeypatch, stage, status, index):
    import sqlite3
    x = app_exchange
    store = x.engine.store
    before = x.engine.state
    saved = store.get("configuration"), store.events(), store.last_event
    connection = store.db
    proxy = TransactionFault(connection, stage)
    original_put = store.put
    def put(key, value):
        original_put(key, value)
        if key == "outbox":
            raise sqlite3.OperationalError("Synthetic mid-write failure")
    try:
        with monkeypatch.context() as patcher:
            if stage == "mid-write":
                patcher.setattr(store, "put", put)
            else:
                patcher.setattr(store, "db", proxy)
            x.send(three_bindings())
            await x.settle()
        assert x.engine.state is before and x.engine.idempotency == {}
        if status is None:
            assert not x.sink.sent and x.adapter.set_error == "storage_commit_unknown"
            assert not connection.in_transaction
            if stage == "commit-after":
                assert store.get("configuration")["vlans"]["1"]["name"] == "Committed"
            else:
                assert (store.get("configuration"), store.events(), store.last_event) == saved
            assert proxy.commit_calls == 1 and proxy.rollback_calls == 0
        else:
            response = x.decode()
            assert (int(v2c.apiPDU.get_error_status(response)), int(v2c.apiPDU.get_error_index(response))) == (status, index)
            if stage == "rollback":
                assert connection.in_transaction and proxy.rollback_calls == 1
                assert x.adapter.set_error == "storage_rollback_failed"
            else:
                assert not connection.in_transaction
                assert (store.get("configuration"), store.events(), store.last_event) == saved
                if stage == "commit-before":
                    assert proxy.commit_calls == proxy.rollback_calls == 1
        x.empty()
    finally:
        connection.rollback()


async def test_application_set_waiting_on_engine_lock_expires_before_effects(app_exchange):
    x = app_exchange
    before = x.engine.state
    async with x.engine.lock:
        x.send(request())
        pending = next(iter(x.adapter.pending_sets.values()))
        await asyncio.sleep(0)
        assert x.adapter.io_lock.locked() and pending.ticket.phase == "queued"
        x.expire()
    await x.settle()
    assert x.engine.state is before and not x.sink.sent
    terminal(pending.ticket)
    x.empty()


async def test_application_set_original_request_id_widths_and_max_varbinds(app_exchange):
    x = app_exchange
    before = x.engine.state
    for identifier in (-2147483648, -129, -128, -1, 0, 127, 128, 32768, 2147483647):
        pdu = request(identifier)
        v2c.apiPDU.set_varbinds(pdu, [])
        x.send(pdu)
        await x.settle()
        response = x.decode()
        assert int(v2c.apiPDU.get_request_id(response)) == identifier
        assert int(v2c.apiPDU.get_error_status(response)) == 0 and not v2c.apiPDU.get_varbinds(response)
        assert x.engine.state is before
    pdu = request(128)
    v2c.apiPDU.set_varbinds(pdu, v2c.apiPDU.get_varbinds(pdu) * 257)
    x.send(pdu)
    await x.settle()
    response = x.decode()
    assert int(v2c.apiPDU.get_error_status(response)) == 1 and not v2c.apiPDU.get_varbinds(response)
    assert x.engine.state is before
    x.empty()


async def test_application_set_then_get_retains_projection_and_read_grant(app_exchange):
    x = app_exchange
    x.send(three_bindings())
    await x.settle()
    assert int(v2c.apiPDU.get_error_status(x.decode())) == 0
    before = x.engine.state
    pdu = v2c.GetRequestPDU()
    v2c.apiPDU.set_defaults(pdu)
    v2c.apiPDU.set_varbinds(pdu, [((1, 3, 6, 1, 2, 1, 2, 2, 1, 7, 101), a.Null()),
                                ((1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 3, 1, 1, 1), a.Null())])
    x.send(pdu)
    response = x.decode()
    values = v2c.apiPDU.get_varbinds(response)
    assert int(values[0][1]) == 2 and values[1][1].asOctets() == b"Committed"
    assert x.engine.state is before
    x.empty()


async def test_application_set_unknown_context_uses_real_report_counter(app_exchange):
    x = app_exchange
    if not x.level:
        # SNMPv2c has no context-name field in its wire message.
        return
    counter = x.agent.get_mib_builder().import_symbols("__SNMP-TARGET-MIB", "snmpUnknownContexts")[0]
    prior = int(counter.syntax)
    before = x.engine.state
    x.send(request(), context_name=b"missing-context")
    await x.settle()
    assert int(counter.syntax) == prior + 1 and x.engine.state is before
    assert len(x.sink.sent) == 1
    wire = x.sink.sent.pop()[0]
    prior_responses = len(x.returned)
    receive(x.manager, wire, TARGET)
    assert len(x.returned) == prior_responses + 1
    # PySNMP maps the actual report into the manager's error indication.
    assert x.returned[-1][9] is not None
    x.empty()


async def test_application_set_insufficient_v3_security_level_drops_without_effect(app_exchange):
    x = app_exchange
    if x.level < 2:
        return
    before = x.engine.state
    x.send(request(), security_level=1)
    await x.settle()
    assert x.engine.state is before and not x.adapter.pending_sets
    # USM rejects this below the application and emits its standard report.
    # This is not a normal SET authorization response or a committed assignment.
    from pysnmp.proto.mpmod.rfc3412 import SNMPv3Message
    from pysnmp.proto.rfc1905 import ReportPDU
    assert len(x.sink.sent) == 1
    message = decoder.decode(x.sink.sent.pop()[0], asn1Spec=SNMPv3Message())[0]
    report = message["msgData"]["plaintext"]["data"].getComponent()
    assert report.tagSet == ReportPDU.tagSet
    fields = v2c.apiPDU.get_varbinds(report)
    assert len(fields) == 1 and tuple(fields[0][0]) == (1, 3, 6, 1, 6, 3, 15, 1, 1, 1, 0)
    assert int(fields[0][1]) >= 1
    x.empty()


async def test_application_set_expired_before_task_start_is_normal_terminal(app_exchange):
    x = app_exchange
    before = x.engine.state
    x.send(request())
    pending = next(iter(x.adapter.pending_sets.values()))
    x.expire()  # No yield: the owning coroutine has not started yet.
    terminal(pending.ticket)
    await x.settle()
    assert x.engine.state is before and not x.sink.sent
    assert x.adapter.set_error is None
    x.empty()


@pytest.mark.parametrize("stage", ["rollback", "commit-after", "commit-rolled-back"])
async def test_application_storage_fault_retires_queued_sets_and_preserves_reads(app_exchange, monkeypatch, stage):
    from switchlab.storage import StorageFault
    x = app_exchange
    store = x.engine.store
    before = x.engine.state
    connection = store.db
    proxy = TransactionFault(connection, stage)
    async with x.adapter.io_lock:
        with monkeypatch.context() as change:
            change.setattr(store, "db", proxy)
            x.send(three_bindings())
            first = next(iter(x.adapter.pending_sets.values()))
            x.send(request(42))
            second = list(x.adapter.pending_sets.values())[1]
        # Keep the failing connection wrapper installed through the transaction.
        store.db = proxy
    try:
        await x.settle()
    finally:
        store.db = connection
    if stage == "rollback":
        assert int(v2c.apiPDU.get_error_status(x.decode())) == 15
    else:
        assert not x.sink.sent
    assert x.engine.state is before and store.fault_reason is not None
    terminal(first.ticket); terminal(second.ticket)
    status = x.adapter.status()
    assert status["ready"] and not status["writing_ready"] and not status["notifications_ready"]
    assert status["storage_status"]["snapshot"] == "last_confirmed"
    # A normal read is available from the last confirmed Runtime, not this
    # connection's possibly committed or uncommitted candidate configuration.
    pdu = v2c.GetRequestPDU(); v2c.apiPDU.set_defaults(pdu)
    v2c.apiPDU.set_varbinds(pdu, [((1, 3, 6, 1, 2, 1, 17, 7, 1, 4, 3, 1, 1, 1), a.Null())])
    x.send(pdu)
    assert v2c.apiPDU.get_varbinds(x.decode())[0][1].asOctets() == b"Default"
    x.send(request(43)); await x.settle()
    assert not x.sink.sent and x.engine.state is before
    for action, payload in [("advance", {"duration_ms": 1000}), ("switch-edit", {"contact": "Unrelated"}),
                            ("notification-result", {}), ("reboot", {}), ("coldStart", {})]:
        with pytest.raises(StorageFault):
            await x.engine.execute(action, payload)
        assert x.engine.state is before
    for operation in (lambda: store.put("fixture", True), lambda: store.create_administrator("not-a-password"),
                      store.engine_boot, store.load, lambda: store.commit(before, {})):
        with pytest.raises(StorageFault):
            operation()
    await x.adapter._reconcile()
    assert x.adapter.listening
    x.empty()
    connection.rollback()  # Test teardown only; this must not heal the incarnation.
    with pytest.raises(StorageFault):
        await x.engine.execute("switch-edit", {"contact": "Still blocked"})


from pysnmp.carrier.base import AbstractTransport, AbstractTransportAddress

class MemoryAddress(tuple, AbstractTransportAddress):
    pass

class MemoryTransport(AbstractTransport):
    PROTO_TRANSPORT_DISPATCHER = AbstractTransportDispatcher
    ADDRESS_TYPE = MemoryAddress
    def open_client_mode(self, iface=None):
        self._lport = asyncio.get_running_loop().create_future()
        self._lport.set_result(None)
        return self
    def open_server_mode(self, iface):
        return self.open_client_mode(iface)


@pytest.mark.parametrize("stage", ["rollback", "commit-after", "commit-rolled-back"])
@pytest.mark.parametrize("level", [0, 1, 2, 3])
async def test_storage_fault_existing_startup_restores_set_and_notification_capabilities(tmp_path, monkeypatch, stage, level):
    from cryptography.fernet import Fernet
    from switchlab.storage import Store, StorageFault
    from switchlab.engine import Engine
    from switchlab.models import initial_configuration
    key = Fernet.generate_key()
    path = str(tmp_path / "recovery.db")
    cfg = initial_configuration(4); cfg.paused = True
    cfg.switch.identity.sys_object_id = "1.3.6.1.4.1.32473.1"
    cfg.snmp.enabled = True
    store = Store(path, key)
    e = Engine(cfg, store)
    fields = {"label": "Recovered credential", "polling": {"enabled": True},
              "writing": {"enabled": True, "view_id": "all"}}
    if level:
        fields.update(version="3", username="lifetime-probe", security_level={1: "noAuthNoPriv", 2: "authNoPriv", 3: "authPriv"}[level],
            auth_key="synthetic-auth-passphrase" if level > 1 else None, priv_key="synthetic-priv-passphrase" if level == 3 else None)
    else:
        fields["community"] = "synthetic-community"
    cid = (await e.execute("credential-save", fields))["id"]
    from conftest import endpoint, tick
    eid = await endpoint(e)
    await tick(e)
    assert e.state.fdb
    tid = (await e.execute("target-save", {"address": "127.0.0.1", "credential_id": cid}))["id"]
    x = ApplicationExchange(e, store, level)
    x.credential_id = cid
    try:
        # Ordinary adapter registration/reconciliation, with only the OS transport
        # replaced. Public notification BER is still serialized and captured.
        with patch("switchlab.snmp.udp.UdpTransport", MemoryTransport):
            await x.start()
        await e.execute("test-notification", {"target_id": tid})
        await x.adapter.drain_one()
        assert len(x.sink.sent) == 1 and not e.state.outbox
        x.sink.sent.clear()
        await e.execute("test-notification", {"target_id": tid})
        before = e.state
        identity, boots = x.adapter.engine_id, x.adapter.boots
        connection = store.db
        with monkeypatch.context() as change:
            change.setattr(store, "db", TransactionFault(connection, stage))
            x.send(three_bindings())
            pending = next(iter(x.adapter.pending_sets.values()))
            await x.settle()
        if stage == "rollback":
            assert int(v2c.apiPDU.get_error_status(x.decode())) == 15
        else:
            assert not x.sink.sent
        queued = copy.deepcopy(e.state.outbox)
        assert queued
        attempts = x.sink.attempts
        await x.adapter.drain_one()
        assert x.sink.attempts == attempts and e.state.outbox == queued and e.state is before
        with pytest.raises(StorageFault):
            await e.execute("switch-edit", {"contact": "Would overwrite unconfirmed primary"})
        await x.close()
        store.close()  # Ends an open failed-rollback transaction; no in-place reset.
        for restart in range(2):
            store = Store(path, key)
            e = Engine(store.load(), store)
            assert e.state.cfg.vlans[1].name == ("Committed" if stage == "commit-after" else "Default")
            assert e.state.cfg.switch.contact == "" and not e.state.fdb
            assert e.storage_status()["healthy"] and cid in e.state.cfg.credentials
            assert eid in e.state.cfg.endpoints and e.state.cfg.credentials[cid] == before.cfg.credentials[cid]
            x = ApplicationExchange(e, store, level); x.credential_id = cid
            x.adapter.cold_sent = False
            with patch("switchlab.snmp.udp.UdpTransport", MemoryTransport):
                await x.start()
            assert x.adapter.engine_id == identity and x.adapter.boots == boots + restart + 1
            # Old queued notifications are canceled at ordinary management startup;
            # the fresh coldStart now has a usable, durable send/result path.
            assert e.state.outbox and e.state.outbox[0]["event"]["kind"] == "coldStart"
            await x.adapter.drain_one()
            assert len(x.sink.sent) == 1 and not e.state.outbox
            if level:
                traps = []
                x.manager.message_dispatcher.register_context_engine_id(b"", (v2c.SNMPv2TrapPDU.tagSet,), lambda *args: traps.append(args[8]))
                receive(x.manager, x.sink.sent.pop()[0], TARGET)
                assert traps and traps[0].tagSet == v2c.SNMPv2TrapPDU.tagSet
            else:
                trap = decoder.decode(x.sink.sent.pop()[0], asn1Spec=v2c.Message())[0]
                assert v2c.apiMessage.get_pdu(trap).tagSet == v2c.SNMPv2TrapPDU.tagSet
            before_late = e.state
            await x.adapter._run_set(pending)
            assert e.state is before_late and not x.sink.sent
            # Fresh SET is available after each ordinary validated restart.
            x.send(request(100 + restart)); await x.settle()
            assert int(v2c.apiPDU.get_error_status(x.decode())) == 0
            assert not next(iter(e.state.cfg.ports.values())).admin_up
            await e.execute("switch-edit", {"location": "Fresh mutation"})
            await x.close(); store.close()
    finally:
        if not store.closed:
            await x.close()
            store.close()
