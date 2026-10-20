"""USM protocol selection at schema, storage, registration, and real UDP boundaries."""
import asyncio
import copy
import json
from unittest.mock import patch

import pytest
from pyasn1.codec.ber import decoder
from pydantic import ValidationError
from pysnmp.entity import config, engine as snmp_engine
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.hlapi.v3arch.asyncio import (
    SnmpEngine, UsmUserData, UdpTransportTarget, ContextData, ObjectType,
    ObjectIdentity, get_cmd, set_cmd,
)
from pysnmp.proto import rfc1902 as a
from pysnmp.proto.mpmod.rfc3412 import SNMPv3Message
from pysnmp.proto.secmod.rfc3414.service import UsmSecurityParameters

from switchlab.engine import Engine
from switchlab.models import CredentialAuth, Configuration
from switchlab.snmp import SnmpAdapter
from switchlab.storage import compose_configuration, split_configuration
from test_wire import start

AUTH = {
    "md5": config.USM_AUTH_HMAC96_MD5,
    "sha1": config.USM_AUTH_HMAC96_SHA,
    "sha224": config.USM_AUTH_HMAC128_SHA224,
    "sha256": config.USM_AUTH_HMAC192_SHA256,
    "sha384": config.USM_AUTH_HMAC256_SHA384,
    "sha512": config.USM_AUTH_HMAC384_SHA512,
}
PRIV = {
    "des": config.USM_PRIV_CBC56_DES,
    "aes128": config.USM_PRIV_CFB128_AES,
    "aes192": config.USM_PRIV_CFB192_AES,
    "aes256": config.USM_PRIV_CFB256_AES,
}
DIGEST = {"md5": 12, "sha1": 12, "sha224": 16, "sha256": 24, "sha384": 32, "sha512": 48}
AUTH_KEY, PRIV_KEY = "fixture-auth-pass", "fixture-priv-pass"
USER = "protocol-fixture"
ADMIN_OID = "1.3.6.1.2.1.2.2.1.7.101"
CASES = [("noAuthNoPriv", "sha512", "des")]
CASES += [("authNoPriv", auth, "aes256") for auth in AUTH]
CASES += [("authPriv", auth, priv) for auth in AUTH for priv in PRIV]


def credential(level="authPriv", auth="sha256", priv="aes128"):
    return dict(version="3", label="Protocols", username=USER, security_level=level,
                auth_protocol=auth, priv_protocol=priv, auth_key=AUTH_KEY, priv_key=PRIV_KEY,
                community=None)


def parameters(level, auth, priv, auth_key=AUTH_KEY, priv_key=PRIV_KEY):
    return dict(authProtocol=AUTH[auth] if level != "noAuthNoPriv" else config.USM_AUTH_NONE,
                authKey=auth_key if level != "noAuthNoPriv" else None,
                privProtocol=PRIV[priv] if level == "authPriv" else config.USM_PRIV_NONE,
                privKey=priv_key if level == "authPriv" else None)


def manager_user(level, auth, priv, **keys):
    p = parameters(level, auth, priv, **keys)
    return UsmUserData(USER, p.pop("authKey"), p.pop("privKey"), **p)


async def query(port, user, value=None):
    manager = SnmpEngine()
    try:
        target = await UdpTransportTarget.create(("127.0.0.1", port), timeout=.2, retries=0)
        binding = ObjectType(ObjectIdentity(ADMIN_OID), a.Integer32(value)) if value is not None else ObjectType(ObjectIdentity(ADMIN_OID))
        command = set_cmd if value is not None else get_cmd
        return await command(manager, user, target, ContextData(), binding)
    finally:
        manager.close_dispatcher()


@pytest.mark.parametrize("level,auth,priv", CASES)
async def test_protocol_get_set_and_notification(engine, level, auth, priv):
    adapter, port = await start(engine, **credential(level, auth, priv),
        writing={"enabled": True, "view_id": "all"})
    receiver = snmp_engine.SnmpEngine()
    packets, delivered = asyncio.Queue(), asyncio.Queue()
    class Capture(udp.UdpTransport):
        def datagram_received(self, data, peer):
            packets.put_nowait(data)
            super().datagram_received(data, peer)
    transport = Capture().open_server_mode(("127.0.0.1", 0))
    await transport._lport
    config.add_transport(receiver, udp.DOMAIN_NAME, transport)
    config.add_v3_user(receiver, USER, securityEngineId=a.OctetString(adapter.engine_id),
                       **parameters(level, auth, priv))
    ntfrcv.NotificationReceiver(receiver, lambda eng, ref, ce, cn, bindings, ctx:
                                delivered.put_nowait(bindings))
    try:
        error, status, _, bindings = await query(port, manager_user(level, auth, priv))
        assert not error and not status, (error, status, adapter.status())
        value = 2
        error, status, _, bindings = await query(port, manager_user(level, auth, priv), value)
        assert not error and not status, (error, status, adapter.status())
        assert int(bindings[0][1]) == value and not next(iter(engine.state.cfg.ports.values())).admin_up
        error, status, _, bindings = await query(port, manager_user(level, auth, priv))
        assert not error and not status and int(bindings[0][1]) == value
        cid = next(iter(engine.state.cfg.credentials))
        tid = (await engine.execute("target-save", {"address": "127.0.0.1", "credential_id": cid,
            "port": transport.transport.get_extra_info("sockname")[1]}))["id"]
        await adapter.reconcile()
        await engine.execute("test-notification", {"target_id": tid})
        await adapter.drain_one()
        notification = await asyncio.wait_for(delivered.get(), 2)
        assert str(notification[1][1]) == "1.3.6.1.6.3.1.1.5.1"
        message = decoder.decode(await packets.get(), asn1Spec=SNMPv3Message())[0]
        usm = decoder.decode(message["msgSecurityParameters"].asOctets(), asn1Spec=UsmSecurityParameters())[0]
        assert len(usm["msgAuthenticationParameters"]) == (0 if level == "noAuthNoPriv" else DIGEST[auth])
        assert message["msgData"].getName() == ("encryptedPDU" if level == "authPriv" else "plaintext")
        # A fresh peer with the wrong active secret cannot read or mutate.
        if level != "noAuthNoPriv":
            wrong = {"priv_key": "incorrect-privacy"} if level == "authPriv" else {"auth_key": "incorrect-auth"}
            error, status, _, _ = await query(port, manager_user(level, auth, priv, **wrong), 1)
            assert error or status
            assert not next(iter(engine.state.cfg.ports.values())).admin_up
    finally:
        receiver.close_dispatcher()
        adapter.close()


@pytest.mark.parametrize("level", ["noAuthNoPriv", "authNoPriv", "authPriv"])
async def test_inactive_registration_material_is_absent(engine, level):
    # Stored selections and inactive secrets can survive without becoming active.
    calls = []
    real = config.add_v3_user
    def record(*args, **kwargs):
        calls.append(kwargs.copy())
        return real(*args, **kwargs)
    with patch("switchlab.snmp.config.add_v3_user", side_effect=record):
        adapter, _ = await start(engine, **credential(level, "sha512", "des"))
    try:
        assert calls == [parameters(level, "sha512", "des")]
        row = engine.state.cfg.credentials[next(iter(engine.state.cfg.credentials))]
        assert row.auth_protocol == "sha512" and row.priv_protocol == "des"
        assert row.auth_key == AUTH_KEY and row.priv_key == PRIV_KEY
    finally:
        adapter.close()


async def test_sparse_selection_preserves_policy_secrets_and_saved_state(engine):
    adapter, _ = await start(engine, **credential(), polling={"enabled": True, "view_id": "all", "networks": ["127.0.0.0/8"]},
                             writing={"enabled": True, "view_id": "all", "networks": ["127.0.0.0/8"]})
    try:
        cid = next(iter(engine.state.cfg.credentials))
        before = engine.state.cfg.credentials[cid].model_dump()
        groups = copy.deepcopy(engine.state.cfg.groups)
        generation = engine.state.credential_generations[cid]
        identity, boots = adapter.engine_id, adapter.boots
        await engine.execute("credential-save", {"id": cid, "auth_protocol": "sha512", "priv_protocol": "des",
                                                  "auth_key": "", "priv_key": ""})
        expected = {**before, "auth_protocol": "sha512", "priv_protocol": "des"}
        assert engine.state.cfg.credentials[cid].model_dump() == expected
        assert engine.state.cfg.groups == groups and engine.state.credential_generations[cid] != generation
        await adapter.reconcile()
        assert adapter.configured[cid] == expected and (adapter.engine_id, adapter.boots) == (identity, boots)
        assert engine.state.cfg.groups[before["group_id"]].polling.networks == ["127.0.0.0/8"]
        await engine.execute("save-startup")
        saved = engine.state.cfg.model_copy(deep=True)
        await engine.execute("credential-save", {"id": cid, "auth_protocol": "md5"})
        assert engine.store.load() == saved
        await engine.execute("reboot")
        assert engine.state.cfg == saved and engine.store.load() == saved
        scenario = engine.export()
        assert "credentials" not in scenario and "groups" not in scenario
        await engine.execute("import", scenario)
        assert engine.state.cfg.credentials[cid].model_dump() == expected
        snapshot = json.dumps(engine.snapshot())
        assert AUTH_KEY not in snapshot and PRIV_KEY not in snapshot
        assert AUTH_KEY not in str(list(engine.store.db.execute("SELECT value FROM kv")))
    finally:
        adapter.close()


@pytest.mark.parametrize("field,value", [("auth_protocol", "sha"), ("auth_protocol", "SHA256"),
    ("auth_protocol", None), ("priv_protocol", "none"), ("priv_protocol", None),
    ("priv_protocol", "aes256-blumenthal"), ("security_level", "noAuthPriv")])
async def test_invalid_selection_rejected_atomically(engine, field, value):
    await engine.execute("credential-save", credential())
    cid = next(iter(engine.state.cfg.credentials))
    before = engine.state
    with pytest.raises(ValidationError):
        await engine.execute("credential-save", {"id": cid, field: value})
    assert engine.state is before


async def test_inline_target_and_missing_only_split_defaults(engine):
    inline = credential(auth="sha384", priv="aes192")
    result = await engine.execute("target-save", {"address": "127.0.0.1", "new_credential": inline})
    cid = result["credential_id"]
    row = engine.state.cfg.credentials[cid]
    assert row.group_id is None and row.auth_protocol == "sha384" and row.priv_protocol == "aes192"
    # Whole configurations and strict pre-selection split records retain identity,
    # policy and keys; only absent protocol fields acquire the historical profile.
    lab, startup = split_configuration(engine.state.cfg)
    startup["credentials"][cid].pop("auth_protocol")
    startup["credentials"][cid].pop("priv_protocol")
    raw = engine.state.cfg.model_dump(mode="json")
    raw["credentials"] = copy.deepcopy(startup["credentials"])
    original = copy.deepcopy(startup)
    normalized = compose_configuration(lab, startup)
    assert startup == original and Configuration.model_validate(raw) == normalized
    expected = row.model_copy(update={"auth_protocol": "sha256", "priv_protocol": "aes128"})
    assert normalized.credentials[cid] == expected
    # Explicit invalid values and other missing security fields still fail.
    for key, value in [("auth_protocol", None), ("priv_protocol", "unknown")]:
        invalid = copy.deepcopy(startup)
        invalid["credentials"][cid][key] = value
        with pytest.raises(ValidationError):
            compose_configuration(lab, invalid)
    missing = copy.deepcopy(startup)
    del missing["credentials"][cid]["auth_key"]
    with pytest.raises((ValidationError, ValueError)):
        compose_configuration(lab, missing)
    await engine.execute("save-startup")
    assert engine.store.load() == engine.state.cfg


def test_defaults_and_active_passphrase_validation():
    user = CredentialAuth.model_validate({"version": "3", "label": "old", "username": "old", "auth_key": AUTH_KEY, "priv_key": PRIV_KEY})
    assert (user.security_level, user.auth_protocol, user.priv_protocol) == ("authPriv", "sha256", "aes128")
    for level in ("noAuthNoPriv", "authNoPriv", "authPriv"):
        fields = credential(level)
        fields.update(auth_key=None, priv_key=None)
        if level == "noAuthNoPriv":
            CredentialAuth.model_validate(fields)
        else:
            with pytest.raises(ValidationError):
                CredentialAuth.model_validate(fields)


async def memory_exchange(engine, store, auth, priv):
    from test_snmp_lifetime import ApplicationExchange
    await engine.execute("switch-edit", {"identity": {"sys_object_id": "1.3.6.1.4.1.32473.1"}})
    await engine.execute("snmp-settings", {"enabled": True})
    gid = (await engine.execute("group-save", {"label": "Boundary group", "minimum_security_level": "authPriv",
        "polling": {"enabled": True}, "writing": {"enabled": True, "view_id": "all"}}))["id"]
    cid = (await engine.execute("credential-save", {**credential(auth=auth, priv=priv),
            "username": "lifetime-probe", "group_id": gid}))["id"]
    def install_manager(snmp, level, security_engine=None):
        config.add_v3_user(snmp, "lifetime-probe", securityEngineId=security_engine,
                           **parameters("authPriv", auth, priv))
    with patch("test_snmp_lifetime.user", side_effect=install_manager):
        exchange = ApplicationExchange(engine, store, 3)
    exchange.credential_id = cid
    return await exchange.start()


def name_request(length, count=1):
    from pysnmp.proto.api import v2c
    from test_snmp_lifetime import request
    pdu = request()
    v2c.apiPDU.set_varbinds(pdu,
        [((1,3,6,1,2,1,17,7,1,4,3,1,1,1), a.OctetString(b"x" * length))] * count +
        [((1,3,6,1,2,1,2,2,1,7,101), a.Integer32(2))])
    return pdu


@pytest.mark.parametrize("auth,priv", [("sha512", "des"), ("md5", "des"), ("sha512", "aes128"), ("md5", "aes128")])
async def test_budget_matches_actual_ber_digest_and_cipher_padding(engine, store, auth, priv):
    from pyasn1.codec.ber import encoder
    from switchlab.snmp import response_budget
    x = await memory_exchange(engine, store, auth, priv)
    try:
        alignments = set()
        # Eight adjacent legal name widths visit all DES block alignments.
        for width in range(24, 32):
            x.send(name_request(width, 13))
            pending = next(iter(x.adapter.pending_sets.values()))
            args, whole = pending.args, pending.whole_message
            await x.settle()
            wire = x.sink.sent[0][0]
            message = decoder.decode(wire, asn1Spec=SNMPv3Message())[0]
            usm = decoder.decode(message["msgSecurityParameters"].asOctets(), asn1Spec=UsmSecurityParameters())[0]
            assert len(usm["msgAuthenticationParameters"]) == DIGEST[auth]
            if priv == "des":
                assert len(message["msgData"]["encryptedPDU"]) % 8 == 0
            # Replace only the actual response's clocks by the largest legal
            # encodings. This independently preserves the real cipher/digest
            # output instead of estimating their lengths in the test.
            usm["msgAuthoritativeEngineBoots"] = usm["msgAuthoritativeEngineTime"] = 2147483647
            message["msgSecurityParameters"] = encoder.encode(usm)
            expected = len(encoder.encode(message))
            assert expected > 484
            incoming = decoder.decode(whole, asn1Spec=SNMPv3Message())[0]
            for maximum in (expected - 1, expected, expected + 1):
                incoming["msgGlobalData"]["msgMaxSize"] = maximum
                assert response_budget(args, encoder.encode(incoming), engine.state.cfg.credentials[x.credential_id]) == (maximum >= expected)
            from pysnmp.proto.api import v2c
            from pysnmp.proto.mpmod.rfc3412 import ScopedPDU
            response = v2c.apiPDU.get_response(args[8])
            v2c.apiPDU.set_varbinds(response, v2c.apiPDU.get_varbinds(args[8]))
            scope = ScopedPDU()
            scope["contextEngineId"], scope["contextName"] = args[5], args[6]
            scope["data"].setComponentByType(response.tagSet, response)
            alignments.add(len(encoder.encode(scope)) % 8)
            if priv == "des":
                scope_length = len(encoder.encode(scope))
                assert len(message["msgData"]["encryptedPDU"]) == scope_length + 8 - scope_length % 8
            x.decode()
        assert alignments == set(range(8))
        x.empty()
    finally:
        await x.close()


@pytest.mark.parametrize("field,value", [("auth_protocol", "sha512"), ("priv_protocol", "des")])
async def test_protocol_rotation_retires_queued_set(engine, store, field, value):
    from test_snmp_lifetime import request
    x = await memory_exchange(engine, store, "sha256", "aes128")
    try:
        generation = engine.state.credential_generations[x.credential_id]
        async with x.adapter.io_lock:
            x.send(request())
            pending = next(iter(x.adapter.pending_sets.values()))
            await asyncio.sleep(0)
            assert pending.ticket.phase == "queued"
            await engine.execute("credential-save", {"id": x.credential_id, field: value})
            await x.adapter._reconcile()
        await x.settle()
        assert engine.state.credential_generations[x.credential_id] != generation
        assert pending.ticket.phase == "terminal"
        assert not x.sink.sent and next(iter(engine.state.cfg.ports.values())).admin_up
        x.empty()
    finally:
        await x.close()


async def test_live_rotation_uses_fresh_profile_for_requests_and_targets(engine):
    adapter, port = await start(engine, **credential(), writing={"enabled": True, "view_id": "all"})
    receiver = snmp_engine.SnmpEngine()
    delivered = asyncio.Queue()
    transport = udp.UdpTransport().open_server_mode(("127.0.0.1", 0))
    await transport._lport
    config.add_transport(receiver, udp.DOMAIN_NAME, transport)
    config.add_v3_user(receiver, USER, securityEngineId=a.OctetString(adapter.engine_id),
                       **parameters("authPriv", "sha256", "aes128"))
    ntfrcv.NotificationReceiver(receiver, lambda eng, ref, ce, cn, bindings, ctx: delivered.put_nowait(bindings))
    try:
        cid = next(iter(engine.state.cfg.credentials))
        tid = (await engine.execute("target-save", {"address": "127.0.0.1", "credential_id": cid,
            "port": transport.transport.get_extra_info("sockname")[1]}))["id"]
        await adapter.reconcile()
        async def trap():
            await engine.execute("test-notification", {"target_id": tid})
            await adapter.drain_one()
            bindings = await asyncio.wait_for(delivered.get(), 2)
            assert str(bindings[1][1]) == "1.3.6.1.6.3.1.1.5.1"
        await trap()
        old_sender = adapter.send_transports[tid][1]
        assert not (await query(port, manager_user("authPriv", "sha256", "aes128")))[0]
        identity = adapter.engine_id
        await engine.execute("credential-save", {"id": cid, "auth_protocol": "md5", "priv_protocol": "des"})
        await adapter.reconcile()
        assert adapter.engine_id == identity and adapter.send_transports[tid][1] is not old_sender
        config.delete_v3_user(receiver, USER, securityEngineId=a.OctetString(adapter.engine_id))
        config.add_v3_user(receiver, USER, securityEngineId=a.OctetString(adapter.engine_id),
                           **parameters("authPriv", "md5", "des"))
        await trap()
        error, status, _, _ = await query(port, manager_user("authPriv", "sha256", "aes128"), 2)
        assert error or status
        assert next(iter(engine.state.cfg.ports.values())).admin_up
        error, status, _, bindings = await query(port, manager_user("authPriv", "md5", "des"), 2)
        assert not error and not status and int(bindings[0][1]) == 2
        assert not next(iter(engine.state.cfg.ports.values())).admin_up
    finally:
        receiver.close_dispatcher()
        adapter.close()


@pytest.mark.parametrize("auth,fit,oversize", [("sha512", 21, 22), ("md5", 26, 27)])
async def test_des_peer_budget_rejects_before_commit_at_boundary(engine, store, auth, fit, oversize):
    from pysnmp.proto.api import v2c
    x = await memory_exchange(engine, store, auth, "des")
    try:
        maximum = x.manager.get_mib_builder().import_symbols(
            "__SNMP-FRAMEWORK-MIB", "snmpEngineMaxMessageSize")[0]
        maximum.syntax = maximum.syntax.clone(484)
        for width, expected_status in [(fit, 0), (oversize, 1)]:
            before = engine.state
            x.send(name_request(width, 7))
            pending = next(iter(x.adapter.pending_sets.values()))
            assert len(pending.whole_message) <= 484
            await x.settle()
            assert len(x.sink.sent[0][0]) <= 484
            response = x.decode()
            assert int(v2c.apiPDU.get_error_status(response)) == expected_status
            if expected_status:
                assert v2c.apiPDU.get_varbinds(response) == []
                assert engine.state is before
            else:
                assert engine.state.revision == before.revision + 1
                assert engine.state.cfg.vlans[1].name == "x" * width
                assert not next(iter(engine.state.cfg.ports.values())).admin_up
            x.empty()
    finally:
        await x.close()


async def test_legacy_split_restart_preserves_policy_and_identity(engine):
    gid = (await engine.execute("group-save", {"label": "Existing policy", "minimum_security_level": "authPriv",
        "polling": {"enabled": True, "view_id": "interfaces", "networks": ["192.0.2.0/24"]},
        "writing": {"enabled": False, "view_id": None, "networks": ["198.51.100.0/24"]}}))["id"]
    cid = (await engine.execute("credential-save", {**credential(), "group_id": gid}))["id"]
    await engine.execute("save-startup")
    expected = engine.state.cfg.model_copy(deep=True)
    saved = engine.store.get("startup_configuration")
    saved["credentials"][cid].pop("auth_protocol")
    saved["credentials"][cid].pop("priv_protocol")
    with engine.store.transaction():
        engine.store.put("startup_configuration", saved)
        engine.store.put("engine_identity", "80000000047363726174636841")
        engine.store.put("engine_boots", 17)
    restarted = Engine(engine.state.cfg, engine.store)
    assert restarted.state.cfg == expected and restarted.store.load() == expected
    assert not restarted.snapshot()["configuration_status"]["unsaved"]
    assert restarted.store.get("engine_identity") == "80000000047363726174636841"
    assert restarted.store.get("engine_boots") == 17
    assert restarted.state.cfg.credentials[cid].group_id == gid
    assert restarted.state.cfg.groups[gid] == expected.groups[gid]
