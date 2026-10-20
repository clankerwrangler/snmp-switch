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
from test_wire import start, free_port

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
        assert not engine.state.cfg.groups[before["group_id"]].polling.networks == []
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
