import copy
import datetime
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from switchlab.engine import Engine, CommandError
from switchlab.models import Configuration, Endpoint, Source, RadiusMaterial, SupplicantProfile, initial_configuration
from switchlab.radius import AccessResult
PEER=("192.0.2.1",1812)
def vlan():return [(64,bytes((0,0,0,13))),(65,bytes((0,0,0,6))),(81,b"20")]


@pytest.fixture
def configured():
    cfg = initial_configuration(1)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"synthetic-radius")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
        .not_valid_before(now-datetime.timedelta(days=1)).not_valid_after(now+datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True).sign(key,hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    private = key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()).decode()
    trust = RadiusMaterial(label="Trust",kind="ca",certificate=pem)
    identity = RadiusMaterial(label="Client",kind="client",certificate=pem,private_key=private)
    cfg.radius.materials={trust.id:trust,identity.id:identity}
    profile = SupplicantProfile(method="tls",identity="synthetic",trust_id=trust.id,client_identity_id=identity.id,server_name="radius-probe.invalid")
    ep=Endpoint(name="Client",sources=[Source(mac="02:00:00:00:00:11",supplicant=profile)])
    cfg.endpoints[ep.id]=ep;pid=next(iter(cfg.ports));cfg.attachments[ep.id]=pid;cfg.ports[pid].authentication.control="auto";cfg.paused=True
    return cfg,pid,ep.id


async def begin(engine,pid,eid):
    address=engine.state.cfg.endpoints[eid].sources[0].mac
    result=await engine.execute("radius-begin",dict(port_id=pid,mac=address))
    return dict(port_id=pid,mac=address,attempt_id=result["attempt_id"])


@pytest.mark.asyncio
async def test_initial_no_grant_then_effective_radius_vlan_without_saved_edits(configured):
    cfg,pid,eid=configured
    from switchlab.models import Vlan
    cfg.vlans[20]=Vlan(vid=20,name="Dynamic",fdb_id=1020)
    engine=Engine(cfg);saved=engine.state.cfg.ports[pid].model_dump()
    waiting=await engine.execute("advance",dict(duration_ms=1000))
    assert waiting["advance"]["status"]=="waiting" and engine.state.sim_ms==0
    assert not engine.state.fdb and engine.state.counters[pid]["in_discards"]==0
    capture=await begin(engine,pid,eid)
    result=await engine.execute("radius-result",{**capture,"result":AccessResult(2,tuple(vlan()),PEER,bytes(16))})
    assert result["accepted"] and not engine.state.fdb
    assert engine.state.cfg.ports[pid].model_dump()==saved
    await engine.continue_advance()
    assert engine.state.sim_ms==1000
    await engine.execute("advance",dict(duration_ms=30000))
    assert {r["vid"] for r in engine.state.fdb.values()}=={20}
    assert engine.snapshot()["authentication_sessions"][0]["vid"]==20


@pytest.mark.asyncio
async def test_invalidated_aba_reply_has_no_publication_or_grant(configured):
    cfg,pid,eid=configured;engine=Engine(cfg);capture=await begin(engine,pid,eid)
    await engine.execute("detach",dict(id=eid));await engine.execute("attach",dict(id=eid,port_id=pid))
    before=engine.state
    result=await engine.execute("radius-result",{**capture,"result":AccessResult(2,(),PEER,bytes(16))})
    assert not result["accepted"] and engine.state is before and not engine.state.radius_sessions
    fresh=await begin(engine,pid,eid);assert fresh["attempt_id"]!=capture["attempt_id"]
    result=await engine.execute("radius-result",{**fresh,"result":AccessResult(2,(),PEER,bytes(16))})
    assert result["accepted"]


@pytest.mark.asyncio
async def test_unusable_accept_is_local_failure_not_reject(configured):
    cfg,pid,eid=configured;engine=Engine(cfg);capture=await begin(engine,pid,eid)
    result=await engine.execute("radius-result",{**capture,"result":AccessResult(2,((11,b"not-enforced"),),PEER,bytes(16))})
    assert not result["accepted"] and not engine.state.radius_sessions
    status=engine.snapshot()["authentication_clients"][0]
    assert status["nas_code"]==2 and status["reason"]=="unsupported_access_control"
    captured=next(row for row in reversed(engine.state.events) if row["kind"]=="authentication-failed")
    saved=copy.deepcopy(captured)
    # The public status summary must not share nested payloads with history.
    status["response"]["attributes"][0]["status"]="caller edit"
    status["response"]["omitted"].clear()
    assert captured==saved
    before=engine.state;old=copy.deepcopy(before)
    await engine.execute("pause")
    engine.snapshot()["authentication_clients"][0]["response"]["attributes"].clear()
    assert captured==saved and before==old
    assert next(row for row in engine.state.events if row["id"]==captured["id"])==saved


def test_redaction_export_and_nonmutating_v3_migration(configured):
    cfg,pid,eid=configured;engine=Engine(cfg)
    text=json.dumps(engine.snapshot());scenario=engine.export()
    assert "BEGIN PRIVATE KEY" not in text and "BEGIN CERTIFICATE" not in text
    assert "radius" not in scenario and "authentication" not in scenario["ports"][pid]
    assert "supplicant" not in scenario["endpoints"][eid]["sources"][0]
    legacy=initial_configuration(1).model_dump(mode="json");legacy["schema_version"]=3;legacy.pop("radius")
    for port in legacy["ports"].values():port.pop("authentication")
    original=copy.deepcopy(legacy);loaded=Configuration.model_validate(legacy)
    assert legacy==original and loaded.schema_version==4 and not loaded.radius.servers
    assert all(p.authentication.control=="force-authorized" for p in loaded.ports.values())


@pytest.mark.asyncio
async def test_scenario_roundtrip_preserves_destination_security(configured):
    cfg,pid,eid=configured;engine=Engine(cfg);scenario=engine.export()
    old_profile=copy.deepcopy(engine.state.cfg.endpoints[eid].sources[0].supplicant)
    await engine.execute("import",scenario)
    assert engine.state.cfg.ports[pid].authentication.control=="auto"
    assert engine.state.cfg.endpoints[eid].sources[0].supplicant==old_profile
    scenario["ports"][pid]["authentication"]={"control":"force-authorized"}
    with pytest.raises(CommandError):await engine.execute("import",scenario)


@pytest.mark.asyncio
@pytest.mark.parametrize("existing_session",[False,True])
async def test_forbidden_aba_retires_initial_or_reauth_attempt(configured,existing_session):
    from switchlab.models import Vlan
    cfg,pid,eid=configured;cfg.vlans[20]=Vlan(vid=20,name="Dynamic",fdb_id=1020)
    engine=Engine(cfg)
    if existing_session:
        first=await begin(engine,pid,eid)
        await engine.execute("radius-result",{**first,"result":AccessResult(2,tuple(vlan()),PEER,bytes(16))})
    capture=await begin(engine,pid,eid)
    await engine.execute("port-edit",{"id":pid,"patch":{"forbidden":[20]}})
    assert not engine.state.radius_sessions
    await engine.execute("port-edit",{"id":pid,"patch":{"forbidden":[]}})
    before=engine.state
    result=await engine.execute("radius-result",{**capture,"result":AccessResult(2,tuple(vlan()),PEER,bytes(16))})
    assert not result["accepted"] and engine.state is before and not engine.state.radius_sessions


@pytest.mark.asyncio
async def test_reauthentication_carries_original_private_state(configured):
    from switchlab.radius import NativeObservation
    from switchlab.models import RadiusServer
    cfg,pid,eid=configured;cfg.radius.servers=[RadiusServer(label="Synthetic",address=PEER[0],secret="synthetic-shared-secret")]
    engine=Engine(cfg);first=await begin(engine,pid,eid)
    opaque=b"private-server-state"
    await engine.execute("radius-result",{**first,"result":AccessResult(2,((24,opaque),(29,(1).to_bytes(4,"big"))),PEER,bytes(16)),
        "server_id":cfg.radius.servers[0].id,"server_signature":engine._server_signature(cfg.radius.servers[0])})
    capture=await begin(engine,pid,eid)
    async def exchange(*args,**kwargs):
        assert kwargs.get("state")==opaque
        return NativeObservation(AccessResult(3,(),PEER,bytes(16)),0,0,0,0,False,False)
    await engine.authenticate(pid,capture["mac"],capture["attempt_id"],exchange=exchange)
    assert opaque.decode() not in json.dumps(engine.snapshot())


@pytest.mark.asyncio
async def test_traffic_edit_preserves_copied_security_and_other_port_work(configured):
    cfg,pid,eid=configured;engine=Engine(cfg)
    source=engine.state.cfg.endpoints[eid].sources[0]
    fields=source.model_dump();fields.pop("supplicant");fields["interval_ms"]=10000
    await engine.execute("endpoint-edit",{"id":eid,"patch":{"sources":[fields]}})
    assert engine.state.cfg.endpoints[eid].sources[0].supplicant==source.supplicant


@pytest.mark.asyncio
@pytest.mark.parametrize("replacement",[False,True])
async def test_lost_session_ownership_blocks_held_reauthentication(configured,replacement):
    from dataclasses import replace
    from switchlab.models import uid
    cfg,pid,eid=configured;engine=Engine(cfg)
    first=await begin(engine,pid,eid)
    await engine.execute("radius-result",{**first,"result":AccessResult(2,(),PEER,bytes(16))})
    capture=await begin(engine,pid,eid);subject=(pid,capture["mac"])
    old_session=engine.state.radius_sessions.pop(subject)
    if replacement:engine.state.radius_sessions[subject]=replace(old_session,id=uid())
    # Fault fixture: the additional claim check is required even if retirement was missed.
    before=engine.state
    result=await engine.execute("radius-result",{**capture,"result":AccessResult(2,(),PEER,bytes(16))})
    assert not result["accepted"] and engine.state is before
    assert all(s.id!=old_session.id for s in engine.state.radius_sessions.values())


@pytest.mark.asyncio
async def test_session_end_retires_its_pending_attempt(configured):
    cfg,pid,eid=configured;engine=Engine(cfg)
    first=await begin(engine,pid,eid)
    await engine.execute("radius-result",{**first,"result":AccessResult(2,(),PEER,bytes(16))})
    capture=await begin(engine,pid,eid);subject=(pid,capture["mac"])
    engine.state.end_session(subject,"synthetic-independent-termination")
    assert subject not in engine.state.radius_attempts
    before=engine.state
    assert not (await engine.execute("radius-result",{**capture,"result":AccessResult(2,(),PEER,bytes(16))}))["accepted"]
    assert engine.state is before


@pytest.mark.asyncio
async def test_noop_baseline_pvid_and_other_port_preserve_current_work(configured):
    from switchlab.models import Port,Vlan
    cfg,pid,eid=configured;cfg.vlans[20]=Vlan(vid=20,name="Dynamic",fdb_id=1020)
    other=Port(bridge_port=2,if_index=102,name="Other")
    cfg.ports[other.id]=other;cfg.switch.port_count=2
    engine=Engine(cfg);first=await begin(engine,pid,eid)
    await engine.execute("radius-result",{**first,"result":AccessResult(2,tuple(vlan()),PEER,bytes(16))})
    capture=await begin(engine,pid,eid);subject=(pid,capture["mac"])
    session_id=engine.state.radius_sessions[subject].id
    for changed,patch in [(pid,{"forbidden":[]}), (other.id,{"forbidden":[20]}), (pid,{"pvid":20,"admitted":[1,20]})]:
        await engine.execute("port-edit",{"id":changed,"patch":patch})
        assert engine.state.current_attempt(subject,capture["attempt_id"]) is not None
        assert engine.state.radius_sessions[subject].id==session_id
    assert (await engine.execute("radius-result",{**capture,"result":AccessResult(2,tuple(vlan()),PEER,bytes(16))}))["accepted"]


@pytest.mark.asyncio
async def test_initial_state_absent_and_invalidated_work_never_calls_exchange(configured):
    from switchlab.models import RadiusServer
    from switchlab.radius import NativeObservation
    cfg,pid,eid=configured;cfg.radius.servers=[RadiusServer(label="Synthetic",address=PEER[0],secret="synthetic-shared-secret")]
    engine=Engine(cfg);first=await begin(engine,pid,eid);calls=[]
    async def exchange(*args,**kwargs):
        calls.append(kwargs.get("state"));return NativeObservation(AccessResult(3,(),PEER,bytes(16)),0,0,0,0,False,False)
    await engine.authenticate(pid,first["mac"],first["attempt_id"],exchange=exchange)
    assert calls==[None]
    capture=await begin(engine,pid,eid)
    await engine.execute("detach",{"id":eid});await engine.execute("attach",{"id":eid,"port_id":pid})
    assert not (await engine.authenticate(pid,capture["mac"],capture["attempt_id"],exchange=exchange))["accepted"]
    assert calls==[None]


@pytest.mark.asyncio
async def test_startup_save_preserves_attempt_and_durable_peer_catalog(configured, store):
    from switchlab.models import SupplicantTemplate, RadiusServer
    cfg,pid,eid = configured
    server = RadiusServer(label="Saved Access", address="192.0.2.1", secret="synthetic-startup-secret")
    cfg.radius.servers = [server]
    engine = Engine(cfg, store)
    capture = await begin(engine,pid,eid)
    before = engine.state
    await engine.execute("save-startup", expected_config=before.configuration_revision)
    assert engine.state.radius_attempts == before.radius_attempts
    assert engine.state.activation == before.activation
    assert engine.state.credential_generations == before.credential_generations
    assert engine.state.epoch == before.epoch
    await engine.execute("radius-server-save", {"id":server.id,"secret":"unsaved-access-secret"})
    assert not engine.state.current_attempt((pid,capture["mac"]),capture["attempt_id"])
    profile = cfg.endpoints[eid].sources[0].supplicant.model_dump()
    template = await engine.execute("radius-template-save", {"label":"Durable template", "profile":profile})
    material = next(iter(cfg.radius.materials.values()))
    await engine.execute("radius-material-save", {"id":material.id,"label":"Durable material rename"})
    await engine.execute("source-supplicant-save", {"id":eid,"source_id":cfg.endpoints[eid].sources[0].id,
        "profile":{**profile,"identity":"durable-peer-identity"}})
    startup_revision = engine.state.startup_revision
    restored = Engine(store.load(),store)
    assert restored.state.cfg.radius.servers[0].secret == "synthetic-startup-secret"
    assert restored.state.cfg.radius.materials[material.id].label == "Durable material rename"
    assert template["id"] in restored.state.cfg.radius.templates
    assert restored.state.cfg.endpoints[eid].sources[0].supplicant.identity == "durable-peer-identity"
    assert restored.state.startup_revision == startup_revision
    assert not restored.state.radius_attempts and not restored.state.radius_sessions
    assert not restored.state.configuration_dirty
    for content in (json.dumps(restored.snapshot()),json.dumps(restored.export())):
        assert "synthetic-startup-secret" not in content and "BEGIN PRIVATE KEY" not in content
    for (encrypted,) in store.db.execute("SELECT value FROM kv"):
        assert b"BEGIN PRIVATE KEY" not in encrypted and b"synthetic-startup-secret" not in encrypted
