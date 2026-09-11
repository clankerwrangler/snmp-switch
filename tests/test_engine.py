import copy
from dataclasses import asdict
import pytest
from pydantic import ValidationError
from switchlab.engine import CommandError, Engine
from switchlab.models import Source, Identity
from conftest import endpoint, tick


async def test_direct_conflict_move_atomic_and_silent(engine):
    e=engine
    a=await endpoint(e, active=False)
    b=await endpoint(e, port=1)
    ports=list(e.state.cfg.ports)
    assert e.state.up(ports[0]) and not e.state.fdb
    before=e.snapshot()
    with pytest.raises(CommandError):
        await e.execute("attach", {"id":b,"port_id":ports[0]})
    assert e.snapshot()["attachments"]==before["attachments"]
    with pytest.raises(CommandError):
        await e.execute("endpoint-delete", {"id":a})
    await tick(e)
    assert len(e.state.fdb)==1


async def test_shared_cache_and_instance_delete(engine):
    e=engine;p=list(e.state.cfg.ports)[0]
    await e.execute("port-edit",{"id":p,"patch":{"mode":"shared"}})
    a=await endpoint(e);b=await endpoint(e,mac="02:00:00:00:00:11")
    await tick(e)
    await e.execute("detach",{"id":a})
    await e.execute("endpoint-delete",{"id":a})
    assert e.state.up(p) and len(e.state.fdb)==2
    await e.execute("detach",{"id":b})
    await tick(e,300000)
    assert e.state.up(p) and not e.state.fdb


async def test_fault_persists_and_admin_flush(engine):
    e=engine;p=list(e.state.cfg.ports)[0]
    await e.execute("port-edit",{"id":p,"patch":{"forced_down":True}})
    await endpoint(e)
    await tick(e)
    assert not e.state.up(p) and not e.state.fdb
    await e.execute("port-edit",{"id":p,"patch":{"forced_down":False}})
    await tick(e)
    await e.execute("port-edit",{"id":p,"patch":{"admin_up":False}})
    assert not e.state.fdb and e.state.cfg.attachments


async def test_live_edit_preserves_deadline_and_sources(engine):
    e=engine;a=await endpoint(e)
    await tick(e);old=copy.deepcopy(e.state.fdb)
    await e.execute("endpoint-edit",{"id":a,"patch":{"sources":[{"mac":"02:00:00:00:00:20"}]}})
    assert e.state.fdb==old
    await tick(e)
    assert len(e.state.fdb)==2
    await e.execute("endpoint-edit",{"id":a,"patch":{"sources":[]}})
    await tick(e,300000)
    assert not e.state.fdb


async def test_selective_pvid_and_delete_fallback(engine):
    e=engine;p=list(e.state.cfg.ports)[0]
    for vid in (10,20):await e.execute("vlan-create",{"vid":vid,"name":str(vid)})
    await e.execute("port-edit",{"id":p,"patch":{"pvid":10,"admitted":[10,20]}})
    await endpoint(e,sources=[{"mac":"02:00:00:00:00:10"},{"mac":"02:00:00:00:00:20","tag":20},{"mac":"02:00:00:00:00:30","tag":10}])
    await tick(e)
    preserved=copy.deepcopy(e.state.fdb[(1020,"02:00:00:00:00:20")])
    await e.execute("vlan-delete",{"vid":10})
    assert e.state.cfg.ports[p].pvid==1 and e.state.cfg.ports[p].admitted==[1,20]
    assert list(e.state.fdb.values())==[preserved]
    await tick(e)
    assert {r["vid"] for r in e.state.fdb.values()}=={1,20}
    assert e.state.counters[p]["in_discards"]==1
    with pytest.raises(CommandError):await e.execute("vlan-delete",{"vid":1})
    await e.execute("port-edit",{"id":p,"patch":{"pvid":20,"admitted":[1,20]}})
    assert {r["vid"] for r in e.state.fdb.values()}=={1,20}


async def test_unknown_tag_does_not_create_vlan(engine):
    a=await endpoint(engine,tag=222)
    await tick(engine)
    assert not engine.state.fdb and 222 not in engine.state.cfg.vlans
    assert next(iter(engine.state.counters.values()))["in_discards"]==1


async def test_duplicate_mac_fdb_isolation_and_last_source_wins(engine):
    e=engine;ports=list(e.state.cfg.ports)
    await e.execute("vlan-create",{"vid":10})
    await e.execute("port-edit",{"id":ports[1],"patch":{"admitted":[1,10]}})
    a=await endpoint(e)
    b=await endpoint(e,port=1,sources=[{"mac":"02:00:00:00:00:10"},{"mac":"02:00:00:00:00:10","tag":10}])
    await tick(e)
    assert len(e.state.fdb)==2
    assert e.state.fdb[(1001,"02:00:00:00:00:10")]["port_id"]==e.state.cfg.attachments[max(a,b)]
    assert e.state.fdb[(1010,"02:00:00:00:00:10")]["port_id"]==ports[1]


@pytest.mark.parametrize("race",["edit","attachment","port","vlan","instance","reboot","clear"])
async def test_obsolete_callback_aba(engine,race):
    e=engine;p=list(e.state.cfg.ports)[0]
    await e.execute("port-edit",{"id":p,"patch":{"mode":"shared"}})
    a=await endpoint(e)
    old=next(iter(e.state.jobs.values()))
    saved=e.state.cfg.endpoints[a].model_dump()
    if race=="edit":
        await e.execute("endpoint-edit",{"id":a,"patch":{"sources":[{"mac":"02:00:00:00:00:22"}]}})
        await e.execute("endpoint-edit",{"id":a,"patch":{"sources":saved["sources"]}})
    elif race=="attachment":
        await e.execute("detach",{"id":a});await e.execute("attach",{"id":a,"port_id":p})
    elif race=="port":
        await e.execute("port-edit",{"id":p,"patch":{"forced_down":True}})
        await e.execute("port-edit",{"id":p,"patch":{"forced_down":False}})
    elif race=="vlan":
        await e.execute("vlan-create",{"vid":10})
        await e.execute("port-edit",{"id":p,"patch":{"pvid":10,"admitted":[1,10]}})
        old=next(iter(e.state.jobs.values()))
        await e.execute("vlan-delete",{"vid":10});await e.execute("vlan-create",{"vid":10})
        await e.execute("port-edit",{"id":p,"patch":{"pvid":10,"admitted":[1,10]}})
    elif race=="instance":
        await e.execute("detach",{"id":a});await e.execute("endpoint-delete",{"id":a})
        await e.execute("endpoint-create",saved);await e.execute("attach",{"id":a,"port_id":p})
    elif race=="reboot":await e.execute("reboot")
    elif race=="clear":await e.execute("clear",{})
    result=await e.execute("job",asdict(old))
    assert not result["accepted"] and not e.state.fdb


async def test_age_change_capacity_and_counters(engine):
    e=engine
    await e.execute("switch-edit",{"fdb_limit":1})
    a=await endpoint(e,sources=[{"mac":"02:00:00:00:00:10"},{"mac":"02:00:00:00:00:11"}])
    await tick(e)
    assert len(e.state.fdb)==1 and e.state.learned_discards==1
    c=next(iter(e.state.counters.values()))
    assert c["in_octets"]==128 and c["in_ucast"]==2 and c["in_discards"]==0
    await e.execute("endpoint-edit",{"id":a,"patch":{"active":False}})
    await tick(e,11000)
    await e.execute("switch-edit",{"aging_seconds":10})
    assert not e.state.fdb


async def test_expire_before_refresh_and_chronological_advance(engine):
    e=engine
    await e.execute("switch-edit",{"aging_seconds":10})
    await endpoint(e,interval_ms=10000)
    await tick(e,31000)
    assert next(iter(e.state.counters.values()))["in_ucast"]==4
    ages=[x for x in e.state.events if x["kind"]=="mac-age"]
    assert [x["simulation_ms"] for x in ages]==[11000,21000,31000]
    assert len(e.state.fdb)==1


async def test_pause_and_restart(engine):
    e=engine;a=await endpoint(e);await tick(e)
    cfg=copy.deepcopy(e.state.cfg)
    restored=Engine(e.store.load(),e.store)
    assert restored.state.cfg==cfg and not restored.state.fdb and restored.state.sim_ms==0 and restored.state.cfg.paused
    assert all(c["last_change"]==0 for c in restored.state.counters.values())
    await tick(restored)
    assert restored.state.fdb
    await restored.execute("resume")
    with pytest.raises(CommandError):await tick(restored)


async def test_import_atomic_identity_preserved_and_security_excluded(engine):
    e=engine;await endpoint(e);await tick(e)
    await e.execute("switch-edit",{"identity":{"sys_object_id":"1.3.6.1.4.1.999.1"}})
    scenario=e.export();old=e.snapshot()
    bad=copy.deepcopy(scenario);bad["attachments"]["absent"]="absent"
    with pytest.raises(ValidationError):await e.execute("import",bad)
    assert e.state.revision==old["revision"] and e.state.fdb
    await e.execute("import",scenario)
    assert e.state.cfg.switch.identity.sys_object_id=="1.3.6.1.4.1.999.1" and not e.state.fdb
    assert "identity" not in str(scenario) and "credentials" not in scenario


async def test_failure_atomicity_idempotency_and_configuration_revision(engine,monkeypatch):
    e=engine;before=e.state
    def fail(*args,**kwargs):raise OSError("disk full")
    with monkeypatch.context() as patch:
        patch.setattr(e.store,"commit",fail)
        with pytest.raises(OSError):await endpoint(e,port=None)
    assert e.state is before
    result=await e.execute("endpoint-create",{"name":"Retry"},expected=e.state.revision,key="request-1")
    retry=await e.execute("endpoint-create",{"name":"Retry"},expected=0,key="request-1")
    assert result==retry and len(e.state.cfg.endpoints)==1
    revision=e.state.configuration_revision
    await tick(e)
    await e.execute("pause",expected_config=revision)
    with pytest.raises(CommandError):await e.execute("resume",expected_config=revision)


async def test_notifications_overflow_capture_and_gate(engine):
    e=engine;p=list(e.state.cfg.ports)[0]
    await e.execute("switch-edit",{"identity":{"sys_object_id":"1.3.6.1.4.1.999.1"},"queue_limit":1})
    c=await e.execute("credential-save",{"label":"traps","community":"fixture-trap"})
    await e.execute("target-save",{"address":"127.0.0.1","credential_id":c["id"]})
    await e.execute("snmp-settings",{"enabled":True})
    a=await endpoint(e)
    await e.execute("detach",{"id":a})
    assert len(e.state.outbox)==1 and e.state.notification_drops==1
    assert e.state.outbox[0]["event"]["kind"]=="linkUp"
    assert e.state.outbox[0]["event"]["after"]==1 and not e.state.up(p)
    await e.execute("switch-edit",{"identity":{"sys_object_id":None}})
    assert not e.state.outbox
    with pytest.raises(CommandError):await e.execute("test-notification",{"target_id":next(iter(e.state.cfg.targets))})


@pytest.mark.parametrize("value",["0","3.1","1.40.1","1.3.-1","1.3.4294967296","bad","1..3"])
def test_invalid_identity(value):
    with pytest.raises(ValidationError):Identity(sys_object_id=value)


@pytest.mark.parametrize("value",["00:00:00:00:00:00","ff:ff:ff:ff:ff:ff","01:02:03:04:05:06","xyz","0200:::00000010"])
def test_invalid_mac(value):
    with pytest.raises(ValidationError):Source(mac=value)


async def test_inline_target_storage_failure_rolls_back(engine, store, monkeypatch):
    import sqlite3
    e = engine
    before = e.state
    persisted, events, idem = store.get("startup_configuration"), store.events(), store.get("idempotency")
    original_put = store.put
    def fail_after_configuration(key, value):
        original_put(key, value)
        if key == "configuration_revision":
            raise sqlite3.OperationalError("synthetic write failure")
    with monkeypatch.context() as patch:
        patch.setattr(store, "put", fail_after_configuration)
        with pytest.raises(sqlite3.OperationalError):
            await e.execute("target-save", {"address": "127.0.0.1", "new_credential": {
                "label": "Atomic", "community": "synthetic-atomic"}}, key="atomic")
    assert e.state is before and not e.idempotency
    assert store.get("startup_configuration") == persisted and store.events() == events and store.get("idempotency") == idem
    result = await e.execute("target-save", {"address": "127.0.0.1", "new_credential": {
        "label": "Atomic", "community": "synthetic-atomic"}}, key="atomic")
    assert e.state.cfg.targets[result["id"]].credential_id == result["credential_id"]
    assert store.load().targets == {}  # Applied running policy is not an implicit Save.
    await e.execute("save-startup")
    assert store.load().targets[result["id"]].credential_id == result["credential_id"]


from pysnmp.proto import rfc1902 as a
from switchlab.mib import plan_set, SetError, Projection, oid
from switchlab.models import Credential, View


async def apply_set(e, bindings):
    async with e.lock:
        return e.set_locked(bindings, ["1.3.6.1.2.1"])


def set_binding(suffix, value):
    return oid("1.3.6.1.2.1." + suffix), value


def stored_state(store):
    return ({key: store.get(key) for key in ("configuration", "configuration_format", "lab_configuration", "startup_configuration", "startup_revision",
                                            "configuration_revision", "revision", "outbox", "idempotency")}, store.events(), store.last_event)


async def test_set_one_transition_learning_notifications_and_noop(engine):
    e = engine
    await e.execute("switch-edit", {"identity": {"sys_object_id": "1.3.6.1.4.1.32473.1"}})
    cred = await e.execute("credential-save", {"label": "Synthetic trap", "community": "synthetic-trap"})
    await e.execute("target-save", {"credential_id": cred["id"], "address": "127.0.0.1"})
    await e.execute("snmp-settings", {"enabled": True})
    eid = await endpoint(e)
    await tick(e)
    assert e.state.fdb
    before = e.state
    commands = [set_binding("2.2.1.7.101", a.Integer32(2)), set_binding("17.7.1.4.3.1.1.1", a.OctetString(b"Renamed"))]
    plan = await apply_set(e, commands)
    assert plan.changed and e.state is not before
    assert e.state.revision == before.revision + 1
    assert e.state.configuration_revision == before.configuration_revision + 1
    assert not e.state.fdb and eid not in {key[0] for key in e.state.jobs}
    assert e.state.cfg.endpoints == before.cfg.endpoints and e.state.cfg.attachments == before.cfg.attachments
    assert [x["event"]["kind"] for x in e.state.outbox] == ["linkUp", "linkDown"]
    assert e.idempotency == {} and e.store.load().vlans[1].name == "Default"
    assert all(p.admin_up for p in e.store.load().ports.values())
    assert e.store.get("revision") == e.state.revision
    before, persisted = e.state, stored_state(e.store)
    for request in (commands, [], [set_binding("17.7.1.4.3.1.5.200", a.Integer32(6))]):
        assert not (await apply_set(e, request)).changed
        assert e.state is before and stored_state(e.store) == persisted
    await apply_set(e, [set_binding("2.2.1.7.101", a.Integer32(1))])
    await tick(e)
    assert e.state.fdb and e.state.outbox[-1]["event"]["kind"] == "linkUp"


async def test_set_rejected_candidate_preserves_whole_runtime_and_storage(engine):
    await endpoint(engine)
    await tick(engine)
    before, persisted = engine.state, stored_state(engine.store)
    request = [set_binding("2.2.1.7.101", a.Integer32(2)),
               set_binding("17.7.1.4.3.1.3.1", a.OctetString(b"\x80")),
               set_binding("17.7.1.4.3.1.1.1", a.OctetString(b"Not committed"))]
    with pytest.raises(SetError) as failure:
        await apply_set(engine, request)
    assert (failure.value.status, failure.value.index) == ("inconsistentValue", 2)
    assert engine.state is before and stored_state(engine.store) == persisted


@pytest.mark.parametrize("failure_key", ["configuration_revision", "outbox"])
async def test_set_real_midtransaction_rollback_and_retry(engine, monkeypatch, failure_key):
    import sqlite3
    e = engine
    await endpoint(e)
    await tick(e)
    before, persisted = e.state, stored_state(e.store)
    request = [set_binding("2.2.1.7.102", a.Integer32(1)),
               set_binding("2.2.1.7.101", a.Integer32(2)),
               set_binding("17.7.1.4.3.1.1.1", a.OctetString(b"Atomic"))]
    assert plan_set(before.cfg, request, ["1.3.6.1.2.1"]).first_effective == 2
    original_put = e.store.put
    def injected(key, value):
        original_put(key, value)
        if key == failure_key:
            raise sqlite3.OperationalError("Synthetic midtransaction failure")
    with monkeypatch.context() as patch:
        patch.setattr(e.store, "put", injected)
        with pytest.raises(sqlite3.OperationalError) as failure:
            await apply_set(e, request)
    assert failure.value.switchlab_rolled_back is True
    assert e.state is before and stored_state(e.store) == persisted
    await apply_set(e, request)
    assert not e.state.fdb and e.state.cfg.vlans[1].name == "Atomic"
    assert e.store.load().vlans[1].name == "Default"
    assert e.store.get("revision") == e.state.revision


async def test_absent_destroy_does_not_rearm_unrelated_tagged_sources(engine):
    e = engine
    eid = await endpoint(e, tag=10, port=1)
    pid = list(e.state.cfg.ports)[1]
    job = next(iter(e.state.jobs.values()))
    before = e.state
    await apply_set(e, [set_binding("17.7.1.4.3.1.5.10", a.Integer32(6)),
                       set_binding("2.2.1.7.101", a.Integer32(2))])
    assert e.state.jobs[(eid, job.source_id)] == job
    assert e.state.egens[eid] == before.egens[eid] and e.state.pgens[pid] == before.pgens[pid]
    assert e.state.vlan_deletes == before.vlan_deletes
    assert not any(event["kind"] == "vlan-delete" for event in e.state.events[len(before.events):])
    # An effective create, unlike absent destroy, invalidates captured tagged work.
    await apply_set(e, [set_binding("17.7.1.4.3.1.5.10", a.Integer32(4))])
    assert e.state.egens[eid] != before.egens[eid] and not e.state.valid(job)


@pytest.mark.parametrize("initial,expected", [([1, 20], {10, 20}), ([20], {10, 20}), ([], {10})])
async def test_native_api_formula_and_raw_set_pvid_are_distinct(engine, initial, expected):
    e = engine
    for vid in (10, 20):
        await e.execute("vlan-create", {"vid": vid})
    pid = next(iter(e.state.cfg.ports))
    await e.execute("port-edit", {"id": pid, "patch": {"admitted": [1, 10, 20], "untagged": initial}})
    await apply_set(e, [set_binding("17.7.1.4.5.1.1.1", a.Gauge32(10))])
    assert e.state.cfg.ports[pid].untagged == initial
    await apply_set(e, [set_binding("17.7.1.4.5.1.1.1", a.Gauge32(1))])
    await e.execute("port-edit", {"id": pid, "patch": {"pvid": 10}})
    assert set(e.state.cfg.ports[pid].untagged) == expected
    await e.execute("port-edit", {"id": pid, "patch": {"pvid": 20, "untagged": []}})
    await e.execute("port-edit", {"id": pid, "patch": {"pvid": 20, "alias": "Unrelated"}})
    assert e.state.cfg.ports[pid].untagged == []


async def test_write_generation_distinct_shared_views_and_reboot(engine):
    e = engine
    await e.execute("view-save", {"id": "write", "name": "SET objects", "includes": ["1.3.6.1.2.1.17"]})
    ids = []
    for number in (1, 2):
        result = await e.execute("credential-save", {"label": str(number), "community": "synthetic-" + str(number),
            "polling": {"enabled": number == 1, "view_id": "interfaces"},
            "writing": {"enabled": True, "view_id": "write"}})
        ids.append(result["id"])
    first = dict(e.state.credential_generations)
    same = e.state.cfg.views["write"].model_dump()
    await e.execute("view-save", same)
    assert e.state.credential_generations == first
    await e.execute("view-save", {"id": "interfaces", "name": "Different read view", "includes": ["1.3.6.1.2.1.2"]})
    assert e.state.credential_generations == first
    await e.execute("view-save", {**same, "includes": ["1.3.6.1.2.1.47"]})
    middle = dict(e.state.credential_generations)
    assert all(middle[c] != first[c] for c in ids)
    await e.execute("view-save", same)
    assert all(e.state.credential_generations[c] not in (first[c], middle[c]) for c in ids)
    old = dict(e.state.credential_generations)
    await e.execute("credential-save", {"id": ids[0], "writing": {"networks": ["192.0.2.0/24"]}})
    assert e.state.credential_generations[ids[0]] != old[ids[0]]
    assert e.state.credential_generations[ids[1]] == old[ids[1]]
    await e.execute("save-startup")
    before = e.state
    await e.execute("reboot")
    assert e.state.activation != before.activation
    assert all(e.state.credential_generations[c] != before.credential_generations[c] for c in ids)
    assert e.state.cfg == before.cfg


async def test_vlan_permission_persistence_scenario_and_legacy_defaults(engine):
    e = engine
    raw = e.state.cfg.model_dump()
    for p in raw["ports"].values():
        del p["untagged"], p["forbidden"]
    raw["credentials"] = {"legacy": {"id": "legacy", "label": "Read", "community": "synthetic-read",
                                     "polling": {"enabled": True}}}
    from switchlab.models import Configuration
    loaded = Configuration.model_validate(raw)
    assert all(p.untagged == [p.pvid] and not p.forbidden for p in loaded.ports.values())
    assert loaded.credentials["legacy"].writing.model_dump() == {"enabled": False, "view_id": None, "networks": []}
    await e.execute("vlan-create", {"vid": 10})
    pid = next(iter(e.state.cfg.ports))
    await e.execute("port-edit", {"id": pid, "patch": {"untagged": [], "forbidden": [10]}})
    result = await e.execute("credential-save", {"label": "Write", "community": "synthetic-write",
                                               "writing": {"enabled": True, "view_id": "all"}})
    scenario = e.export()
    assert scenario["schema_version"] == 1 and "credentials" not in scenario
    await e.execute("import", scenario)
    assert e.state.cfg.ports[pid].untagged == [] and e.state.cfg.ports[pid].forbidden == [10]
    await e.execute("save-startup")
    restored = Engine(e.store.load(), e.store)
    assert restored.state.cfg == e.state.cfg
    assert restored.state.cfg.credentials[result["id"]].writing.enabled
    assert restored.state.cfg.credentials[result["id"]].polling.enabled is False


@pytest.mark.parametrize("level", ["noAuthNoPriv", "authNoPriv", "authPriv"])
@pytest.mark.parametrize("read,write", [(False, False), (True, False), (True, True), (False, True)])
@pytest.mark.parametrize("enabled", [False, True])
def test_schema2_groups_preserve_encrypted_policy_and_identity(store, level, read, write, enabled):
    import copy
    from switchlab.models import Configuration, initial_configuration
    raw = initial_configuration(4).model_dump(mode="json")
    raw.pop("radius")
    for port in raw["ports"].values():port.pop("authentication")
    raw.pop("groups")
    raw["schema_version"] = 2
    policy = {"polling": {"enabled": read, "view_id": "interfaces" if read else "missing-read", "networks": ["192.0.2.0/24"]},
              "writing": {"enabled": write, "view_id": "all" if write else None, "networks": ["2001:db8::/32"]}}
    raw["credentials"] = {cid: dict(id=cid, label="Same label", version="3", username=cid, enabled=enabled,
        security_level=level, community="inert-community", auth_key="synthetic-auth", priv_key="synthetic-priv", **policy)
        for cid in ("one", "two")}
    raw["credentials"]["community"] = dict(id="community", label="Community", version="2c", community="synthetic-community",
        username="retained-inactive", auth_key="inactive-auth", priv_key="inactive-priv", **policy)
    raw["targets"] = {"t": dict(id="t", address="127.0.0.1", credential_id="one", enabled=False)}
    before = copy.deepcopy(raw)
    with store.db:
        store.put("configuration", raw)
        store.put("engine_identity", "40000102030405060708090a0b")
        store.put("engine_boots", 9)
    cfg = store.load()
    assert raw == before and cfg.schema_version == 4
    assert Configuration.model_validate(raw) == cfg
    assert len(cfg.groups) == 2
    for cid in ("one", "two"):
        user = cfg.credentials[cid]
        group = cfg.groups[user.group_id]
        assert user.group_id == "user-policy:" + cid.encode("utf-8").hex()
        assert group.minimum_security_level == user.security_level == level
        assert user.enabled == enabled and user.id == cid and user.username == cid
        assert user.auth_key == "synthetic-auth" and user.priv_key == "synthetic-priv" and user.community == "inert-community"
        assert "polling" not in user.model_dump() and "writing" not in user.model_dump()
        assert group.polling.model_dump() == policy["polling"] and group.writing.model_dump() == policy["writing"]
    community = cfg.credentials["community"]
    assert community.polling.model_dump() == policy["polling"] and community.writing.model_dump() == policy["writing"]
    assert (community.username, community.auth_key, community.priv_key) == ("retained-inactive", "inactive-auth", "inactive-priv")
    e = Engine(cfg, store)
    assert store.load() == cfg and store.get("startup_configuration")["schema_version"] == 4
    assert store.get("configuration") is None and store.get("configuration_format") == 1
    assert store.get("engine_identity") == "40000102030405060708090a0b" and store.get("engine_boots") == 9
    assert e.export()["schema_version"] == 1 and not {"credentials", "groups"} & e.export().keys()
    assert "synthetic-auth" not in str(e.snapshot()) and "inactive-auth" not in str(e.snapshot())


async def test_group_defaults_references_sparse_policy_and_shared_generations(engine):
    from pydantic import ValidationError
    e = engine
    gid = (await e.execute("group-save", {"label": "Management"}))["id"]
    group = e.state.cfg.groups[gid]
    assert group.minimum_security_level == "authPriv" and not group.polling.enabled and not group.writing.enabled
    ids = []
    for n in (1, 2):
        cid = (await e.execute("credential-save", {"label": str(n), "version": "3", "username": str(n),
            "auth_key": "synthetic-auth", "priv_key": "synthetic-priv", "group_id": gid}))["id"]
        ids.append(cid)
        assert e.state.cfg.credentials[cid].security_level == "authPriv"
    await e.execute("credential-save", {"id": ids[1], "enabled": False})
    before = e.state
    with pytest.raises(ValidationError):
        await e.execute("group-delete", {"id": gid})
    assert e.state is before
    tokens = dict(e.state.credential_generations)
    await e.execute("group-save", {"id": gid, "label": "Renamed"})
    assert e.state.credential_generations == tokens
    await e.execute("group-save", e.state.cfg.groups[gid].model_dump())
    assert e.state.credential_generations == tokens
    await e.execute("group-save", {"id": gid, "polling": {"view_id": "interfaces", "networks": ["192.0.2.1/24"]},
                                  "writing": {"enabled": True, "view_id": "all"}})
    assert all(e.state.credential_generations[c] != tokens[c] for c in ids)
    old = e.state.cfg.groups[gid]
    await e.execute("group-save", {"id": gid, "polling": {"enabled": True}})
    assert e.state.cfg.groups[gid].polling.networks == ["192.0.2.0/24"]
    assert e.state.cfg.groups[gid].writing == old.writing
    tokens = dict(e.state.credential_generations)
    view = e.state.cfg.views["all"].model_dump()
    await e.execute("view-save", {**view, "includes": ["1.3.6.1.2.1.47"]})
    middle = dict(e.state.credential_generations)
    await e.execute("view-save", view)
    assert all(e.state.credential_generations[c] not in (tokens[c], middle[c]) for c in ids)
    tokens = dict(e.state.credential_generations)
    await e.execute("credential-save", {"id": ids[0], "group_id": None})
    assert e.state.credential_generations[ids[0]] != tokens[ids[0]]
    assert e.state.credential_generations[ids[1]] == tokens[ids[1]]
    with pytest.raises(CommandError, match="belongs to"):
        await e.execute("credential-save", {"id": ids[0], "polling": {"enabled": True}})
    # An unused group's active view remains a required reference.
    with pytest.raises(ValidationError):
        await e.execute("group-save", {"label": "Invalid", "writing": {"enabled": True}})
    with pytest.raises(ValidationError):
        await e.execute("view-delete", {"id": "all"})
    await e.execute("group-save", {"id": gid, "writing": {"enabled": False}})
    await e.execute("view-delete", {"id": "all"})
    assert e.state.cfg.groups[gid].writing.view_id == "all"


@pytest.mark.parametrize("choice", ["keep", "none", "group", "null"])
async def test_protocol_conversion_explicit_saved_policy_and_targets(engine, choice):
    e = engine
    policy = {"polling": {"enabled": True, "view_id": "interfaces", "networks": ["192.0.2.0/24"]},
              "writing": {"enabled": True, "view_id": "all", "networks": ["2001:db8::/32"]}}
    cid = (await e.execute("credential-save", {"label": "Converted", "community": "synthetic", **policy}))["id"]
    tid = (await e.execute("target-save", {"credential_id": cid, "address": "127.0.0.1"}))["id"]
    gid = (await e.execute("group-save", {"label": "Existing", "polling": {"enabled": True}}))["id"]
    existing = e.state.cfg.groups[gid].model_dump()
    fields = dict(id=cid, version="3", username="converted", security_level="authNoPriv", auth_key="new-auth-passphrase")
    intent = {"group_id": gid if choice == "group" else None} if choice in ("group", "null") else {"access_transfer": choice}
    result = await e.execute("credential-save", {**fields, **intent}, key="convert")
    saved = e.state.cfg
    assert await e.execute("credential-save", {**fields, **intent}, key="convert") == result
    assert e.state.cfg is saved
    user = saved.credentials[cid]
    assert saved.targets[tid].credential_id == cid and user.community is None and user.priv_key is None
    assert "access_transfer" not in user.model_dump()
    if choice == "keep":
        group = saved.groups[user.group_id]
        assert group.minimum_security_level == "authNoPriv"
        assert group.polling.model_dump() == policy["polling"] and group.writing.model_dump() == policy["writing"]
    else:
        assert user.group_id == (gid if choice == "group" else None)
    assert saved.groups[gid].model_dump() == existing
    groups = dict(saved.groups)
    await e.execute("credential-save", {"id": cid, "version": "2c", "community": "new-community", "access_transfer": "keep"})
    community = e.state.cfg.credentials[cid]
    expected = groups[user.group_id] if user.group_id else None
    assert community.polling.enabled == (expected.polling.enabled if expected else False)
    assert community.writing.enabled == (expected.writing.enabled if expected else False)
    assert e.state.cfg.groups == groups and e.state.cfg.targets[tid].credential_id == cid


@pytest.mark.parametrize("intent", [{}, {"access_transfer": "keep", "group_id": None},
    {"access_transfer": "keep", "polling": {"enabled": False}}, {"group_id": "missing"}, {"access_transfer": None}])
async def test_conversion_rejects_ambiguous_or_invalid_intent_without_effect(engine, intent):
    e = engine
    cid = (await e.execute("credential-save", {"label": "Before", "community": "synthetic"}))["id"]
    before, persisted = e.state, stored_state(e.store)
    with pytest.raises(CommandError):
        await e.execute("credential-save", {"id": cid, "label": "After", "version": "3", "username": "converted",
            "security_level": "noAuthNoPriv", **intent}, key="rejected")
    assert e.state is before and stored_state(e.store) == persisted and "rejected" not in e.idempotency


async def test_conversion_group_and_user_rollback_together(engine, monkeypatch):
    import sqlite3
    e = engine
    cid = (await e.execute("credential-save", {"label": "Before", "community": "synthetic", "polling": {"enabled": True}}))["id"]
    request = {"id": cid, "version": "3", "username": "new-user", "security_level": "noAuthNoPriv", "access_transfer": "keep"}
    before, persisted = e.state, stored_state(e.store)
    original = e.store.put
    def fail_after_write(key, value):
        original(key, value)
        if key == "configuration_revision":
            raise sqlite3.OperationalError("Synthetic conversion write failure")
    with monkeypatch.context() as patch:
        patch.setattr(e.store, "put", fail_after_write)
        with pytest.raises(sqlite3.OperationalError):
            await e.execute("credential-save", request, key="conversion")
    assert e.state is before and stored_state(e.store) == persisted and not e.idempotency
    with pytest.raises(CommandError):
        await e.execute("credential-save", request, expected_config=e.state.configuration_revision-1)
    assert e.state is before and not e.state.cfg.groups
    await e.execute("credential-save", request)
    assert len(e.state.cfg.groups) == 1


@pytest.mark.parametrize("intent", ["keep", "none", "group"])
async def test_conversion_requires_explicit_new_user_profile(engine, intent):
    e = engine
    gid = (await e.execute("group-save", {"label": "Selected group"}))["id"]
    cid = (await e.execute("credential-save", {"label": "Existing", "community": "synthetic-community"}))["id"]
    choice = {"group_id": gid} if intent == "group" else {"access_transfer": intent}
    fields = {"id": cid, "version": "3", "username": "converted", "auth_key": "synthetic-auth",
              "priv_key": "synthetic-priv", **choice}
    before, persisted = e.state, stored_state(e.store)
    with pytest.raises(CommandError, match="explicit protection profile"):
        await e.execute("credential-save", fields, key="missing-profile")
    assert e.state is before and stored_state(e.store) == persisted and not e.idempotency
    await e.execute("credential-save", {**fields, "security_level": "authPriv"})
    assert e.state.cfg.credentials[cid].security_level == "authPriv"


def test_schema2_generated_group_ids_are_url_safe_distinct_and_repeatable():
    import copy
    from switchlab.models import Configuration, initial_configuration
    raw = initial_configuration(4).model_dump()
    raw.pop("radius")
    for port in raw["ports"].values():port.pop("authentication")
    raw.pop("groups"); raw["schema_version"] = 2
    ids = ["a/b", "a?b", "a#b", "管理", "a:b", "a%2Fb"]
    raw["credentials"] = {cid: {"id": cid, "label": "Saved user", "version": "3", "username": str(n),
        "security_level": "noAuthNoPriv"} for n, cid in enumerate(ids)}
    before = copy.deepcopy(raw)
    cfg = Configuration.model_validate(raw)
    assert raw == before and cfg == Configuration.model_validate(raw)
    assert len(cfg.groups) == len(ids)
    for cid, user in cfg.credentials.items():
        assert user.id == cid and user.group_id in cfg.groups
        assert set(user.group_id) <= set("user-policy:0123456789abcdef")


@pytest.mark.parametrize("prefix,normalized", [("0", "0"), ("1", "1"), ("2", "2"), (" 01 ", "1")])
def test_view_root_prefix_is_not_a_complete_identity(prefix, normalized):
    from switchlab.models import View
    assert View(name="Root", includes=[prefix]).includes == [normalized]
    with pytest.raises(ValidationError):
        Identity(sys_object_id=prefix)


@pytest.mark.parametrize("prefix", ["", " ", "3", "3.1", "1.40", "1..3", ".1", "1.", "-1", "1.3.-1", "1.3.4294967296", "1." + ".".join(["3"] * 128)])
def test_invalid_view_prefix_is_rejected(prefix):
    from switchlab.models import View
    with pytest.raises(ValidationError):
        View(name="Invalid", includes=[prefix])


def test_fresh_view_defaults_are_iso_and_internet_without_access():
    from switchlab.models import Configuration, PollingAccess, WritingAccess, initial_configuration
    for cfg in (Configuration(), initial_configuration(4)):
        assert cfg.views["all"].model_dump() == {"id":"all", "name":"iso", "includes":["1"]}
        assert cfg.views["internet"].model_dump() == {"id":"internet", "name":"internet", "includes":["1.3.6.1"]}
        assert cfg.views["interfaces"].includes == ["1.3.6.1.2.1.1", "1.3.6.1.2.1.2", "1.3.6.1.2.1.31"]
        assert not cfg.credentials and not cfg.groups and not cfg.snmp.enabled
    assert PollingAccess().model_dump() == {"enabled":False, "view_id":"all", "networks":[]}
    assert WritingAccess().model_dump() == {"enabled":False, "view_id":None, "networks":[]}


@pytest.mark.parametrize("version", [1, 2, 3, 4])
@pytest.mark.parametrize("view_kind", ["omitted", "stock", "custom", "empty"])
def test_saved_views_preserve_effective_policy_on_close_reload(tmp_path, version, view_kind):
    import copy
    from cryptography.fernet import Fernet
    from switchlab.models import initial_configuration
    from switchlab.storage import Store
    legacy_views = {
        "all": {"id":"all", "name":"All implemented objects", "includes":["1.3.6.1.2.1"]},
        "interfaces": {"id":"interfaces", "name":"Identity and interfaces", "includes":["1.3.6.1.2.1.1", "1.3.6.1.2.1.2", "1.3.6.1.2.1.31"]},
    }
    custom_views = {
        "all": {"id":"all", "name":"iso", "includes":["1.3.6.1.2.1.2"]},
        "internet": {"id":"internet", "name":"internet", "includes":["1.3.6.1.2.1.31"]},
        "custom": {"id":"custom", "name":"All implemented objects", "includes":["1.0.8802.1.1.1.1.2.1.1.6"]},
    }
    raw = initial_configuration(4).model_dump(mode="json")
    raw["schema_version"] = version
    if version < 4:
        raw.pop("radius")
        for port in raw["ports"].values(): port.pop("authentication")
    if version < 3: raw.pop("groups")
    expected_views = custom_views if view_kind == "custom" else {} if view_kind == "empty" else legacy_views
    if view_kind == "omitted": raw.pop("views")
    else: raw["views"] = copy.deepcopy(expected_views)
    enabled = view_kind != "empty"
    read = {"enabled":enabled, "view_id":"all", "networks":["192.0.2.0/24"]}
    write = {"enabled":enabled, "view_id":"all", "networks":["2001:db8::/32"]}
    credential = {"id":"saved", "label":"Saved", "version":"2c", "community":"synthetic-saved-view", "enabled":True}
    if version == 1:
        credential.update(purpose="polling" if enabled else "notification", view_id="all", networks=read["networks"])
    else: credential.update(polling=read, writing=write)
    raw["credentials"] = {"saved":credential}
    original = copy.deepcopy(raw); path = str(tmp_path / "saved.db"); key = Fernet.generate_key()
    store = Store(path, key)
    try:
        with store.transaction(): store.put("configuration", raw)
        encrypted = store.db.execute("SELECT value FROM kv WHERE key='configuration'").fetchone()[0]
        loaded = store.load()
        assert {k:v.model_dump() for k,v in loaded.views.items()} == expected_views
        assert loaded.credentials["saved"].polling.model_dump() == read
        if version != 1: assert loaded.credentials["saved"].writing.model_dump() == write
        assert store.get("configuration") == original == raw
        assert store.db.execute("SELECT value FROM kv WHERE key='configuration'").fetchone()[0] == encrypted
    finally: store.close()
    restored = Store(path, key)
    try:
        again = restored.load()
        assert again == loaded and restored.get("configuration") == original
        engine = Engine(again, restored)
        assert {k:v.model_dump() for k,v in engine.state.cfg.views.items()} == expected_views
        assert restored.load() == loaded
        assert "views" not in engine.export()
    finally: restored.close()


@pytest.mark.parametrize("restore", ["process", "reboot"])
async def test_running_startup_logical_and_mixed_lab_lifetimes(tmp_path, restore):
    from cryptography.fernet import Fernet
    from switchlab.models import initial_configuration
    from switchlab.storage import Store
    key = Fernet.generate_key()
    path = str(tmp_path / "startup.db")
    store = Store(path, key)
    try:
        cfg = initial_configuration(2); cfg.paused = True
        e = Engine(cfg, store); pid = next(iter(cfg.ports))
        await e.execute("vlan-create", {"vid": 20})
        await e.execute("port-edit", {"id": pid, "patch": {
            "pvid": 20, "admitted": [1,20], "alias": "unsaved", "mode": "shared", "speed": 100000000}})
        eid = await endpoint(e, active=False)
        assert e.state.cfg.ports[pid].pvid == 20
        assert 20 not in store.load().vlans
        assert store.load().ports[pid].mode == "shared"
        if restore == "process":
            store.close(); store = Store(path, key); e = Engine(store.load(), store)
        else:
            await e.execute("reboot")
        assert e.state.cfg.ports[pid].pvid == 1
        assert e.state.cfg.ports[pid].alias == ""
        assert e.state.cfg.ports[pid].mode == "shared"
        assert e.state.cfg.ports[pid].speed == 100000000
        assert e.state.cfg.attachments == {eid: pid}
        assert eid in e.state.cfg.endpoints and e.state.cfg.paused
        assert not e.snapshot()["configuration_status"]["unsaved"]
        await e.execute("vlan-create", {"vid": 20})
        await e.execute("port-edit", {"id": pid, "patch": {"pvid": 20, "admitted": [1,20], "admin_up": False}})
        revision = e.state.configuration_revision
        before = e.state
        with pytest.raises(CommandError, match="Configuration changed"):
            await e.execute("save-startup", expected_config=revision-1)
        assert e.state is before
        await e.execute("save-startup", expected_config=revision)
        saved_revision = e.snapshot()["configuration_status"]["startup_revision"]
        assert saved_revision == e.state.configuration_revision
        assert not e.snapshot()["configuration_status"]["unsaved"]
        await e.execute("port-edit", {"id": pid, "patch": {"pvid": 1, "admin_up": True}})
        await e.execute("detach", {"id": eid})
        await e.execute("endpoint-delete", {"id": eid})
        before_revision = e.state.configuration_revision
        if restore == "process":
            store.close(); store = Store(path, key); e = Engine(store.load(), store)
        else:
            await e.execute("reboot")
        assert e.state.configuration_revision > before_revision
        assert e.state.cfg.ports[pid].pvid == 20 and not e.state.cfg.ports[pid].admin_up
        assert not e.state.cfg.endpoints and not e.state.cfg.attachments
        assert e.snapshot()["configuration_status"]["startup_revision"] == saved_revision
        assert not e.state.fdb and e.state.sim_ms == 0
    finally:
        store.close()


@pytest.mark.parametrize("restore", ["process", "reboot"])
async def test_running_startup_effect_scoped_idempotency(engine, restore):
    e = engine; pid = next(iter(e.state.cfg.ports))
    payload = {"name": "Running name", "description": "Durable hardware description"}
    await e.execute("switch-edit", payload, key="mixed")
    physical = await e.execute("endpoint-create", {"name": "Durable client"}, key="physical")
    await e.execute("save-startup", key="save")
    await e.execute("switch-edit", {"name": "Discard me"}, key="logical")
    reboot = await e.execute("reboot", key="reboot-once")
    if restore == "process":
        e = Engine(e.store.load(), e.store)
    epoch, revision = e.state.epoch, e.state.revision
    assert await e.execute("reboot", key="reboot-once") == reboot
    assert (e.state.epoch, e.state.revision) == (epoch, revision)
    assert await e.execute("endpoint-create", {"name": "Durable client"}, key="physical") == physical
    for action, body, key in [("switch-edit", payload, "mixed"),
                              ("switch-edit", {"name": "Discard me"}, "logical")]:
        with pytest.raises(CommandError, match="earlier running configuration") as error:
            await e.execute(action, body, key=key)
        assert error.value.status == 409
    assert e.state.cfg.switch.name == "Running name"
    assert e.state.cfg.switch.description == "Durable hardware description"


@pytest.mark.parametrize("action", ["save-startup", "switch-edit", "reboot"])
@pytest.mark.parametrize("stage", ["mid-write", "commit-before", "rollback", "commit-after", "commit-rolled-back"])
async def test_startup_sqlite_failure_publication_and_recovery(tmp_path, monkeypatch, action, stage):
    import sqlite3
    from cryptography.fernet import Fernet
    from switchlab.models import initial_configuration
    from switchlab.storage import Store, StorageFault, RollbackFailed, CommitUncertain
    from test_snmp_lifetime import TransactionFault
    path = str(tmp_path / "fault.db"); key = Fernet.generate_key(); store = Store(path, key)
    e = Engine(initial_configuration(1), store)
    await e.execute("switch-edit", {"name": "Unsaved"})
    before, persisted = e.state, stored_state(store)
    connection = store.db; proxy = TransactionFault(connection, stage); original = store.put
    def fail(name, value):
        original(name, value)
        if name == "outbox":
            raise sqlite3.OperationalError("Synthetic write failure")
    try:
        with monkeypatch.context() as patcher:
            if stage == "mid-write": patcher.setattr(store, "put", fail)
            else: patcher.setattr(store, "db", proxy)
            expected = RollbackFailed if stage == "rollback" else CommitUncertain if stage in ("commit-after", "commit-rolled-back") else sqlite3.OperationalError
            with pytest.raises(expected):
                await e.execute(action, {"name": "Mixed", "description": "New hardware"} if action == "switch-edit" else {}, key="uncertain")
        assert e.state is before and "uncertain" not in e.idempotency
        if stage in ("commit-after", "commit-rolled-back", "rollback"):
            assert e.storage_fault
            for command in ("save-startup", "reboot", "pause"):
                with pytest.raises(StorageFault): await e.execute(command)
            with pytest.raises(StorageFault): store.load()
        else:
            assert not e.storage_fault and stored_state(store) == persisted
        # Ordinary SQLite close, including a still-open failed rollback, owns
        # recovery. Do not repair the connection with a test-only rollback.
        store.close(); store = Store(path, key)
        recovered = Engine(store.load(), store)
        committed = stage == "commit-after"
        assert recovered.state.cfg.switch.name == ("Unsaved" if committed and action == "save-startup" else "Switch Lab")
        assert recovered.state.cfg.switch.description == ("New hardware" if committed and action == "switch-edit" else "Generic Ethernet switch management simulation")
        assert recovered.state.configuration_revision >= before.configuration_revision
        assert not recovered.snapshot()["configuration_status"]["unsaved"]
        assert ("uncertain" in recovered.idempotency) == committed
        if committed:
            current = recovered.state
            if action == "switch-edit":
                with pytest.raises(CommandError, match="earlier running configuration"):
                    await recovered.execute(action, {"name":"Mixed", "description":"New hardware"}, key="uncertain")
            else:
                await recovered.execute(action, key="uncertain")
            assert recovered.state is current
    finally:
        if not store.closed: store.close()


@pytest.mark.parametrize("stage", ["mid-write", "commit-before", "rollback", "commit-after", "commit-rolled-back"])
def test_startup_legacy_split_migration_is_atomic(tmp_path, monkeypatch, stage):
    import sqlite3
    from cryptography.fernet import Fernet
    from switchlab.models import initial_configuration
    from switchlab.storage import Store, RollbackFailed, CommitUncertain
    from test_snmp_lifetime import TransactionFault
    path = str(tmp_path / "migration.db"); key = Fernet.generate_key(); store = Store(path, key)
    cfg = initial_configuration(2); cfg.switch.name = "Preserved legacy"
    raw = cfg.model_dump(mode="json")
    with store.transaction():
        store.put("configuration", raw); store.put("configuration_revision", 41); store.put("revision", 70)
    connection = store.db; original = store.put
    def fail(name, value):
        original(name, value)
        if name == "configuration_format": raise sqlite3.OperationalError("Synthetic migration failure")
    try:
        with monkeypatch.context() as patcher:
            if stage == "mid-write": patcher.setattr(store, "put", fail)
            else: patcher.setattr(store, "db", TransactionFault(connection, stage))
            expected = RollbackFailed if stage == "rollback" else CommitUncertain if stage in ("commit-after", "commit-rolled-back") else sqlite3.OperationalError
            with pytest.raises(expected): Engine(store.load(), store)
        store.close(); store = Store(path, key)
        assert (store.get("configuration") is None) == (stage == "commit-after")
        if stage != "commit-after":
            assert store.get("configuration") == raw
            assert store.get("configuration_format") is None
            assert store.get("lab_configuration") is None and store.get("startup_configuration") is None
        restored = Engine(store.load(), store)
        assert restored.state.cfg == cfg and restored.state.configuration_revision > 41
        assert store.get("configuration") is None and store.get("configuration_format") == 1
        assert store.load() == cfg
    finally: store.close()


def test_startup_composition_retains_ids_defaults_replacements_and_rejects_missing_restrictions():
    from switchlab.models import initial_configuration, Port, Vlan, Community
    from switchlab.storage import split_configuration, compose_configuration
    cfg = initial_configuration(2); first, removed = list(cfg.ports)
    cfg.vlans[20] = Vlan(vid=20, fdb_id=1020)
    cfg.ports[first].pvid = 20; cfg.ports[first].admitted = [1,20]
    cfg.ports[removed].admin_up = False
    cfg.credentials["manager"] = Community(id="manager", label="Manager", community="synthetic", polling={"enabled":True, "view_id":"all"})
    lab, startup = split_configuration(cfg)
    assert compose_configuration(lab, startup) == cfg
    old = lab["ports"].pop(removed)
    replacement = Port(if_index=old["if_index"], bridge_port=old["bridge_port"], name="Replacement")
    lab["ports"][replacement.id] = {key:getattr(replacement,key) for key in old}
    restored = compose_configuration(lab, startup)
    assert set(restored.ports) == {first,replacement.id} and removed not in restored.ports
    assert restored.ports[first].pvid == 20
    assert restored.ports[replacement.id].pvid == 1 and restored.ports[replacement.id].admin_up
    assert restored.ports[replacement.id].authentication.control == "force-authorized"
    bad = copy.deepcopy(startup); bad["views"].pop("all")
    with pytest.raises(ValidationError, match="Unknown read view"): compose_configuration(lab,bad)
    bad = copy.deepcopy(startup); bad["ports"][first].pop("forbidden")
    with pytest.raises(ValueError, match="configuration fragment"): compose_configuration(lab,bad)
    lab["attachments"]["missing-client"] = removed
    with pytest.raises(ValidationError, match="attachment"): compose_configuration(lab,startup)


@pytest.mark.parametrize("field", ["configuration_format", "lab_configuration", "startup_configuration", "startup_revision"])
def test_startup_partial_even_null_is_not_fresh_configuration(store, field):
    with store.transaction(): store.put(field, None)
    with pytest.raises(ValueError, match="Incomplete stored configuration"): store.load()


async def test_startup_import_idempotency_tracks_actual_logical_effect(engine):
    e = engine
    scenario = e.export(); scenario["lab_settings"]["aging_seconds"] = 60
    scenario["endpoints"]["new"] = {"id":"new", "name":"Imported durable client", "sources":[], "active":False}
    await e.execute("import", scenario, key="mixed-import")
    incarnation = e.state.configuration_incarnation
    await e.execute("import", e.export())
    assert e.state.configuration_incarnation == incarnation
    before = e.state
    await e.execute("import", scenario, key="mixed-import")
    assert e.state is before
    await e.execute("reboot")
    assert e.state.cfg.switch.aging_seconds == 300 and "new" in e.state.cfg.endpoints
    with pytest.raises(CommandError, match="earlier running configuration"):
        await e.execute("import", scenario, key="mixed-import")


async def test_set_candidate_clone_isolated_from_old_runtime_plan_and_lazy_reads(engine, monkeypatch):
    from switchlab.models import Configuration
    e=engine;await endpoint(e);await tick(e)
    before=e.state;old_cfg=before.cfg.model_dump(mode="json");old_fdb=copy.deepcopy(before.fdb);old_events=copy.deepcopy(before.events)
    old_projection=Projection(before,["1"])
    binding=set_binding("2.2.1.7.101",a.Integer32(2));plan=plan_set(before.cfg,[binding],["1"])
    copied=[];original=Configuration.__deepcopy__
    def observed(self,memo=None):
        copied.append(id(self));return original(self,memo)
    with monkeypatch.context() as patcher:
        patcher.setattr(Configuration,"__deepcopy__",observed)
        async with e.lock: e.commit_set_locked(plan)
    assert id(before.cfg) not in copied and copied.count(id(plan.candidate)) == 1
    assert before.cfg.model_dump(mode="json") == old_cfg and before.fdb == old_fdb and before.events == old_events
    assert int(old_projection.get(binding[0])[1]) == 1
    assert int(Projection(e.state,["1"]).get(binding[0])[1]) == 2
    assert plan.candidate is not e.state.cfg and e.state.cfg is not before.cfg
    pid=next(iter(e.state.cfg.ports));published=e.state.cfg.model_dump(mode="json")
    plan.candidate.ports[pid].admin_up=True;plan.candidate.switch.name="Changed after commit"
    assert e.state.cfg.model_dump(mode="json") == published
    with pytest.raises(CommandError,match="Stale SET plan"):
        async with e.lock: e.commit_set_locked(plan)
    same=e.state
    async with e.lock: e.commit_set_locked(plan_set(same.cfg,[binding],["1"]))
    assert e.state is same


@pytest.mark.parametrize("stage", ["candidate-copy", "validation", "store"])
async def test_set_clone_elision_failure_never_mutates_published_runtime(engine,monkeypatch,stage):
    from switchlab.models import Configuration
    e=engine;await endpoint(e);await tick(e)
    before=e.state;saved=copy.deepcopy(before);persisted=stored_state(e.store)
    plan=plan_set(before.cfg,[set_binding("2.2.1.7.101",a.Integer32(2))],["1"])
    candidate=plan.candidate.model_dump(mode="json")
    def fail(*args,**kwargs):raise ValueError("Synthetic selected boundary failure")
    original=Configuration.model_copy
    def fail_candidate(self,*args,**kwargs):
        if self is plan.candidate: fail()
        return original(self,*args,**kwargs)
    with monkeypatch.context() as patcher:
        if stage == "candidate-copy":patcher.setattr(Configuration,"model_copy",fail_candidate)
        elif stage == "validation":patcher.setattr(Configuration,"model_validate",classmethod(fail))
        else:patcher.setattr(e.store,"commit",fail)
        with pytest.raises(ValueError,match="Synthetic selected boundary failure"):
            async with e.lock:e.commit_set_locked(plan)
    assert e.state is before and e.state == saved
    assert plan.candidate.model_dump(mode="json") == candidate
    assert stored_state(e.store) == persisted


@pytest.mark.parametrize("owner,path", [
    ("startup", ("ports", "port", "authentication", "control")),
    ("startup", ("ports", "port", "authentication", "fallback_no_supplicant")),
    ("startup", ("credentials", "restricted", "enabled")),
    ("startup", ("credentials", "restricted", "polling", "view_id")),
    ("startup", ("credentials", "restricted", "polling", "networks")),
    ("startup", ("radius", "servers", 0, "enabled")),
    ("startup", ("radius", "accounting", "attempts")),
    ("lab", ("endpoints", "client", "active")),
    ("lab", ("endpoints", "client", "sources", 0, "octets")),
])
def test_startup_nested_omission_never_fills_current_restrictions(store,owner,path):
    from switchlab.models import initial_configuration, Community, RadiusServer, Endpoint
    from switchlab.storage import split_configuration
    cfg=initial_configuration(1);pid=next(iter(cfg.ports));cfg.ports[pid].authentication.control="auto"
    cfg.ports[pid].authentication.fallback_no_supplicant=False
    cfg.credentials["restricted"]=Community(id="restricted",label="Restricted",community="synthetic",enabled=False,
        polling={"enabled":True,"view_id":"interfaces","networks":["192.0.2.0/24"]})
    cfg.radius.servers=[RadiusServer(label="Disabled",address="192.0.2.1",secret="synthetic",enabled=False)]
    cfg.endpoints["client"]=Endpoint(id="client",name="Silent",active=False,sources=[Source(mac="02:00:00:00:00:11",octets=512)])
    Engine(cfg,store)
    fragment=store.get("startup_configuration" if owner=="startup" else "lab_configuration")
    actual_path=[pid if key=="port" else key for key in path]
    parent=fragment
    for key in actual_path[:-1]:parent=parent[key]
    del parent[actual_path[-1]]
    with store.transaction():store.put("startup_configuration" if owner=="startup" else "lab_configuration",fragment)
    with pytest.raises(ValueError):store.load()


def test_startup_complete_force_unauthorized_is_preserved_and_omission_rejected(store):
    from switchlab.models import initial_configuration
    cfg=initial_configuration(1);pid=next(iter(cfg.ports))
    cfg.ports[pid].authentication.control="force-unauthorized"
    Engine(cfg,store)
    assert store.load().ports[pid].authentication.control == "force-unauthorized"
    broken=store.get("startup_configuration")
    del broken["ports"][pid]["authentication"]["control"]
    with store.transaction():store.put("startup_configuration",broken)
    with pytest.raises(ValueError,match="configuration fragment"):store.load()


async def test_event_history_port_effects_replay_and_attachment_context(engine, store):
    e = engine
    ports = list(e.state.cfg.ports)
    eid = await endpoint(e, active=False)
    before = e.state.event_id
    await e.execute("attach", {"id":eid,"port_id":ports[1]}, key="event-move")
    rows = [row for row in e.state.events if row["id"] > before]
    move = next(row for row in rows if row["kind"] == "attach")
    assert (move["endpoint_id"],move["before_port_id"],move["after_port_id"]) == (eid,ports[0],ports[1])
    assert {row["revision"] for row in rows} == {e.state.revision}
    confirmed = e.state
    await e.execute("attach", {"id":eid,"port_id":ports[1]}, key="event-move")
    assert e.state is confirmed
    await e.execute("attach", {"id":eid,"port_id":ports[1]})
    assert e.state.events == confirmed.events
    await e.execute("detach", {"id":eid})
    detach = next(row for row in reversed(e.state.events) if row["kind"] == "detach")
    assert (detach["before_port_id"],detach["after_port_id"]) == (ports[1],None)
    # Field names are public; user-controlled free-form values are not an event diff.
    marker = "private-looking-alias-not-for-history"
    before = e.state.event_id
    await e.execute("port-edit", {"id":ports[0],"patch":{"alias":marker,"admin_up":False}}, key="event-port")
    changed = [row for row in e.state.events if row["id"] > before]
    effect = next(row for row in changed if row["kind"] == "port-edit")
    assert effect["fields"] == ["admin_up","alias"]
    assert effect["changes"] == {"admin_up":{"before":True,"after":False}}
    import json
    assert marker not in json.dumps(store.events())
    confirmed = e.state
    await e.execute("port-edit", {"id":ports[0],"patch":{"alias":marker,"admin_up":False}}, key="event-port")
    assert e.state is confirmed
    await e.execute("port-edit", {"id":ports[0],"patch":{"alias":marker,"admin_up":False}})
    assert e.state.events == confirmed.events
    assert store.events() == e.state.events


async def test_event_history_retained_identity_and_simulation_reset(engine, store):
    e = engine
    await e.execute("advance", {"duration_ms":1234})
    await e.execute("pause")
    event = e.state.events[-1]
    assert event["simulation_ms"] == 1234
    await e.execute("save-startup")
    saved = e.state.events[-1]
    assert saved["kind"] == "configuration-saved"
    await e.execute("reboot")
    boot = e.state.events[-1]
    assert (boot["kind"],boot["simulation_ms"]) == ("boot",0)
    assert boot["id"] > saved["id"] > event["id"]
    assert event in e.state.events and store.events() == e.state.events


@pytest.mark.parametrize("notifications,gate,target_enabled,credential_enabled", [
    (True,True,True,True), (False,True,True,True), (True,False,True,True),
    (True,True,False,True), (True,True,True,False),
])
async def test_event_history_link_fact_and_exact_trap_gates(engine, notifications, gate, target_enabled, credential_enabled):
    e=engine;pid=next(iter(e.state.cfg.ports))
    await e.execute("switch-edit", {"identity":{"sys_object_id":"1.3.6.1.4.1.32473.1"}})
    credential=await e.execute("credential-save", {"label":"Synthetic trap", "community":"synthetic-trap", "enabled":credential_enabled})
    target=await e.execute("target-save", {"address":"192.0.2.1", "credential_id":credential["id"], "enabled":target_enabled})
    await e.execute("snmp-settings", {"enabled":gate})
    await e.execute("port-edit", {"id":pid,"patch":{"link_notifications":notifications}})
    before=e.state.event_id
    await endpoint(e,active=False)
    rows=[row for row in e.state.events if row["id"]>before]
    links=[row for row in rows if row["kind"]=="linkUp"]
    assert len(links)==1
    link=links[0]
    assert (link["port_id"],link["if_index"],link["admin"],link["before"],link["after"])==(pid,101,1,2,1)
    queued=notifications and gate and target_enabled and credential_enabled
    assert len(e.state.outbox)==int(queued)
    deliveries=[row for row in rows if row["kind"]=="notification"]
    assert len(deliveries)==int(queued)
    if queued:
        assert e.state.outbox[0]=={"event":link,"target_id":target["id"],"destination":"192.0.2.1:162"}
        assert deliveries[0]["notification_id"]==link["id"] and deliveries[0]["status"]=="queued"
        before=e.state;old=copy.deepcopy(before)
        await e.execute("notification-result",{"notification_id":link["id"],"target_id":target["id"],"status":"sent"})
        assert before==old and not e.state.outbox
        assert next(row for row in e.state.events if row["id"]==link["id"])==link
        assert e.state.events[-1]["destination"]=="192.0.2.1:162"
    assert e.store.events()==e.state.events


async def test_event_history_typed_port_effects_and_field_only_other_resources(engine):
    e=engine;pid=next(iter(e.state.cfg.ports))
    await e.execute("vlan-create", {"vid":20,"name":"private-looking-vlan"})
    await e.execute("vlan-create", {"vid":30,"name":"private-looking-vlan"})
    await e.execute("port-edit", {"id":pid,"patch":{"mode":"shared"}})
    before=e.state.event_id
    patch={"admin_up":False,"shared_partner":False,"forced_down":True,"pvid":20,
           "admitted":[1,20],"untagged":[20],"forbidden":[30],"link_notifications":False,
           "authentication":{"control":"auto"},"alias":"private-looking-alias"}
    await e.execute("port-edit", {"id":pid,"patch":patch})
    effect=next(row for row in e.state.events if row["id"]>before and row["kind"]=="port-edit")
    assert effect["fields"]==sorted(patch)
    old={"admin_up":True,"shared_partner":True,"forced_down":False,"pvid":1,
         "admitted":[1],"untagged":[1],"forbidden":[],"link_notifications":True}
    assert effect["changes"]=={key:{"before":value,"after":patch[key]} for key,value in old.items()}
    await e.execute("switch-edit", {"name":"private-looking-switch"})
    assert e.state.events[-1]["fields"]==["name"]
    await e.execute("vlan-edit", {"vid":20,"name":"private-looking-renamed-vlan"})
    assert e.state.events[-1]["fields"]==["name"]
    import json
    assert "private-looking" not in json.dumps(e.store.events())


async def test_event_history_retention_and_ids_across_sqlite_reload(tmp_path, monkeypatch):
    from cryptography.fernet import Fernet
    from switchlab.storage import Store
    from switchlab.models import initial_configuration
    from switchlab.mib import Projection
    key=Fernet.generate_key();path=str(tmp_path/"history.db")
    cfg=initial_configuration(1);cfg.paused=True
    store=Store(path,key);e=Engine(cfg,store)
    try:
        # Seed the retention boundary without thousands of unrelated transactions.
        candidate=copy.deepcopy(e.state)
        details={"fields":["admitted"],"changes":{"admitted":{"before":[1],"after":[1,20]}}}
        for _ in range(2005):candidate.event("port-edit",**details)
        captured=copy.deepcopy(candidate.events)
        details["fields"].clear();details["changes"]["admitted"]["after"].append(30)
        assert candidate.events==captured
        candidate.revision+=1;store.commit(candidate,{});e.state=candidate
        before=e.state;old=copy.deepcopy(before);retained=copy.deepcopy(before.events)
        projection=Projection(before,["1"])
        with monkeypatch.context() as m:
            await e.execute("advance",{"duration_ms":100})
            await e.execute("pause",key="retained-pause")
            confirmed=e.state;durable=store.events()
            await e.execute("pause",key="retained-pause")
            assert e.state is confirmed
            with pytest.raises(CommandError):await e.execute("advance",{"duration_ms":0})
            assert e.state is confirmed and store.events()==durable
            def fail(*args,**kwargs):raise RuntimeError("synthetic commit failure")
            m.setattr(store,"commit",fail)
            with pytest.raises(RuntimeError,match="synthetic commit failure"):
                await e.execute("pause")
            assert e.state is confirmed and e.state.events==durable[-2000:]
        assert before==old and len(before.events)==len(e.state.events)==2000
        assert e.state.events[:-1]==retained[1:]
        assert int(projection.get("1.3.6.1.2.1.2.2.1.1.101")[1])==101
        assert projection.state is before
        last=e.state.event_id;retained=copy.deepcopy(e.state.events)
    finally:store.close()
    store=Store(path,key)
    try:
        restored=Engine(None,store)
        assert len(restored.state.events)==2000
        assert restored.state.events[:-1]==retained[1:]
        assert restored.state.events[-1]["kind"]=="boot"
        assert restored.state.events[-1]["id"]==last+1
        assert restored.state.events[-1]["simulation_ms"]==0
        assert restored.state.events[-1]["revision"]==restored.state.revision
        assert store.events()[-2000:]==restored.state.events
        loaded=store.events();loaded[-2]["kind"]="caller edit"
        assert restored.state.events[-2]["kind"]=="pause"
    finally:store.close()



async def test_event_display_port_endpoint_and_source_capture(engine, store):
    e = engine
    ports = list(e.state.cfg.ports)
    eid = await endpoint(e, name="Lab <client>", active=False)
    created = next(row for row in e.state.events if row["kind"] == "endpoint-created")
    assert created["endpoint_name"] == "Lab <client>"
    await e.execute("attach", {"id":eid, "port_id":ports[1]})
    move = next(row for row in reversed(e.state.events) if row["kind"] == "attach")
    assert (move["before_if_index"], move["after_if_index"]) == (101, 102)
    sid = e.state.cfg.endpoints[eid].sources[0].id
    await e.execute("source-supplicant-save", {"id":eid, "source_id":sid, "profile":None})
    profile = e.state.events[-1]
    assert profile["source_mac"] == "02:00:00:00:00:10"
    assert profile["endpoint_name"] == "Lab <client>"
    await e.execute("endpoint-edit", {"id":eid, "patch":{"name":"Renamed client"}})
    await e.execute("port-edit", {"id":ports[1], "patch":{"alias":"not-public-alias", "admin_up":False}})
    changed = next(row for row in reversed(e.state.events) if row["kind"] == "port-edit")
    assert changed["if_index"] == 102
    await e.execute("detach", {"id":eid})
    await e.execute("endpoint-delete", {"id":eid})
    deleted = e.state.events[-1]
    assert deleted["endpoint_name"] == "Renamed client"
    assert created["endpoint_name"] == move["endpoint_name"] == "Lab <client>"
    assert store.events() == e.state.events
    import json
    assert "not-public-alias" not in json.dumps(store.events())
    # Explicit captured facts are authoritative, even if a current row differs.
    captured = e.state.event("linkDown", port_id=ports[1], if_index=999)
    assert captured["if_index"] == 999


@pytest.mark.parametrize("kind,fields", [
    ("credential", {"label":"Public community", "community":"private-community"}),
    ("group", {"label":"Public group"}),
    ("view", {"name":"Public view", "includes":["1"]}),
    ("radius-server", {"label":"Public server", "address":"192.0.2.20", "secret":"private-radius"}),
    ("accounting-target", {"label":"Public collector", "address":"192.0.2.21", "secret":"private-accounting"}),
    ("dynamic-sender", {"label":"Public sender", "address":"192.0.2.22", "secret":"private-dynamic"}),
])
async def test_event_display_saved_and_deleted_resource_labels(engine, kind, fields):
    e = engine
    result = await e.execute(kind+"-save", fields)
    first = e.state.events[-1]
    label = fields.get("label", fields.get("name"))
    assert first["resource_label"] == label
    key = "name" if kind == "view" else "label"
    await e.execute(kind+"-save", {"id":result["id"], key:"Renamed <public>"})
    await e.execute(kind+"-delete", {"id":result["id"]})
    assert e.state.events[-1]["resource_label"] == "Renamed <public>"
    assert first["resource_label"] == label
    import json
    text = json.dumps(e.store.events())
    assert "private-" not in text
    assert fields.get("address", "never-present") not in text


@pytest.mark.parametrize("address,display", [("192.0.2.1","192.0.2.1:162"), ("2001:db8::1","[2001:db8::1]:162")])
async def test_event_display_notification_original_destination(engine, address, display):
    e=engine
    credential=await e.execute("credential-save", {"label":"Not a destination", "community":"private-community"})
    source_address="2001:db8::200" if ":" in address else "192.0.2.200"
    target=await e.execute("target-save", {"address":address, "credential_id":credential["id"], "source_address":source_address})
    assert e.state.events[-1]["resource_label"] == display
    await e.execute("snmp-settings", {"enabled":True})
    await e.execute("switch-edit", {"identity":{"sys_object_id":"1.3.6.1.4.1.32473.1"}})
    await e.execute("test-notification", {"target_id":target["id"]})
    queued=e.state.outbox[0]
    assert queued["destination"] == display
    assert e.state.events[-1]["destination"] == display
    await e.execute("notification-result", {"notification_id":queued["event"]["id"], "target_id":target["id"], "status":"sent", "attempted":True})
    assert e.state.events[-1]["destination"] == display
    await e.execute("test-notification", {"target_id":target["id"]})
    queued=e.state.outbox[0]
    await e.execute("target-save", {"id":target["id"], "address":"192.0.2.2", "port":1162, "credential_id":credential["id"], "source_address":None})
    canceled=e.state.events[-1]
    assert (canceled["status"],canceled["destination"]) == ("canceled-on-configuration",display)
    await e.execute("test-notification", {"target_id":target["id"]})
    await e.execute("target-delete", {"id":target["id"]})
    assert e.state.events[-1]["destination"] == "192.0.2.2:1162"
    assert next(row for row in reversed(e.state.events) if row["kind"]=="target-delete")["resource_label"] == "192.0.2.2:1162"
    import json
    assert source_address not in json.dumps(e.store.events())
    # Legacy queue records do not acquire a fictitious capture during cancellation.
    e.state.outbox=[{"event":queued["event"],"target_id":target["id"]}]
    e.state.cancel_outbox("canceled-on-configuration")
    assert "destination" not in e.state.events[-1]


async def test_event_display_accounting_uses_captured_server_label(engine, monkeypatch):
    e=engine
    target=await e.execute("accounting-target-save", {"label":"Original collector", "address":"192.0.2.30", "secret":"private-accounting"})
    await e.execute("accounting-settings", {"enabled":True})
    await e.execute("radius-shutdown")
    record=e.state.accounting_outbox[0]
    async def delivery(captured, targets, **kwargs):
        assert targets[target["id"]].label == "Original collector"
        await e.execute("accounting-target-save", {"id":target["id"], "label":"Current collector"})
        assert e.accounting_current(record["id"]) is not None
        await kwargs["on_event"]("attempting",target["id"])
        return True,target["id"]
    monkeypatch.setattr("switchlab.radius.accounting_delivery",delivery)
    await e.deliver_accounting(record["id"])
    rows=[row for row in e.state.events if row["kind"]=="accounting" and row.get("target_id")==target["id"]]
    assert [row["status"] for row in rows] == ["attempting","delivered"]
    assert all(row["server_label"]=="Original collector" for row in rows)
    assert not e.state.accounting_outbox


async def test_event_display_failed_publication_and_reload(tmp_path, monkeypatch):
    from cryptography.fernet import Fernet
    from switchlab.storage import Store
    from switchlab.models import initial_configuration
    key=Fernet.generate_key();path=str(tmp_path/"display.db")
    store=Store(path,key);e=Engine(initial_configuration(2),store)
    try:
        eid=await endpoint(e,name="Original label",port=None,active=False)
        captured=copy.deepcopy(e.state.events[-1])
        before=e.state;durable=store.events()
        def fail(*args,**kwargs):raise RuntimeError("synthetic commit failure")
        with monkeypatch.context() as m:
            m.setattr(store,"commit",fail)
            with pytest.raises(RuntimeError,match="synthetic commit failure"):
                await e.execute("endpoint-edit",{"id":eid,"patch":{"name":"Unpublished label"}})
        assert e.state is before and store.events()==durable
        await e.execute("endpoint-edit",{"id":eid,"patch":{"name":"Changed label"}},key="display-edit")
        before=e.state
        await e.execute("endpoint-edit",{"id":eid,"patch":{"name":"Changed label"}},key="display-edit")
        assert e.state is before
        await e.execute("endpoint-delete",{"id":eid})
    finally:store.close()
    store=Store(path,key)
    try:
        restored=Engine(None,store)
        assert eid not in restored.state.cfg.endpoints
        assert captured in restored.state.events
        assert next(row for row in restored.state.events if row["kind"]=="endpoint-delete")["endpoint_name"]=="Changed label"
        assert not any(row.get("endpoint_name")=="Unpublished label" for row in restored.state.events)
    finally:store.close()
