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
    persisted, events, idem = store.get("configuration"), store.events(), store.get("idempotency")
    original_put = store.put
    def fail_after_configuration(key, value):
        original_put(key, value)
        if key == "configuration":
            raise sqlite3.OperationalError("synthetic write failure")
    with monkeypatch.context() as patch:
        patch.setattr(store, "put", fail_after_configuration)
        with pytest.raises(sqlite3.OperationalError):
            await e.execute("target-save", {"address": "127.0.0.1", "new_credential": {
                "label": "Atomic", "community": "synthetic-atomic"}}, key="atomic")
    assert e.state is before and not e.idempotency
    assert store.get("configuration") == persisted and store.events() == events and store.get("idempotency") == idem
    result = await e.execute("target-save", {"address": "127.0.0.1", "new_credential": {
        "label": "Atomic", "community": "synthetic-atomic"}}, key="atomic")
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
    return ({key: store.get(key) for key in ("configuration", "configuration_revision", "revision",
                                            "outbox", "idempotency")}, store.events(), store.last_event)


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
    assert e.idempotency == {} and e.store.load() == e.state.cfg
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


@pytest.mark.parametrize("failure_key", ["configuration", "outbox"])
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
    assert e.store.load() == e.state.cfg


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
    restored = Engine(e.store.load(), e.store)
    assert restored.state.cfg == e.state.cfg
    assert restored.state.cfg.credentials[result["id"]].writing.enabled
    assert restored.state.cfg.credentials[result["id"]].polling.enabled is False
