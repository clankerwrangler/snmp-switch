import copy
import csv
import sqlite3
import time
import uuid
import pytest
from pathlib import Path
from pysnmp.proto import rfc1902, rfc1905
from switchlab.engine import CommandError, Engine
from switchlab.models import initial_configuration
from switchlab.mib import CURRENT, ENTITY, Projection, entity_inventory, oid
from conftest import endpoint, tick


async def test_manifest_and_nonidentical_indexes(engine):
    e=engine
    await e.execute("switch-edit",{"identity":{"sys_object_id":"2.999.4"}})
    await endpoint(e);await tick(e)
    m=Projection(e.state,["1.3.6"])
    manifest=Path(__file__).parents[1]/"specification/docs/mib-coverage.csv"
    with manifest.open() as stream:
        definitions = list(csv.DictReader(stream))
    readable = {"read-only", "read-write", "read-create"}
    for row in definitions:
        assert (oid(row["base_oid"]) in m.bases) == (row["release_access"] in readable), row["object"]
    assert {oid(row["base_oid"]) for row in definitions if row["release_access"] in readable} == m.bases
    assert {oid(row["base_oid"]) for row in definitions if row["release_access"] in {"read-write", "read-create"}} == set(WRITE_OBJECTS)
    assert isinstance(m.get("1.3.6.1.2.1.1.2.0")[1],rfc1902.ObjectIdentifier)
    assert str(m.get("1.3.6.1.2.1.1.2.0")[1])=="2.999.4"
    assert int(m.get("1.3.6.1.2.1.17.1.4.1.2.1")[1])==101
    assert m.get("1.3.6.1.2.1.17.7.1.4.3.1.2.1")[1].asOctets()==b"\xf0"
    assert int(m.get("1.3.6.1.2.1.17.7.1.2.2.1.2.1001.2.0.0.0.0.16")[1])==1
    assert m.get("1.3.6.1.2.1.17.7.1.2.2.1.1.1001.2.0.0.0.0.16")[1].tagSet==rfc1905.noSuchObject.tagSet


def test_exceptions_view_walk_and_numeric_order(engine):
    m=Projection(engine.state,["1.3.6.1.2.1.1","1.3.6.1.2.1.31"])
    assert m.get("1.3.6.1.2.1.1.1.99")[1].tagSet==rfc1905.noSuchInstance.tagSet
    assert m.get("1.3.6.1.2.1.99.1.0")[1].tagSet==rfc1905.noSuchObject.tagSet
    assert m.next("1.3.6.1.2.1.1.7.0")[0][:7]==oid("1.3.6.1.2.1.31")
    assert m.next("2.999")[1].tagSet==rfc1905.endOfMibView.tagSet


async def test_timefilter_single_traversal_and_deletion(engine):
    e=engine
    e.state.boot_start-=2
    await e.execute("vlan-create",{"vid":10})
    m=Projection(e.state,["1.3.6"])
    assert int(m.get(CURRENT+(3,100,10))[1])==1010
    assert m.get(CURRENT+(3,100,1))[1].tagSet==rfc1905.noSuchInstance.tagSet
    assert m.next(CURRENT+(3,100,10))[0]==CURRENT+(4,100,10)
    assert m.next(CURRENT+(7,100,10))[0]==oid("1.3.6.1.2.1.17.7.1.4.3.1.1.1")
    assert m.next(CURRENT+(3,500,0))[0]==oid("1.3.6.1.2.1.17.7.1.4.3.1.1.1")
    await e.execute("vlan-delete",{"vid":10})
    assert Projection(e.state,["1.3.6"]).get(CURRENT+(3,100,10))[1].tagSet==rfc1905.noSuchInstance.tagSet


async def test_management_wrap_and_counter_wrap(engine):
    e=engine;p=next(iter(e.state.cfg.ports))
    e.state.boot_start=time.monotonic()-(2**32+50)/100
    e.state.counters[p]["in_octets"]=2**32+12
    m=Projection(e.state,["1.3.6"])
    assert int(m.get("1.3.6.1.2.1.1.3.0")[1])<100
    assert m.get(CURRENT+(3,1,1))[1].tagSet==rfc1905.noSuchInstance.tagSet
    assert int(m.get("1.3.6.1.2.1.2.2.1.10.101")[1])==12
    assert int(m.get("1.3.6.1.2.1.31.1.1.1.6.101")[1])==2**32+12


@pytest.mark.parametrize("count", [1, 4, 24, 256])
def test_entity_physical_types_and_inventory(count):
    cfg = initial_configuration(count)
    e = Engine(cfg)
    m = Projection(e.state, ["1.3.6.1.2.1.47"])
    entry = ENTITY + (1, 1, 1, 1)
    assert len(m.values) == 18 * (count + 1) + 2 * count + 1
    assert {base for base in m.bases if base[:len(entry)] == entry} == {entry + (c,) for c in range(2, 20)}
    expected_records = [(1, cfg.switch, 0, 3, -1)] + [
        (p.bridge_port + 1, p, 1, 10, p.bridge_port) for p in cfg.ports.values()]
    for index, record, parent, kind, position in expected_records:
        cells = {column: m.get(entry + (column, index))[1] for column in range(2, 20)}
        for column, value in cells.items():
            typ = rfc1902.ObjectIdentifier if column == 3 else rfc1902.Integer32 if column in (4, 5, 6, 16) else rfc1902.OctetString
            assert value.tagSet == typ.tagSet, (column, value)
        assert str(cells[2]) == (cfg.switch.description if index == 1 else "Emulated Ethernet port")
        assert tuple(cells[3]) == (0, 0)
        assert [int(cells[c]) for c in (4, 5, 6, 16)] == [parent, kind, position, 2]
        assert str(cells[7]) == record.name
        assert all(cells[c].asOctets() == b"" for c in range(8, 16))
        assert cells[17].asOctets() == bytes(8)
        assert cells[18].asOctets() == uuid.UUID(record.id).urn.encode()
        assert cells[19].asOctets() == uuid.UUID(record.id).bytes
        assert len(cells[19].asOctets()) == 16
    for column in (1, 20, 21, 22):
        assert m.get(entry + (column, 1))[1].tagSet == rfc1905.noSuchObject.tagSet
    assert m.get(entry + (7, count + 2))[1].tagSet == rfc1905.noSuchInstance.tagSet
    assert m.get(ENTITY + (1, 4, 1, 0))[1].tagSet == rfc1902.TimeTicks.tagSet
    assert int(m.get(ENTITY + (1, 4, 1, 0))[1]) == 0
    for unsupported in ((1, 2, 1, 1, 2, 1), (1, 3, 1, 1, 1, 1, 1), (2, 0, 1)):
        assert m.get(ENTITY + unsupported)[1].tagSet == rfc1905.noSuchObject.tagSet


def test_entity_sparse_independent_indexes_and_unknown_ids():
    cfg = initial_configuration(4)
    cfg.switch.id = "saved-non-uuid-switch"
    ports = list(cfg.ports.values())
    for p, bridge, interface in zip(ports, (1, 9, 300, 65535), (2147483647, 2, 400, 101)):
        p.bridge_port, p.if_index = bridge, interface
    prior_id = ports[0].id
    ports[0].id = "saved-non-uuid-port"
    cfg.ports[ports[0].id] = cfg.ports.pop(prior_id)
    cfg.ports = dict(reversed(list(cfg.ports.items())))
    cfg = type(cfg).model_validate(cfg.model_dump())
    e = Engine(cfg)
    m = Projection(e.state, ["1.3.6.1.2.1"])
    entry = ENTITY + (1, 1, 1, 1)
    for index in (1, 2):
        assert m.get(entry + (18, index))[1].asOctets() == b""
        assert m.get(entry + (19, index))[1].asOctets() == b""
    for p in ports:
        index = p.bridge_port + 1
        pointer = tuple(m.get(ENTITY + (1, 3, 2, 1, 2, index, 0))[1])
        assert pointer == oid("1.3.6.1.2.1.2.2.1.1") + (p.if_index,)
        assert int(m.get(pointer)[1]) == p.if_index
        assert int(m.get(oid("1.3.6.1.2.1.17.1.4.1.2") + (p.bridge_port,))[1]) == p.if_index
        assert int(m.get(ENTITY + (1, 3, 3, 1, 1, 1, index))[1]) == index
    assert m.get(ENTITY + (1, 3, 2, 1, 2, 1, 0))[1].tagSet == rfc1905.noSuchInstance.tagSet
    assert m.get(ENTITY + (1, 3, 3, 1, 1, 0, 1))[1].tagSet == rfc1905.noSuchInstance.tagSet
    assert [r[0] for r in entity_inventory(cfg)] == [1, 2, 10, 301, 65536]


def test_entity_filtered_walk_and_alias_pointer_access(engine):
    e = engine
    before = copy.deepcopy(e.state)
    m = Projection(e.state, ["1.3.6.1.2.1.47"])
    walked, cursor = [], ENTITY
    for _ in range(100):
        name, value = m.next(cursor)
        if value.tagSet == rfc1905.endOfMibView.tagSet:
            break
        assert name > cursor
        walked.append(name)
        cursor = name
    assert len(walked) == 99
    assert walked == sorted(m.values)
    assert walked[89] == ENTITY + (1, 1, 1, 1, 19, 5)
    assert walked[90] == ENTITY + (1, 3, 2, 1, 2, 2, 0)
    assert walked[94] == ENTITY + (1, 3, 3, 1, 1, 1, 2)
    assert walked[-1] == ENTITY + (1, 4, 1, 0)
    alias = ENTITY + (1, 3, 2, 1, 2, 2, 0)
    pointer = tuple(m.get(alias)[1])
    assert m.get(pointer)[1].tagSet == rfc1905.noSuchObject.tagSet
    one = Projection(e.state, [".".join(map(str, alias))])
    assert one.next(ENTITY)[0] == alias
    assert one.next(alias)[1].tagSet == rfc1905.endOfMibView.tagSet
    assert one.get(ENTITY + (1, 1, 1, 1, 7, 2))[1].tagSet == rfc1905.noSuchObject.tagSet
    assert Projection(e.state, e.state.cfg.views["interfaces"].includes).get(alias)[1].tagSet == rfc1905.noSuchObject.tagSet
    assert Projection(e.state, e.state.cfg.views["all"].includes).get(alias)[1].tagSet == rfc1902.ObjectIdentifier.tagSet
    assert e.state == before


async def test_entity_change_clock_reboot_wrap_and_snapshot(engine, monkeypatch):
    e = engine
    now = [1000.0]
    monkeypatch.setattr(time, "monotonic", lambda: now[0])
    e.state.boot_start = now[0]
    pid = next(iter(e.state.cfg.ports))
    assert e.state.cfg.switch.identity.sys_object_id is None and not e.state.cfg.snmp.enabled
    old = Projection(e.state, ["1.3.6.1.2.1.47"])
    now[0] += 2
    await e.execute("port-edit", {"id": pid, "patch": {"name": "Physical port"}})
    assert e.state.entity_last_change == 200
    current = Projection(e.state, ["1.3.6.1.2.1.47"])
    name_oid = ENTITY + (1, 1, 1, 1, 7, 2)
    assert str(old.get(name_oid)[1]) == "Ethernet1"
    assert int(old.get(ENTITY + (1, 4, 1, 0))[1]) == 0
    assert str(current.get(name_oid)[1]) == "Physical port"
    assert int(current.get(ENTITY + (1, 4, 1, 0))[1]) == 200
    # Multiple actual changes in the same centisecond need no fabricated tick.
    await e.execute("switch-edit", {"description": "Physical chassis"})
    assert e.state.entity_last_change == 200
    now[0] += 1
    await e.execute("switch-edit", {"description": "Physical chassis"})
    await e.execute("port-edit", {"id": pid, "patch": {"alias": "a" * 64, "admin_up": False}})
    await e.execute("switch-edit", {"identity": {"sys_descr": "System, not physical"}, "contact": "Lab", "location": "Room"})
    eid = await endpoint(e, active=False)
    await e.execute("detach", {"id": eid})
    await e.execute("vlan-create", {"vid": 10})
    await e.execute("port-edit", {"id": pid, "patch": {"pvid": 10, "admitted": [1, 10]}})
    await tick(e)
    assert e.state.entity_last_change == 200
    assert Projection(e.state, ["1.3.6.1.2.1.47"]).get(ENTITY + (1, 1, 1, 1, 14, 2))[1].asOctets() == b""
    scenario = e.export()
    await e.execute("import", scenario)
    assert e.state.entity_last_change == 200
    scenario["ports"][pid]["name"] = "Imported physical port"
    await e.execute("import", scenario)
    assert e.state.entity_last_change == 300
    inventory = entity_inventory(e.state.cfg)
    now[0] = e.state.boot_start + (2**32 + 500) / 100
    await tick(e)
    assert e.state.uptime_epoch == 1 and e.state.entity_last_change == 300
    assert int(Projection(e.state, ["1.3.6.1.2.1.47"]).get(ENTITY + (1, 4, 1, 0))[1]) == 300
    await e.execute("reboot")
    assert e.state.entity_last_change == 0
    assert entity_inventory(e.state.cfg) == inventory
    reloaded = Engine(e.store.load(), e.store)
    assert reloaded.state.entity_last_change == 0
    assert entity_inventory(reloaded.state.cfg) == inventory


async def test_entity_rejected_and_rolled_back_changes(engine, monkeypatch):
    e = engine
    e.state.boot_start -= 2
    await e.execute("switch-edit", {"name": "Committed physical name"})
    state = e.state
    rows = entity_inventory(state.cfg)
    db_before = e.store.db.execute("SELECT * FROM kv ORDER BY key").fetchall()
    events_before = e.store.events()
    event_id = e.store.last_event
    pid = next(iter(state.cfg.ports))
    with pytest.raises(ValueError):
        await e.execute("port-edit", {"id": pid, "patch": {"name": "Invalid candidate", "admitted": []}})
    scenario = e.export()
    scenario["ports"][pid]["bridge_port"] += 10
    with pytest.raises(CommandError):
        await e.execute("import", scenario)
    original_put = e.store.put
    def failing_put(key, value):
        original_put(key, value)
        if key == "outbox":
            raise sqlite3.OperationalError("Injected transaction rollback")
    monkeypatch.setattr(e.store, "put", failing_put)
    with pytest.raises(sqlite3.OperationalError):
        await e.execute("switch-edit", {"name": "Uncommitted physical name"}, key="failed-physical-change")
    assert e.state is state
    assert entity_inventory(e.state.cfg) == rows
    assert e.store.db.execute("SELECT * FROM kv ORDER BY key").fetchall() == db_before
    assert e.store.events() == events_before and e.store.last_event == event_id
    assert "failed-physical-change" not in e.idempotency


@pytest.mark.parametrize("text", ["café", "交换机"])
def test_entity_utf8_and_hidden_inventory(engine, text):
    cfg = engine.state.cfg
    cfg.switch.name = text
    cfg.switch.description = text
    p = next(iter(cfg.ports.values()))
    p.name = text
    expected = text.encode("utf-8")
    m = Projection(engine.state, cfg.views["all"].includes)
    for name in ("1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.2.2.1.2.101", "1.3.6.1.2.1.31.1.1.1.1.101",
                 "1.3.6.1.2.1.47.1.1.1.1.2.1", "1.3.6.1.2.1.47.1.1.1.1.7.1", "1.3.6.1.2.1.47.1.1.1.1.7.2"):
        assert m.get(name)[1].asOctets() == expected
    hidden = Projection(engine.state, cfg.views["interfaces"].includes)
    assert hidden.get("1.3.6.1.2.1.1.5.0")[1].asOctets() == expected
    assert hidden.get("1.3.6.1.2.1.47.1.1.1.1.2.1")[1].tagSet == rfc1905.noSuchObject.tagSet
    assert m.get("1.3.6.1.2.1.47.1.1.1.1.19.1")[1].asOctets() == uuid.UUID(cfg.switch.id).bytes
    assert m.get("1.3.6.1.2.1.17.1.1.0")[1].asOctets() == bytes.fromhex(cfg.switch.base_mac.replace(":", ""))


# SET planning is exercised without an SNMP engine, listener, or response cache.
from itertools import permutations
from pysnmp.proto import rfc1902 as a
from switchlab.mib import plan_set, SetError, WRITE_OBJECTS
from switchlab.models import Configuration, Vlan, initial_configuration

SET_BASE = {kind: base for base, (kind, tag) in WRITE_OBJECTS.items()}
ALL_OBJECTS = ["1.3.6.1.2.1"]


def binding(kind, key, value):
    return SET_BASE[kind] + (key,), value


@pytest.mark.parametrize("kind,key,value,status", [
    ("admin", 101, a.OctetString(b"2"), "wrongType"),
    ("admin", 101, a.Integer32(3), "wrongValue"),
    ("admin", 101, a.Integer32(0), "wrongValue"),
    ("admin", 1, a.Integer32(1), "noCreation"),
    ("pvid", 1, a.Integer32(1), "wrongType"),
    ("pvid", 1, a.Counter32(1), "wrongType"),
    ("pvid", 1, a.Gauge32(0), "wrongValue"),
    ("pvid", 1, a.Gauge32(4095), "wrongValue"),
    ("pvid", 1, a.Gauge32(4096), "wrongValue"),
    ("pvid", 101, a.Gauge32(1), "noCreation"),
    ("name", 1, a.Integer32(1), "wrongType"),
    ("name", 1, a.OctetString(b"x" * 33), "wrongLength"),
    ("name", 1, a.OctetString(b"\xff"), "wrongValue"),
    ("name", 0, a.OctetString(b""), "noCreation"),
    ("name", 4095, a.OctetString(b""), "noCreation"),
    ("name", 10, a.OctetString(b""), "inconsistentName"),
    ("egress", 1, a.Integer32(1), "wrongType"),
    ("egress", 1, a.OctetString(b"\x08"), "wrongValue"),
    ("untagged", 1, a.Counter32(1), "wrongType"),
    ("forbidden", 1, a.OctetString(b"\x00\x80"), "wrongValue"),
    ("row", 1, a.Gauge32(1), "wrongType"),
])
@pytest.mark.parametrize("position", [1, 2, 3])
def test_set_typed_errors_keep_original_position(kind, key, value, status, position):
    cfg = initial_configuration(4)
    before = cfg.model_dump()
    bindings = [binding("admin", 102 + n, a.Integer32(1)) for n in range(3)]
    bindings[position - 1] = binding(kind, key, value)
    with pytest.raises(SetError) as failure:
        plan_set(cfg, bindings, ALL_OBJECTS)
    assert (failure.value.status, failure.value.index) == (status, position)
    assert cfg.model_dump() == before


@pytest.mark.parametrize("present", [False, True])
@pytest.mark.parametrize("value", [-1, 0, 1, 2, 3, 4, 5, 6, 7])
def test_set_active_only_row_status_matrix(present, value):
    cfg = initial_configuration(4)
    if present:
        cfg.vlans[10] = Vlan(vid=10, fdb_id=1010)
    expected = ("inconsistentValue" if (present and value in (4, 5)) or
                (not present and value in (1, 2)) else
                "wrongValue" if value not in (1, 4, 6) else None)
    request = [binding("row", 10, a.Integer32(value))]
    if expected:
        with pytest.raises(SetError) as failure:
            plan_set(cfg, request, ALL_OBJECTS)
        assert (failure.value.status, failure.value.index) == (expected, 1)
    else:
        plan = plan_set(cfg, request, ALL_OBJECTS)
        assert (10 in plan.candidate.vlans) == (value != 6)
        assert plan.changed == (value == 4 or (value == 6 and present))
        assert plan.first_effective == (1 if plan.changed else 0)


def test_set_simultaneous_creation_every_order_and_independent_untagged():
    cfg = initial_configuration(4)
    commands = [binding("row", 10, a.Integer32(4)), binding("egress", 10, a.OctetString(b"\x80")),
                binding("pvid", 1, a.Gauge32(10)), binding("name", 10, a.OctetString("研发".encode()))]
    plans = [plan_set(cfg, order, ALL_OBJECTS) for order in permutations(commands)]
    assert all(p.candidate == plans[0].candidate for p in plans)
    p = next(iter(plans[0].candidate.ports.values()))
    assert p.pvid == 10 and p.untagged == [1] and p.admitted == [1, 10] and not p.forbidden
    assert plans[0].candidate.vlans[10].name == "研发"
    assert 10 not in cfg.vlans


def test_set_view_precedes_type_writability_and_instance_errors():
    cfg = initial_configuration(4)
    readonly = (oid("1.3.6.1.2.1.2.2.1.8.101"), a.Integer32(2))
    for item in (readonly, binding("admin", 999, a.OctetString(b"x"))):
        with pytest.raises(SetError) as failure:
            plan_set(cfg, [item], ["1.3.6.1.2.1.47"])
        assert (failure.value.status, failure.value.index) == ("noAccess", 1)
    with pytest.raises(SetError) as failure:
        plan_set(cfg, [readonly], ALL_OBJECTS)
    assert failure.value.status == "notWritable"
    # Exact instance syntax is checked after its ASN.1 value.
    malformed = SET_BASE["admin"] + (101, 9)
    for value, status in [(a.OctetString(b"x"), "wrongType"), (a.Integer32(1), "noCreation")]:
        with pytest.raises(SetError) as failure:
            plan_set(cfg, [(malformed, value)], ALL_OBJECTS)
        assert failure.value.status == status


def test_set_bitmap_padding_sparse_inventory_and_duplicates():
    cfg = initial_configuration(4)
    for p, bridge in zip(cfg.ports.values(), (1, 3, 9, 17)):
        p.bridge_port = bridge
    cfg.vlans[10] = Vlan(vid=10, fdb_id=1010)
    selected = {p.id for p in cfg.ports.values() if p.bridge_port in (1, 9)}
    for raw in (b"\x80\x80", b"\x80\x80\x00", b"\x80\x80\x00\x00"):
        request = [binding("egress", 10, a.OctetString(raw))] * 2
        plan = plan_set(cfg, request, ALL_OBJECTS)
        assert {p.id for p in plan.candidate.ports.values() if 10 in p.admitted} == selected
        assert plan.first_effective == 1
    for raw in (b"\x40", b"\x00\x00\x40"):
        with pytest.raises(SetError) as failure:
            plan_set(cfg, [binding("egress", 10, a.OctetString(raw))], ALL_OBJECTS)
        assert failure.value.status == "wrongValue"
    with pytest.raises(SetError) as failure:
        plan_set(cfg, [binding("admin", 101, a.Integer32(2)), binding("admin", 101, a.Integer32(1))], ALL_OBJECTS)
    assert (failure.value.status, failure.value.index) == ("inconsistentValue", 2)


@pytest.mark.parametrize("first", ["pvid", "row"])
def test_set_conflict_index_names_actual_relation_participant(first):
    cfg = initial_configuration(4)
    cfg.vlans[10] = Vlan(vid=10, fdb_id=1010)
    next(iter(cfg.ports.values())).admitted = [1, 10]
    good = binding("pvid", 1, a.Gauge32(10)) if first == "pvid" else binding("row", 1, a.Integer32(1))
    with pytest.raises(SetError) as failure:
        plan_set(cfg, [good, binding("forbidden", 1, a.OctetString(b"\x80"))], ALL_OBJECTS)
    assert (failure.value.status, failure.value.index) == ("inconsistentValue", 2)


def test_set_delete_fallback_respects_explicit_final_bitmaps_and_pvid():
    cfg = initial_configuration(4)
    for vid in (10, 20):
        cfg.vlans[vid] = Vlan(vid=vid, fdb_id=1000 + vid)
    p = next(iter(cfg.ports.values()))
    p.pvid, p.admitted, p.untagged, p.forbidden = 10, [10, 20], [10, 20], [1]
    destroy = binding("row", 10, a.Integer32(6))
    with pytest.raises(SetError) as failure:
        plan_set(cfg, [destroy], ALL_OBJECTS)
    assert (failure.value.status, failure.value.index) == ("inconsistentValue", 1)
    for order in permutations([destroy, binding("pvid", 1, a.Gauge32(20))]):
        candidate = plan_set(cfg, order, ALL_OBJECTS).candidate.ports[p.id]
        assert (candidate.pvid, candidate.admitted, candidate.untagged, candidate.forbidden) == (20, [20], [20], [1])
    p.forbidden = []
    candidate = plan_set(cfg, [destroy], ALL_OBJECTS).candidate.ports[p.id]
    assert candidate.pvid == 1 and set(candidate.untagged) == {1, 20}
    # Explicit untagged bitmap wins over the implicit native fallback.
    request = [destroy, binding("untagged", 1, a.OctetString(b"\x70"))]
    assert plan_set(cfg, request, ALL_OBJECTS).candidate.ports[p.id].untagged == [20]
    # Explicit removal of the fallback membership is rejected, not repaired.
    with pytest.raises(SetError) as failure:
        plan_set(cfg, [destroy, binding("egress", 1, a.OctetString(b"\x70"))], ALL_OBJECTS)
    assert failure.value.status == "inconsistentValue"
    with pytest.raises(SetError) as failure:
        plan_set(cfg, [binding("row", 1, a.Integer32(6))], ALL_OBJECTS)
    assert failure.value.status == "inconsistentValue"


def test_set_noop_retains_configuration_order_and_empty_values():
    cfg = initial_configuration(4)
    cfg.vlans[10] = Vlan(vid=10, fdb_id=1010)
    for p in cfg.ports.values():
        p.admitted = [10, 1]
    for request in ([], [binding("row", 20, a.Integer32(6))],
                    [binding("egress", 1, a.OctetString(b"\xf0\x00"))]):
        plan = plan_set(cfg, request, ALL_OBJECTS)
        assert not plan.changed and plan.first_effective == 0 and plan.candidate == cfg
    request = [binding("untagged", 1, a.OctetString(b"")), binding("name", 1, a.OctetString(b""))]
    candidate = plan_set(cfg, request, ALL_OBJECTS).candidate
    assert all(not p.untagged for p in candidate.ports.values()) and candidate.vlans[1].name == ""


@pytest.mark.parametrize("present,order,status,index", [
    (True, ("active", "name", "destroy"), "inconsistentValue", 3),
    (True, ("name", "active", "destroy"), "inconsistentValue", 3),
    (False, ("destroy", "name", "create"), "inconsistentName", 2),
    (False, ("name", "destroy", "create"), "inconsistentName", 1),
])
def test_set_first_row_intent_preserves_duplicate_error_position(present, order, status, index):
    cfg = initial_configuration(4)
    if present:
        cfg.vlans[10] = Vlan(vid=10, fdb_id=1010)
    commands = {"active": binding("row", 10, a.Integer32(1)),
                "destroy": binding("row", 10, a.Integer32(6)),
                "create": binding("row", 10, a.Integer32(4)),
                "name": binding("name", 10, a.OctetString(b"Changed"))}
    before = cfg.model_dump()
    with pytest.raises(SetError) as failure:
        plan_set(cfg, [commands[item] for item in order], ALL_OBJECTS)
    assert (failure.value.status, failure.value.index) == (status, index)
    assert cfg.model_dump() == before


def test_set_multiple_vlan_assignments_permute_as_sets_without_reordering_noops():
    cfg = initial_configuration(4)
    commands = [binding("row", 10, a.Integer32(4)), binding("row", 20, a.Integer32(4)),
                binding("egress", 10, a.OctetString(b"\x80")), binding("egress", 20, a.OctetString(b"\xc0"))]
    for order in permutations(commands):
        plan = plan_set(cfg, order, ALL_OBJECTS)
        ports = list(plan.candidate.ports.values())
        assert set(ports[0].admitted) == {1, 10, 20} and set(ports[1].admitted) == {1, 20}
        assert all(p.untagged == [1] and not p.forbidden for p in ports)
        # A repeated bitmap assignment preserves the already saved list order.
        before = plan.candidate.model_dump()
        repeat = plan_set(plan.candidate, [binding("egress", 20, a.OctetString(b"\xc0")),
                                          binding("egress", 10, a.OctetString(b"\x80"))], ALL_OBJECTS)
        assert not repeat.changed and repeat.candidate.model_dump() == before
