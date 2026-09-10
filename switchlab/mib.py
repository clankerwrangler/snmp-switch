"""Numeric, typed MIB projections. No simulation state is mutated by polling."""
from bisect import bisect_right
from dataclasses import dataclass
import time
import uuid

from pysnmp.proto import rfc1902 as a, rfc1905 as exceptions

from .models import Configuration, Vlan


def oid(value):
    return tuple(int(x) for x in value.split(".")) if isinstance(value, str) else tuple(value)


CURRENT = oid("1.3.6.1.2.1.17.7.1.4.2.1")


ENTITY = oid("1.3.6.1.2.1.47")
PAE = oid("1.0.8802.1.1.1.1")


def octets(value):
    return a.OctetString(value.encode("utf-8") if isinstance(value, str) else value)


def entity_inventory(cfg):
    """Return the fixed emulated inventory used by projection and change detection."""
    records = [(1, cfg.switch, cfg.switch.description, 0, 3, -1, None)]
    records.extend((p.bridge_port + 1, p, "Emulated Ethernet port", 1, 10, p.bridge_port, p.if_index)
                   for p in sorted(cfg.ports.values(), key=lambda p: p.bridge_port))
    rows = []
    for index, record, description, parent, kind, position, if_index in records:
        try:
            identity = uuid.UUID(record.id)
            identifier, uri = identity.bytes, identity.urn
        except ValueError:
            identifier, uri = b"", ""
        columns = {2: description, 3: (0, 0), 4: parent, 5: kind, 6: position, 7: record.name,
                   **{column: "" for column in range(8, 16)}, 16: 2, 17: bytes(8), 18: uri, 19: identifier}
        rows.append((index, columns, if_index))
    return tuple(rows)


def port_list(state, predicate):
    data = bytearray((max(p.bridge_port for p in state.cfg.ports.values()) + 7) // 8)
    for p in state.cfg.ports.values():
        if predicate(p):
            data[(p.bridge_port-1)//8] |= 0x80 >> ((p.bridge_port-1) % 8)
    return bytes(data)


def current_vlan_ports(state, vid):
    return {p.id for p in state.cfg.ports.values() if vid in p.admitted} | {
        session.port_id for session in state.radius_sessions.values() if state.session_vid(session) == vid}


class Projection:
    def __init__(self, state, includes):
        self.state = state  # Published states are never subsequently changed by the engine.
        self.includes = tuple(oid(p) for p in includes)
        self._values = {}
        self.materialized = {}
        self.bases = set()
        self.filtered = {}
        self._filtered_keys = {}
        self._tables = {}
        self._table_keys = {}
        elapsed = int((time.monotonic() - state.boot_start) * 100)
        self.ticks = elapsed % 2**32
        self.wrapped = elapsed // 2**32 != state.uptime_epoch
        self.build()
        self._scalar_keys = sorted(self._values)
        self._families = sorted((*self._tables, CURRENT))

    @property
    def values(self):
        # Full ordinary enumeration is an inspection path, not a read-PDU cost.
        for prefix in self._tables:
            self.load_table(prefix)
        return self._values

    @property
    def keys(self):
        return sorted(self.values)

    def allowed(self, name):
        return any(name[:len(p)] == p for p in self.includes)

    def overlaps(self, prefix):
        return any(prefix[:len(p)] == p or p[:len(prefix)] == prefix for p in self.includes)

    def put(self, base, suffix, value):
        base = oid(base)
        self.bases.add(base)
        full = base + tuple(suffix)
        if self.allowed(full):
            self._values[full] = value

    def table(self, prefix, columns, rows):
        prefix = oid(prefix)
        bases = {col: prefix + (col,) for col in columns}
        self.bases.update(bases.values())
        self._tables[prefix] = (bases, rows)

    def load_table(self, prefix):
        if prefix not in self._table_keys:
            bases, rows = self._tables[prefix]
            keys = []
            if self.overlaps(prefix):
                for index, values in rows():
                    for column, value in values.items():
                        name = bases[column] + tuple(index)
                        if self.allowed(name):
                            self._values[name] = value
                            keys.append(name)
            self._table_keys[prefix] = sorted(keys)
        return self._table_keys[prefix]

    def materialize(self, name):
        if name not in self.materialized:
            syntax, value = self._values[name]
            self.materialized[name] = syntax(value)
        return self.materialized[name]

    def build(self):
        # Builders use only this immutable published Runtime and this PDU's time.
        s = self.state
        I = lambda value, syntax=a.Integer32: (syntax, value)
        O = lambda value, syntax=octets: (syntax, value)
        C = lambda value, syntax=a.Counter32: (syntax, value)
        G = lambda value, syntax=a.Gauge32: (syntax, value)
        T = lambda value, syntax=a.TimeTicks: (syntax, value)
        H = lambda value, syntax=a.Counter64: (syntax, value)
        D = lambda value, syntax=a.ObjectIdentifier: (syntax, value)
        sw = s.cfg.switch
        system = [O(sw.identity.sys_descr), D(sw.identity.sys_object_id) if sw.identity.sys_object_id else None,
                  T(self.ticks), O(sw.contact), O(sw.name), O(sw.location), I(2)]
        for n, value in enumerate(system, 1):
            if value is not None:
                self.put(f"1.3.6.1.2.1.1.{n}", (0,), value)
        self.put("1.3.6.1.2.1.2.1", (0,), I(len(s.cfg.ports)))

        def interfaces():
            rows = []
            for pid, p in s.cfg.ports.items():
                c, up = s.counters[pid], s.up(pid)
                physical = ((int(sw.base_mac.replace(":", ""), 16) + p.bridge_port) % 2**48).to_bytes(6, "big")
                physical = bytes([(physical[0] | 2) & 254]) + physical[1:]
                rows.append(((p.if_index,), {1: I(p.if_index), 2: O(p.name), 3: I(6), 4: I(p.mtu),
                    5: G(min(p.speed, 2**32-1) if up else 0), 6: O(physical), 7: I(1 if p.admin_up else 2), 8: I(1 if up else 2),
                    9: T(c["last_change"]), 10: C(c["in_octets"] % 2**32), 11: C(c["in_ucast"] % 2**32),
                    13: C(c["in_discards"] % 2**32), **{i: C(0) for i in (14, 16, 17, 19, 20)}}))
            return rows
        self.table("1.3.6.1.2.1.2.2.1", [1,2,3,4,5,6,7,8,9,10,11,13,14,16,17,19,20], interfaces)

        def extended():
            return [((p.if_index,), {1: O(p.name), 6: H(s.counters[pid]["in_octets"] % 2**64),
                7: H(s.counters[pid]["in_ucast"] % 2**64), 10: H(0), 11: H(0),
                14: I(1 if p.link_notifications else 2), 15: G(p.speed//1000000 if s.up(pid) else 0),
                17: I(1), 18: O(p.alias), 19: T(s.counters[pid]["discontinuity"])}) for pid,p in s.cfg.ports.items()]
        self.table("1.3.6.1.2.1.31.1.1.1", [1,6,7,10,11,14,15,17,18,19], extended)

        self.table("1.3.6.1.2.1.17.1.4.1", [1,2], lambda: [
            ((p.bridge_port,), {1:I(p.bridge_port), 2:I(p.if_index)}) for p in s.cfg.ports.values()])
        self.table("1.3.6.1.2.1.17.7.1.4.5.1", [1,2,3,4], lambda: [
            ((p.bridge_port,), {1:G(p.pvid), 2:I(1), 3:I(1), 4:I(2)}) for p in s.cfg.ports.values()])
        for base, val in {
            "17.1.1": O(bytes.fromhex(sw.base_mac.replace(":", ""))), "17.1.2": I(len(s.cfg.ports)), "17.1.3": I(2),
            "17.4.1": C(s.learned_discards % 2**32), "17.4.2": I(sw.aging_seconds),
            "17.7.1.1.1": I(1), "17.7.1.1.2": I(4094), "17.7.1.1.3": G(4094),
            "17.7.1.1.4": G(len(s.cfg.vlans)), "17.7.1.1.5": I(2), "17.7.1.4.1": C(s.vlan_deletes % 2**32),
        }.items():
            self.put("1.3.6.1.2.1."+base, (0,), val)

        def legacy_fdb():
            rows = []
            for (_, address), r in s.fdb.items():
                if r["vid"] == sw.legacy_vlan:
                    index = tuple(bytes.fromhex(address.replace(":", "")))
                    rows.append((index, {1:O(bytes(index)), 2:I(r["bridge_port"]), 3:I(3)}))
            return rows
        self.table("1.3.6.1.2.1.17.4.3.1", [1,2,3], legacy_fdb)
        self.table("1.3.6.1.2.1.17.7.1.2.2.1", [2,3], lambda: [
            ((fid,)+tuple(bytes.fromhex(address.replace(":", ""))), {2:I(r["bridge_port"]), 3:I(3)})
            for (fid,address),r in s.fdb.items()])
        self.table("1.3.6.1.2.1.17.7.1.2.1.1", [2], lambda: [
            ((v.fdb_id,), {2:C(sum(1 for r in s.fdb.values() if r["fdb_id"] == v.fdb_id))}) for v in s.cfg.vlans.values()])

        def static_vlans():
            return [((vid,), {1:O(v.name), 2:O(port_list(s, lambda p: vid in p.admitted)),
                3:O(port_list(s, lambda p: vid in p.forbidden)), 4:O(port_list(s, lambda p: vid in p.untagged)), 5:I(1)})
                for vid,v in s.cfg.vlans.items()]
        self.table("1.3.6.1.2.1.17.7.1.4.3.1", [1,2,3,4,5], static_vlans)
        self.bases.update(CURRENT+(i,) for i in range(3,8))

        def physical_inventory():
            return [((index,), {column: (D if column == 3 else I if column in (4,5,6,16) else O)(value)
                for column,value in columns.items()}) for index,columns,_ in entity_inventory(s.cfg)]
        self.table(ENTITY+(1,1,1,1), range(2,20), physical_inventory)
        self.table(ENTITY+(1,3,2,1), (2,), lambda: [
            ((index,0), {2:D(oid("1.3.6.1.2.1.2.2.1.1")+(if_index,))})
            for index,_,if_index in entity_inventory(s.cfg) if if_index is not None])
        self.table(ENTITY+(1,3,3,1), (1,), lambda: [
            ((1,index), {1:I(index)}) for index,_,if_index in entity_inventory(s.cfg) if if_index is not None])
        self.put(ENTITY+(1,4,1), (0,), T(s.entity_last_change))
        self.put(PAE+(1,1), (0,), I(1))
        pae_cache = None
        def pae_rows():
            nonlocal pae_cache
            if pae_cache is not None:
                return pae_cache
            pae_ports, configuration, statistics, diagnostics, sessions = [], [], [], [], []
            for pid, port in s.cfg.ports.items():
                index = (port.if_index,)
                facts = s.pae.get(pid)
                port_values = {3: O(b"\x80"), 4: I(2), 5: I(2)}
                if facts and facts["version"] is not None:port_values[2] = G(facts["version"])
                pae_ports.append((index, port_values))
                control = port.authentication.control
                multiple = control == "auto" and port.authentication.host_mode == "multi-auth"
                cfg_values = {3:I(1),4:I(1),6:I({"force-unauthorized":1,"auto":2,"force-authorized":3}[control]),14:I(2)}
                active = next((session for session in s.radius_sessions.values() if session.port_id==pid),None)
                if not multiple:
                    if control != "auto":
                        cfg_values.update({1:I(8 if control=="force-authorized" else 9),2:I(6),5:I(1 if control=="force-authorized" else 2)})
                    else:
                        cfg_values[5] = I(1 if active else 2)
                        if not s.up(pid):cfg_values.update({1:I(2),2:I(6)})
                        elif facts:
                            if facts["state"] is not None:cfg_values[1]=I(facts["state"])
                            if facts["backend"] is not None:cfg_values[2]=I(facts["backend"])
                        elif port.authentication.method=="mab":cfg_values.update({1:I(2),2:I(6)})
                    if active and active.policy.session_timeout is not None:
                        enabled = active.policy.termination_action == 1
                        period = active.policy.session_timeout if enabled else 0
                    else:
                        period = s.cfg.radius.reauthentication_seconds
                        enabled = period > 0
                    cfg_values.update({12:G(period),13:I(1 if enabled else 2)})
                    last = s.last_auth_sessions.get(pid)
                    if active:
                        last = dict(id=active.id,in_octets=active.in_octets,in_packets=active.in_packets,
                            started_ms=active.started_ms,ended_ms=s.sim_ms,cause=999)
                    if last:
                        row={1:H(last["in_octets"] % 2**64),3:C(last["in_packets"] % 2**32),5:O(last["id"]),6:I(1),
                             7:T(((last["ended_ms"]-last["started_ms"])//10) % 2**32)}
                        if last["cause"] is not None:row[8]=I(last["cause"])
                        sessions.append((index,row))
                configuration.append((index,cfg_values))
                if facts is None or facts["precise"]:
                    counters = facts["counters"] if facts else [0]*8
                    stat = {col:C(value % 2**32) for col,value in enumerate(counters,1)}
                    diag = facts["diagnostics"] if facts else [0]*4
                    diagnostics.append((index,{col:C(value % 2**32) for col,value in enumerate(diag,3)}))
                else:stat={}
                if facts and facts["precise"] and facts["last_version"] is not None:
                    stat.update({11:G(facts["last_version"]),12:O(facts["last_source"])})
                statistics.append((index,stat))
            pae_cache = (pae_ports, configuration, statistics, diagnostics, sessions)
            return pae_cache
        self.table(PAE+(1,2,1), (2,3,4,5), lambda: pae_rows()[0])
        self.table(PAE+(2,1,1), (1,2,3,4,5,6,12,13,14), lambda: pae_rows()[1])
        self.table(PAE+(2,2,1), (1,2,3,4,5,6,7,8,11,12), lambda: pae_rows()[2])
        self.table(PAE+(2,3,1), (3,4,5,6), lambda: pae_rows()[3])
        self.table(PAE+(2,4,1), (1,3,5,6,7,8), lambda: pae_rows()[4])

    def current(self, cutoff):
        if cutoff in self.filtered:
            return self.filtered[cutoff]
        values = {}
        if not self.overlaps(CURRENT):
            self.filtered[cutoff] = values
            self._filtered_keys[cutoff] = []
            return values
        s = self.state
        for vid, v in s.cfg.vlans.items():
            # Wrap resets conceptual row timestamps independently of USM time.
            created, changed = [0,0] if self.wrapped else s.vlan_times[vid]
            if cutoff and (cutoff > self.ticks or changed < cutoff):
                continue
            members = current_vlan_ports(s, vid)
            columns = {3: a.Gauge32(v.fdb_id), 4: a.OctetString(port_list(s, lambda p: p.id in members)),
                       5: a.OctetString(port_list(s, lambda p: vid in p.untagged)), 6: a.Integer32(2), 7: a.TimeTicks(created)}
            for col, value in columns.items():
                name = CURRENT + (col, cutoff, vid)
                if self.allowed(name):
                    values[name] = value
        self.filtered[cutoff] = values
        self._filtered_keys[cutoff] = sorted(values)
        return values

    def cutoff(self, name):
        return name[len(CURRENT)+1] if name[:len(CURRENT)] == CURRENT and len(name) >= len(CURRENT)+2 else 0

    def get(self, name):
        name = oid(name)
        if not self.allowed(name):
            return name, exceptions.noSuchObject
        known = any(name[:len(base)] == base for base in self.bases)
        if not known:
            return name, exceptions.noSuchObject
        if name[:len(CURRENT)] == CURRENT:
            value = self.current(self.cutoff(name)).get(name)
        else:
            for prefix in self._tables:
                if name[:len(prefix)] == prefix:
                    self.load_table(prefix)
                    break
            value = self.materialize(name) if name in self._values else None
        return name, value if value is not None else exceptions.noSuchInstance

    def next(self, name):
        name = oid(name)
        index = bisect_right(self._scalar_keys, name)
        scalar = self._scalar_keys[index] if index < len(self._scalar_keys) else None
        for prefix in self._families:
            # Registered table intervals are disjoint. An unknown/hidden/empty
            # family cannot terminate a walk; continue to the global successor.
            if name >= prefix[:-1] + (prefix[-1]+1,) or not self.overlaps(prefix):
                continue
            if scalar is not None and scalar < prefix:
                return scalar, self.materialize(scalar)
            if prefix == CURRENT:
                cutoff = self.cutoff(name)
                values = self.current(cutoff)
                keys = self._filtered_keys[cutoff]
            else:
                keys = self.load_table(prefix)
            index = bisect_right(keys, name)
            if index < len(keys):
                candidate = keys[index]
                if scalar is not None and scalar < candidate:
                    return scalar, self.materialize(scalar)
                return candidate, values[candidate] if prefix == CURRENT else self.materialize(candidate)
        if scalar is not None:
            return scalar, self.materialize(scalar)
        return name, exceptions.endOfMibView


# Maximum access and this product's write subset are separate metadata. The
# descriptor keys are the exact column prefixes; indexes retain their MIB owner.
WRITE_OBJECTS = {
    oid("1.3.6.1.2.1.2.2.1.7"): ("admin", a.Integer32.tagSet),
    PAE+(1,2,1,4): ("pae-initialize", a.Integer32.tagSet),
    PAE+(1,2,1,5): ("pae-reauthenticate", a.Integer32.tagSet),
    PAE+(2,1,1,6): ("pae-control", a.Integer32.tagSet),
    oid("1.3.6.1.2.1.17.7.1.4.5.1.1"): ("pvid", a.Gauge32.tagSet),
    **{oid("1.3.6.1.2.1.17.7.1.4.3.1") + (column,): (kind, syntax.tagSet)
       for column, kind, syntax in ((1, "name", a.OctetString), (2, "egress", a.OctetString),
           (3, "forbidden", a.OctetString), (4, "untagged", a.OctetString), (5, "row", a.Integer32))},
}
BITMAP_FIELDS = {"egress": "admitted", "untagged": "untagged", "forbidden": "forbidden"}


class SetError(Exception):
    def __init__(self, status, index):
        self.status, self.index = status, index
        super().__init__(f"{status} at binding {index}")


@dataclass(frozen=True)
class Assignment:
    index: int
    kind: str
    key: int | str
    value: object


@dataclass(frozen=True)
class SetPlan:
    before: object
    candidate: object
    assignments: tuple
    creates: frozenset
    deletes: frozenset
    affected_ports: frozenset
    first_effective: int
    pae_actions: tuple = ()

    @property
    def changed(self):
        return self.candidate != self.before or bool(self.pae_actions)


def _write_object(name):
    return next(((base, kind, tag) for base, (kind, tag) in WRITE_OBJECTS.items()
                 if name[:len(base)] == base), None)


def _row_error(exists, vid, value):
    if value not in (1, 2, 4, 5, 6):
        return "wrongValue"
    if (exists and value in (4, 5)) or (not exists and value in (1, 2)):
        return "inconsistentValue"
    if value in (2, 5):
        return "wrongValue"
    if vid == 1 and value == 6:
        return "inconsistentValue"
    return None


def plan_set(cfg, bindings, includes):
    """Validate original positions and return one simultaneous configuration plan.

    Authentication and response-budget checks belong to the adapter. This pure
    function never changes the caller's configuration or derives runtime effects.
    """
    prefixes = tuple(oid(p) for p in includes)
    original = [(oid(name), value) for name, value in bindings]
    row_intent = {}
    # Look ahead only for row intent. Each occurrence still receives all ordinary
    # checks in its original position, including denied or malformed row commands.
    # The first occurrence supplies intent; a later duplicate cannot alter it.
    for name, value in original:
        descriptor = _write_object(name)
        if descriptor:
            base, kind, tag = descriptor
            if kind == "row" and len(name) == len(base) + 1:
                row_intent.setdefault(name[-1], int(value) if value.tagSet == tag else None)
    creates = {vid for vid, value in row_intent.items() if value == 4}
    destroys = {vid for vid, value in row_intent.items() if value == 6}
    ports_by_if = {p.if_index: p.id for p in cfg.ports.values()}
    ports_by_bridge = {p.bridge_port: p.id for p in cfg.ports.values()}
    assignments, seen = [], {}
    for index, (name, wire) in enumerate(original, 1):
        def fail(status):
            raise SetError(status, index)
        if not any(name[:len(p)] == p for p in prefixes):
            fail("noAccess")
        descriptor = _write_object(name)
        if descriptor is None:
            fail("notWritable")
        base, kind, tag = descriptor
        if wire.tagSet != tag:
            fail("wrongType")
        if kind in ("admin", "pvid", "row", "pae-control", "pae-initialize", "pae-reauthenticate"):
            value = int(wire)
            if ((kind == "admin" and value not in (1, 2)) or
                    (kind == "pvid" and not 1 <= value <= 4094) or
                    (kind == "row" and value not in (1, 2, 4, 5, 6)) or
                    (kind == "pae-control" and value not in (1,2,3)) or
                    (kind in ("pae-initialize","pae-reauthenticate") and value not in (1,2))):
                fail("wrongValue")
        elif kind == "name":
            raw = wire.asOctets()
            if len(raw) > 32:
                fail("wrongLength")
            try:
                value = raw.decode("utf-8")
            except UnicodeDecodeError:
                fail("wrongValue")
        else:
            members = set()
            for offset, octet in enumerate(wire.asOctets()):
                for bit in range(8):
                    if octet & (0x80 >> bit):
                        port = ports_by_bridge.get(offset * 8 + bit + 1)
                        if port is None:
                            fail("wrongValue")
                        members.add(port)
            value = frozenset(members)
        if len(name) != len(base) + 1:
            fail("noCreation")
        key = name[-1]
        if kind in ("admin", "pvid", "pae-control", "pae-initialize", "pae-reauthenticate"):
            key = (ports_by_bridge if kind == "pvid" else ports_by_if).get(key)
            if key is None:
                fail("noCreation")
        elif not 1 <= key <= 4094:
            fail("noCreation")
        if kind == "row":
            error = _row_error(key in cfg.vlans, key, value)
            if error:
                fail(error)
        elif kind not in ("admin", "pvid", "pae-control", "pae-initialize", "pae-reauthenticate"):
            if key not in cfg.vlans and key not in creates:
                fail("inconsistentName")
            if key in destroys:
                fail("inconsistentValue")
        prior = seen.get((kind, key))
        if prior is not None and prior.value != value:
            fail("inconsistentValue")
        assignment = Assignment(index, kind, key, value)
        assignments.append(assignment)
        seen.setdefault((kind, key), assignment)

    deletes = destroys & cfg.vlans.keys()
    candidate = cfg.model_copy(deep=True)
    for vid in deletes:
        del candidate.vlans[vid]
    for vid in creates:
        candidate.vlans[vid] = Vlan(vid=vid, fdb_id=1000 + vid)
    for pid, port in candidate.ports.items():
        old = cfg.ports[pid]
        for field in BITMAP_FIELDS.values():
            setattr(port, field, [v for v in getattr(old, field) if v not in deletes])
        if old.pvid in deletes and ("pvid", pid) not in seen:
            port.pvid = 1
            if 1 not in port.admitted:
                port.admitted.append(1)
            if old.pvid in old.untagged and 1 not in port.untagged:
                port.untagged.append(1)
    if candidate.switch.legacy_vlan in deletes:
        candidate.switch.legacy_vlan = 1
    effective = []
    pae_actions = {}
    for op in seen.values():
        kind, key, value = op.kind, op.key, op.value
        if kind == "admin":
            candidate.ports[key].admin_up = value == 1
            changed = (value == 1) != cfg.ports[key].admin_up
        elif kind == "pae-control":
            control = {1:"force-unauthorized",2:"auto",3:"force-authorized"}[value]
            candidate.ports[key].authentication.control = control
            changed = control != cfg.ports[key].authentication.control
        elif kind in ("pae-initialize", "pae-reauthenticate"):
            changed = value == 1
            if changed and (kind == "pae-initialize" or key not in pae_actions):
                pae_actions[key] = "initialize" if kind == "pae-initialize" else "reauthenticate"
        elif kind == "pvid":
            candidate.ports[key].pvid = value
            changed = value != cfg.ports[key].pvid
        elif kind == "name":
            candidate.vlans[key].name = value
            changed = key not in cfg.vlans or value != cfg.vlans[key].name
        elif kind == "row":
            changed = value == 4 or (value == 6 and key in cfg.vlans)
        else:
            field = BITMAP_FIELDS[kind]
            changed = value != {p.id for p in cfg.ports.values() if key in getattr(p, field)}
            for pid, port in candidate.ports.items():
                memberships = list(getattr(port, field))
                if pid in value and key not in memberships:
                    memberships.append(key)
                elif pid not in value and key in memberships:
                    memberships.remove(key)
                setattr(port, field, memberships)
        if changed:
            effective.append(op.index)

    conflicts = set()
    for pid, port in candidate.ports.items():
        admitted = set(port.admitted)
        overlap = admitted & set(port.forbidden)
        missing_tags = set(port.untagged) - admitted
        missing_pvid = port.pvid not in admitted
        illegal = overlap | missing_tags | ({port.pvid} if missing_pvid else set())
        if not illegal:
            continue
        for op in assignments:
            if ((op.kind == "pvid" and op.key == pid and missing_pvid) or
                (op.kind == "egress" and (op.key in overlap | missing_tags or
                                         (op.key == port.pvid and missing_pvid))) or
                (op.kind == "forbidden" and op.key in overlap) or
                (op.kind == "untagged" and op.key in missing_tags) or
                (op.kind == "row" and op.value == 6 and op.key == cfg.ports[pid].pvid and
                 op.key in deletes and ("pvid", pid) not in seen and 1 in illegal)):
                conflicts.add(op.index)
    if conflicts:
        raise SetError("inconsistentValue", min(conflicts))
    # Existing custom FDB identifiers stay stable. A colliding new static row
    # cannot be allocated in this fixed independent-FDB profile.
    for op in assignments:
        if op.kind == "row" and op.value == 4 and any(
                v.vid != op.key and v.fdb_id == candidate.vlans[op.key].fdb_id for v in candidate.vlans.values()):
            raise SetError("resourceUnavailable", op.index)
    candidate = Configuration.model_validate(candidate.model_dump())
    fields = ("admin_up", "pvid", "admitted", "untagged", "forbidden", "authentication")
    affected = frozenset(pid for pid, p in candidate.ports.items()
                         if any(getattr(p, f) != getattr(cfg.ports[pid], f) for f in fields))
    return SetPlan(cfg, candidate, tuple(assignments), frozenset(creates), frozenset(deletes),
                   affected, min(effective, default=0), tuple(sorted(pae_actions.items())))
