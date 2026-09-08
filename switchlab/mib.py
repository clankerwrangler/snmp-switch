"""Numeric, typed MIB projections. No simulation state is mutated by polling."""
from bisect import bisect_right
import time

from pysnmp.proto import rfc1902 as a, rfc1905 as exceptions


def oid(value):
    return tuple(int(x) for x in value.split(".")) if isinstance(value, str) else tuple(value)


CURRENT = oid("1.3.6.1.2.1.17.7.1.4.2.1")


def port_list(state, predicate):
    data = bytearray((max(p.bridge_port for p in state.cfg.ports.values()) + 7) // 8)
    for p in state.cfg.ports.values():
        if predicate(p):
            data[(p.bridge_port-1)//8] |= 0x80 >> ((p.bridge_port-1) % 8)
    return bytes(data)


class Projection:
    def __init__(self, state, includes):
        self.state = state  # Published states are never subsequently changed by the engine.
        self.includes = [oid(p) for p in includes]
        self.values = {}
        self.bases = set()
        self.filtered = {}
        elapsed = int((time.monotonic() - state.boot_start) * 100)
        self.ticks = elapsed % 2**32
        self.wrapped = elapsed // 2**32 != state.uptime_epoch
        self.build()
        self.keys = sorted(self.values)

    def allowed(self, name):
        return any(name[:len(p)] == p for p in self.includes)

    def put(self, base, suffix, value):
        base = oid(base)
        self.bases.add(base)
        full = base + tuple(suffix)
        if self.allowed(full):
            self.values[full] = value

    def table(self, prefix, columns, rows):
        for col in columns:
            self.bases.add(oid(prefix) + (col,))
        for index, values in rows:
            for col, val in values.items():
                self.put(oid(prefix)+(col,), index, val)

    def build(self):
        s, I, O, C, G, T, H = self.state, a.Integer32, a.OctetString, a.Counter32, a.Gauge32, a.TimeTicks, a.Counter64
        sw = s.cfg.switch
        system = [O(sw.identity.sys_descr), a.ObjectIdentifier(sw.identity.sys_object_id) if sw.identity.sys_object_id else None,
                  T(self.ticks), O(sw.contact), O(sw.name), O(sw.location), I(2)]
        for n, value in enumerate(system, 1):
            if value is not None:
                self.put(f"1.3.6.1.2.1.1.{n}", (0,), value)
        self.put("1.3.6.1.2.1.2.1", (0,), I(len(s.cfg.ports)))
        ports, extended, bridge, qports = [], [], [], []
        for pid, p in s.cfg.ports.items():
            c, up = s.counters[pid], s.up(pid)
            physical = ((int(sw.base_mac.replace(":", ""), 16) + p.bridge_port) % 2**48).to_bytes(6, "big")
            physical = bytes([(physical[0] | 2) & 254]) + physical[1:]
            ports.append(((p.if_index,), {1: I(p.if_index), 2: O(p.name), 3: I(6), 4: I(p.mtu),
                5: G(min(p.speed, 2**32-1) if up else 0), 6: O(physical), 7: I(1 if p.admin_up else 2), 8: I(1 if up else 2),
                9: T(c["last_change"]), 10: C(c["in_octets"] % 2**32), 11: C(c["in_ucast"] % 2**32),
                13: C(c["in_discards"] % 2**32), **{i: C(0) for i in (14, 16, 17, 19, 20)}}))
            extended.append(((p.if_index,), {1: O(p.name), 6: H(c["in_octets"] % 2**64), 7: H(c["in_ucast"] % 2**64),
                10: H(0), 11: H(0), 14: I(1 if p.link_notifications else 2), 15: G(p.speed//1000000 if up else 0),
                17: I(1), 18: O(p.alias), 19: T(c["discontinuity"])}))
            bridge.append(((p.bridge_port,), {1: I(p.bridge_port), 2: I(p.if_index)}))
            qports.append(((p.bridge_port,), {1: G(p.pvid), 2: I(1), 3: I(1), 4: I(2)}))
        self.table("1.3.6.1.2.1.2.2.1", [1,2,3,4,5,6,7,8,9,10,11,13,14,16,17,19,20], ports)
        self.table("1.3.6.1.2.1.31.1.1.1", [1,6,7,10,11,14,15,17,18,19], extended)
        self.table("1.3.6.1.2.1.17.1.4.1", [1,2], bridge)
        self.table("1.3.6.1.2.1.17.7.1.4.5.1", [1,2,3,4], qports)
        for base, val in {
            "17.1.1": O(bytes.fromhex(sw.base_mac.replace(":", ""))), "17.1.2": I(len(ports)), "17.1.3": I(2),
            "17.4.1": C(s.learned_discards % 2**32), "17.4.2": I(sw.aging_seconds),
            "17.7.1.1.1": I(1), "17.7.1.1.2": I(4094), "17.7.1.1.3": G(4094),
            "17.7.1.1.4": G(len(s.cfg.vlans)), "17.7.1.1.5": I(2), "17.7.1.4.1": C(s.vlan_deletes % 2**32),
        }.items():
            self.put("1.3.6.1.2.1."+base, (0,), val)
        legacy, full = [], []
        for (fid, address), r in s.fdb.items():
            mac_index = tuple(bytes.fromhex(address.replace(":", "")))
            if r["vid"] == sw.legacy_vlan:
                legacy.append((mac_index, {1: O(bytes(mac_index)), 2: I(r["bridge_port"]), 3: I(3)}))
            full.append(((fid,)+mac_index, {2: I(r["bridge_port"]), 3: I(3)}))
        self.table("1.3.6.1.2.1.17.4.3.1", [1,2,3], legacy)
        self.table("1.3.6.1.2.1.17.7.1.2.2.1", [2,3], full)
        self.table("1.3.6.1.2.1.17.7.1.2.1.1", [2], [((v.fdb_id,), {2: C(sum(1 for r in s.fdb.values() if r["fdb_id"] == v.fdb_id))}) for v in s.cfg.vlans.values()])
        static = []
        for vid, v in s.cfg.vlans.items():
            static.append(((vid,), {1: O(v.name), 2: O(port_list(s, lambda p: vid in p.admitted)),
                3: O(port_list(s, lambda p: False)), 4: O(port_list(s, lambda p: p.pvid == vid)), 5: I(1)}))
        self.table("1.3.6.1.2.1.17.7.1.4.3.1", [1,2,3,4,5], static)
        self.bases.update(CURRENT+(i,) for i in range(3,8))

    def current(self, cutoff):
        if cutoff in self.filtered:
            return self.filtered[cutoff]
        values = {}
        s = self.state
        for vid, v in s.cfg.vlans.items():
            # Wrap resets conceptual row timestamps independently of USM time.
            created, changed = [0,0] if self.wrapped else s.vlan_times[vid]
            if cutoff and (cutoff > self.ticks or changed < cutoff):
                continue
            columns = {3: a.Gauge32(v.fdb_id), 4: a.OctetString(port_list(s, lambda p: vid in p.admitted)),
                       5: a.OctetString(port_list(s, lambda p: p.pvid == vid)), 6: a.Integer32(2), 7: a.TimeTicks(created)}
            for col, value in columns.items():
                name = CURRENT + (col, cutoff, vid)
                if self.allowed(name):
                    values[name] = value
        self.filtered[cutoff] = values
        return values

    def cutoff(self, name):
        return name[len(CURRENT)+1] if name[:len(CURRENT)] == CURRENT and len(name) >= len(CURRENT)+2 else 0

    def get(self, name):
        name = oid(name)
        if not self.allowed(name):
            return name, exceptions.noSuchObject
        val = self.current(self.cutoff(name)).get(name) if name[:len(CURRENT)] == CURRENT else self.values.get(name)
        if val is not None:
            return name, val
        known = any(name[:len(base)] == base for base in self.bases)
        return name, exceptions.noSuchInstance if known else exceptions.noSuchObject

    def next(self, name):
        name = oid(name)
        idx = bisect_right(self.keys, name)
        normal = self.keys[idx] if idx < len(self.keys) else None
        filtered = self.current(self.cutoff(name))
        candidates = [k for k in filtered if k > name]
        candidate = min(candidates) if candidates else None
        if normal is not None and (candidate is None or normal < candidate):
            return normal, self.values[normal]
        if candidate is not None:
            return candidate, filtered[candidate]
        return name, exceptions.endOfMibView
