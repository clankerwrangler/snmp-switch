from __future__ import annotations

import asyncio
import copy
import hashlib
import heapq
import json
import time
from dataclasses import asdict, dataclass, field

from .mib import entity_inventory, plan_set
from .models import Configuration, Credential, CredentialAuth, Community, UsmUser, AccessGroup, PollingAccess, WritingAccess, incoming_policy, Endpoint, Port, SnmpSettings, Source, Target, View, Vlan, uid


class CommandError(Exception):
    def __init__(self, status: int, message: str):
        self.status, self.message = status, message
        super().__init__(message)


def require(condition, message, status=409):
    if not condition:
        raise CommandError(status, message)


def merge_policy(saved, fields):
    fields = dict(fields)
    for use in ("polling", "writing"):
        if use in saved and isinstance(fields.get(use), dict):
            fields[use] = {**saved[use], **fields[use]}
    return {**saved, **fields}


def merge_credential(cfg, previous, fields):
    saved = previous.model_dump() if previous else {}
    fields = dict(fields)
    version = fields.get("version", previous.version if previous else "2c")
    converting = previous is not None and version != previous.version
    transfer_present = "access_transfer" in fields
    transfer = fields.pop("access_transfer", None)
    group_present = "group_id" in fields
    if converting:
        require(not {"polling", "writing"} & fields.keys(),
                "Protocol conversion cannot include read/write overrides", 422)
        if version == "3":
            require(fields.get("security_level") in ("noAuthNoPriv", "authNoPriv", "authPriv"),
                    "Select an explicit protection profile for protocol conversion", 422)
            require(transfer_present != group_present,
                    "Choose keep, none, or an existing group for protocol conversion", 422)
        else:
            require(transfer_present and not group_present,
                    "Choose keep or none for protocol conversion", 422)
        if transfer_present:
            require(transfer in ("keep", "none"), "Invalid access transfer", 422)
        policy = incoming_policy(cfg, previous)
        kept = ({use: getattr(policy, use).model_dump() for use in ("polling", "writing")}
                if policy else {"polling": PollingAccess().model_dump(), "writing": WritingAccess().model_dump()})
        for name in ("polling", "writing", "group_id"):
            saved.pop(name, None)
        if version == "3":
            if transfer == "keep":
                group = AccessGroup(label=fields.get("label", previous.label),
                    minimum_security_level=fields.get("security_level", "authPriv"), **kept)
                cfg.groups[group.id] = group
                fields["group_id"] = group.id
            elif transfer == "none":
                fields["group_id"] = None
        elif transfer == "keep":
            fields.update(kept)
    else:
        require(not transfer_present, "Access transfer is only valid for protocol conversion", 422)
    if version == "3":
        require(not {"polling", "writing"} & fields.keys(),
                "SNMPv3 incoming access belongs to the selected group", 422)
    else:
        require(not group_present, "SNMPv2c communities cannot select a group", 422)
    if previous is None or converting:
        for key in ("community", "username", "security_level", "auth_key", "priv_key"):
            saved.pop(key, None)
        if version == "2c":
            fields.update(username="", security_level="noAuthNoPriv", auth_key=None, priv_key=None)
        else:
            fields["community"] = None
    else:
        for key in ("community", "auth_key", "priv_key"):
            if fields.get(key) == "":
                fields.pop(key)
    cls = Community if version == "2c" else UsmUser
    return cls.model_validate(merge_policy(saved, fields))


@dataclass(frozen=True)
class Job:
    endpoint_id: str
    source_id: str
    port_id: str
    epoch: str
    endpoint_generation: str
    port_generation: str
    mac: str
    vid: int
    due: int


@dataclass
class Runtime:
    cfg: Configuration
    revision: int = 0
    configuration_revision: int = 0
    sim_ms: int = 0
    epoch: str = field(default_factory=uid)
    boot_start: float = field(default_factory=time.monotonic)
    uptime_epoch: int = 0
    entity_last_change: int = 0
    egens: dict = field(default_factory=dict)
    pgens: dict = field(default_factory=dict)
    credential_generations: dict = field(default_factory=dict)
    activation: str = field(default_factory=uid)
    jobs: dict = field(default_factory=dict)
    fdb: dict = field(default_factory=dict)
    counters: dict = field(default_factory=dict)
    vlan_times: dict = field(default_factory=dict)
    events: list = field(default_factory=list)
    outbox: list = field(default_factory=list)
    event_id: int = 0
    learned_discards: int = 0
    vlan_deletes: int = 0
    notification_drops: int = 0

    def uptime(self):
        return int((time.monotonic() - self.boot_start) * 100) % 2**32

    def attached(self, port_id):
        return [eid for eid, pid in self.cfg.attachments.items() if pid == port_id]

    def carrier(self, port_id):
        p = self.cfg.ports[port_id]
        return p.shared_partner if p.mode == "shared" else bool(self.attached(port_id))

    def up(self, port_id):
        p = self.cfg.ports[port_id]
        return p.admin_up and not p.forced_down and self.carrier(port_id)

    def gate(self):
        return bool(self.cfg.switch.identity.sys_object_id and self.cfg.snmp.enabled)

    def event(self, kind, **details):
        self.event_id += 1
        event = dict(id=self.event_id, kind=kind, simulation_ms=self.sim_ms, uptime=self.uptime(), revision=self.revision + 1, **details)
        self.events.append(event)
        self.events = self.events[-2000:]
        return event

    def notify(self, kind, **details):
        event = self.event(kind, status="committed", **details)
        if not self.gate():
            return
        for target in self.cfg.targets.values():
            cred = self.cfg.credentials[target.credential_id]
            if not target.enabled or not cred.enabled or kind not in target.types:
                continue
            if len(self.outbox) >= self.cfg.switch.queue_limit:
                self.notification_drops += 1
                self.event("notification", status="dropped-on-overflow", target_id=target.id, notification_id=event["id"])
            else:
                self.outbox.append(dict(event=copy.deepcopy(event), target_id=target.id))
                self.event("notification", status="queued", target_id=target.id, notification_id=event["id"])

    def cancel_outbox(self, reason):
        for item in self.outbox:
            self.event("notification", status=reason, target_id=item["target_id"], notification_id=item["event"]["id"])
        self.outbox.clear()

    def schedule(self, eid, delay=True):
        for key in [k for k in self.jobs if k[0] == eid]:
            del self.jobs[key]
        ep = self.cfg.endpoints.get(eid)
        pid = self.cfg.attachments.get(eid)
        if ep is None or not ep.active or pid is None or not self.up(pid):
            return
        for src in ep.sources:
            self.jobs[(eid, src.id)] = Job(eid, src.id, pid, self.epoch, self.egens[eid], self.pgens[pid], src.mac,
                                         self.cfg.ports[pid].pvid if src.tag == "untagged" else src.tag,
                                         self.sim_ms + (src.initial_delay_ms if delay else src.interval_ms))

    def valid(self, job):
        ep = self.cfg.endpoints.get(job.endpoint_id)
        if ep is None or not ep.active or self.cfg.attachments.get(job.endpoint_id) != job.port_id:
            return False
        src = next((s for s in ep.sources if s.id == job.source_id), None)
        return bool(src and self.up(job.port_id) and self.epoch == job.epoch and
                    self.egens.get(job.endpoint_id) == job.endpoint_generation and
                    self.pgens.get(job.port_id) == job.port_generation and src.mac == job.mac and
                    (self.cfg.ports[job.port_id].pvid if src.tag == "untagged" else src.tag) == job.vid)

    def observe(self, job):
        if not self.valid(job):
            self.event("invalidated-work", endpoint_id=job.endpoint_id)
            return False
        src = next(s for s in self.cfg.endpoints[job.endpoint_id].sources if s.id == job.source_id)
        ctr = self.counters[job.port_id]
        ctr["in_octets"] += src.octets
        if job.vid not in self.cfg.vlans or job.vid not in self.cfg.ports[job.port_id].admitted:
            ctr["in_discards"] += 1
            # First rejection is visible; repeating rejections are counted without unbounded logs.
            if ctr["in_discards"] == 1:
                self.event("admission-rejected", endpoint_id=job.endpoint_id, vid=job.vid, port_id=job.port_id)
            return False
        ctr["in_ucast"] += 1
        key = (self.cfg.vlans[job.vid].fdb_id, job.mac)
        old = self.fdb.get(key)
        if old is None and len(self.fdb) >= self.cfg.switch.fdb_limit:
            self.learned_discards += 1
            if self.learned_discards == 1:
                self.event("learning-capacity", limit=self.cfg.switch.fdb_limit)
            return False
        p = self.cfg.ports[job.port_id]
        self.fdb[key] = dict(fdb_id=key[0], mac=job.mac, vid=job.vid, port_id=p.id, bridge_port=p.bridge_port,
                             if_index=p.if_index, last_seen_ms=self.sim_ms,
                             expires_at_ms=self.sim_ms + self.cfg.switch.aging_seconds * 1000)
        if old is None or old["port_id"] != p.id:
            self.event("mac-learn" if old is None else "mac-move", mac=job.mac, vid=job.vid, port_id=p.id)
        return True

    def expire(self):
        for key, row in list(self.fdb.items()):
            if row["expires_at_ms"] <= self.sim_ms:
                del self.fdb[key]
                self.event("mac-age", mac=row["mac"], vid=row["vid"], port_id=row["port_id"])

    def advance(self, duration):
        target = self.sim_ms + duration
        # Guard the transaction before it does any work; rejected advances publish nothing.
        estimated = sum(max(0, (target-j.due)//next(s.interval_ms for s in self.cfg.endpoints[j.endpoint_id].sources if s.id == j.source_id)+1)
                        for j in self.jobs.values() if self.valid(j))
        require(estimated <= 200000, "Advance would exceed 200,000 source observations; use smaller steps", 429)
        heap = [(j.due, j.endpoint_id, j.source_id, j) for j in self.jobs.values()]
        heapq.heapify(heap)
        while heap and heap[0][0] <= target:
            deadline = heap[0][0]
            # Expire at the actual expiry boundary even between source deadlines.
            expiry = min((r["expires_at_ms"] for r in self.fdb.values()), default=deadline)
            if expiry < deadline:
                self.sim_ms = expiry
                self.expire()
                continue
            self.sim_ms = deadline
            self.expire()
            while heap and heap[0][0] == deadline:
                _, eid, sid, j = heapq.heappop(heap)
                self.observe(j)
                if self.valid(j):
                    src = next(s for s in self.cfg.endpoints[eid].sources if s.id == sid)
                    following = Job(**{**asdict(j), "due": deadline + src.interval_ms})
                    self.jobs[(eid, sid)] = following
                    heapq.heappush(heap, (following.due, eid, sid, following))
        while self.fdb:
            expiry = min(r["expires_at_ms"] for r in self.fdb.values())
            if expiry > target:
                break
            self.sim_ms = expiry
            self.expire()
        self.sim_ms = target

    def reset_operational(self, reboot=False):
        self.cancel_outbox("canceled-on-reboot" if reboot else "canceled-on-reset")
        self.epoch = uid()
        self.sim_ms = 0
        self.fdb.clear()
        self.jobs.clear()
        if reboot:
            self.activation = uid()
            self.credential_generations = {cid: uid() for cid in self.cfg.credentials}
            self.boot_start = time.monotonic()
            self.uptime_epoch = 0
            self.entity_last_change = 0
            self.vlan_deletes = 0
            self.vlan_times = {vid: [0, 0] for vid in self.cfg.vlans}
        self.learned_discards = 0
        self.counters = {pid: dict(in_octets=0, in_ucast=0, in_discards=0, last_change=0 if reboot else self.uptime(),
                                   discontinuity=0 if reboot else self.uptime()) for pid in self.cfg.ports}
        self.egens = {eid: uid() for eid in self.cfg.endpoints}
        self.pgens = {pid: uid() for pid in self.cfg.ports}
        for eid in self.cfg.endpoints:
            self.schedule(eid)


class Engine:
    def __init__(self, cfg, store=None):
        self.store = store
        if store:
            store.require_healthy()
        self.lock = asyncio.Lock()
        self.idempotency = store.get("idempotency", {}) if store else {}
        self.state = Runtime(cfg, revision=store.get("revision", 0) if store else 0)
        self.state.configuration_revision = store.get("configuration_revision", 0) if store else 0
        if store:
            self.state.events = store.events()
            self.state.event_id = max((e["id"] for e in self.state.events), default=0)
            self.state.outbox = store.get("outbox", [])
        self.state.reset_operational(reboot=True)
        self.state.event("boot")
        self.state.revision += 1
        if store:
            store.commit(self.state, self.idempotency)

    @property
    def storage_fault(self):
        return (self.store.fault_reason or ("storage_closed" if self.store.closed else None)) if self.store else None

    def require_storage(self):
        if self.store:
            self.store.require_healthy()

    def storage_status(self):
        return dict(healthy=not self.storage_fault, reason=self.storage_fault,
                    snapshot="last_confirmed" if self.storage_fault else "current")

    def snapshot(self):
        s = self.state
        data = s.cfg.model_dump(mode="json")
        for c in data["credentials"].values():
            community, auth_key, priv_key = (c.pop(k) for k in ("community", "auth_key", "priv_key"))
            if c["version"] == "2c":
                c.pop("username")
                c.pop("security_level")
                c["has_community"] = bool(community)
            else:
                if c["security_level"] != "noAuthNoPriv":
                    c["has_auth_key"] = bool(auth_key)
                if c["security_level"] == "authPriv":
                    c["has_priv_key"] = bool(priv_key)
        data.update(revision=s.revision, configuration_revision=s.configuration_revision, simulation_ms=s.sim_ms, uptime=s.uptime(), epoch=s.epoch,
                    fdb=[dict(r, remaining_ms=max(0, r["expires_at_ms"] - s.sim_ms)) for r in s.fdb.values()],
                    counters=dict(learning_discards=s.learned_discards, notification_drops=s.notification_drops, vlan_deletes=s.vlan_deletes),
                    queued_notifications=len(s.outbox), storage_status=self.storage_status())
        for pid, p in data["ports"].items():
            p.update(carrier=s.carrier(pid), operational_up=s.up(pid), attachments=s.attached(pid),
                     learned_count=sum(1 for r in s.fdb.values() if r["port_id"] == pid), counters=s.counters[pid].copy())
        return data

    def export(self):
        c = self.state.cfg.model_dump(mode="json")
        # Deployment identity, security and destinations are deliberately absent.
        return {"schema_version": 1, "ports": c["ports"], "vlans": c["vlans"], "endpoints": c["endpoints"],
                "attachments": c["attachments"], "paused": c["paused"],
                "lab_settings": {k: c["switch"][k] for k in ("legacy_vlan", "aging_seconds")}}

    async def execute(self, action, payload=None, expected=None, key=None, expected_config=None):
        payload = payload or {}
        async with self.lock:
            return self._execute(action, payload, expected, key, expected_config)

    def set_locked(self, bindings, includes):
        """Plan and commit while the caller holds io_lock then this engine's lock.

        The adapter claims its response ticket before entering this synchronous
        transaction. There is no await between this method and response completion.
        """
        self.require_storage()
        require(self.lock.locked(), "SET requires the engine lock", 500)
        plan = plan_set(self.state.cfg, bindings, includes)
        self.commit_set_locked(plan)
        return plan

    def commit_set_locked(self, plan):
        self.require_storage()
        require(self.lock.locked() and plan.before is self.state.cfg, "Stale SET plan", 500)
        if plan.changed:
            self._execute("snmp-set", plan)

    def _execute(self, action, payload, expected=None, key=None, expected_config=None):
        self.require_storage()
        signature = hashlib.sha256(json.dumps([action, payload], sort_keys=True).encode()).hexdigest() if key else None
        if key and key in self.idempotency:
            prior = self.idempotency[key]
            require(prior["signature"] == signature, "Idempotency key was used for another command")
            return prior["result"]
        require(expected is None or expected == self.state.revision, "Stale state revision; reload and retry")
        require(expected_config is None or expected_config == self.state.configuration_revision, "Configuration changed while editing; reload and retry")
        old = self.state
        s = copy.deepcopy(old)
        affected_e, affected_p = set(), set()
        result = self._apply(s, action, payload, affected_e, affected_p)
        s.cfg = Configuration.model_validate(s.cfg.model_dump(mode="json"))
        if action != "reboot":
            lifecycle = lambda c: (c.snmp, c.switch.identity.sys_object_id)
            if lifecycle(s.cfg) != lifecycle(old.cfg):
                s.activation = uid()
            s.credential_generations = {}
            for cid, credential in s.cfg.credentials.items():
                before = old.cfg.credentials.get(cid)
                policy = incoming_policy(s.cfg, credential)
                old_policy = incoming_policy(old.cfg, before) if before else None
                view_id = policy.writing.view_id if policy else None
                # Group labels are not authorization. Policy and selected-view
                # changes invalidate every member, including remove/restore ABA.
                auth_policy = lambda p: (p.polling, p.writing, getattr(p, "minimum_security_level", None)) if p else None
                changed_policy = auth_policy(policy) != auth_policy(old_policy)
                changed_view = s.cfg.views.get(view_id) != old.cfg.views.get(view_id)
                s.credential_generations[cid] = (uid() if credential != before or changed_policy or changed_view
                    else old.credential_generations[cid])
        if entity_inventory(s.cfg) != entity_inventory(old.cfg):
            s.entity_last_change = s.uptime()
        require(len(s.cfg.endpoints) <= s.cfg.switch.endpoint_limit, "Endpoint capacity reached", 429)
        require(sum(len(e.sources) for e in s.cfg.endpoints.values()) <= s.cfg.switch.source_limit, "Source capacity reached", 429)
        if action not in ("advance", "job", "reboot", "notification-result", "coldStart", "test-notification"):
            for pid in s.cfg.ports:
                if old.up(pid) != s.up(pid):
                    affected_p.add(pid)
                    s.counters[pid]["last_change"] = s.uptime()
                    if s.cfg.ports[pid].link_notifications:
                        p = s.cfg.ports[pid]
                        s.notify("linkUp" if s.up(pid) else "linkDown", port_id=pid, if_index=p.if_index,
                                 admin=1 if p.admin_up else 2, before=1 if old.up(pid) else 2, after=1 if s.up(pid) else 2)
            for fkey, row in list(s.fdb.items()):
                if row["vid"] not in s.cfg.vlans or not s.up(row["port_id"]) or row["vid"] not in s.cfg.ports[row["port_id"]].admitted:
                    del s.fdb[fkey]
            for pid in affected_p:
                s.pgens[pid] = uid()
            for eid in affected_e:
                s.egens[eid] = uid()
            affected_e.update(eid for eid, pid in old.cfg.attachments.items() if pid in affected_p)
            affected_e.update(eid for eid, pid in s.cfg.attachments.items() if pid in affected_p)
            for eid in affected_e:
                s.schedule(eid)
            for vid in s.cfg.vlans:
                if vid not in old.cfg.vlans:
                    s.vlan_times[vid] = [s.uptime(), s.uptime()]
                elif s.cfg.vlans[vid] != old.cfg.vlans[vid] or any(
                        tuple(vid in getattr(old.cfg.ports[p], field) for field in ("admitted", "untagged", "forbidden")) !=
                        tuple(vid in getattr(s.cfg.ports[p], field) for field in ("admitted", "untagged", "forbidden")) or
                        (old.cfg.ports[p].pvid == vid) != (s.cfg.ports[p].pvid == vid) for p in s.cfg.ports):
                    s.vlan_times[vid][1] = s.uptime()
        for vid in list(s.vlan_times):
            if vid not in s.cfg.vlans:
                del s.vlan_times[vid]
        current_epoch = int((time.monotonic() - s.boot_start) * 100) // 2**32
        if current_epoch != s.uptime_epoch:
            s.uptime_epoch = current_epoch
            s.vlan_times = {v: [0, 0] for v in s.cfg.vlans}
        if not s.gate() or s.cfg.credentials != old.cfg.credentials or s.cfg.targets != old.cfg.targets:
            s.cancel_outbox("canceled-on-configuration")
        s.revision += 1
        durable = action not in ("advance", "job", "notification-result", "coldStart", "test-notification")
        if durable:
            s.configuration_revision += 1
        result = dict(result or {}, revision=s.revision, configuration_revision=s.configuration_revision, simulation_ms=s.sim_ms)
        idem = self.idempotency.copy()
        if key:
            idem[key] = dict(signature=signature, result=result)
            idem = dict(list(idem.items())[-256:])
        if self.store:
            self.store.commit(s, idem, durable=durable)
        self.state, self.idempotency = s, idem
        return result

    def _apply(self, s, action, d, es, ps):
        cfg = s.cfg

        def get(collection, ident):
            require(ident in collection, "Resource not found", 404)
            return collection[ident]

        if action == "snmp-set":
            cfg = s.cfg = d.candidate.model_copy(deep=True)
            ps.update(d.affected_ports)
            es.update(e.id for e in cfg.endpoints.values()
                      if any(src.tag in d.creates | d.deletes for src in e.sources))
            s.vlan_deletes += len(d.deletes)
            for vid in sorted(d.creates):
                s.event("vlan-create", vid=vid)
            for vid in sorted(d.deletes):
                s.event("vlan-delete", vid=vid)
            s.event("snmp-set", assignments=len(d.assignments))
            return
        if action == "endpoint-create":
            ep = Endpoint.model_validate(d)
            require(ep.id not in cfg.endpoints, "Endpoint ID already exists")
            cfg.endpoints[ep.id] = ep
            es.add(ep.id)
            s.event("endpoint-created", endpoint_id=ep.id)
            return {"id": ep.id}
        if action.startswith("endpoint-") or action in ("attach", "detach"):
            eid = d["id"]
            ep = get(cfg.endpoints, eid)
            if action == "endpoint-delete":
                require(eid not in cfg.attachments, "Disconnect the endpoint before deleting it")
                del cfg.endpoints[eid]
                es.add(eid)
            elif action == "endpoint-edit":
                patch = d["patch"]
                require(not set(patch) - {"name", "metadata", "active", "sources"}, "Unsupported endpoint field", 422)
                cfg.endpoints[eid] = Endpoint.model_validate({**ep.model_dump(), **patch, "revision": ep.revision+1})
                if {"sources", "active"} & patch.keys():
                    es.add(eid)
            elif action == "endpoint-clone":
                clone = ep.model_dump()
                clone.update(id=uid(), name=d.get("name") or ep.name + " copy", revision=0)
                for src in clone["sources"]:
                    src["id"] = uid()
                    if not d.get("preserve_macs", False):
                        src["mac"] = "02:" + bytes.fromhex(uid().replace("-", "")[:10]).hex(":")
                return self._apply(s, "endpoint-create", clone, es, ps)
            elif action == "attach":
                pid = d["port_id"]
                p = get(cfg.ports, pid)
                require(p.mode == "shared" or not [e for e in s.attached(pid) if e != eid], "Direct port already has an endpoint")
                cfg.attachments[eid] = pid
                es.add(eid)
            elif action == "detach":
                cfg.attachments.pop(eid, None)
                es.add(eid)
            s.event(action, endpoint_id=eid)
            return {"id": eid}
        if action == "port-edit":
            pid, patch = d["id"], d["patch"]
            p = get(cfg.ports, pid)
            require(not set(patch) - {"name", "alias", "admin_up", "mode", "shared_partner", "forced_down", "speed", "mtu", "pvid", "admitted", "untagged", "forbidden", "link_notifications"}, "Unsupported port field", 422)
            if patch.get("mode") == "shared" and p.mode != "shared":
                patch = {**patch, "shared_partner": True}
            if patch.get("mode") == "direct":
                require(len(s.attached(pid)) <= 1, "Disconnect extra endpoints before selecting direct mode")
            if "pvid" in patch and patch["pvid"] != p.pvid and "untagged" not in patch:
                patch = {**patch, "untagged": sorted((set(p.untagged) - {p.pvid}) | {patch["pvid"]})}
            cfg.ports[pid] = Port.model_validate({**p.model_dump(), **patch})
            if set(patch) - {"name", "alias", "link_notifications"}:
                ps.add(pid)
            s.event(action, port_id=pid)
        elif action == "vlan-create":
            v = Vlan.model_validate({"fdb_id": 1000+d["vid"], **d})
            require(v.vid not in cfg.vlans, "VLAN already exists")
            cfg.vlans[v.vid] = v
            # Re-creation invalidates explicit jobs that captured the absent VLAN.
            es.update(e.id for e in cfg.endpoints.values() if any(x.tag == v.vid for x in e.sources))
            s.event(action, vid=v.vid)
            return {"vid": v.vid}
        elif action in ("vlan-edit", "vlan-delete"):
            vid = d["vid"]
            v = get(cfg.vlans, vid)
            if action == "vlan-edit":
                cfg.vlans[vid] = Vlan.model_validate({**v.model_dump(), "name": d["name"]})
            else:
                require(vid != 1, "VLAN 1 cannot be deleted")
                del cfg.vlans[vid]
                s.vlan_deletes += 1
                for pid, p in cfg.ports.items():
                    if any(vid in getattr(p, field) for field in ("admitted", "untagged", "forbidden")) or p.pvid == vid:
                        native = vid in p.untagged
                        for field in ("admitted", "untagged", "forbidden"):
                            setattr(p, field, [x for x in getattr(p, field) if x != vid])
                        if p.pvid == vid:
                            p.pvid = 1
                            p.admitted = sorted(set(p.admitted + [1]))
                            if native:
                                p.untagged = sorted(set(p.untagged + [1]))
                        ps.add(pid)
                if cfg.switch.legacy_vlan == vid:
                    cfg.switch.legacy_vlan = 1
                es.update(e.id for e in cfg.endpoints.values() if any(x.tag == vid for x in e.sources))
            s.event(action, vid=vid)
        elif action == "switch-edit":
            require(not set(d) - {"name", "description", "contact", "location", "identity", "base_mac", "legacy_vlan", "aging_seconds", "fdb_limit", "endpoint_limit", "source_limit", "queue_limit"}, "Unsupported switch field", 422)
            previous_age = cfg.switch.aging_seconds
            cfg.switch = type(cfg.switch).model_validate({**cfg.switch.model_dump(), **d})
            if previous_age != cfg.switch.aging_seconds:
                for row in s.fdb.values():
                    row["expires_at_ms"] = row["last_seen_ms"] + cfg.switch.aging_seconds*1000
                s.expire()
            s.event(action)
        elif action == "clear":
            pid, vid = d.get("port_id"), d.get("vid")
            if pid is not None:
                get(cfg.ports, pid)
            if vid is not None:
                get(cfg.vlans, vid)
            for k, r in list(s.fdb.items()):
                if (pid is None or r["port_id"] == pid) and (vid is None or r["vid"] == vid):
                    del s.fdb[k]
            # A token invalidates the entire affected endpoint, including captured late jobs.
            es.update(eid for eid, attached in cfg.attachments.items() if (pid is None or attached == pid) and
                      (vid is None or any((cfg.ports[attached].pvid if x.tag == "untagged" else x.tag) == vid for x in cfg.endpoints[eid].sources)))
            s.event("fdb-clear", port_id=pid, vid=vid)
        elif action in ("pause", "resume"):
            cfg.paused = action == "pause"
            s.event(action)
        elif action == "advance":
            require(d.get("automatic", False) or cfg.paused, "Pause the clock before manual advancement")
            require(isinstance(d["duration_ms"], int) and 0 < d["duration_ms"] <= 86400000, "Duration must be 1–86400000 ms", 422)
            s.advance(d["duration_ms"])
        elif action == "job":
            return {"accepted": s.observe(Job(**d))}
        elif action == "reboot":
            s.reset_operational(reboot=True)
            s.event("boot")
        elif action == "import":
            require(set(d) == {"schema_version", "ports", "vlans", "endpoints", "attachments", "paused", "lab_settings"} and d["schema_version"] == 1,
                    "Invalid lab schema; deployment settings cannot be imported", 422)
            require(set(d["lab_settings"]) == {"legacy_vlan", "aging_seconds"}, "Invalid lab settings", 422)
            # Same deployment: preserve all stable interface IDs and numeric assignments.
            require(set(d["ports"]) == set(cfg.ports), "Scenario must use this switch's fixed port inventory", 422)
            for pid, p in d["ports"].items():
                require(p["if_index"] == cfg.ports[pid].if_index and p["bridge_port"] == cfg.ports[pid].bridge_port,
                        "Scenario cannot change interface indexes", 422)
            merged = {**cfg.model_dump(mode="json"), **{k: v for k, v in d.items() if k not in ("lab_settings", "schema_version")}}
            merged["switch"].update(d["lab_settings"])
            s.cfg = Configuration.model_validate(merged)
            s.reset_operational()
            s.event("scenario-import")
        elif action == "snmp-settings":
            cfg.snmp = SnmpSettings.model_validate({**cfg.snmp.model_dump(), **d})
            s.event("snmp-settings")
        elif action in ("credential-save", "group-save", "view-save", "target-save"):
            cls, collection = {"credential-save": (Credential, cfg.credentials), "group-save": (AccessGroup, cfg.groups), "view-save": (View, cfg.views), "target-save": (Target, cfg.targets)}[action]
            previous = collection.get(d.get("id"))
            fields = dict(d)
            if action == "target-save":
                inline = fields.pop("new_credential", None)
                require((fields.get("credential_id") is None) != (inline is None),
                        "Select an existing credential or create one, not both", 422)
                if inline is not None:
                    auth = CredentialAuth.model_validate(inline)
                    credential = merge_credential(cfg, None, auth.model_dump())
                    cfg.credentials[credential.id] = credential
                    fields["credential_id"] = credential.id
                    s.event("credential-save", resource_id=credential.id)
            if action == "credential-save":
                obj = merge_credential(cfg, previous, fields)
                if obj.version == "3" and obj.group_id not in s.cfg.groups:
                    require(obj.group_id is None, "Unknown SNMPv3 group", 422)
            elif action == "group-save":
                obj = cls.model_validate(merge_policy(previous.model_dump() if previous else {}, fields))
            else:
                obj = cls.model_validate({**(previous.model_dump() if previous else {}), **fields})
            collection[obj.id] = obj
            s.event(action, resource_id=obj.id)
            return {"id": obj.id, **({"credential_id": obj.credential_id} if action == "target-save" else {})}
        elif action in ("credential-delete", "group-delete", "view-delete", "target-delete"):
            collection = {"credential-delete": cfg.credentials, "group-delete": cfg.groups, "view-delete": cfg.views, "target-delete": cfg.targets}[action]
            get(collection, d["id"])
            del collection[d["id"]]
            s.event(action, resource_id=d["id"])
        elif action == "coldStart":
            s.notify("coldStart")
        elif action == "test-notification":
            require(s.gate(), "SNMP disabled: configure identity and enable SNMP", 409)
            target = get(cfg.targets, d["target_id"])
            require(target.enabled and cfg.credentials[target.credential_id].enabled, "Notification target is disabled")
            event = s.event("coldStart", status="committed", test=True)
            require(len(s.outbox) < cfg.switch.queue_limit, "Notification queue is full", 429)
            s.outbox.append(dict(event=event, target_id=target.id))
            s.event("notification", status="queued", target_id=target.id, notification_id=event["id"])
        elif action == "notification-result":
            if s.outbox and s.outbox[0]["event"]["id"] == d["notification_id"] and s.outbox[0]["target_id"] == d["target_id"]:
                s.outbox.pop(0)
            s.event("notification", **d)
        else:
            raise CommandError(404, "Unknown command")
