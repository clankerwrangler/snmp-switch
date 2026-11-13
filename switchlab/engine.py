from __future__ import annotations

import asyncio
import copy
import hashlib
import heapq
import json
import time
from collections import Counter
from dataclasses import asdict, dataclass, field

from .mib import entity_inventory, plan_set, current_vlan_ports
from .storage import split_configuration, compose_configuration, reconciled_startup
from .radius import RadiusError, resolve_nas_identity
from .models import Configuration, Credential, CredentialAuth, Community, UsmUser, AccessGroup, PollingAccess, WritingAccess, incoming_policy, Endpoint, Port, SnmpSettings, Target, View, Vlan, configuration_error, uid
from .common import CommandError, event_resource_label, require
from .access_commands import ACCESS_ACTIONS, apply_access
from .access_state import AccessSession, AccessState  # AccessSession is re-exported for callers
from .dynamic_authorization import DynamicAuthorization
from .radius_workers import Accounting, Authentication




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
                cfg.check_snmp_limit("groups")
                cfg.check_policy(group)
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
        for key in ("community", "username", "security_level", "auth_protocol", "priv_protocol", "auth_key", "priv_key"):
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
class Runtime(AccessState):
    cfg: Configuration
    revision: int = 0
    configuration_revision: int = 0
    startup: dict = field(default_factory=dict, repr=False)
    startup_revision: int = 0
    configuration_dirty: bool = False
    configuration_incarnation: str = field(default_factory=uid, repr=False)
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
    radius_attempts: dict = field(default_factory=dict)
    radius_sessions: dict = field(default_factory=dict)
    radius_status: dict = field(default_factory=dict)
    advance_operation: dict | None = None
    renewal_budget_time: int = 0
    renewal_budget: dict = field(default_factory=dict)
    accounting_outbox: list = field(default_factory=list, repr=False)
    accounting_sequence: int = 0
    accounting_drops: dict = field(default_factory=dict)
    pae: dict = field(default_factory=dict)
    last_auth_sessions: dict = field(default_factory=dict, repr=False)

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
        # Capture public subject facts on this candidate, not on later display.
        # Explicit context (including old objects) always takes precedence.
        for id_field, index_field in (("port_id", "if_index"),
                ("before_port_id", "before_if_index"), ("after_port_id", "after_if_index")):
            port = self.cfg.ports.get(details.get(id_field))
            if port is not None:
                details.setdefault(index_field, port.if_index)
        endpoint = self.cfg.endpoints.get(details.get("endpoint_id"))
        if endpoint is not None:
            details.setdefault("endpoint_name", endpoint.name)
            source = next((source for source in endpoint.sources if source.id == details.get("source_id")), None)
            if source is not None:
                details.setdefault("source_mac", source.mac)
        self.event_id += 1
        # History owns its nested payloads; status and caller data can change.
        event = dict(id=self.event_id, kind=kind, simulation_ms=self.sim_ms, uptime=self.uptime(), revision=self.revision + 1, **copy.deepcopy(details))
        self.events.append(event)
        self.events = self.events[-2000:]
        return event

    def configuration_events(self, before):
        """Record actual resource effects, never arbitrary configuration values."""
        public_port_fields = {"admin_up", "shared_partner", "forced_down", "pvid",
                              "admitted", "untagged", "forbidden", "link_notifications"}
        for pid in sorted(self.cfg.ports.keys() & before.ports.keys()):
            old, current = before.ports[pid], self.cfg.ports[pid]
            fields = sorted(name for name in Port.model_fields if getattr(old, name) != getattr(current, name))
            if fields:
                changes = {name: {"before": copy.deepcopy(getattr(old, name)),
                                  "after": copy.deepcopy(getattr(current, name))}
                           for name in fields if name in public_port_fields}
                self.event("port-edit", port_id=pid, fields=fields, changes=changes)
        fields = sorted(name for name in type(self.cfg.switch).model_fields
                        if getattr(before.switch, name) != getattr(self.cfg.switch, name))
        if fields:
            self.event("switch-edit", fields=fields)
        for vid in sorted(self.cfg.vlans.keys() | before.vlans.keys()):
            old, current = before.vlans.get(vid), self.cfg.vlans.get(vid)
            if old is None:
                self.event("vlan-create", vid=vid, fields=sorted(Vlan.model_fields))
            elif current is None:
                self.event("vlan-delete", vid=vid)
            else:
                fields = sorted(name for name in Vlan.model_fields if getattr(old, name) != getattr(current, name))
                if fields:
                    self.event("vlan-edit", vid=vid, fields=fields)

    def notify(self, kind, *, enabled=True, **details):
        event = self.event(kind, status="committed", **details)
        if not enabled or not self.gate():
            return
        for target in self.cfg.targets.values():
            cred = self.cfg.credentials[target.credential_id]
            if not target.enabled or not cred.enabled or kind not in target.types:
                continue
            if len(self.outbox) >= self.cfg.switch.queue_limit:
                self.notification_drops += 1
                self.event("notification", status="dropped-on-overflow", target_id=target.id, notification_id=event["id"], destination=event_resource_label(target))
            else:
                self.outbox.append(dict(event=copy.deepcopy(event), target_id=target.id, destination=event_resource_label(target)))
                self.event("notification", status="queued", target_id=target.id, notification_id=event["id"], destination=event_resource_label(target))

    def cancel_outbox(self, reason):
        for item in self.outbox:
            self.event("notification", status=reason, target_id=item["target_id"], notification_id=item["event"]["id"],
                **({"destination":item["destination"]} if "destination" in item else {}))
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
        observed_session = self.radius_sessions.get((job.port_id, job.mac))
        if observed_session is not None:
            observed_session.observation_generation = uid()
            pending = self.radius_attempts.get((job.port_id, job.mac))
            if pending is not None and pending.session_owned:
                self.retire_authentication((job.port_id, job.mac))
                observed_session.renewal_started_ms = None
        ctr["in_octets"] += src.octets
        port = self.cfg.ports[job.port_id]
        session = self.session(job.port_id, job.mac) if port.authentication.control == "auto" else None
        vid = job.vid
        allowed = port.authentication.control == "force-authorized" and vid in port.admitted
        if session is not None:
            vid = self.session_vid(session)
            allowed = src.tag == "untagged" or src.tag == vid
        if not allowed or vid not in self.cfg.vlans or vid in port.forbidden:
            ctr["in_discards"] += 1
            status = self.radius_status.get((job.port_id, job.mac), {})
            if (port.authentication.control == "auto" and session is None and len(self.radius_attempts) < 8 and
                    (port.authentication.method == "mab" or status.get("status") == "waiting-activity") and
                    status.get("retry_at_ms", 0) <= self.sim_ms):
                try:
                    self.begin_authentication(job.port_id, job.mac,
                        mab_trigger=port.authentication.method == "mab" or status.get("method") == "mab")
                except CommandError:
                    self.radius_status[(job.port_id,job.mac)] = dict(status="blocked", reason="nas-identifier-override-required",
                        retry_at_ms=self.sim_ms + self.cfg.radius.failed_cycle_retry_seconds * 1000)
            # First rejection is visible; repeating rejections are counted without unbounded logs.
            if ctr["in_discards"] == 1:
                self.event("admission-rejected", endpoint_id=job.endpoint_id, vid=job.vid, port_id=job.port_id)
            return False
        ctr["in_ucast"] += 1
        if session is not None:
            session.last_activity_ms = self.sim_ms
            session.in_octets += src.octets
            session.in_packets += 1
        key = (self.cfg.vlans[vid].fdb_id, job.mac)
        old = self.fdb.get(key)
        if old is None and len(self.fdb) >= self.cfg.switch.fdb_limit:
            self.learned_discards += 1
            if self.learned_discards == 1:
                self.event("learning-capacity", limit=self.cfg.switch.fdb_limit)
            return False
        p = self.cfg.ports[job.port_id]
        self.fdb[key] = dict(fdb_id=key[0], mac=job.mac, vid=vid, port_id=p.id, bridge_port=p.bridge_port,
                             if_index=p.if_index, last_seen_ms=self.sim_ms,
                             expires_at_ms=self.sim_ms + self.cfg.switch.aging_seconds * 1000)
        if old is None or old["port_id"] != p.id:
            self.event("mac-learn" if old is None else "mac-move", mac=job.mac, vid=vid, port_id=p.id)
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
        estimated += sum(max(0,(target-session.accounting_next_ms)//(session.accounting_interval*1000)+1)
            for session in self.radius_sessions.values() if session.accounting_next_ms is not None)
        require(estimated <= 200000, "Advance would exceed 200,000 observations/snapshots; use smaller steps", 429)
        self.process_session_deadlines()
        self.prepare_authentication()
        if self.radius_attempts:
            return False
        heap = [(j.due, j.endpoint_id, j.source_id, j) for j in self.jobs.values()]
        heapq.heapify(heap)
        while True:
            candidates = []
            if heap:
                candidates.append(heap[0][0])
            if self.fdb:
                candidates.append(min(row["expires_at_ms"] for row in self.fdb.values()))
            retry = self.authentication_retry()
            if retry is not None:
                candidates.append(retry)
            session_deadline = self.next_session_deadline()
            if session_deadline is not None:
                candidates.append(session_deadline)
            accounting_deadline = self.next_accounting_deadline()
            if accounting_deadline is not None:
                candidates.append(accounting_deadline)
            if not candidates or min(candidates) > target:
                self.reach_time(target)
                return True
            deadline = min(candidates)
            self.reach_time(deadline)
            self.process_session_deadlines()
            self.expire()
            self.prepare_authentication()
            if self.radius_attempts:
                return False
            while heap and heap[0][0] == deadline:
                _, eid, sid, job = heapq.heappop(heap)
                self.observe(job)
                if self.valid(job):
                    source = next(s for s in self.cfg.endpoints[eid].sources if s.id == sid)
                    following = Job(**{**asdict(job), "due": deadline + source.interval_ms})
                    self.jobs[(eid, sid)] = following
                    heapq.heappush(heap, (following.due, eid, sid, following))
                if self.radius_attempts:
                    return False
            self.accounting_tick()

    def reset_operational(self, reboot=False, announce=True):
        for key in list(self.radius_sessions):
            self.end_session(key, "management-reboot" if reboot else "administrative-reset")
        if reboot and announce:
            self.queue_accounting(8, reason="management-reboot")
        self.cancel_outbox("canceled-on-reboot" if reboot else "canceled-on-reset")
        if self.advance_operation and self.advance_operation["status"] == "waiting":
            self.advance_operation.update(status="interrupted-on-boot" if reboot else "interrupted-on-reset", waiting_reason=None)
        self.epoch = uid()
        self.sim_ms = 0
        self.fdb.clear()
        self.jobs.clear()
        for key in list(self.radius_attempts):
            self.retire_authentication(key)
        self.radius_sessions.clear()
        self.radius_status.clear()
        self.renewal_budget.clear()
        self.renewal_budget_time = 0
        if reboot:
            self.configuration_incarnation = self.epoch
            self.pae.clear()
            self.last_auth_sessions.clear()
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
        saved = None
        if store:
            store.require_healthy()
            saved = store.load()
            if saved is not None:
                cfg = saved
        # Intake owns broad validation and detaches caller-owned input. Loaded
        # storage has already crossed its complete shape/reference boundary.
        if saved is None:
            cfg = Configuration.model_validate(cfg.model_dump(mode="json"))
        self.check_endpoint_capacity(cfg)
        self.check_source_capacity(cfg)
        self.lock = asyncio.Lock()
        self._closed = False
        self._closing = False  # RADIUS shutdown has begun: no new authentication work
        self.authentication = Authentication(self)
        self.accounting = Accounting(self)
        self.dynamic = DynamicAuthorization(self, store)
        self.idempotency = store.get("idempotency", {}) if store else {}
        for item in self.idempotency.values():
            operation = item.get("result", {}).get("advance")
            if operation and operation["status"] == "waiting":
                operation.update(status="interrupted-on-boot", waiting_reason=None)
        self.state = Runtime(cfg, revision=store.get("revision", 0) if store else 0)
        self.state.configuration_revision = store.get("configuration_revision", 0) if store else 0
        self.state.startup = split_configuration(cfg)[1]
        self.state.startup_revision = store.get("startup_revision", self.state.configuration_revision) if store else 0
        self.state.configuration_revision += 1
        if store:
            self.state.events = store.events()
            self.state.event_id = max((e["id"] for e in self.state.events), default=0)
            self.state.outbox = store.get("outbox", [])
            self.state.accounting_outbox = store.get("radius_accounting_outbox", [])
            self.state.accounting_sequence = store.get("radius_accounting_sequence", 0)
            self.state.accounting_drops = store.get("radius_accounting_drops", {})
            if len(self.state.accounting_outbox) > 1024 or len(json.dumps(self.state.accounting_outbox).encode()) > 8*1024*1024:
                raise ValueError("Invalid saved accounting queue")
        for record in list(self.state.accounting_outbox):
            if not self.state.accounting_policy_matches(record):
                self.state.accounting_outbox.remove(record)
                self.state.accounting_drop("configuration-change", record_id=record["id"])
        self.state.reset_operational(reboot=True, announce=False)
        self.state.event("boot")
        self.state.queue_accounting(7)
        self.state.revision += 1
        generations = self.dynamic.next_generations(self.state.cfg)
        metadata = {"radius_sender_generations": generations} if generations != self.dynamic.generations else None
        if store:
            store.commit(self.state, self.idempotency, **({"radius_metadata":metadata} if metadata else {}))
        self.dynamic.generations = generations

    @staticmethod
    def check_endpoint_capacity(cfg):
        require(len(cfg.endpoints) <= cfg.switch.endpoint_limit, "Endpoint capacity reached", 429)

    @staticmethod
    def check_source_capacity(cfg):
        require(sum(len(e.sources) for e in cfg.endpoints.values()) <= cfg.switch.source_limit, "Source capacity reached", 429)

    @property
    def closed(self):
        return self._closed

    @property
    def closing(self):
        """RADIUS shutdown has begun; no new authentication work starts."""
        return self._closing

    @property
    def storage_fault(self):
        return (self.store.fault_reason or ("storage_closed" if self.store.closed else None)) if self.store else None

    def require_storage(self):
        require(not self._closed, "Engine is closed", 503)
        if self.store:
            self.store.require_healthy()

    def storage_status(self):
        return dict(healthy=not self.storage_fault, reason=self.storage_fault,
                    snapshot="last_confirmed" if self.storage_fault else "current")

    def advance_status(self):
        operation = self.state.advance_operation
        if operation is None:
            return None
        public = {k: v for k, v in operation.items() if k != "epoch"}
        if self.storage_fault and public["status"] == "waiting":
            public.update(status="failed-on-storage", waiting_reason=None)
        return public

    async def continue_advance(self):
        async with self.lock:
            self.require_storage()
            operation = self.state.advance_operation
            if operation and operation["status"] == "waiting" and not self.state.radius_attempts:
                try:
                    return self._execute("advance-continue", {"id": operation["id"], "epoch": operation["epoch"]})
                except CommandError as error:
                    if error.status != 429:
                        raise
                    return self._execute("advance-fail", {"id": operation["id"]})

    def snapshot(self, *, diagnostics=True):
        s = self.state
        data = s.cfg.model_dump(mode="json")
        # Resource projections share serialization/redaction, but do not own a
        # native-helper integrity audit whose result they discard. Full state
        # remains fresh; native execution retains its independent pre-use gate.
        if diagnostics:
            from .radius import eap_capability
            data["radius"]["eap_capability"] = eap_capability()
        data["radius"]["server_status"] = self.authentication.server_status()

        try:
            resolve_nas_identity(s.cfg)
            data["radius"]["nas_identity_ready"] = True
        except RadiusError:
            data["radius"]["nas_identity_ready"] = False
        for target in [*data["radius"]["servers"], *data["radius"]["accounting"]["targets"], *data["radius"]["dynamic_authorization"]["senders"]]:
            target["has_secret"] = bool(target.pop("secret"))
        for material in data["radius"]["materials"].values():
            for name in ("certificate", "private_key", "key_password"):
                material["has_" + name] = bool(material.pop(name))
        profiles = [t["profile"] for t in data["radius"]["templates"].values()] + [src["supplicant"] for e in data["endpoints"].values() for src in e["sources"] if src["supplicant"] is not None]
        for profile in profiles:
            profile["has_password"] = bool(profile.pop("password"))
        for c in data["credentials"].values():
            community, auth_key, priv_key = (c.pop(k) for k in ("community", "auth_key", "priv_key"))
            if c["version"] == "2c":
                c.pop("username")
                c.pop("security_level")
                c.pop("auth_protocol")
                c.pop("priv_protocol")
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
        data["configuration_status"] = dict(unsaved=s.configuration_dirty, startup_revision=s.startup_revision)
        data["advance"] = self.advance_status()
        data["radius"]["dynamic_status"] = self.dynamic.status()
        data["radius"]["accounting_status"] = dict(queued=len(s.accounting_outbox), drops=s.accounting_drops.copy(),
            records=[{name: record[name] for name in ("id", "sequence", "session_id", "status_type", "simulation_ms", "status", "attempts", "late")} for record in s.accounting_outbox[:100]])
        data["authentication_clients"] = [dict(port_id=pid, mac=mac, **{k:v for k,v in status.items() if not k.startswith("_")}) for (pid, mac), status in s.radius_status.items()]
        data["authentication_sessions"] = [dict(id=session.id, port_id=session.port_id, mac=session.mac,
            method=session.method, vid=s.session_vid(session), source=session.policy.source,
            started_ms=session.started_ms, last_activity_ms=session.last_activity_ms,
            in_octets=session.in_octets, in_packets=session.in_packets,
            lease_deadline_ms=session.lease_deadline_ms, idle_deadline_ms=s.session_deadlines(session)[0],
            reauthentication_deadline_ms=s.session_deadlines(session)[2])
            for session in s.radius_sessions.values()]
        learned_counts = Counter(r["port_id"] for r in s.fdb.values())
        for pid, p in data["ports"].items():
            p.update(carrier=s.carrier(pid), operational_up=s.up(pid), attachments=s.attached(pid),
                     learned_count=learned_counts[pid], counters=s.counters[pid].copy())
        return data

    def export(self):
        c = self.state.cfg.model_dump(mode="json")
        # Deployment identity, security and destinations are deliberately absent.
        for port in c["ports"].values():
            port.pop("authentication")
        for endpoint in c["endpoints"].values():
            for source in endpoint["sources"]:
                source.pop("supplicant")
        return {"schema_version": 1, "ports": c["ports"], "vlans": c["vlans"], "endpoints": c["endpoints"],
                "attachments": c["attachments"], "paused": c["paused"],
                "lab_settings": {k: c["switch"][k] for k in ("legacy_vlan", "aging_seconds")}}

    async def execute(self, action, payload=None, expected=None, key=None, expected_config=None):
        payload = payload or {}
        async with self.lock:
            return self._execute(action, payload, expected, key, expected_config)

    async def close_radius(self, deadline_seconds=5):
        """Shut RADIUS down in one order: stop authentication so no grant can follow,
        end sessions and queue Accounting-Off, drain accounting, then close."""
        self._closing = True
        await self.authentication.stop()
        if not self.storage_fault and not self._closed:
            await self.execute("radius-shutdown")
            await self.accounting.drain(deadline_seconds)
        self._closed = True
        await self.accounting.stop()

    async def close_authentication(self):
        """Close without the accounting drain (tests and storage faults)."""
        self._closed = True
        await self.authentication.stop()

    def _cancel_inactive_work(self):
        self.authentication.cancel_inactive()
        self.accounting.cancel_inactive()
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

    def _execute(self, action, payload, expected=None, key=None, expected_config=None, radius_updates=None):
        self.require_storage()
        if action in ("accounting-event", "accounting-result") and not any(item["id"] == payload["id"] for item in self.state.accounting_outbox):
            return {"current": False, "revision": self.state.revision, "configuration_revision": self.state.configuration_revision, "simulation_ms": self.state.sim_ms}
        if action in ("radius-result", "radius-pae-events"):
            identity = (payload["port_id"], payload["mac"])
            attempt = self.state.current_attempt(identity, payload["attempt_id"])
            if attempt is None:
                return dict(accepted=False, reason="stale-attempt", revision=self.state.revision,
                            configuration_revision=self.state.configuration_revision, simulation_ms=self.state.sim_ms)
        if action == "advance" and payload.get("automatic") and (
                self.state.radius_attempts or self.state.advance_operation and self.state.advance_operation["status"] == "waiting"):
            return dict(revision=self.state.revision, configuration_revision=self.state.configuration_revision,
                        simulation_ms=self.state.sim_ms, advance=self.advance_status())
        signature = hashlib.sha256(json.dumps([action, payload], sort_keys=True).encode()).hexdigest() if key else None
        if key and key in self.idempotency:
            prior = self.idempotency[key]
            require(prior["signature"] == signature, "Idempotency key was used for another command")
            require(prior.get("configuration_incarnation", self.state.configuration_incarnation) == self.state.configuration_incarnation,
                    "Command belongs to an earlier running configuration; use a new idempotency key")
            return prior["result"]
        require(expected is None or expected == self.state.revision, "Stale state revision; reload and retry")
        require(expected_config is None or expected_config == self.state.configuration_revision, "Configuration changed while editing; reload and retry")
        old = self.state
        # Records own immutable captured payloads; only the history sequence is
        # appended to or trimmed. Other Runtime fields keep independent copies.
        memo = {id(old.events): old.events.copy()}
        # SET installs its separately copied candidate before touching cfg. Keep
        # the old published cfg immutable without copying it just to discard it.
        if action == "snmp-set":
            memo[id(old.cfg)] = old.cfg
        s = copy.deepcopy(old, memo)
        affected_e, affected_p = set(), set()
        result = self._apply(s, action, payload, affected_e, affected_p)
        # Published cfg is known-valid. _apply validates changed inputs and
        # their dependency closure before reconciliation or durable publication.
        if action in ("snmp-set", "port-edit", "switch-edit", "vlan-create", "vlan-edit", "vlan-delete"):
            s.configuration_events(old.cfg)
        s.reconcile_authentication(old)
        s.reconcile_accounting(old)
        if action == "reboot":
            s.queue_accounting(7)
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
        if action not in ("advance", "job", "reboot", "notification-result", "coldStart", "test-notification"):
            for pid in old.cfg.ports.keys() | s.cfg.ports.keys():
                before = pid in old.cfg.ports and old.up(pid)
                after = pid in s.cfg.ports and s.up(pid)
                if before != after:
                    affected_p.add(pid)
                    if pid in s.counters:
                        s.counters[pid]["last_change"] = s.uptime()
                    p = s.cfg.ports.get(pid) or old.cfg.ports[pid]
                    s.notify("linkUp" if after else "linkDown", enabled=p.link_notifications,
                             port_id=pid, if_index=p.if_index, admin=1 if p.admin_up else 2,
                             before=1 if before else 2, after=1 if after else 2)
            for fkey, row in list(s.fdb.items()):
                if row["port_id"] not in s.cfg.ports or row["vid"] not in s.cfg.vlans or not s.up(row["port_id"]) or (row["vid"] not in s.cfg.ports[row["port_id"]].admitted and not any(session.port_id == row["port_id"] and s.session_vid(session) == row["vid"] for session in s.radius_sessions.values())):
                    del s.fdb[fkey]
            for pid in affected_p & s.cfg.ports.keys():
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
                        {p.id for p in old.cfg.ports.values() if vid in getattr(p, field)} !=
                        {p.id for p in s.cfg.ports.values() if vid in getattr(p, field)}
                        for field in ("admitted", "untagged", "forbidden")) or (
                        {p.id for p in old.cfg.ports.values() if p.pvid == vid} !=
                        {p.id for p in s.cfg.ports.values() if p.pvid == vid}):
                    s.vlan_times[vid][1] = s.uptime()
        for vid in s.cfg.vlans.keys() & old.cfg.vlans.keys():
            if current_vlan_ports(s,vid) != current_vlan_ports(old,vid):
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
        durable = action not in ("advance", "job", "notification-result", "coldStart", "test-notification", "radius-begin", "radius-result", "radius-pae-events", "radius-discover", "source-authentication", "radius-session-action", "accounting-prune", "accounting-event", "accounting-result", "radius-shutdown", "radius-dynamic", "advance-continue", "advance-cancel", "advance-fail")
        if durable:
            s.configuration_revision += 1
        if action == "save-startup":
            s.startup = split_configuration(s.cfg)[1]
            s.startup_revision = s.configuration_revision
        elif action in ("port-create", "port-delete"):
            # Save only this inventory's default/new or removed policy rows.
            s.startup = reconciled_startup(s.startup, split_configuration(s.cfg)[0]["ports"])
            s.startup_revision = s.configuration_revision
        if durable:
            lab, logical = split_configuration(s.cfg)
            s.configuration_dirty = logical != reconciled_startup(s.startup, lab["ports"])
        result = dict(result or {}, revision=s.revision, configuration_revision=s.configuration_revision, simulation_ms=s.sim_ms)
        idem = copy.deepcopy(self.idempotency)
        if s.advance_operation:
            public_operation = {k:v for k,v in s.advance_operation.items() if k != "epoch"}
            for entry in idem.values():
                prior_operation = entry["result"].get("advance")
                if prior_operation and prior_operation["id"] == s.advance_operation["id"]:
                    entry["result"].update(advance=public_operation.copy(), simulation_ms=s.advance_operation["reached_ms"])
        if key:
            idem[key] = dict(signature=signature, result=result)
            if action not in ("save-startup", "reboot", "port-create", "port-delete") and split_configuration(old.cfg)[1] != split_configuration(s.cfg)[1]:
                idem[key]["configuration_incarnation"] = s.configuration_incarnation
            idem = dict(list(idem.items())[-256:])
        updates = self.dynamic.transaction_updates(action, s.cfg, radius_updates)
        if self.store:
            try:
                self.store.commit(s, idem, durable=durable, **({"radius_metadata":updates} if updates else {}),
                                  **({"save_startup":True} if action in ("save-startup", "port-create", "port-delete") else {}))
            except Exception:
                if self.storage_fault:
                    self._cancel_inactive_work()
                raise
        self.state, self.idempotency = s, idem
        self.dynamic.publish(updates)
        self.authentication.sync_health()
        self._cancel_inactive_work()
        return result

    def _apply(self, s, action, d, es, ps):
        cfg = s.cfg

        def get(collection, ident):
            require(ident in collection, "Resource not found", 404)
            return collection[ident]

        if action in ACCESS_ACTIONS:
            return apply_access(self, s, action, d)
        if action == "snmp-set":
            cfg = s.cfg = d.candidate.model_copy(deep=True)
            ps.update(d.affected_ports)
            es.update(e.id for e in cfg.endpoints.values()
                      if any(src.tag in d.creates | d.deletes for src in e.sources))
            s.vlan_deletes += len(d.deletes)
            s.event("snmp-set", assignments=len(d.assignments))
            for pid, action in d.pae_actions:
                if action == "initialize":
                    for key in [key for key in s.radius_sessions if key[0]==pid]:s.end_session(key,"port-initialized",cause=21)
                    for key,attempt in list(s.radius_attempts.items()):
                        if key[0]==pid:
                            s.retire_authentication(key)
                    for key in [key for key in s.radius_status if key[0]==pid]:s.radius_status.pop(key,None)
                    s.pae_port(pid).update(state=1,backend=7)
                elif cfg.ports[pid].authentication.control == "auto":
                    for key in [key for key in s.radius_sessions if key[0]==pid]:
                        s.retire_authentication(key)
                        s.request_renewal(key,automatic=False)
                if cfg.ports[pid].authentication.control == "auto" and s.up(pid):
                    for address in sorted({source.mac for eid in s.attached(pid) for source in cfg.endpoints[eid].sources}):
                        if s.session(pid,address) is None:
                            try:s.begin_authentication(pid,address)
                            except CommandError:
                                s.radius_status[(pid,address)] = dict(status="blocked",reason="local-configuration-error")
                control = cfg.ports[pid].authentication.control
                if action == "initialize" and control == "auto" and not any(key[0]==pid for key in s.radius_attempts):
                    s.pae_port(pid).update(state=3 if s.up(pid) else 2,backend=6)
                if control != "auto":s.pae_port(pid).update(state=8 if control=="force-authorized" else 9,backend=6)
                s.event("pae-"+action,port_id=pid)
            return
        if action == "endpoint-create":
            ep = Endpoint.model_validate(d)
            require(ep.id not in cfg.endpoints, "Endpoint ID already exists")
            cfg.endpoints[ep.id] = ep
            for source in ep.sources:
                cfg.check_profile(source.supplicant)
            self.check_endpoint_capacity(cfg)
            self.check_source_capacity(cfg)
            es.add(ep.id)
            s.event("endpoint-created", endpoint_id=ep.id)
            return {"id": ep.id}
        if action.startswith("endpoint-") or action in ("attach", "detach"):
            eid = d["id"]
            ep = get(cfg.endpoints, eid)
            before_port = cfg.attachments.get(eid)
            if action == "endpoint-delete":
                require(eid not in cfg.attachments, "Disconnect the endpoint before deleting it")
                del cfg.endpoints[eid]
                es.add(eid)
            elif action == "endpoint-edit":
                patch = dict(d["patch"])
                require(not set(patch) - {"name", "metadata", "active", "sources"}, "Unsupported endpoint field", 422)
                if "sources" in patch:
                    saved = {src.id: src for src in ep.sources}
                    patch["sources"] = [{**source, **({"supplicant": saved[source["id"]].supplicant.model_dump() if saved[source["id"]].supplicant else None}
                        if source.get("id") in saved and "supplicant" not in source else {})} for source in patch["sources"]]
                cfg.endpoints[eid] = Endpoint.model_validate({**ep.model_dump(), **patch, "revision": ep.revision+1})
                if "sources" in patch:
                    for source in cfg.endpoints[eid].sources:
                        cfg.check_profile(source.supplicant)
                    self.check_source_capacity(cfg)
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
            if action in ("attach", "detach"):
                after_port = cfg.attachments.get(eid)
                if before_port != after_port:
                    s.event(action, endpoint_id=eid, before_port_id=before_port, after_port_id=after_port)
            else:
                s.event(action, endpoint_id=eid, endpoint_name=cfg.endpoints[eid].name if eid in cfg.endpoints else ep.name)
            return {"id": eid}
        if action == "port-create":
            require(not set(d) - {"name", "speed", "mtu"}, "Unsupported port field", 422)
            require(len(cfg.ports) < 256, "Port limit reached (256)", 429)
            require(cfg.switch.next_bridge_port <= 65535, "Bridge port identity space exhausted", 429)
            require(cfg.switch.next_if_index <= 2147483647, "Interface identity space exhausted", 429)
            p = Port(bridge_port=cfg.switch.next_bridge_port, if_index=cfg.switch.next_if_index,
                     **{"name": f"Ethernet{cfg.switch.next_bridge_port}", **d})
            cfg.ports[p.id] = p
            cfg.switch.port_count += 1
            cfg.switch.next_bridge_port += 1
            cfg.switch.next_if_index += 1
            s.counters[p.id] = dict(in_octets=0, in_ucast=0, in_discards=0,
                                   last_change=s.uptime(), discontinuity=s.uptime())
            ps.add(p.id)
            s.event("port-create", port_id=p.id)
            return {"id": p.id}
        if action == "port-delete":
            pid = d["id"]
            p = get(cfg.ports, pid)
            # Capture Stop and public history before removing their port context.
            for key in [key for key in s.radius_sessions if key[0] == pid]:
                s.end_session(key, "port-deleted", cause=6)
            for key in [key for key in s.radius_attempts if key[0] == pid]:
                s.retire_authentication(key)
            for eid in s.attached(pid):
                del cfg.attachments[eid]
                es.add(eid)
                s.event("detach", endpoint_id=eid, before_port_id=pid, after_port_id=None)
            s.event("port-delete", port_id=pid)
            del cfg.ports[pid]
            cfg.switch.port_count -= 1
            for rows in (s.counters, s.pgens, s.pae, s.last_auth_sessions):
                rows.pop(pid, None)
            for rows in (s.radius_status, s.renewal_budget):
                for key in [key for key in rows if key[0] == pid]:
                    del rows[key]
            ps.add(pid)
            return {"id": pid}
        if action == "port-edit":
            pid, patch = d["id"], d["patch"]
            p = get(cfg.ports, pid)
            require(not set(patch) - {"name", "alias", "admin_up", "mode", "shared_partner", "forced_down", "speed", "mtu", "pvid", "admitted", "untagged", "forbidden", "link_notifications", "authentication"}, "Unsupported port field", 422)
            if patch.get("mode") == "shared" and p.mode != "shared":
                patch = {**patch, "shared_partner": True}
            if patch.get("mode") == "direct":
                require(len(s.attached(pid)) <= 1, "Disconnect extra endpoints before selecting direct mode")
            if "pvid" in patch and patch["pvid"] != p.pvid and "untagged" not in patch:
                patch = {**patch, "untagged": sorted((set(p.untagged) - {p.pvid}) | {patch["pvid"]})}
            cfg.ports[pid] = Port.model_validate({**p.model_dump(), **patch})
            if {"pvid", "admitted", "untagged", "forbidden"} & patch.keys():
                cfg.check_port(pid, cfg.ports[pid])
            changed = {name for name in patch if getattr(cfg.ports[pid], name) != getattr(p, name)}
            if changed - {"name", "alias", "link_notifications"}:
                ps.add(pid)
        elif action == "vlan-create":
            v = Vlan.model_validate({"fdb_id": 1000+d["vid"], **d})
            require(v.vid not in cfg.vlans, "VLAN already exists")
            if any(existing.fdb_id == v.fdb_id for existing in cfg.vlans.values()):
                configuration_error("FDB IDs must be distinct")
            cfg.vlans[v.vid] = v
            # Re-creation invalidates explicit jobs that captured the absent VLAN.
            es.update(e.id for e in cfg.endpoints.values() if any(x.tag == v.vid for x in e.sources))
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
                        cfg.check_port(pid, p)
                        ps.add(pid)
                if cfg.switch.legacy_vlan == vid:
                    cfg.switch.legacy_vlan = 1
                es.update(e.id for e in cfg.endpoints.values() if any(x.tag == vid for x in e.sources))
        elif action == "switch-edit":
            require(not set(d) - {"name", "description", "contact", "location", "identity", "base_mac", "legacy_vlan", "aging_seconds", "fdb_limit", "endpoint_limit", "source_limit", "queue_limit"}, "Unsupported switch field", 422)
            previous_age = cfg.switch.aging_seconds
            cfg.switch = type(cfg.switch).model_validate({**cfg.switch.model_dump(), **d})
            if "legacy_vlan" in d and cfg.switch.legacy_vlan not in cfg.vlans:
                configuration_error("VLAN 1 and the legacy VLAN must exist")
            if "endpoint_limit" in d:
                self.check_endpoint_capacity(cfg)
            if "source_limit" in d:
                self.check_source_capacity(cfg)
            if previous_age != cfg.switch.aging_seconds:
                for row in s.fdb.values():
                    row["expires_at_ms"] = row["last_seen_ms"] + cfg.switch.aging_seconds*1000
                s.expire()
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
            require(action != "resume" or not s.advance_operation or s.advance_operation["status"] != "waiting",
                    "An advance owns the timeline; complete or cancel it before resuming")
            cfg.paused = action == "pause"
            s.event(action)
        elif action == "advance":
            require(not s.advance_operation or s.advance_operation["status"] != "waiting",
                    "An advance already owns the timeline: " + (s.advance_operation["id"] if s.advance_operation else ""))
            require(d.get("automatic", False) or cfg.paused, "Pause the clock before manual advancement")
            require(type(d["duration_ms"]) is int and 0 < d["duration_ms"] <= 86400000, "Duration must be 1–86400000 ms", 422)
            start = s.sim_ms
            if not s.advance(d["duration_ms"]):
                s.advance_operation = dict(id=uid(), epoch=s.epoch, status="waiting", start_ms=start,
                    target_ms=start + d["duration_ms"], reached_ms=s.sim_ms, waiting_reason="authentication")
                return {"advance": {k:v for k,v in s.advance_operation.items() if k != "epoch"}}
        elif action in ("advance-continue", "advance-cancel", "advance-fail"):
            operation = s.advance_operation
            require(operation is not None and operation["id"] == d["id"], "This advance is no longer current")
            if operation["status"] == "waiting":
                if action in ("advance-cancel", "advance-fail"):
                    operation.update(status="canceled" if action == "advance-cancel" else "failed-on-guard", waiting_reason=None)
                else:
                    require(operation["epoch"] == s.epoch == d["epoch"], "Advance belongs to an earlier simulation")
                    reached = s.advance(operation["target_ms"] - s.sim_ms)
                    operation.update(reached_ms=s.sim_ms, status="completed" if reached else "waiting",
                                     waiting_reason=None if reached else "authentication")
            return {"advance": {k:v for k,v in operation.items() if k != "epoch"}}
        elif action == "job":
            return {"accepted": s.observe(Job(**d))}
        elif action == "save-startup":
            s.event("configuration-saved")
        elif action == "reboot":
            restored = compose_configuration(split_configuration(cfg)[0], s.startup)
            # Capture Stop/Off with the old session and target policy, then reset
            # against startup on the current physical lab. Reconciliation below
            # cancels revoked generations; it never restores old protocol queues.
            for key in list(s.radius_sessions):
                s.end_session(key, "management-reboot")
            s.queue_accounting(8, reason="management-reboot")
            self.check_endpoint_capacity(restored)
            self.check_source_capacity(restored)
            s.cfg = restored
            s.reset_operational(reboot=True, announce=False)
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
            imported = copy.deepcopy(d)
            for pid, fields in imported["ports"].items():
                require("authentication" not in fields, "Scenario cannot contain port authentication settings", 422)
                fields["authentication"] = cfg.ports[pid].authentication.model_dump()
            saved_profiles = {(eid, src.id): src.supplicant for eid, endpoint in cfg.endpoints.items() for src in endpoint.sources}
            for eid, endpoint in imported["endpoints"].items():
                for fields in endpoint["sources"]:
                    require("supplicant" not in fields, "Scenario cannot contain supplicant security settings", 422)
                    profile = saved_profiles.get((eid, fields["id"]))
                    fields["supplicant"] = profile.model_dump() if profile else None
            merged = {**cfg.model_dump(mode="json"), **{k: v for k, v in imported.items() if k not in ("lab_settings", "schema_version")}}
            merged["switch"].update(d["lab_settings"])
            s.cfg = Configuration.model_validate(merged)
            self.check_endpoint_capacity(s.cfg)
            self.check_source_capacity(s.cfg)
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
                    cfg.check_snmp_limit("credentials")
                    cfg.check_credential(credential, unique=True)
                    fields["credential_id"] = credential.id
                    s.event("credential-save", resource_id=credential.id, resource_label=event_resource_label(credential))
            if action == "credential-save":
                obj = merge_credential(cfg, previous, fields)
                if obj.version == "3" and obj.group_id not in s.cfg.groups:
                    require(obj.group_id is None, "Unknown SNMPv3 group", 422)
            elif action == "group-save":
                obj = cls.model_validate(merge_policy(previous.model_dump() if previous else {}, fields))
            else:
                obj = cls.model_validate({**(previous.model_dump() if previous else {}), **fields})
            collection[obj.id] = obj
            family = {"credential-save": "credentials", "group-save": "groups", "view-save": "views", "target-save": "targets"}[action]
            cfg.check_snmp_limit(family)
            if action == "credential-save":
                cfg.check_credential(obj, unique=True)
            elif action == "group-save":
                cfg.check_policy(obj)
            elif action == "target-save":
                cfg.check_target(obj)
            s.event(action, resource_id=obj.id, resource_label=event_resource_label(obj))
            return {"id": obj.id, **({"credential_id": obj.credential_id} if action == "target-save" else {})}
        elif action in ("credential-delete", "group-delete", "view-delete", "target-delete"):
            collection = {"credential-delete": cfg.credentials, "group-delete": cfg.groups, "view-delete": cfg.views, "target-delete": cfg.targets}[action]
            previous = get(collection, d["id"])
            del collection[d["id"]]
            if action == "credential-delete":
                for target in cfg.targets.values():
                    if target.credential_id == d["id"]:
                        cfg.check_target(target)
            elif action == "group-delete":
                for credential in cfg.credentials.values():
                    if credential.version == "3" and credential.group_id == d["id"]:
                        cfg.check_credential(credential)
            elif action == "view-delete":
                for policy in [c for c in cfg.credentials.values() if c.version == "2c"] + list(cfg.groups.values()):
                    if d["id"] in (policy.polling.view_id, policy.writing.view_id):
                        cfg.check_policy(policy)
            s.event(action, resource_id=d["id"], resource_label=event_resource_label(previous))
        elif action == "coldStart":
            s.notify("coldStart")
        elif action == "test-notification":
            require(s.gate(), "SNMP disabled: configure identity and enable SNMP", 409)
            target = get(cfg.targets, d["target_id"])
            require(target.enabled and cfg.credentials[target.credential_id].enabled, "Notification target is disabled")
            event = s.event("coldStart", status="committed", test=True)
            require(len(s.outbox) < cfg.switch.queue_limit, "Notification queue is full", 429)
            s.outbox.append(dict(event=event, target_id=target.id, destination=event_resource_label(target)))
            s.event("notification", status="queued", target_id=target.id, notification_id=event["id"], destination=event_resource_label(target))
        elif action == "notification-result":
            if s.outbox and s.outbox[0]["event"]["id"] == d["notification_id"] and s.outbox[0]["target_id"] == d["target_id"]:
                item = s.outbox.pop(0)
                if "destination" in item:
                    d = {**d, "destination":item["destination"]}
            s.event("notification", **d)
        else:
            raise CommandError(404, "Unknown command")
