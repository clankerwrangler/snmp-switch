from __future__ import annotations

import asyncio
import base64
import copy
import hashlib
import heapq
import json
import ipaddress
import math
import time
from dataclasses import asdict, dataclass, field, replace

from .mib import entity_inventory, plan_set, current_vlan_ports
from .storage import split_configuration, compose_configuration, reconciled_startup
from .radius import AccessResult, Authorization, NasIdentity, RadiusError, authorization, resolve_nas_identity, access_attributes, mab_username, encode_attributes
from .models import Configuration, Credential, CredentialAuth, Community, UsmUser, AccessGroup, PollingAccess, WritingAccess, incoming_policy, Endpoint, Port, SnmpSettings, Source, Target, View, Vlan, RadiusSettings, RadiusServer, RadiusMaterial, SupplicantProfile, SupplicantTemplate, DynamicSettings, DynamicSender, uid


def _clock_origin():
    from pathlib import Path
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        return "process:" + uid()


ACCOUNTING_CLOCK_ORIGIN = _clock_origin()


def accounting_elapsed_clock():
    return time.clock_gettime(time.CLOCK_BOOTTIME) if hasattr(time, "CLOCK_BOOTTIME") else time.monotonic()


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


def merge_supplicant(previous, fields):
    if fields is None:
        return None
    fields = dict(fields)
    method = fields.get("method", previous.method if previous else None)
    if previous is None or method != previous.method:
        required = {"identity", "trust_id", "server_name"} | ({"username", "password"} if method == "peap" else {"client_identity_id"})
        require(required <= fields.keys(), "Select the active identity, trust and credentials for this supplicant type", 422)
    elif fields.get("password") == "":
        fields.pop("password")
    return SupplicantProfile.model_validate({**(previous.model_dump() if previous else {}), **fields})


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


@dataclass(frozen=True)
class AuthenticationAttempt:
    id: str
    session_id: str
    port_id: str
    mac: str
    epoch: str
    context: str = field(repr=False)
    method: str = "tls"
    state: bytes | None = field(default=None, repr=False)
    prior_session_id: str | None = None
    nas_identity: NasIdentity | None = field(default=None, repr=False)
    session_owned: bool = False
    automatic_renewal: bool = False
    prior_grant_generation: str | None = None
    username: bytes | None = field(default=None, repr=False)
    state_server_id: str | None = None
    state_server_signature: str | None = field(default=None, repr=False)
    pae_state: int | None = None
    pae_backend: int | None = None


@dataclass
class AccessSession:
    id: str
    port_id: str
    mac: str
    method: str
    policy: Authorization = field(repr=False)
    started_ms: int = 0
    last_activity_ms: int | None = None
    in_octets: int = 0
    in_packets: int = 0
    nas_identity: NasIdentity | None = field(default=None, repr=False)
    grant_generation: str = field(default_factory=uid)
    observation_generation: str = field(default_factory=uid)
    last_auth_ms: int = 0
    idle_origin_ms: int = 0
    lease_deadline_ms: int | None = None
    renewal_started_ms: int | None = None
    renewal_automatic: bool = False
    accounting_identity: tuple = field(default=(), repr=False)
    user_name: bytes | None = field(default=None, repr=False)
    accounting_interval: int = 0
    accounting_next_ms: int | None = None
    auth_server_id: str | None = None
    auth_server_signature: str | None = field(default=None, repr=False)


@dataclass(repr=False)
class AuthServerHealth:
    signature: str
    available: bool | None = None
    failures: int = 0
    probe_after: float = 0
    probe_owner: str | None = None


@dataclass
class Runtime:
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

    def pae_port(self, pid):
        return self.pae.setdefault(pid, dict(counters=[0]*8, diagnostics=[0]*4, precise=True,
            version=None, last_version=None, last_source=None, state=2, backend=6))

    def retire_authentication(self, key):
        attempt = self.radius_attempts.get(key)
        if attempt is not None:
            # Queued native events can arrive after this capture becomes stale.
            # Preserve numeric history, but stop claiming complete observation.
            if attempt.method != "mab":
                self.pae_port(key[0])["precise"] = False
            del self.radius_attempts[key]

    def pae_observe(self, key, attempt_id, events):
        attempt = self.current_attempt(key, attempt_id)
        if attempt is None or attempt.method == "mab":return False
        port = self.pae_port(key[0])
        state, backend = attempt.pae_state, attempt.pae_backend
        for event in events:
            direction, version, kind, code, identifier, method = event[:6]
            port["version"] = version
            counters = port["counters"]
            if direction == 1:
                counters[0] += 1
                port["last_version"], port["last_source"] = version, bytes(event[8:14])
                if kind == 1:counters[2] += 1
                elif kind == 2:counters[3] += 1
                elif kind == 0 and code == 2:
                    counters[4 if method == 1 else 5] += 1
                    backend = 2
                    if method == 1 and state == 3:
                        state = 4
                        port["diagnostics"][0] += 1
            else:
                counters[1] += 1
                if kind == 0 and code == 1:
                    counters[6 if method == 1 else 7] += 1
                    backend = 1
        self.radius_attempts[key] = replace(attempt, pae_state=state, pae_backend=backend)
        if self.cfg.ports[key[0]].authentication.host_mode != "multi-auth":
            port["state"], port["backend"] = state, backend
        return True

    def pae_finish(self, attempt, outcome):
        if attempt.method == "mab":return
        port = self.pae_port(attempt.port_id)
        state, backend = attempt.pae_state, attempt.pae_backend
        if state == 4 and outcome in ("success", "reject", "timeout"):
            index, state, backend = {"success":(1,5,3), "reject":(3,7,4), "timeout":(2,6,5)}[outcome]
            port["diagnostics"][index] += 1
        elif outcome == "local":
            state, backend = None, None
        if self.cfg.ports[attempt.port_id].authentication.host_mode != "multi-auth":
            port["state"], port["backend"] = state, backend

    def begin_authentication(self, pid, address, *, mab_trigger=False, automatic=False, renewal=False):
        p = self.cfg.ports[pid]
        key = (pid, address)
        prior = self.radius_sessions.get(key)
        context = self.authentication_context(pid, address)
        session_owned = bool((automatic or renewal) and prior is not None and prior.method == "mab" and context is None)
        if session_owned:
            context = self.session_authentication_context(key)
            mab_trigger = True
        require(context is not None, "No current automatic authentication subject")
        if key in self.radius_attempts:
            return {"attempt_id": self.radius_attempts[key].id}
        previous = self.radius_status.get(key, {})
        if p.authentication.host_mode != "multi-auth" and any(other[0] == pid and other != key for other in self.radius_attempts.keys() | self.radius_sessions.keys()):
            self.radius_status[key] = dict(status="blocked", reason="host-mode-limit", _context=context)
            if previous.get("reason") != "host-mode-limit":
                self.event("authentication-blocked", port_id=pid, mac=address, reason="host-mode-limit")
            return {"blocked": True, "reason": "host-mode-limit"}
        profiles = [src.supplicant for eid in self.attached(pid) for src in self.cfg.endpoints[eid].sources if src.mac == address and src.supplicant is not None]
        prior = self.radius_sessions.get(key)
        use_mab = p.authentication.method == "mab" or mab_trigger
        if use_mab:
            require(p.authentication.method != "dot1x", "This port does not permit MAB")
            if not mab_trigger and prior is None:
                self.radius_status[key] = dict(status="waiting-activity", method="mab", _context=context)
                return {"waiting": True}
            method = "mab"
        elif not profiles:
            if previous.get("status") != "discovering" or previous.get("_context") != context:
                self.radius_status[key] = dict(status="discovering", method="dot1x", _context=context,
                    discovery_due_ms=self.sim_ms + self.cfg.radius.discovery_seconds * 1000)
                self.event("authentication-discovery", port_id=pid, mac=address)
            elif previous["discovery_due_ms"] <= self.sim_ms:
                fallback = p.authentication.method == "dot1x-mab" and p.authentication.fallback_no_supplicant
                self.radius_status[key] = dict(status="waiting-activity" if fallback else "failed", reason="no-supplicant",
                    method="mab" if fallback else "dot1x", _context=context,
                    retry_at_ms=self.sim_ms if fallback else self.sim_ms + self.cfg.radius.failed_cycle_retry_seconds * 1000)
                self.event("authentication-no-supplicant", port_id=pid, mac=address, mab_fallback=fallback)
            return {"waiting": True}
        elif any(profile != profiles[0] for profile in profiles):
            self.radius_status[key] = dict(status="blocked", reason="profile-conflict", _context=context)
            if previous.get("reason") != "profile-conflict" or previous.get("_context") != context:
                self.event("authentication-blocked", port_id=pid, mac=address, reason="profile-conflict")
            return {"blocked": True, "reason": "profile-conflict"}
        else:
            method = profiles[0].method
        try:
            nas_identity = resolve_nas_identity(self.cfg)
        except RadiusError:
            raise CommandError(422, "Configure a representable explicit NAS identifier for RADIUS") from None
        if automatic and not self.reserve_renewal(key):
            return {"blocked": True, "reason": "renewal-work-limit"}
        attempt = AuthenticationAttempt(uid(), prior.id if prior else uid(), pid, address, self.epoch, context, method,
            prior.policy.state if prior and prior.policy.termination_action == 1 else None,
            prior.id if prior else None, nas_identity, session_owned, automatic,
            prior.grant_generation if prior else None,
            mab_username(address, self.cfg.radius) if method == "mab" else profiles[0].identity.encode(),
            prior.auth_server_id if prior else None,
            prior.auth_server_signature if prior else None)
        if method != "mab":
            attempt = replace(attempt, pae_state=3, pae_backend=6)
            if p.authentication.host_mode != "multi-auth":
                self.pae_port(pid).update(state=3, backend=6)
        self.radius_attempts[key] = attempt
        self.radius_status[key] = dict(status="pending", method=attempt.method, attempt_id=attempt.id)
        self.event("authentication-started", port_id=pid, mac=address, attempt_id=attempt.id, method=method)
        return {"attempt_id": attempt.id}

    def authentication_candidates(self):
        subjects = sorted({(pid, src.mac) for eid,pid in self.cfg.attachments.items()
            if self.up(pid) and self.cfg.ports[pid].authentication.control == "auto" and self.cfg.ports[pid].authentication.method != "mab"
            for src in self.cfg.endpoints[eid].sources})
        for key in subjects:
            if key in self.radius_attempts or self.session(*key) is not None:
                continue
            previous = self.radius_status.get(key, {})
            context = self.authentication_context(*key)
            if previous.get("_context") == context:
                if previous.get("status") == "waiting-activity" or previous.get("reason") == "profile-conflict":
                    continue
                if previous.get("reason") == "host-mode-limit" and any(other[0] == key[0] and other != key for other in self.radius_attempts.keys() | self.radius_sessions.keys()):
                    continue
                if max(previous.get("retry_at_ms", 0), previous.get("discovery_due_ms", 0)) > self.sim_ms:
                    continue
            yield key, context

    def prepare_authentication(self):
        for key, context in self.authentication_candidates():
            if len(self.radius_attempts) >= 8:
                break
            try:
                self.begin_authentication(*key)
            except CommandError as error:
                self.radius_status[key] = dict(status="blocked", reason="nas-identifier-override-required" if error.status == 422 else "local-configuration-error",
                    _context=context, retry_at_ms=self.sim_ms + self.cfg.radius.failed_cycle_retry_seconds * 1000)

    def authentication_retry(self):
        times = []
        for key,status in self.radius_status.items():
            if self.authentication_context(*key) is None or self.session(*key) is not None:
                continue
            for name in ("discovery_due_ms", "retry_at_ms"):
                deadline = status.get(name)
                if deadline is not None and deadline > self.sim_ms and self.cfg.ports[key[0]].authentication.method != "mab":
                    times.append(deadline)
        return min(times, default=None)

    def authentication_context(self, port_id, address):
        p = self.cfg.ports.get(port_id)
        if p is None or not self.up(port_id) or p.authentication.control != "auto":
            return None
        sources = [(eid, src.id, src.model_dump(mode="json"))
                   for eid in sorted(self.attached(port_id)) for src in self.cfg.endpoints[eid].sources if src.mac == address]
        if not sources:
            return None
        if p.authentication.method == "mab":
            for _, _, source in sources:
                source["supplicant"] = None
        # A digest is an opaque capture, never a public credential fingerprint.
        # Reconciliation invalidates on each genuine change, including ABA.
        settings = self.cfg.radius.model_dump(mode="json", exclude={"materials", "templates", "accounting", "dynamic_authorization"})
        if settings["nas_identifier"] is None:
            settings["nas_identifier"] = self.cfg.switch.name
        for server in settings["servers"]:
            server.pop("label")
        material_ids = {ref for _, _, src in sources if src["supplicant"] for ref in
                        (src["supplicant"]["trust_id"], src["supplicant"]["client_identity_id"]) if ref}
        settings["materials"] = {mid: self.cfg.radius.materials[mid].model_dump(mode="json", exclude={"label"})
                                 for mid in material_ids}
        return hashlib.sha256(json.dumps([p.name, p.authentication.model_dump(), sorted(p.forbidden), sources, settings], sort_keys=True).encode()).hexdigest()

    def session_authentication_context(self, key):
        session = self.radius_sessions.get(key)
        p = self.cfg.ports.get(key[0])
        if (session is None or session.method != "mab" or p is None or not self.up(p.id) or
                p.authentication.control != "auto" or p.authentication.method == "dot1x"):
            return None
        settings = self.cfg.radius.model_dump(mode="json", exclude={"materials", "templates", "accounting", "dynamic_authorization"})
        if settings["nas_identifier"] is None:
            settings["nas_identifier"] = self.cfg.switch.name
        for server in settings["servers"]:
            server.pop("label")
        value = [self.epoch, key, session.id, session.grant_generation, session.observation_generation,
                 p.name, p.authentication.model_dump(), sorted(p.forbidden), settings]
        return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()

    def reach_time(self, value):
        if value > self.sim_ms:
            self.renewal_budget.clear()
            self.renewal_budget_time = value
        self.sim_ms = value

    def reserve_renewal(self, key):
        if self.renewal_budget_time != self.sim_ms:
            self.renewal_budget.clear()
            self.renewal_budget_time = self.sim_ms
        count = self.renewal_budget.get(key, 0)
        if count >= 64 or (key not in self.renewal_budget and len(self.renewal_budget) >= self.cfg.switch.source_limit):
            self.end_session(key, "renewal-work-limit")
            self.retire_authentication(key)
            self.radius_status[key] = dict(status="failed", reason="renewal-work-limit",
                _context=self.authentication_context(*key), retry_at_ms=self.sim_ms + self.cfg.radius.failed_cycle_retry_seconds * 1000)
            if self.advance_operation and self.advance_operation["status"] == "waiting":
                self.advance_operation.update(status="failed-on-guard", reached_ms=self.sim_ms, waiting_reason=None)
            self.event("authentication-work-limit", port_id=key[0], mac=key[1])
            return False
        self.renewal_budget[key] = count + 1
        return True

    def session_deadlines(self, session):
        idle = []
        if session.policy.idle_timeout is not None:
            idle.append(session.policy.idle_timeout * 1000)
        elif self.cfg.radius.inactivity_seconds:
            idle.append(self.cfg.radius.inactivity_seconds * 1000)
        activity = session.last_activity_ms if session.last_activity_ms is not None else session.idle_origin_ms
        idle_deadline = activity + min(idle) if idle else None
        termination = session.lease_deadline_ms if session.policy.termination_action == 0 else None
        renewal = []
        if session.policy.termination_action == 1 and session.lease_deadline_ms is not None:
            renewal.append(session.lease_deadline_ms)
        if session.policy.session_timeout is None and self.cfg.radius.reauthentication_seconds:
            renewal.append(session.last_auth_ms + self.cfg.radius.reauthentication_seconds * 1000)
        return idle_deadline, termination, min(renewal) if renewal else None

    def next_session_deadline(self):
        candidates = []
        for key, session in self.radius_sessions.items():
            idle, termination, renewal = self.session_deadlines(session)
            candidates.extend(d for d in (idle, termination) if d is not None)
            if session.renewal_started_ms is None:
                if renewal is not None:
                    candidates.append(renewal)
            else:
                status = self.radius_status.get(key, {})
                if "discovery_due_ms" in status:
                    candidates.append(status["discovery_due_ms"])
        return max(self.sim_ms, min(candidates)) if candidates else None

    def request_renewal(self, key, *, automatic):
        session = self.radius_sessions.get(key)
        if session is None:
            return {"accepted": False, "reason": "session-ended"}
        session.renewal_started_ms = self.sim_ms
        session.renewal_automatic = automatic
        if self.authentication_context(*key) is None and session.method != "mab":
            self.radius_status[key] = dict(status="discovering", method="dot1x", reason="required-reauthentication",
                discovery_due_ms=self.sim_ms + self.cfg.radius.discovery_seconds * 1000, reauth_session_id=session.id)
            return {"waiting": True}
        return self.begin_authentication(*key, automatic=automatic, renewal=True)

    def process_session_deadlines(self):
        # Independent termination precedes reauthentication and all same-time data.
        for key, session in list(self.radius_sessions.items()):
            idle, termination, _ = self.session_deadlines(session)
            reason = ("idle-timeout" if idle is not None and idle <= self.sim_ms else
                      "session-timeout" if termination is not None and termination <= self.sim_ms else None)
            if reason:
                self.end_session(key, reason)
                self.radius_status[key] = dict(status="waiting-activity", method="configured", reason=reason,
                    _context=self.authentication_context(*key))
        for key, session in list(self.radius_sessions.items()):
            _, _, renewal = self.session_deadlines(session)
            if session.renewal_started_ms is None and (renewal is None or renewal > self.sim_ms):
                continue
            if key in self.radius_attempts:
                continue
            status = self.radius_status.get(key, {})
            if session.renewal_started_ms is None:
                session.renewal_started_ms = self.sim_ms
                session.renewal_automatic = True
                if self.authentication_context(*key) is None and session.method != "mab":
                    self.radius_status[key] = dict(status="discovering", method="dot1x", reason="required-reauthentication",
                        discovery_due_ms=self.sim_ms + self.cfg.radius.discovery_seconds * 1000, reauth_session_id=session.id)
                    continue
            elif status.get("discovery_due_ms", self.sim_ms) > self.sim_ms:
                continue
            if self.authentication_context(*key) is None and session.method != "mab":
                self.end_session(key, "no-supplicant")
                self.radius_status[key] = dict(status="failed", reason="no-supplicant",
                    retry_at_ms=self.sim_ms + self.cfg.radius.failed_cycle_retry_seconds * 1000)
                continue
            try:
                result = self.begin_authentication(*key, automatic=session.renewal_automatic, renewal=True)
            except CommandError:
                self.end_session(key, "reauthentication-configuration-error")
                self.radius_status[key] = dict(status="failed", reason="reauthentication-configuration-error",
                    _context=self.authentication_context(*key), retry_at_ms=self.sim_ms + self.cfg.radius.failed_cycle_retry_seconds * 1000)
                continue
            if key in self.radius_sessions and self.radius_status.get(key, {}).get("status") in ("failed", "waiting-activity"):
                # No active renewal exchange can keep an old grant alive indefinitely.
                final_status = self.radius_status[key]
                self.end_session(key, final_status.get("reason", "no-supplicant"))
                self.radius_status[key] = final_status

    def current_attempt(self, key, attempt_id):
        attempt = self.radius_attempts.get(key)
        session = self.radius_sessions.get(key)
        if (attempt is None or attempt.id != attempt_id or attempt.epoch != self.epoch or
                (self.session_authentication_context(key) if attempt.session_owned else self.authentication_context(*key)) != attempt.context or
                (session.id if session else None) != attempt.prior_session_id or
                (session.grant_generation if session else None) != attempt.prior_grant_generation):
            return None
        return attempt

    def session(self, port_id, address):
        p = self.cfg.ports[port_id]
        if p.authentication.host_mode == "multi-host":
            return next((session for (pid, _), session in self.radius_sessions.items() if pid == port_id), None)
        return self.radius_sessions.get((port_id, address))

    def session_vid(self, session):
        return self.cfg.ports[session.port_id].pvid if session.policy.source == "port-default" else session.policy.vid

    def accounting_drop(self, reason, **details):
        count = self.accounting_drops.get(reason, 0) + 1
        self.accounting_drops[reason] = count
        if count == 1 or count & (count - 1) == 0:
            self.event("accounting", status="dropped", reason=reason, count=count, **details)

    def accounting_period(self, session):
        local = self.cfg.radius.accounting.interim_seconds
        return (session.policy.interim_seconds or 0) if local is None else local

    def queue_accounting(self, status_type, session=None, *, cause=None, reason=None, late=False, effective_vid=None):
        settings = self.cfg.radius.accounting
        targets = [target for target in settings.targets if target.enabled]
        if not settings.enabled or not targets:
            return
        try:
            if session is not None:
                values = list(session.accounting_identity)
                if session.user_name is not None:
                    values.append((1, session.user_name))
                values.extend((25,value) for value in session.policy.classes)
                vid = self.session_vid(session) if effective_vid is None else effective_vid
                values.extend(((64,(13).to_bytes(4,"big")), (65,(6).to_bytes(4,"big")), (81,str(vid).encode())))
                if status_type in (2,3):
                    elapsed = (self.sim_ms - session.started_ms) // 1000
                    if not 0 <= elapsed <= 0xffffffff or session.in_octets > 0xffffffffffffffff:
                        raise RadiusError("accounting-value-range")
                    values.extend(((46,elapsed.to_bytes(4,"big")), (42,(session.in_octets & 0xffffffff).to_bytes(4,"big")),
                        (52,(session.in_octets >> 32).to_bytes(4,"big")), (47,(session.in_packets & 0xffffffff).to_bytes(4,"big"))))
                if status_type == 2 and cause is not None:
                    values.append((49,cause.to_bytes(4,"big")))
            else:
                nas = resolve_nas_identity(self.cfg)
                values = [(32,nas.identifier)] + ([(4,nas.ipv4)] if nas.ipv4 is not None else [])
            # Leave room for Status-Type and changing real Delay-Time, with no truncation.
            if 20 + len(encode_attributes(values)) + 12 > 4095:
                raise RadiusError("packet_budget")
        except (RadiusError, OverflowError):
            self.accounting_drop("representation", session_id=session.id if session else None)
            return
        self.accounting_sequence += 1
        created = time.time()
        record = dict(id=uid(), sequence=self.accounting_sequence, session_id=session.id if session else "nas-lifecycle",
            status_type=status_type, attributes=[[kind,base64.b64encode(value).decode()] for kind,value in values],
            simulation_ms=self.sim_ms, original_start_ms=session.started_ms if session else None,
            cumulative_octets=session.in_octets if session else None, cumulative_packets=session.in_packets if session else None,
            generated_wall=created, expires_wall=created+300, generated_elapsed=accounting_elapsed_clock(),
            clock_origin=ACCOUNTING_CLOCK_ORIGIN, status="queued", attempts=0, late=late, reason=reason,
            targets=[dict(id=target.id, signature=Engine._server_signature(target)) for target in targets],
            delivery_policy={name:getattr(settings,name) for name in
                ("response_timeout_seconds","attempts","retry_backoff_seconds")})
        size = lambda item: len(json.dumps(item,sort_keys=True,separators=(",", ":")).encode())
        if len(self.accounting_outbox) >= 1024 or sum(size(item) for item in self.accounting_outbox) + size(record) > 8*1024*1024:
            self.accounting_drop("overflow", session_id=record["session_id"])
            return
        self.accounting_outbox.append(record)
        self.event("accounting", status="queued", record_id=record["id"], session_id=record["session_id"], accounting_type=status_type, late=late)

    def accounting_policy_matches(self, record):
        settings = self.cfg.radius.accounting
        return (settings.enabled and
                record["targets"] == [dict(id=target.id, signature=Engine._server_signature(target))
                                      for target in settings.targets if target.enabled] and
                record["delivery_policy"] == {name: getattr(settings, name) for name in
                    ("response_timeout_seconds", "attempts", "retry_backoff_seconds")})

    def reconcile_accounting(self, before):
        shape = lambda c: (c.enabled,c.response_timeout_seconds,c.attempts,c.retry_backoff_seconds,
            [(target.id, target.enabled, Engine._server_signature(target)) for target in c.targets])
        changed = shape(self.cfg.radius.accounting) != shape(before.cfg.radius.accounting)
        if changed:
            count = len(self.accounting_outbox)
            self.accounting_outbox.clear()
            for _ in range(count):
                self.accounting_drop("configuration-change")
        for session in self.radius_sessions.values():
            interval = self.accounting_period(session) if self.cfg.radius.accounting.enabled else 0
            if changed or interval != session.accounting_interval:
                session.accounting_interval = interval
                session.accounting_next_ms = self.sim_ms + interval*1000 if interval else None
            if changed and self.cfg.radius.accounting.enabled:
                self.queue_accounting(1, session, late=True)

    def accounting_tick(self):
        for session in self.radius_sessions.values():
            if session.accounting_next_ms is not None and session.accounting_next_ms <= self.sim_ms:
                self.queue_accounting(3, session)
                session.accounting_next_ms += session.accounting_interval * 1000

    def next_accounting_deadline(self):
        values = [s.accounting_next_ms for s in self.radius_sessions.values() if s.accounting_next_ms is not None]
        return min(values, default=None)

    def end_session(self, key, reason, *, cause=None, effective_vid=None):
        session = self.radius_sessions.pop(key, None)
        if session is None:
            return
        if cause is None:
            cause = {"lost-carrier":2, "idle-timeout":4, "session-timeout":5,
                "administrative-reset":6, "configuration-change":6, "manual-restart":6,
                "vlan-deleted":6, "vlan-forbidden":6, "reauthentication-policy-change":15,
                "supplicant-restart":19, "no-supplicant":20, "reauthentication-configuration-error":20,
                "renewal-work-limit":20, "port-initialized":21, "port-disabled":22,
                "management-reboot":7, "application-shutdown":11}.get(reason, 20 if session.renewal_started_ms is not None else 10)
        self.queue_accounting(2, session, cause=cause, reason=reason, effective_vid=effective_vid)
        if session.method != "mab" and cause in (4,5,6,9,10):
            self.pae_port(session.port_id).update(state=None,backend=6)
        if self.cfg.ports[session.port_id].authentication.host_mode != "multi-auth":
            pae_cause = {1:1,2:2,19:3,20:4,21:6,22:7}.get(cause)
            if cause == 6 and self.cfg.ports[session.port_id].authentication.control == "force-unauthorized":pae_cause=5
            self.last_auth_sessions[session.port_id] = dict(id=session.id, in_octets=session.in_octets,
                in_packets=session.in_packets, started_ms=session.started_ms, ended_ms=self.sim_ms, cause=pae_cause)
        # A terminated grant cannot be revived by its formerly pending reauth.
        pending = self.radius_attempts.get(key)
        if pending is not None and pending.prior_session_id == session.id:
            self.retire_authentication(key)
        shared = self.cfg.ports[session.port_id].authentication.host_mode == "multi-host"
        for fkey, row in list(self.fdb.items()):
            if row["port_id"] == session.port_id and (shared or row["mac"] == session.mac):
                del self.fdb[fkey]
        self.radius_status[key] = dict(status="ended", reason=reason, session_id=session.id)
        self.event("authentication-ended", port_id=session.port_id, mac=session.mac, session_id=session.id, reason=reason)

    def reconcile_authentication(self, before):
        for key, attempt in list(self.radius_attempts.items()):
            context = self.session_authentication_context(key) if attempt.session_owned else self.authentication_context(*key)
            if attempt.epoch != self.epoch or context != attempt.context or set(before.cfg.vlans) != set(self.cfg.vlans):
                self.retire_authentication(key)
                self.radius_status[key] = dict(status="invalidated", reason="configuration-change")
                if key in self.radius_sessions:
                    self.radius_sessions[key].renewal_started_ms = None
        for key, status in list(self.radius_status.items()):
            if status.get("_context") is not None and status["_context"] != self.authentication_context(*key):
                self.radius_status[key] = dict(status="invalidated", reason="configuration-change")
        for key, session in list(self.radius_sessions.items()):
            pid, address = key
            p = self.cfg.ports[pid]
            old = before.cfg.ports[pid]
            old_vid = old.pvid if session.policy.source == "port-default" else session.policy.vid
            reason = ("port-disabled" if not p.admin_up else "lost-carrier" if not self.up(pid) else
                      "administrative-reset" if p.authentication != old.authentication else
                      "vlan-deleted" if old_vid not in self.cfg.vlans else
                      "vlan-forbidden" if self.session_vid(session) in p.forbidden else None)
            if reason:
                self.end_session(key, reason, effective_vid=old_vid)

    def event(self, kind, **details):
        self.event_id += 1
        event = dict(id=self.event_id, kind=kind, simulation_ms=self.sim_ms, uptime=self.uptime(), revision=self.revision + 1, **details)
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
        if store:
            store.require_healthy()
            saved = store.load()
            if saved is not None:
                cfg = saved
        self.lock = asyncio.Lock()
        self._authentication_tasks = {}
        self._accounting_tasks = {}
        self._account_clock = accounting_elapsed_clock
        self._account_wall = time.time
        self._closed = False
        self._server_health = {}
        self._auth_clock = time.monotonic
        self._das_clock = accounting_elapsed_clock
        self._das_wall = time.time
        self._das_protocol = None
        self._das_closing = False
        self._das_pending = {}
        self._das_drops = {}
        self._das_error = None
        self._das_cache = store.radius_decisions() if store else {}
        self._das_high_water = store.get("radius_replay_high_water", 0) if store else 0
        self._das_generations = store.get("radius_sender_generations", {}) if store else {}
        if not isinstance(self._das_high_water, (int,float)) or not math.isfinite(self._das_high_water) or self._das_high_water < 0:
            raise ValueError("Invalid dynamic authorization clock state")
        for fingerprint,record in self._das_cache.items():
            if (not isinstance(fingerprint,str) or len(fingerprint)!=64 or
                    not isinstance(record.get("generation"),str) or not isinstance(record.get("sender_id"),str) or
                    not isinstance(record.get("expires_wall"),(int,float)) or not math.isfinite(record["expires_wall"]) or
                    not isinstance(record.get("expires_elapsed"),(int,float)) or not math.isfinite(record["expires_elapsed"]) or
                    not isinstance(record.get("clock_origin"),str)):
                raise ValueError("Invalid dynamic authorization receipt")
            if record.get("response") is not None:
                response = base64.b64decode(record["response"],validate=True)
                if not 20 <= len(response) <= 4096:raise ValueError("Invalid dynamic authorization response")
            if record.get("clock_origin") != ACCOUNTING_CLOCK_ORIGIN:
                record["expires_elapsed"] = self._das_clock() + max(0,record["expires_wall"]-self._das_wall())
                record["clock_origin"] = ACCOUNTING_CLOCK_ORIGIN
        self.idempotency = store.get("idempotency", {}) if store else {}
        for item in self.idempotency.values():
            operation = item.get("result", {}).get("advance")
            if operation and operation["status"] == "waiting":
                operation.update(status="interrupted-on-boot", waiting_reason=None)
        self.state = Runtime(cfg, revision=store.get("revision", 0) if store else 0)
        self.state.configuration_revision = store.get("configuration_revision", 0) if store else 0
        self.state.startup = (store.get("startup_configuration") if store else None) or split_configuration(cfg)[1]
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
        generations = self._next_dynamic_generations(self.state.cfg)
        metadata = {"radius_sender_generations": generations} if generations != self._das_generations else None
        if store:
            store.commit(self.state, self.idempotency, **({"radius_metadata":metadata} if metadata else {}))
        self._das_generations = generations

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

    def snapshot(self):
        s = self.state
        data = s.cfg.model_dump(mode="json")
        from .radius import eap_capability
        data["radius"]["eap_capability"] = eap_capability()
        now = self._auth_clock()
        data["radius"]["server_status"] = {sid: dict(status="unknown" if h.available is None else "available" if h.available else "probing" if h.probe_owner else "unavailable",
            retry_after_seconds=max(0, h.probe_after - now)) for sid,h in self._server_health.items()}
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
        data["radius"]["dynamic_status"] = dict(ready=bool(self._das_protocol and self._dynamic_current(self._das_protocol)),
            clock_safe=self.dynamic_clock_safe(), reason=self._das_error, cached=len(self._das_cache), pending=len(self._das_pending), drops=self._das_drops.copy())
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
        for pid, p in data["ports"].items():
            p.update(carrier=s.carrier(pid), operational_up=s.up(pid), attachments=s.attached(pid),
                     learned_count=sum(1 for r in s.fdb.values() if r["port_id"] == pid), counters=s.counters[pid].copy())
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

    @staticmethod
    def _server_signature(server):
        value = [server.address, server.port, server.source_address, server.secret]
        return hashlib.sha256(json.dumps(value).encode()).hexdigest()

    def _sync_server_health(self):
        current = {server.id: server for server in self.state.cfg.radius.servers}
        for identity in list(self._server_health):
            if identity not in current:
                del self._server_health[identity]
        for identity, server in current.items():
            signature = self._server_signature(server)
            if identity not in self._server_health or self._server_health[identity].signature != signature:
                self._server_health[identity] = AuthServerHealth(signature)

    def _take_server(self, server, attempt_id):
        self._sync_server_health()
        health = self._server_health.get(server.id)
        if health is None or health.signature != self._server_signature(server):
            return None
        if health.available is False:
            if self._auth_clock() < health.probe_after or health.probe_owner not in (None, attempt_id):
                return None
            health.probe_owner = attempt_id
        return health

    def _server_response(self, server_id, health, key, attempt_id):
        # This synchronous callback observes a cryptographically verified packet,
        # not a grant. It runs on the same event loop and never performs I/O.
        if (self._closed or self.storage_fault or self._server_health.get(server_id) is not health or
                self.state.current_attempt(key, attempt_id) is None):
            return
        health.available, health.failures, health.probe_after, health.probe_owner = True, 0, 0, None

    def _server_exhausted(self, server_id, health, key, attempt_id):
        if (self._closed or self.storage_fault or self._server_health.get(server_id) is not health or
                self.state.current_attempt(key, attempt_id) is None):
            return
        health.failures += 1
        health.available = False
        health.probe_after = self._auth_clock() + (1, 2, 4, 8, 16, 30)[min(health.failures - 1, 5)]

    def _release_server(self, server_id, health, attempt_id):
        if self._server_health.get(server_id) is health and health.probe_owner == attempt_id:
            health.probe_owner = None

    def _cancel_inactive_authentication(self):
        current = {a.id for a in self.state.radius_attempts.values()} if not self.storage_fault and not self._closed else set()
        try:
            running = asyncio.current_task()
        except RuntimeError:
            running = None
        for identity, task in self._authentication_tasks.items():
            if identity not in current and task is not running and not task.done() and not task.cancelling():
                task.cancel()
        for identity, task in self._accounting_tasks.items():
            if self.accounting_current(identity) is None and task is not running and not task.done() and not task.cancelling():
                task.cancel()

    async def service_authentication(self):
        """Bounded process tasks refer to Runtime attempts; they do not own grants."""
        active = {attempt.id for attempt in self.state.radius_attempts.values()} if not self.storage_fault and not self._closed else set()
        for identity, task in list(self._authentication_tasks.items()):
            if identity not in active and not task.cancelling():
                task.cancel()
            if task.done():
                try:
                    task.result()
                except (asyncio.CancelledError, CommandError):
                    pass
                finally:
                    del self._authentication_tasks[identity]
        if self.storage_fault or self._closed:
            return
        # Avoid empty transactions on every refresh; the real transaction alone allocates IDs.
        deadline = self.state.next_session_deadline()
        if (deadline is not None and deadline <= self.state.sim_ms or
                len(self.state.radius_attempts) < 8 and next(self.state.authentication_candidates(), None) is not None):
            await self.execute("radius-discover")
        for key, attempt in self.state.radius_attempts.items():
            if len(self._authentication_tasks) >= 8:
                break
            if attempt.id not in self._authentication_tasks:
                self._authentication_tasks[attempt.id] = asyncio.create_task(self.authenticate(*key, attempt.id))

    @staticmethod
    def _sender_signature(sender):
        return hashlib.sha256(json.dumps([sender.address, sender.secret, sender.enabled]).encode()).hexdigest()

    def _next_dynamic_generations(self, cfg):
        result = {}
        for sender in cfg.radius.dynamic_authorization.senders:
            signature = self._sender_signature(sender)
            previous = self._das_generations.get(sender.id)
            result[sender.id] = previous if previous and previous.get("signature")==signature else dict(signature=signature,generation=uid())
        return result

    def _publish_dynamic_metadata(self, changes):
        if "radius_sender_generations" in changes:self._das_generations = changes["radius_sender_generations"]
        if "radius_replay_high_water" in changes:self._das_high_water = changes["radius_replay_high_water"]
        if changes.get("das_put") or changes.get("das_delete"):
            cache = self._das_cache.copy()
            cache.update(changes.get("das_put", {}))
            for key in changes.get("das_delete", ()):cache.pop(key, None)
            self._das_cache = cache

    def _commit_dynamic_metadata(self, changes):
        self.require_storage()
        if self.store:
            with self.store.transaction():self.store._radius_metadata(changes)
        self._publish_dynamic_metadata(changes)

    def dynamic_drop(self, reason):
        self._das_drops[reason] = self._das_drops.get(reason,0) + 1

    def dynamic_clock_safe(self):
        wall = self._das_wall()
        return math.isfinite(wall) and wall >= self._das_high_water

    def _dynamic_binding(self):
        settings = self.state.cfg.radius.dynamic_authorization
        return settings.enabled, settings.host, settings.port

    def _dynamic_current(self, protocol):
        return (not self._closed and not self._das_closing and not self.storage_fault and
                protocol is self._das_protocol and protocol.transport is not None and protocol.binding == self._dynamic_binding())

    def _dynamic_expired(self, record, *, wall=None, elapsed=None):
        wall = self._das_wall() if wall is None else wall
        elapsed = self._das_clock() if elapsed is None else elapsed
        return wall > record["expires_wall"] or elapsed > record["expires_elapsed"]

    def _dynamic_record(self, pending, response, disposition):
        return dict(sender_id=pending["sender_id"], generation=pending["generation"],
            response=base64.b64encode(response).decode() if response is not None else None,
            expires_wall=pending["expires_wall"], expires_elapsed=pending["expires_elapsed"],
            clock_origin=ACCOUNTING_CLOCK_ORIGIN, disposition=disposition)

    async def reconcile_dynamic(self):
        from .radius import DynamicListener
        binding = self._dynamic_binding()
        if self._das_protocol is not None and (self._das_protocol.binding != binding or self._das_closing or self._closed):
            if self._das_protocol.transport is not None:self._das_protocol.transport.close()
            self._das_protocol = None
        if not binding[0] or self._closed or self._das_closing or self.storage_fault:return
        if self._das_protocol is None:
            protocol = DynamicListener(self,binding)
            try:
                transport,_ = await asyncio.get_running_loop().create_datagram_endpoint(lambda:protocol,local_addr=(binding[1],binding[2]))
            except OSError:
                self._das_error = "bind-failed"
                return
            if binding != self._dynamic_binding() or self._das_closing or self._closed:
                transport.close();return
            self._das_protocol = protocol;self._das_error = None

    async def prune_dynamic(self):
        async with self.lock:
            if self.storage_fault or not self.dynamic_clock_safe():return
            for fingerprint,pending in list(self._das_pending.items()):
                if pending["task"].done() and self._dynamic_expired(pending):
                    self._retire_expired_dynamic(fingerprint,pending)
                    if self._das_pending.get(fingerprint) is pending:del self._das_pending[fingerprint]
            if not self.dynamic_clock_safe():return
            expired = [key for key,record in self._das_cache.items() if self._dynamic_expired(record)]
            if not expired:return
            wall = self._das_wall()
            # If the elapsed clock expired first after a wall-clock regression,
            # retire only behind a persisted strictly-after-expiry watermark.
            high = max([self._das_high_water, wall] + [math.nextafter(self._das_cache[key]["expires_wall"], math.inf) for key in expired])
            self._commit_dynamic_metadata({"radius_replay_high_water":high, "das_delete":expired})

    def receive_dynamic(self, protocol, data, address):
        from .radius import verify_dynamic_request
        if not self._dynamic_current(protocol):return
        ip = ipaddress.ip_address(address[0])
        if isinstance(ip,ipaddress.IPv6Address) and ip.ipv4_mapped is not None:ip=ip.ipv4_mapped
        peer = (str(ip), address[1])
        sender = next((sender for sender in self.state.cfg.radius.dynamic_authorization.senders if sender.enabled and sender.address == peer[0]), None)
        if sender is None:self.dynamic_drop("untrusted-source");return
        try:request = verify_dynamic_request(bytes(data), sender.secret.encode())
        except RadiusError:self.dynamic_drop("invalid-packet");return
        if not self.dynamic_clock_safe():self.dynamic_drop("clock-unsafe");return
        if abs(self._das_wall()-request.timestamp)>300:self.dynamic_drop("timestamp-window");return
        fingerprint = hashlib.sha256(json.dumps(["radius-das",*peer]).encode()+request.packet).hexdigest()
        generation = self._das_generations[sender.id]["generation"]
        cached = self._das_cache.get(fingerprint)
        if cached is not None:
            if cached["generation"] != generation:self.dynamic_drop("retired-generation");return
            if self._dynamic_expired(cached):self.dynamic_drop("expired-duplicate");return
            if cached["response"] is not None:
                try:protocol.transport.sendto(base64.b64decode(cached["response"]),address)
                except (OSError,RuntimeError):self.dynamic_drop("transport-error")
            return
        if fingerprint in self._das_pending:return
        if len(set(self._das_cache)|set(self._das_pending)) >= 4096:self.dynamic_drop("cache-full");return
        pending = dict(request=request, peer=peer, address=address, sender_id=sender.id, generation=generation,
            epoch=self.state.epoch, protocol=protocol, expires_wall=request.timestamp+300,
            expires_elapsed=self._das_clock()+max(0,request.timestamp+300-self._das_wall()))
        self._das_pending[fingerprint] = pending
        pending["task"] = asyncio.create_task(self._handle_dynamic(fingerprint,pending))

    def _retire_expired_dynamic(self, fingerprint, pending):
        high = max(self._das_high_water, self._das_wall(), math.nextafter(pending["expires_wall"], math.inf))
        changes = {"radius_replay_high_water":high}
        if fingerprint not in self._das_cache:
            changes["das_put"] = {fingerprint:self._dynamic_record(pending,None,"expired-reservation")}
        self._commit_dynamic_metadata(changes)

    async def _handle_dynamic(self, fingerprint, pending):
        from .radius import plan_dynamic_request, dynamic_response
        keep_reservation = False
        try:
            async with self.lock:
                wall, elapsed = self._das_wall(), self._das_clock()
                if self._dynamic_expired(pending, wall=wall, elapsed=elapsed):
                    # Do not forget the elapsed lifetime even if wall time moved
                    # backwards while this request waited for serialization.
                    keep_reservation = True
                    self._retire_expired_dynamic(fingerprint,pending)
                    keep_reservation = False
                    return
                self.require_storage()
                sender = next((sender for sender in self.state.cfg.radius.dynamic_authorization.senders if sender.id==pending["sender_id"] and sender.enabled),None)
                current = self._das_generations.get(pending["sender_id"])
                if (not self._dynamic_current(pending["protocol"]) or sender is None or current is None or
                        current["generation"]!=pending["generation"] or self.state.epoch!=pending["epoch"] or
                        not math.isfinite(wall) or wall < self._das_high_water or
                        abs(wall-pending["request"].timestamp)>300):
                    return
                existing = self._das_cache.get(fingerprint)
                if existing is not None:return
                request = pending["request"]
                plan = plan_dynamic_request(request,self.state)
                code = (41 if request.code==40 else 44) if plan.error_cause is None else (42 if request.code==40 else 45)
                response = dynamic_response(request,code,sender.secret.encode(),error_cause=plan.error_cause)
                record = self._dynamic_record(pending,response,"ack" if plan.error_cause is None else "nak")
                updates = {"das_put":{fingerprint:record}, "radius_replay_high_water":max(self._das_high_water,wall)}
                if plan.error_cause is None:
                    self._execute("radius-dynamic",plan,radius_updates=updates)
                else:self._commit_dynamic_metadata(updates)
            if (self._dynamic_current(pending["protocol"]) and self.dynamic_clock_safe() and not self._dynamic_expired(record) and
                    self._das_generations.get(sender.id,{}).get("generation")==pending["generation"] and
                    abs(self._das_wall()-pending["request"].timestamp)<=300):
                pending["protocol"].transport.sendto(response,pending["address"])
        except (CommandError, RadiusError):
            self.dynamic_drop("processing-failed")
        except Exception:
            self.dynamic_drop("storage-or-transport-failed")
        finally:
            if self._das_pending.get(fingerprint) is pending and not keep_reservation and not self._das_closing:
                del self._das_pending[fingerprint]

    async def close_dynamic(self):
        self._das_closing = True
        async with self.lock:
            # Handlers keep these reservations while closing, even when they
            # acquire the lock first. Failed persistence leaves ownership intact.
            retired = {fingerprint:self._dynamic_record(item,None,"retired") for fingerprint,item in self._das_pending.items() if fingerprint not in self._das_cache}
            if retired:self._commit_dynamic_metadata({"das_put":retired})
        if self._das_protocol is not None and self._das_protocol.transport is not None:self._das_protocol.transport.close()
        self._das_protocol = None
        pending = list(self._das_pending.items())
        for _,item in pending:
            if not item["task"].cancelling():item["task"].cancel()
        await asyncio.gather(*(item["task"] for _,item in pending),return_exceptions=True)
        for fingerprint,item in pending:
            if self._das_pending.get(fingerprint) is item:del self._das_pending[fingerprint]

    def accounting_expired(self, record):
        return (record.get("clock_origin") != ACCOUNTING_CLOCK_ORIGIN or
                self._account_clock() > record["generated_elapsed"] + 300 or
                self._account_wall() > record["expires_wall"] or self._account_wall() < record["generated_wall"])

    def accounting_remaining(self, record):
        if record.get("clock_origin") != ACCOUNTING_CLOCK_ORIGIN or self._account_wall() < record["generated_wall"]:
            return 0
        return max(0,min(record["generated_elapsed"]+300-self._account_clock(),record["expires_wall"]-self._account_wall()))

    def accounting_current(self, record_id):
        if self._closed or self.storage_fault or not self.state.cfg.radius.accounting.enabled:
            return None
        record = next((item for item in self.state.accounting_outbox if item["id"] == record_id), None)
        if record is None or self.accounting_expired(record):return None
        return record if self.state.accounting_policy_matches(record) else None

    async def service_accounting(self):
        for record_id, task in list(self._accounting_tasks.items()):
            if self.accounting_current(record_id) is None and not task.cancelling():task.cancel()
            if task.done():
                try:task.result()
                except (asyncio.CancelledError, CommandError):pass
                finally:del self._accounting_tasks[record_id]
        if self._closed or self.storage_fault:return
        if any(self.accounting_expired(record) for record in self.state.accounting_outbox):await self.execute("accounting-prune")
        heads = {}
        records = self.state.accounting_outbox
        lifecycle = next((record for record in records if record["status_type"] in (7,8)), None)
        if lifecycle is not None:
            earlier = [record for record in records if record["sequence"] < lifecycle["sequence"]]
            records = earlier or [lifecycle]
        for record in records:heads.setdefault(record["session_id"], record)
        for record in heads.values():
            if len(self._accounting_tasks) >= 8:break
            if record["id"] not in self._accounting_tasks and self.accounting_current(record["id"]) is not None:
                self._accounting_tasks[record["id"]] = asyncio.create_task(self.deliver_accounting(record["id"]))

    async def deliver_accounting(self, record_id):
        from .radius import accounting_delivery
        record = self.accounting_current(record_id)
        if record is None:return
        captured = copy.deepcopy(record)
        targets = {target.id: target.model_copy(deep=True) for target in self.state.cfg.radius.accounting.targets}
        async def event(phase, target_id):
            await self.execute("accounting-event", {"id":record_id, "phase":phase, "target_id":target_id})
        outcome = await accounting_delivery(captured, targets, ready=lambda:self.accounting_current(record_id) is not None,
            elapsed=lambda:max(0, self._account_clock()-captured["generated_elapsed"]),
            remaining=lambda:self.accounting_remaining(captured), on_event=event)
        if outcome is not None and self.accounting_current(record_id) is not None:
            delivered, target_id = outcome
            await self.execute("accounting-result", {"id":record_id, "delivered":delivered, "target_id":target_id, "reason":"exhausted"})

    async def close_accounting(self, deadline_seconds=5):
        if not self.storage_fault and not self._closed:
            await self.execute("radius-shutdown")
            deadline = time.monotonic() + deadline_seconds
            while self.state.accounting_outbox and time.monotonic() < deadline:
                await self.service_accounting()
                await asyncio.sleep(0.02)
        tasks = list(self._accounting_tasks.values())
        for task in tasks:
            if not task.cancelling():task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._accounting_tasks.clear()

    async def close_authentication(self):
        self._closed = True
        tasks = list(self._authentication_tasks.values())
        for task in tasks:
            if not task.cancelling():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._authentication_tasks.clear()

    async def authenticate(self, port_id, address, attempt_id, *, exchange=None):
        """Run one captured exchange without holding the simulation/SNMP lock."""
        from .radius import native_exchange, mab_exchange
        key = (port_id, address)
        async with self.lock:
            self.require_storage()
            attempt = self.state.current_attempt(key, attempt_id)
            if attempt is None:
                return {"accepted": False, "reason": "stale-attempt"}
            cfg = self.state.cfg.model_copy(deep=True)
            profile = (next(src.supplicant for eid in self.state.attached(port_id)
                           for src in cfg.endpoints[eid].sources if src.mac == address and src.supplicant is not None)
                       if attempt.method != "mab" else None)
        exchange = exchange or (mab_exchange if attempt.method == "mab" else native_exchange)
        async def eap_events(events):
            await self.execute("radius-pae-events", dict(port_id=port_id, mac=address, attempt_id=attempt_id, events=events))
        failure = "server-unavailable"
        for server in cfg.radius.servers:
            if not server.enabled:
                continue
            async with self.lock:
                self.require_storage()
                current = self.state.current_attempt(key, attempt_id)
                if current is None:
                    return {"accepted": False, "reason": "stale-attempt"}
                health = self._take_server(server, attempt_id)
            if health is None:
                continue
            callback_active = [True]
            try:
                observed = await exchange(cfg.radius, server, profile, cfg.ports[port_id], address, attempt.session_id,
                    state=attempt.state if (attempt.state_server_id == server.id and
                        attempt.state_server_signature == self._server_signature(server)) else None,
                    nas_identity=attempt.nas_identity, on_eap_events=eap_events,
                    on_response=lambda sid=server.id, owner=health, live=callback_active:
                        self._server_response(sid, owner, key, attempt_id) if live[0] else None)
                if observed.result is not None or observed.challenges:
                    self._server_response(server.id, health, key, attempt_id)
                if observed.result is not None:
                    result = await self.execute("radius-result", dict(port_id=port_id, mac=address,
                        attempt_id=attempt_id, result=observed.result, server_id=server.id,
                        server_signature=self._server_signature(server)))
                    return {**result, "nas_code": observed.result.code, "peer_result": observed.peer_result,
                            "challenges": observed.challenges, "eap_frames": observed.eap_frames}
                if observed.tls_errors or observed.preparation_failed or observed.peer_result in (1, 3):
                    failure = "certificate-validation-failure" if observed.tls_errors else "eap-method-failure"
                    break
                if observed.timed_out and observed.unanswered_retries >= cfg.radius.attempts:
                    self._server_exhausted(server.id, health, key, attempt_id)
                    failure = "invalid-reply" if observed.invalid_replies else "server-unavailable"
                    continue
                failure = "exchange-deadline" if observed.timed_out else "incomplete-exchange"
                break
            except RadiusError as error:
                # Local capability/encoding/channel failures are not server outages.
                failure = str(error)
                break
            finally:
                callback_active[0] = False
                self._release_server(server.id, health, attempt_id)
        return await self.execute("radius-result", dict(port_id=port_id, mac=address,
            attempt_id=attempt_id, result=None, failure=failure))

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
        # SET installs its separately copied candidate before touching cfg. Keep
        # the old published cfg immutable without copying it just to discard it.
        s = copy.deepcopy(old, {id(old.cfg): old.cfg} if action == "snmp-set" else None)
        affected_e, affected_p = set(), set()
        result = self._apply(s, action, payload, affected_e, affected_p)
        s.cfg = Configuration.model_validate(s.cfg.model_dump(mode="json"))
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
        require(len(s.cfg.endpoints) <= s.cfg.switch.endpoint_limit, "Endpoint capacity reached", 429)
        require(sum(len(e.sources) for e in s.cfg.endpoints.values()) <= s.cfg.switch.source_limit, "Source capacity reached", 429)
        if action not in ("advance", "job", "reboot", "notification-result", "coldStart", "test-notification"):
            for pid in s.cfg.ports:
                if old.up(pid) != s.up(pid):
                    affected_p.add(pid)
                    s.counters[pid]["last_change"] = s.uptime()
                    p = s.cfg.ports[pid]
                    s.notify("linkUp" if s.up(pid) else "linkDown", enabled=p.link_notifications,
                             port_id=pid, if_index=p.if_index, admin=1 if p.admin_up else 2,
                             before=1 if old.up(pid) else 2, after=1 if s.up(pid) else 2)
            for fkey, row in list(s.fdb.items()):
                if row["vid"] not in s.cfg.vlans or not s.up(row["port_id"]) or (row["vid"] not in s.cfg.ports[row["port_id"]].admitted and not any(session.port_id == row["port_id"] and s.session_vid(session) == row["vid"] for session in s.radius_sessions.values())):
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
            if action not in ("save-startup", "reboot") and split_configuration(old.cfg)[1] != split_configuration(s.cfg)[1]:
                idem[key]["configuration_incarnation"] = s.configuration_incarnation
            idem = dict(list(idem.items())[-256:])
        updates = dict(radius_updates or {})
        generations = self._next_dynamic_generations(s.cfg)
        if generations != self._das_generations:
            updates["radius_sender_generations"] = generations
        retired = {}
        for fingerprint,pending in self._das_pending.items():
            current = generations.get(pending["sender_id"])
            if action in ("reboot", "radius-shutdown") or current is None or current["generation"] != pending["generation"]:
                if fingerprint not in self._das_cache:
                    retired[fingerprint] = self._dynamic_record(pending, None, "retired")
        if retired:updates.setdefault("das_put", {}).update(retired)
        if self.store:
            try:
                self.store.commit(s, idem, durable=durable, **({"radius_metadata":updates} if updates else {}),
                                  **({"save_startup":True} if action == "save-startup" else {}))
            except Exception:
                if self.storage_fault:
                    self._cancel_inactive_authentication()
                raise
        self.state, self.idempotency = s, idem
        self._publish_dynamic_metadata(updates)
        self._sync_server_health()
        self._cancel_inactive_authentication()
        return result

    def _apply(self, s, action, d, es, ps):
        cfg = s.cfg

        def get(collection, ident):
            require(ident in collection, "Resource not found", 404)
            return collection[ident]

        if action == "radius-dynamic":
            for change in d.sessions:
                session = s.radius_sessions.get(change.key)
                require(session is not None and session.id==change.session_id and session.grant_generation==change.grant_generation,
                        "Dynamic session changed before commit", 409)
            for change in d.sessions:
                session = s.radius_sessions[change.key]
                if change.policy is None:
                    s.end_session(change.key,"dynamic-disconnect",cause=6)
                    s.radius_status[change.key] = dict(status="waiting-activity", method="configured", reason="dynamic-disconnect",
                        _context=s.authentication_context(*change.key))
                elif session.policy != change.policy or session.lease_deadline_ms != change.lease_deadline_ms:
                    old_vid = s.session_vid(session)
                    s.retire_authentication(change.key)
                    session.policy = change.policy;session.lease_deadline_ms = change.lease_deadline_ms
                    session.grant_generation = uid();session.renewal_started_ms = None
                    if s.session_vid(session) != old_vid:
                        shared = cfg.ports[session.port_id].authentication.host_mode=="multi-host"
                        for key,row in list(s.fdb.items()):
                            if row["port_id"]==session.port_id and (shared or row["mac"]==session.mac):del s.fdb[key]
                    s.event("dynamic-coa",port_id=session.port_id,mac=session.mac,session_id=session.id)
            s.process_session_deadlines()
            return
        if action == "dynamic-settings":
            require("senders" not in d,"Use dynamic sender operations",422)
            cfg.radius.dynamic_authorization = DynamicSettings.model_validate({**cfg.radius.dynamic_authorization.model_dump(),**d})
            s.event(action);return
        if action == "dynamic-sender-save":
            previous = next((sender for sender in cfg.radius.dynamic_authorization.senders if sender.id==d.get("id")),None)
            fields = dict(d)
            if previous is not None and fields.get("secret")=="":fields.pop("secret")
            sender = DynamicSender.model_validate({**(previous.model_dump() if previous else {}),**fields})
            cfg.radius.dynamic_authorization.senders = [value for value in cfg.radius.dynamic_authorization.senders if value.id!=sender.id] + [sender]
            s.event(action,resource_id=sender.id);return {"id":sender.id}
        if action == "dynamic-sender-delete":
            require(any(sender.id==d["id"] for sender in cfg.radius.dynamic_authorization.senders),"Sender not found",404)
            cfg.radius.dynamic_authorization.senders = [sender for sender in cfg.radius.dynamic_authorization.senders if sender.id!=d["id"]]
            s.event(action,resource_id=d["id"]);return
        if action == "accounting-settings":
            require("targets" not in d, "Use accounting target operations", 422)
            cfg.radius.accounting = type(cfg.radius.accounting).model_validate({**cfg.radius.accounting.model_dump(), **d})
            s.event(action)
            return
        if action == "accounting-target-save":
            fields = dict(d); position = fields.pop("position", None)
            previous = next((target for target in cfg.radius.accounting.targets if target.id == fields.get("id")), None)
            if previous is not None and fields.get("secret") == "":fields.pop("secret")
            target = RadiusServer.model_validate({**(previous.model_dump() if previous else {"port":1813}), **fields})
            old_position = next((i for i,value in enumerate(cfg.radius.accounting.targets) if value.id == target.id), len(cfg.radius.accounting.targets))
            cfg.radius.accounting.targets = [value for value in cfg.radius.accounting.targets if value.id != target.id]
            cfg.radius.accounting.targets.insert(min(len(cfg.radius.accounting.targets), old_position if position is None else position), target)
            s.event(action, resource_id=target.id)
            return {"id": target.id}
        if action == "accounting-target-delete":
            require(any(target.id == d["id"] for target in cfg.radius.accounting.targets), "Accounting target not found", 404)
            cfg.radius.accounting.targets = [target for target in cfg.radius.accounting.targets if target.id != d["id"]]
            s.event(action, resource_id=d["id"])
            return
        if action == "accounting-prune":
            remaining = []
            for record in s.accounting_outbox:
                if self.accounting_expired(record):
                    s.accounting_drop("expired", record_id=record["id"])
                else:remaining.append(record)
            s.accounting_outbox = remaining
            return
        if action == "accounting-event":
            record = next((item for item in s.accounting_outbox if item["id"] == d["id"]), None)
            if record is None:return {"current": False}
            if d["phase"] == "attempting":
                record["status"] = "sending";record["attempts"] += 1
            s.event("accounting", status=d["phase"], record_id=record["id"], session_id=record["session_id"], target_id=d.get("target_id"))
            return {"current": True}
        if action == "accounting-result":
            record = next((item for item in s.accounting_outbox if item["id"] == d["id"]), None)
            if record is None:return {"current": False}
            s.accounting_outbox = [item for item in s.accounting_outbox if item["id"] != record["id"]]
            if d["delivered"]:
                s.event("accounting", status="delivered", record_id=record["id"], session_id=record["session_id"], target_id=d["target_id"])
            else:s.accounting_drop(d["reason"], record_id=record["id"], session_id=record["session_id"])
            return {"current": True}
        if action == "radius-shutdown":
            for key in list(s.radius_sessions):s.end_session(key, "application-shutdown")
            s.queue_accounting(8, reason="application-shutdown")
            return
        if action == "radius-settings":
            require(not {"servers", "materials", "templates", "accounting", "dynamic_authorization"} & d.keys(), "Use the RADIUS record operations", 422)
            cfg.radius = RadiusSettings.model_validate({**cfg.radius.model_dump(), **d})
            s.event("radius-settings")
            return
        if action == "radius-server-save":
            fields = dict(d)
            position = fields.pop("position", None)
            previous = next((server for server in cfg.radius.servers if server.id == fields.get("id")), None)
            if previous is not None and fields.get("secret") == "":
                fields.pop("secret")
            server = RadiusServer.model_validate({**(previous.model_dump() if previous else {}), **fields})
            old_position = next((i for i,value in enumerate(cfg.radius.servers) if value.id == server.id), len(cfg.radius.servers))
            cfg.radius.servers = [value for value in cfg.radius.servers if value.id != server.id]
            cfg.radius.servers.insert(min(len(cfg.radius.servers), old_position if position is None else position), server)
            s.event(action, resource_id=server.id)
            return {"id": server.id}
        if action == "radius-server-delete":
            require(any(server.id == d["id"] for server in cfg.radius.servers), "Server not found", 404)
            cfg.radius.servers = [server for server in cfg.radius.servers if server.id != d["id"]]
            s.event(action, resource_id=d["id"])
            return
        if action in ("radius-material-save", "radius-template-save"):
            fields = dict(d)
            collection = cfg.radius.materials if action == "radius-material-save" else cfg.radius.templates
            previous = collection.get(fields.get("id"))
            if action == "radius-material-save":
                if previous:
                    for name in ("certificate", "private_key", "key_password"):
                        if fields.get(name) == "":
                            fields.pop(name)
                record = RadiusMaterial.model_validate({**(previous.model_dump() if previous else {}), **fields})
            else:
                if "profile" in fields:
                    fields["profile"] = merge_supplicant(previous.profile if previous else None, fields["profile"])
                fields["revision"] = previous.revision + 1 if previous else 0
                record = SupplicantTemplate.model_validate({**(previous.model_dump() if previous else {}), **fields})
            collection[record.id] = record
            s.event(action, resource_id=record.id)
            return {"id": record.id}
        if action in ("radius-material-delete", "radius-template-delete"):
            collection = cfg.radius.materials if action == "radius-material-delete" else cfg.radius.templates
            get(collection, d["id"])
            del collection[d["id"]]
            s.event(action, resource_id=d["id"])
            return
        if action in ("source-supplicant-save", "source-authentication"):
            endpoint = get(cfg.endpoints, d["id"])
            source = next((source for source in endpoint.sources if source.id == d["source_id"]), None)
            require(source is not None, "Source not found", 404)
            key = (cfg.attachments.get(endpoint.id), source.mac)
            if action == "source-supplicant-save":
                previous = source.supplicant
                if d.get("template_id") is not None:
                    previous = get(cfg.radius.templates, d["template_id"]).profile.model_copy(deep=True)
                    require(d.get("profile", {}) is not None, "A template copy cannot also clear the profile", 422)
                else:
                    require("profile" in d, "Supply a profile or a template", 422)
                source.supplicant = merge_supplicant(previous, d.get("profile", {}))
                endpoint.revision += 1
                s.event(action, endpoint_id=endpoint.id, source_id=source.id)
                restart = d.get("restart", False)
            else:
                restart = d["action"] == "restart"
            if key[0] is not None and (restart or action == "source-authentication"):
                session = s.session(*key)
                # An action on a multi-host dependent names the actual shared owner.
                target = (key[0], session.mac) if session is not None else key
                s.retire_authentication(target)
                if restart:
                    s.end_session(target, "manual-restart")
                    s.radius_status.pop(target, None)
                    # Restarting a shared service may nominate the selected, still
                    # attached source; it never borrows a departed owner/profile.
                    if s.authentication_context(*key) is not None:
                        s.begin_authentication(*key)
                elif session is not None:
                    s.request_renewal(target, automatic=False)
                elif s.authentication_context(*key) is not None:
                    s.begin_authentication(*key)
                s.event("authentication-restart" if restart else "authentication-reauthenticate", port_id=key[0], mac=target[1])
            return {"source_id": source.id}
        if action == "radius-session-action":
            selected = next(((key, session) for key,session in s.radius_sessions.items() if session.id == d["id"]), None)
            require(selected is not None, "Session no longer exists", 404)
            key, session = selected
            s.retire_authentication(key)
            if d["action"] == "restart":
                s.end_session(key, "manual-restart")
                s.radius_status.pop(key, None)
                if s.authentication_context(*key) is not None:
                    s.begin_authentication(*key)
            else:
                s.request_renewal(key, automatic=False)
            s.event("authentication-"+d["action"], port_id=key[0], mac=key[1], session_id=session.id)
            return {"session_id": session.id}
        if action == "radius-begin":
            return s.begin_authentication(d["port_id"], d["mac"])
        if action == "radius-discover":
            s.process_session_deadlines()
            s.prepare_authentication()
            return
        if action == "radius-pae-events":
            return {"observed":s.pae_observe((d["port_id"],d["mac"]),d["attempt_id"],d["events"])}
        if action == "radius-result":
            key = (d["port_id"], d["mac"])
            attempt = s.current_attempt(key, d["attempt_id"])
            if attempt is None:
                return {"accepted": False, "reason": "stale-attempt"}
            # Completion consumes the observation; it is not incomplete retirement.
            del s.radius_attempts[key]
            received = d["result"]
            require(received is None or isinstance(received, AccessResult), "Expected a validated transport result", 500)
            code = received.code if received is not None else None
            from .radius import safe_access_summary
            summary = safe_access_summary(received) if received is not None else None
            policy = None
            reason = d.get("failure", "incomplete-exchange") if received is None else "server-reject" if code == 3 else "incomplete-exchange"
            if code == 2:
                try:
                    policy = authorization(received, cfg.ports[key[0]], cfg.vlans)
                except RadiusError as error:
                    reason = str(error)
            s.pae_finish(attempt, "success" if policy is not None else "reject" if code == 3 else
                         "timeout" if reason in ("server-unavailable", "invalid-reply") else "local")
            if reason.startswith("native_"):
                s.pae_port(key[0])["precise"] = False
            if (code == 3 and attempt.method != "mab" and cfg.ports[key[0]].authentication.method == "dot1x-mab"
                    and cfg.ports[key[0]].authentication.fallback_reject):
                # A current represented EAP peer supplied its MAC in the rejected
                # exchange; this opt-in transition does not need an ordinary frame.
                s.begin_authentication(*key, mab_trigger=True, automatic=attempt.automatic_renewal)
                s.event("authentication-method-fallback", port_id=key[0], mac=key[1], reason="server-reject", method="mab", response=summary)
                return {"accepted": False, "pending": True, "reason": "mab-fallback"}
            if policy is None:
                s.end_session(key, reason, cause=20)
                s.radius_status[key] = dict(status="failed", reason=reason, nas_code=code, response=summary, _context=attempt.context,
                    retry_at_ms=s.sim_ms + cfg.radius.failed_cycle_retry_seconds * 1000)
                s.event("authentication-failed", port_id=key[0], mac=key[1], reason=reason, nas_code=code, response=summary)
                return {"accepted": False, "reason": reason}
            old_session = s.radius_sessions.get(key)
            previous_session = old_session
            access_policy = lambda p: (p.vid, p.source, p.session_timeout, p.idle_timeout, p.termination_action)
            if old_session and access_policy(old_session.policy) != access_policy(policy):
                s.end_session(key, "reauthentication-policy-change")
                attempt = replace(attempt, session_id=uid())
                old_session = None
            require(old_session is not None or len(s.radius_sessions) < cfg.switch.source_limit, "Authentication session capacity reached", 429)
            session = old_session or AccessSession(attempt.session_id, *key, attempt.method, policy, s.sim_ms, nas_identity=attempt.nas_identity,
                idle_origin_ms=previous_session.idle_origin_ms if previous_session else s.sim_ms,
                last_activity_ms=previous_session.last_activity_ms if previous_session else None)
            session.policy = policy
            session.method = attempt.method
            session.auth_server_id = d.get("server_id")
            session.auth_server_signature = d.get("server_signature")
            session.user_name = policy.username or attempt.username
            if old_session is None:
                session.accounting_identity = access_attributes(cfg.radius, cfg.ports[key[0]], key[1], session.id,
                    nas_identity=attempt.nas_identity)
            period = s.accounting_period(session) if cfg.radius.accounting.enabled else 0
            if old_session is None or period != session.accounting_interval:
                session.accounting_interval = period
                session.accounting_next_ms = s.sim_ms + period*1000 if period else None
            session.last_auth_ms = s.sim_ms
            session.lease_deadline_ms = s.sim_ms + policy.session_timeout * 1000 if policy.session_timeout is not None else None
            session.renewal_started_ms = None
            s.radius_sessions[key] = session
            if cfg.ports[key[0]].authentication.host_mode == "multi-auth":s.last_auth_sessions.pop(key[0],None)
            if old_session is None:
                s.queue_accounting(1, session)
            if policy.accounting_warning:
                s.event("accounting-warning", session_id=session.id, reason=policy.accounting_warning)
            s.radius_status[key] = dict(status="authorized", method=attempt.method, session_id=session.id, response=summary)
            s.event("authentication-authorized", port_id=key[0], mac=key[1], session_id=session.id, vid=s.session_vid(session), source=policy.source, response=summary)
            s.process_session_deadlines()
            return {"accepted": True, "session_id": session.id, "active": key in s.radius_sessions}
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
                s.event(action, endpoint_id=eid)
            return {"id": eid}
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
            changed = {name for name in patch if getattr(cfg.ports[pid], name) != getattr(p, name)}
            if changed - {"name", "alias", "link_notifications"}:
                ps.add(pid)
        elif action == "vlan-create":
            v = Vlan.model_validate({"fdb_id": 1000+d["vid"], **d})
            require(v.vid not in cfg.vlans, "VLAN already exists")
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
                        ps.add(pid)
                if cfg.switch.legacy_vlan == vid:
                    cfg.switch.legacy_vlan = 1
                es.update(e.id for e in cfg.endpoints.values() if any(x.tag == vid for x in e.sources))
        elif action == "switch-edit":
            require(not set(d) - {"name", "description", "contact", "location", "identity", "base_mac", "legacy_vlan", "aging_seconds", "fdb_limit", "endpoint_limit", "source_limit", "queue_limit"}, "Unsupported switch field", 422)
            previous_age = cfg.switch.aging_seconds
            cfg.switch = type(cfg.switch).model_validate({**cfg.switch.model_dump(), **d})
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
