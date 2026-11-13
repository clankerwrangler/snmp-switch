"""RADIUS access state of the simulated switch: authentication attempts and
sessions, port PAE observation, and the accounting queue they produce.

These methods run on Runtime, which keeps the fields. Runtime stays one object
because every engine transaction copies the whole state and publishes it
atomically; access state must change together with ports, VLANs and the
forwarding table.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass, field, replace

from .common import ACCOUNTING_CLOCK_ORIGIN, CommandError, accounting_elapsed_clock, require
from .models import uid
from .radius import Authorization, NasIdentity, RadiusError, encode_attributes, mab_username, resolve_nas_identity
from .radius_workers import server_signature


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


class AccessState:
    """RADIUS access behavior of Runtime; see the module docstring."""

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
            targets=[dict(id=target.id, signature=server_signature(target)) for target in targets],
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
                record["targets"] == [dict(id=target.id, signature=server_signature(target))
                                      for target in settings.targets if target.enabled] and
                record["delivery_policy"] == {name: getattr(settings, name) for name in
                    ("response_timeout_seconds", "attempts", "retry_backoff_seconds")})

    def reconcile_accounting(self, before):
        shape = lambda c: (c.enabled,c.response_timeout_seconds,c.attempts,c.retry_backoff_seconds,
            [(target.id, target.enabled, server_signature(target)) for target in c.targets])
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
