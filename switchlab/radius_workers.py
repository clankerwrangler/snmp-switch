"""Background RADIUS work for one engine: authentication exchanges and
accounting delivery.

Workers hold no grants or records of their own. Each refers to a Runtime
attempt or queued accounting record by id, captures what it needs under the
engine lock, runs its network exchange without the lock, and reports the
outcome through an engine transaction, which rejects it if it went stale.
"""
from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import time
from dataclasses import dataclass

from .common import ACCOUNTING_CLOCK_ORIGIN, CommandError, accounting_elapsed_clock
from .radius import RadiusError

LIMIT = 8  # concurrent workers of each kind


def server_signature(server):
    value = [server.address, server.port, server.source_address, server.secret]
    return hashlib.sha256(json.dumps(value).encode()).hexdigest()


def _stop_tasks(tasks):
    for task in tasks:
        if not task.cancelling():
            task.cancel()
    return asyncio.gather(*tasks, return_exceptions=True)


def _cancel_unless_running(tasks, keep):
    try:
        running = asyncio.current_task()
    except RuntimeError:
        running = None
    for identity, task in tasks.items():
        if not keep(identity) and task is not running and not task.done() and not task.cancelling():
            task.cancel()


def _reap(tasks, keep):
    for identity, task in list(tasks.items()):
        if not keep(identity) and not task.cancelling():
            task.cancel()
        if task.done():
            try:
                task.result()
            except (asyncio.CancelledError, CommandError):
                pass
            finally:
                del tasks[identity]


@dataclass(repr=False)
class AuthServerHealth:
    signature: str
    available: bool | None = None
    failures: int = 0
    probe_after: float = 0
    probe_owner: str | None = None


class Authentication:
    """Authentication exchanges and per-server availability."""

    def __init__(self, engine):
        self.engine = engine
        self.tasks = {}
        self.health = {}
        self.clock = time.monotonic

    def _stopped(self):
        engine = self.engine
        return engine.storage_fault or engine.closed or engine.closing

    def server_status(self):
        now = self.clock()
        return {sid: dict(status="unknown" if h.available is None else "available" if h.available else "probing" if h.probe_owner else "unavailable",
            retry_after_seconds=max(0, h.probe_after - now)) for sid,h in self.health.items()}

    def sync_health(self):
        current = {server.id: server for server in self.engine.state.cfg.radius.servers}
        for identity in list(self.health):
            if identity not in current:
                del self.health[identity]
        for identity, server in current.items():
            signature = server_signature(server)
            if identity not in self.health or self.health[identity].signature != signature:
                self.health[identity] = AuthServerHealth(signature)

    def take_server(self, server, attempt_id):
        self.sync_health()
        health = self.health.get(server.id)
        if health is None or health.signature != server_signature(server):
            return None
        if health.available is False:
            if self.clock() < health.probe_after or health.probe_owner not in (None, attempt_id):
                return None
            health.probe_owner = attempt_id
        return health

    def _health_current(self, server_id, health, key, attempt_id):
        engine = self.engine
        return not (engine.closed or engine.storage_fault or self.health.get(server_id) is not health or
                    engine.state.current_attempt(key, attempt_id) is None)

    def server_response(self, server_id, health, key, attempt_id):
        # This synchronous callback observes a cryptographically verified packet,
        # not a grant. It runs on the same event loop and never performs I/O.
        if self._health_current(server_id, health, key, attempt_id):
            health.available, health.failures, health.probe_after, health.probe_owner = True, 0, 0, None

    def server_exhausted(self, server_id, health, key, attempt_id):
        if self._health_current(server_id, health, key, attempt_id):
            health.failures += 1
            health.available = False
            health.probe_after = self.clock() + (1, 2, 4, 8, 16, 30)[min(health.failures - 1, 5)]

    def release_server(self, server_id, health, attempt_id):
        if self.health.get(server_id) is health and health.probe_owner == attempt_id:
            health.probe_owner = None

    def cancel_inactive(self):
        engine = self.engine
        current = {a.id for a in engine.state.radius_attempts.values()} if not engine.storage_fault and not engine.closed else set()
        _cancel_unless_running(self.tasks, lambda identity: identity in current)

    async def service(self):
        """Start workers for current attempts and reap finished or stale ones."""
        engine = self.engine
        stopped = self._stopped()
        active = {attempt.id for attempt in engine.state.radius_attempts.values()} if not stopped else set()
        _reap(self.tasks, lambda identity: identity in active)
        if stopped:
            return
        # Avoid empty transactions on every refresh; the real transaction alone allocates IDs.
        deadline = engine.state.next_session_deadline()
        if (deadline is not None and deadline <= engine.state.sim_ms or
                len(engine.state.radius_attempts) < LIMIT and next(engine.state.authentication_candidates(), None) is not None):
            await engine.execute("radius-discover")
        for key, attempt in engine.state.radius_attempts.items():
            if len(self.tasks) >= LIMIT:
                break
            if attempt.id not in self.tasks:
                self.tasks[attempt.id] = asyncio.create_task(self.authenticate(*key, attempt.id))

    async def stop(self):
        tasks = list(self.tasks.values())
        await _stop_tasks(tasks)
        self.tasks.clear()

    async def authenticate(self, port_id, address, attempt_id, *, exchange=None):
        """Run one captured exchange without holding the simulation/SNMP lock."""
        from .radius import native_exchange, mab_exchange
        engine = self.engine
        key = (port_id, address)
        async with engine.lock:
            engine.require_storage()
            attempt = engine.state.current_attempt(key, attempt_id)
            if attempt is None:
                return {"accepted": False, "reason": "stale-attempt"}
            cfg = engine.state.cfg.model_copy(deep=True)
            profile = (next(src.supplicant for eid in engine.state.attached(port_id)
                           for src in cfg.endpoints[eid].sources if src.mac == address and src.supplicant is not None)
                       if attempt.method != "mab" else None)
        exchange = exchange or (mab_exchange if attempt.method == "mab" else native_exchange)
        async def eap_events(events):
            await engine.execute("radius-pae-events", dict(port_id=port_id, mac=address, attempt_id=attempt_id, events=events))
        failure = "server-unavailable"
        for server in cfg.radius.servers:
            if not server.enabled:
                continue
            async with engine.lock:
                engine.require_storage()
                current = engine.state.current_attempt(key, attempt_id)
                if current is None:
                    return {"accepted": False, "reason": "stale-attempt"}
                health = self.take_server(server, attempt_id)
            if health is None:
                continue
            callback_active = [True]
            try:
                observed = await exchange(cfg.radius, server, profile, cfg.ports[port_id], address, attempt.session_id,
                    state=attempt.state if (attempt.state_server_id == server.id and
                        attempt.state_server_signature == server_signature(server)) else None,
                    nas_identity=attempt.nas_identity, on_eap_events=eap_events,
                    on_response=lambda sid=server.id, owner=health, live=callback_active:
                        self.server_response(sid, owner, key, attempt_id) if live[0] else None)
                if observed.result is not None or observed.challenges:
                    self.server_response(server.id, health, key, attempt_id)
                if observed.result is not None:
                    result = await engine.execute("radius-result", dict(port_id=port_id, mac=address,
                        attempt_id=attempt_id, result=observed.result, server_id=server.id,
                        server_signature=server_signature(server)))
                    return {**result, "nas_code": observed.result.code, "peer_result": observed.peer_result,
                            "challenges": observed.challenges, "eap_frames": observed.eap_frames}
                if observed.tls_errors or observed.preparation_failed or observed.peer_result in (1, 3):
                    failure = "certificate-validation-failure" if observed.tls_errors else "eap-method-failure"
                    break
                if observed.timed_out and observed.unanswered_retries >= cfg.radius.attempts:
                    self.server_exhausted(server.id, health, key, attempt_id)
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
                self.release_server(server.id, health, attempt_id)
        return await engine.execute("radius-result", dict(port_id=port_id, mac=address,
            attempt_id=attempt_id, result=None, failure=failure))


class Accounting:
    """Delivery of the Runtime's accounting queue, one head record per session."""

    def __init__(self, engine):
        self.engine = engine
        self.tasks = {}
        self.clock = accounting_elapsed_clock
        self.wall = time.time

    def expired(self, record):
        return (record.get("clock_origin") != ACCOUNTING_CLOCK_ORIGIN or
                self.clock() > record["generated_elapsed"] + 300 or
                self.wall() > record["expires_wall"] or self.wall() < record["generated_wall"])

    def remaining(self, record):
        if record.get("clock_origin") != ACCOUNTING_CLOCK_ORIGIN or self.wall() < record["generated_wall"]:
            return 0
        return max(0,min(record["generated_elapsed"]+300-self.clock(),record["expires_wall"]-self.wall()))

    def current(self, record_id):
        engine = self.engine
        if engine.closed or engine.storage_fault or not engine.state.cfg.radius.accounting.enabled:
            return None
        record = next((item for item in engine.state.accounting_outbox if item["id"] == record_id), None)
        if record is None or self.expired(record):return None
        return record if engine.state.accounting_policy_matches(record) else None

    def cancel_inactive(self):
        _cancel_unless_running(self.tasks, lambda identity: self.current(identity) is not None)

    async def service(self):
        engine = self.engine
        _reap(self.tasks, lambda identity: self.current(identity) is not None)
        if engine.closed or engine.storage_fault:return
        if any(self.expired(record) for record in engine.state.accounting_outbox):await engine.execute("accounting-prune")
        heads = {}
        records = engine.state.accounting_outbox
        lifecycle = next((record for record in records if record["status_type"] in (7,8)), None)
        if lifecycle is not None:
            earlier = [record for record in records if record["sequence"] < lifecycle["sequence"]]
            records = earlier or [lifecycle]
        for record in records:heads.setdefault(record["session_id"], record)
        for record in heads.values():
            if len(self.tasks) >= LIMIT:break
            if record["id"] not in self.tasks and self.current(record["id"]) is not None:
                self.tasks[record["id"]] = asyncio.create_task(self.deliver(record["id"]))

    async def deliver(self, record_id):
        from .radius import accounting_delivery
        engine = self.engine
        record = self.current(record_id)
        if record is None:return
        captured = copy.deepcopy(record)
        targets = {target.id: target.model_copy(deep=True) for target in engine.state.cfg.radius.accounting.targets}
        def server_context(target_id):
            target = targets.get(target_id)
            return {"server_label":target.label} if target is not None else {}
        async def event(phase, target_id):
            await engine.execute("accounting-event", {"id":record_id, "phase":phase, "target_id":target_id, **server_context(target_id)})
        outcome = await accounting_delivery(captured, targets, ready=lambda:self.current(record_id) is not None,
            elapsed=lambda:max(0, self.clock()-captured["generated_elapsed"]),
            remaining=lambda:self.remaining(captured), on_event=event)
        if outcome is not None and self.current(record_id) is not None:
            delivered, target_id = outcome
            await engine.execute("accounting-result", {"id":record_id, "delivered":delivered, "target_id":target_id, "reason":"exhausted", **server_context(target_id)})

    async def drain(self, deadline_seconds):
        deadline = time.monotonic() + deadline_seconds
        while self.engine.state.accounting_outbox and time.monotonic() < deadline:
            await self.service()
            await asyncio.sleep(0.02)

    async def stop(self):
        tasks = list(self.tasks.values())
        await _stop_tasks(tasks)
        self.tasks.clear()
