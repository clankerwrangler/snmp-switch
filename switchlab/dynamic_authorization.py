"""RADIUS CoA/Disconnect (dynamic authorization) for one engine.

Owns the UDP listener, the persisted replay cache and high-water clock, the
per-sender generations, in-flight request reservations and drop counters. A
request it accepts changes sessions only through the engine's transaction
("radius-dynamic"), with its cache record committed in the same transaction.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import json
import math
import time

from .common import ACCOUNTING_CLOCK_ORIGIN, CommandError, accounting_elapsed_clock, listen_port
from .models import uid
from .radius import RadiusError


def sender_signature(sender):
    return hashlib.sha256(json.dumps([sender.address, sender.secret, sender.enabled]).encode()).hexdigest()


class DynamicAuthorization:
    def __init__(self, engine, store):
        self.engine = engine
        self.clock = accounting_elapsed_clock
        self.wall = time.time
        self.protocol = None
        self.closing = False
        self.pending = {}
        self.drops = {}
        self.error = None
        self.cache = store.radius_decisions() if store else {}
        self.high_water = store.get("radius_replay_high_water", 0) if store else 0
        self.generations = store.get("radius_sender_generations", {}) if store else {}
        if not isinstance(self.high_water, (int,float)) or not math.isfinite(self.high_water) or self.high_water < 0:
            raise ValueError("Invalid dynamic authorization clock state")
        for fingerprint,record in self.cache.items():
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
                record["expires_elapsed"] = self.clock() + max(0,record["expires_wall"]-self.wall())
                record["clock_origin"] = ACCOUNTING_CLOCK_ORIGIN

    # -- Used by the engine's transaction -----------------------------------

    def next_generations(self, cfg):
        result = {}
        for sender in cfg.radius.dynamic_authorization.senders:
            signature = sender_signature(sender)
            previous = self.generations.get(sender.id)
            result[sender.id] = previous if previous and previous.get("signature")==signature else dict(signature=signature,generation=uid())
        return result

    def transaction_updates(self, action, cfg, updates=None):
        """Metadata to commit with a transaction that produced `cfg`: changed sender
        generations, and retirement of reservations those changes (or a reboot or
        shutdown) made stale."""
        updates = dict(updates or {})
        generations = self.next_generations(cfg)
        if generations != self.generations:
            updates["radius_sender_generations"] = generations
        retired = {}
        for fingerprint,pending in self.pending.items():
            current = generations.get(pending["sender_id"])
            if action in ("reboot", "radius-shutdown") or current is None or current["generation"] != pending["generation"]:
                if fingerprint not in self.cache:
                    retired[fingerprint] = self._record(pending, None, "retired")
        if retired:updates.setdefault("das_put", {}).update(retired)
        return updates

    def publish(self, changes):
        if "radius_sender_generations" in changes:self.generations = changes["radius_sender_generations"]
        if "radius_replay_high_water" in changes:self.high_water = changes["radius_replay_high_water"]
        if changes.get("das_put") or changes.get("das_delete"):
            cache = self.cache.copy()
            cache.update(changes.get("das_put", {}))
            for key in changes.get("das_delete", ()):cache.pop(key, None)
            self.cache = cache

    def status(self):
        return dict(ready=bool(self.protocol and self._current(self.protocol)), clock_safe=self.clock_safe(),
            reason=self.error, cached=len(self.cache), pending=len(self.pending), drops=self.drops.copy())

    # -- Listener lifecycle ---------------------------------------------------

    def binding(self):
        settings = self.engine.state.cfg.radius.dynamic_authorization
        return settings.enabled, settings.host, listen_port("coa", settings.port)

    def _stopped(self):
        return self.engine.closed or self.closing or self.engine.storage_fault

    def _current(self, protocol):
        return (not self._stopped() and protocol is self.protocol and
                protocol.transport is not None and protocol.binding == self.binding())

    async def reconcile(self):
        from .radius import DynamicListener
        binding = self.binding()
        if self.protocol is not None and (self.protocol.binding != binding or self.closing or self.engine.closed):
            if self.protocol.transport is not None:self.protocol.transport.close()
            self.protocol = None
        if not binding[0] or self._stopped():return
        if self.protocol is None:
            protocol = DynamicListener(self,binding)
            try:
                transport,_ = await asyncio.get_running_loop().create_datagram_endpoint(lambda:protocol,local_addr=(binding[1],binding[2]))
            except OSError:
                self.error = "bind-failed"
                return
            if binding != self.binding() or self.closing or self.engine.closed:
                transport.close();return
            self.protocol = protocol;self.error = None

    async def close(self):
        """Persist retirement of in-flight requests, then stop the listener and
        handlers. If the save fails, everything still stops and the error is
        raised, but the reservations are kept so a later close can save them."""
        self.closing = True
        retired_saved = False
        try:
            async with self.engine.lock:
                # Handlers keep these reservations while closing, even when they
                # acquire the lock first.
                retired = {fingerprint:self._record(item,None,"retired") for fingerprint,item in self.pending.items() if fingerprint not in self.cache}
                if retired:self._commit({"das_put":retired})
            retired_saved = True
        finally:
            if self.protocol is not None and self.protocol.transport is not None:self.protocol.transport.close()
            self.protocol = None
            pending = list(self.pending.items())
            for _,item in pending:
                if not item["task"].cancelling():item["task"].cancel()
            await asyncio.gather(*(item["task"] for _,item in pending),return_exceptions=True)
            if retired_saved:
                for fingerprint,item in pending:
                    if self.pending.get(fingerprint) is item:del self.pending[fingerprint]

    # -- Requests -------------------------------------------------------------

    def drop(self, reason):
        self.drops[reason] = self.drops.get(reason,0) + 1

    def clock_safe(self):
        wall = self.wall()
        return math.isfinite(wall) and wall >= self.high_water

    def _commit(self, changes):
        self.engine.require_storage()
        store = self.engine.store
        if store:
            with store.transaction():store._radius_metadata(changes)
        self.publish(changes)

    def _expired(self, record, *, wall=None, elapsed=None):
        wall = self.wall() if wall is None else wall
        elapsed = self.clock() if elapsed is None else elapsed
        return wall > record["expires_wall"] or elapsed > record["expires_elapsed"]

    def _record(self, pending, response, disposition):
        return dict(sender_id=pending["sender_id"], generation=pending["generation"],
            response=base64.b64encode(response).decode() if response is not None else None,
            expires_wall=pending["expires_wall"], expires_elapsed=pending["expires_elapsed"],
            clock_origin=ACCOUNTING_CLOCK_ORIGIN, disposition=disposition)

    async def prune(self):
        async with self.engine.lock:
            if self.engine.storage_fault or not self.clock_safe():return
            for fingerprint,pending in list(self.pending.items()):
                if pending["task"].done() and self._expired(pending):
                    self._retire_expired(fingerprint,pending)
                    if self.pending.get(fingerprint) is pending:del self.pending[fingerprint]
            if not self.clock_safe():return
            expired = [key for key,record in self.cache.items() if self._expired(record)]
            if not expired:return
            wall = self.wall()
            # If the elapsed clock expired first after a wall-clock regression,
            # retire only behind a persisted strictly-after-expiry watermark.
            high = max([self.high_water, wall] + [math.nextafter(self.cache[key]["expires_wall"], math.inf) for key in expired])
            self._commit({"radius_replay_high_water":high, "das_delete":expired})

    def receive(self, protocol, data, address):
        from .radius import verify_dynamic_request
        if not self._current(protocol):return
        ip = ipaddress.ip_address(address[0])
        if isinstance(ip,ipaddress.IPv6Address) and ip.ipv4_mapped is not None:ip=ip.ipv4_mapped
        peer = (str(ip), address[1])
        sender = next((sender for sender in self.engine.state.cfg.radius.dynamic_authorization.senders if sender.enabled and sender.address == peer[0]), None)
        if sender is None:self.drop("untrusted-source");return
        try:request = verify_dynamic_request(bytes(data), sender.secret.encode())
        except RadiusError:self.drop("invalid-packet");return
        if not self.clock_safe():self.drop("clock-unsafe");return
        if abs(self.wall()-request.timestamp)>300:self.drop("timestamp-window");return
        fingerprint = hashlib.sha256(json.dumps(["radius-das",*peer]).encode()+request.packet).hexdigest()
        generation = self.generations[sender.id]["generation"]
        cached = self.cache.get(fingerprint)
        if cached is not None:
            if cached["generation"] != generation:self.drop("retired-generation");return
            if self._expired(cached):self.drop("expired-duplicate");return
            if cached["response"] is not None:
                try:protocol.transport.sendto(base64.b64decode(cached["response"]),address)
                except (OSError,RuntimeError):self.drop("transport-error")
            return
        if fingerprint in self.pending:return
        if len(set(self.cache)|set(self.pending)) >= 4096:self.drop("cache-full");return
        pending = dict(request=request, peer=peer, address=address, sender_id=sender.id, generation=generation,
            epoch=self.engine.state.epoch, protocol=protocol, expires_wall=request.timestamp+300,
            expires_elapsed=self.clock()+max(0,request.timestamp+300-self.wall()))
        self.pending[fingerprint] = pending
        pending["task"] = asyncio.create_task(self._handle(fingerprint,pending))

    def _retire_expired(self, fingerprint, pending):
        high = max(self.high_water, self.wall(), math.nextafter(pending["expires_wall"], math.inf))
        changes = {"radius_replay_high_water":high}
        if fingerprint not in self.cache:
            changes["das_put"] = {fingerprint:self._record(pending,None,"expired-reservation")}
        self._commit(changes)

    async def _handle(self, fingerprint, pending):
        from .radius import plan_dynamic_request, dynamic_response
        engine = self.engine
        keep_reservation = False
        try:
            async with engine.lock:
                wall, elapsed = self.wall(), self.clock()
                if self._expired(pending, wall=wall, elapsed=elapsed):
                    # Do not forget the elapsed lifetime even if wall time moved
                    # backwards while this request waited for serialization.
                    keep_reservation = True
                    self._retire_expired(fingerprint,pending)
                    keep_reservation = False
                    return
                engine.require_storage()
                sender = next((sender for sender in engine.state.cfg.radius.dynamic_authorization.senders if sender.id==pending["sender_id"] and sender.enabled),None)
                current = self.generations.get(pending["sender_id"])
                if (not self._current(pending["protocol"]) or sender is None or current is None or
                        current["generation"]!=pending["generation"] or engine.state.epoch!=pending["epoch"] or
                        not math.isfinite(wall) or wall < self.high_water or
                        abs(wall-pending["request"].timestamp)>300):
                    return
                existing = self.cache.get(fingerprint)
                if existing is not None:return
                request = pending["request"]
                plan = plan_dynamic_request(request,engine.state)
                code = (41 if request.code==40 else 44) if plan.error_cause is None else (42 if request.code==40 else 45)
                response = dynamic_response(request,code,sender.secret.encode(),error_cause=plan.error_cause)
                record = self._record(pending,response,"ack" if plan.error_cause is None else "nak")
                updates = {"das_put":{fingerprint:record}, "radius_replay_high_water":max(self.high_water,wall)}
                if plan.error_cause is None:
                    engine._execute("radius-dynamic",plan,radius_updates=updates)
                else:self._commit(updates)
            if (self._current(pending["protocol"]) and self.clock_safe() and not self._expired(record) and
                    self.generations.get(sender.id,{}).get("generation")==pending["generation"] and
                    abs(self.wall()-pending["request"].timestamp)<=300):
                pending["protocol"].transport.sendto(response,pending["address"])
        except (CommandError, RadiusError):
            self.drop("processing-failed")
        except Exception:
            self.drop("storage-or-transport-failed")
        finally:
            if self.pending.get(fingerprint) is pending and not keep_reservation and not self.closing:
                del self.pending[fingerprint]
