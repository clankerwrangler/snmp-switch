"""Inbound response ownership for the pinned PySNMP adapter.

PySNMP 7.1.29 expires MP server records without releasing their security state.
This per-engine integration uses those records as the only cache. It does not
alter outgoing requests, serialization, USM, or the existing expiration clock.
"""
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
import hashlib
import logging
from pathlib import Path

import pysnmp


# These are the reviewed wheel's ownership boundaries, not credential hashes.
PINNED_SOURCES = {
    "proto/mpmod/cache.py": "0cbb9aa45b5b8e49f47ee26ffee5054bb12c280a16c14f0bfbd56922f6c1159d",
    "proto/mpmod/base.py": "024af206696a60ed98462c68dcb49523207114810c809b80fd6212af221cdacd",
    "proto/mpmod/rfc2576.py": "059574305a5a35ca0399d331b08db2fe0c9ce032a1fda964b2991f319ee62dfb",
    "proto/mpmod/rfc3412.py": "9cde00131ab61d7ac664f8ee230ddcddb888535e9cff41f7d602655315a9158c",
    "proto/secmod/cache.py": "bfa04d56cccfa6cb880f7cacd120633ae6f7c2553988a3cf24d61b40debff063",
    "proto/secmod/base.py": "51db2edfea3227429480c8388bb5b4d0a3508cb4589728574f8328cc28482acb",
    "proto/secmod/rfc2576.py": "0acef9777ce0cd068c170ecee564ca9693767d81f4f03e4cdb506f6287c584e5",
    "proto/secmod/rfc3414/service.py": "d5ec45b870a4545ef617d3b03d4f217ae9b834d7c879bf91bc7d10a83962b78c",
    "proto/rfc3412.py": "e1fc8acf92b47a0775c55e5825e3b668620e639360d9d18699102f111802a11c"
}


# Reserved metadata in the existing MP server record; never wire data.
SECURITY_WITNESS = "_switchlab_inbound_security"


@dataclass(frozen=True, eq=False, repr=False, slots=True)
class SecurityWitness:
    lifetime: object
    security: object
    record: object


class UnsupportedLifetime(RuntimeError):
    """The new SET path cannot use this library layout; reads/traps remain usable."""


class OwnershipError(RuntimeError):
    """An inbound response lost an expected opaque owner."""


@dataclass(eq=False, repr=False)
class InboundTicket:
    # Opaque references only. Never render, copy, or serialize these records.
    owner: object
    model: int
    mp: object
    reference: int
    mp_record: object
    security: object
    security_reference: int
    security_record: object
    phase: str = "queued"
    reason: str | None = None


class InboundLifetime:
    def __init__(self, snmp, pending=lambda: ()):
        self._check_layout(snmp)
        self.snmp = snmp
        # The caller owns the bounded pending requests; this helper has no index.
        self.pending = pending
        self.active = True
        self.error = None
        for model, mp in snmp.message_processing_subsystems.items():
            cache = mp._cache
            original = cache.expire_caches
            original_push = cache.push_by_state_reference

            def push(stateReference, original_push=original_push, **params):
                security = self.snmp.security_models.get(params.get("securityModel"))
                record = (security._cache._Cache__cache_entries.get(params.get("securityStateReference"))
                          if security is not None else None)
                # Bind the original association before dispatch, including
                # report insertion. A missing record stays unknown permanently.
                params[SECURITY_WITNESS] = SecurityWitness(self, security, record)
                original_push(stateReference, **params)

            def expire(model=model, cache=cache, original=original):
                queue = cache._Cache__expirationQueue
                due = queue.get(cache._Cache__expirationTimer, {})
                for reference in tuple(due.get("stateReference", ())):
                    record = cache._Cache__stateReferenceIndex.get(reference)
                    ticket = next((t for t in self.pending() if t.owner is self
                        and t.model == model and t.mp_record is record), None)
                    if ticket is None:
                        ticket = self._capture(model, reference)
                    self.discard(ticket, "expiry")
                original()

            cache.push_by_state_reference = push
            cache.expire_caches = expire

    @staticmethod
    def _check_layout(snmp):
        try:
            if version("pysnmp") != "7.1.29":
                raise ValueError
            base = Path(pysnmp.__file__).parent
            if any(hashlib.sha256((base / name).read_bytes()).hexdigest() != digest
                   for name, digest in PINNED_SOURCES.items()):
                raise ValueError
            from pysnmp.proto.mpmod import cache as mp_cache
            from pysnmp.proto.secmod import cache as security_cache
            from pysnmp.proto.mpmod.rfc2576 import SnmpV1MessageProcessingModel, SnmpV2cMessageProcessingModel
            from pysnmp.proto.mpmod.rfc3412 import SnmpV3MessageProcessingModel
            from pysnmp.proto.secmod.rfc2576 import SnmpV1SecurityModel, SnmpV2cSecurityModel
            from pysnmp.proto.secmod.rfc3414.service import SnmpUSMSecurityModel
            from pysnmp.proto.rfc3412 import MsgAndPduDispatcher
            if set(snmp.message_processing_subsystems) != {0, 1, 3} or set(snmp.security_models) != {1, 2, 3}:
                raise ValueError
            if (type(snmp.message_dispatcher) is not MsgAndPduDispatcher
                or snmp.message_dispatcher.return_response_pdu.__func__ is not MsgAndPduDispatcher.return_response_pdu):
                raise ValueError
            for model, expected in ((0, SnmpV1MessageProcessingModel), (1, SnmpV2cMessageProcessingModel), (3, SnmpV3MessageProcessingModel)):
                mp = snmp.message_processing_subsystems[model]
                if (type(mp) is not expected
                    or mp.prepare_response_message.__func__ is not expected.prepare_response_message
                    or mp.prepare_data_elements.__func__ is not expected.prepare_data_elements):
                    raise ValueError
                cache = mp._cache
                if (type(cache) is not mp_cache.Cache or cache._Cache__expirationTimer != 0
                    or any(type(getattr(cache, field)) is not dict or getattr(cache, field)
                           for field in ("_Cache__stateReferenceIndex", "_Cache__expirationQueue",
                                         "_Cache__msgIdIndex", "_Cache__sendPduHandleIdx"))
                    or cache.expire_caches.__func__ is not mp_cache.Cache.expire_caches
                    or cache.push_by_state_reference.__func__ is not mp_cache.Cache.push_by_state_reference
                    or cache.pop_by_state_reference.__func__ is not mp_cache.Cache.pop_by_state_reference):
                    raise ValueError
            for model, expected in ((1, SnmpV1SecurityModel), (2, SnmpV2cSecurityModel), (3, SnmpUSMSecurityModel)):
                security = snmp.security_models[model]
                if (type(security) is not expected
                    or security.generate_response_message.__func__ is not expected.generate_response_message
                    or security.release_state_information.__func__ is not expected.release_state_information):
                    raise ValueError
                cache = security._cache
                if (type(cache) is not security_cache.Cache
                    or type(cache._Cache__cache_entries) is not dict or cache._Cache__cache_entries
                    or cache.pop.__func__ is not security_cache.Cache.pop
                    or not callable(security.release_state_information)):
                    raise ValueError
        except (AttributeError, ImportError, KeyError, OSError, ValueError, PackageNotFoundError) as exc:
            raise UnsupportedLifetime("Unsupported PySNMP inbound response layout") from exc

    def _fault(self):
        if self.error is None:
            self.error = "inbound_response_ownership_lost"
            logging.getLogger(__name__).error("SNMP inbound response ownership lost")

    def _capture(self, model, reference):
        mp = self.snmp.message_processing_subsystems[model]
        record = mp._cache._Cache__stateReferenceIndex.get(reference)
        if record is None:
            self._fault()
            raise OwnershipError("Missing inbound MP record")
        params = record[0]
        security = self.snmp.security_models.get(params["securityModel"])
        witness = params.get(SECURITY_WITNESS)
        if (type(witness) is SecurityWitness and witness.lifetime is self
                and witness.security is security):
            sec_record = witness.record
        else:
            # Preserve unknown security, but still retire the exact MP row.
            # One malformed row must not abort expiry or the remaining drain.
            self._fault()
            security = sec_record = None
        return InboundTicket(self, model, mp, reference, record, security,
                             params["securityStateReference"], sec_record)

    def capture(self, model, reference):
        ticket = self._capture(model, reference)
        self.ready(ticket)
        return ticket

    def _owns_mp(self, ticket):
        return (self.snmp.message_processing_subsystems.get(ticket.model) is ticket.mp
                and ticket.mp._cache._Cache__stateReferenceIndex.get(ticket.reference) is ticket.mp_record)

    def _owns_security(self, ticket):
        return (ticket.security_record is not None
                and self.snmp.security_models.get(ticket.security.SECURITY_MODEL_ID) is ticket.security
                and ticket.security._cache._Cache__cache_entries.get(ticket.security_reference) is ticket.security_record)

    def ready(self, ticket):
        if ticket.owner is not self or ticket.phase != "queued":
            return False
        if not self.active:
            self.discard(ticket, "closed")
            return False
        if not self._owns_mp(ticket) or not self._owns_security(ticket):
            self._fault()
            self.discard(ticket, "ownership_error")
            return False
        return True

    def _finish(self, ticket, reason):
        queued = ticket.phase == "queued"
        ticket.phase, ticket.reason = "terminal", reason
        try:
            own_mp, own_security = self._owns_mp(ticket), self._owns_security(ticket)
            if queued and own_mp and not own_security:
                self._fault()
            if own_mp:
                ticket.mp._cache.pop_by_state_reference(ticket.reference)
            if own_security:
                ticket.security.release_state_information(ticket.security_reference)
        finally:
            ticket.owner = ticket.mp = ticket.mp_record = None
            ticket.security = ticket.security_record = None

    def discard(self, ticket, reason="cancel"):
        if ticket.owner is not self or ticket.phase == "terminal":
            return False
        self._finish(ticket, reason)
        return True

    def complete(self, ticket, operation):
        """Claim, then synchronously commit/respond/finalize without yielding.

        The caller rechecks current authorization before this call. Operation
        uses the public return_response_pdu path exactly once. Delivery failure
        propagates after cleanup; it never rolls back an already committed state.
        """
        if not self.ready(ticket):
            return False
        ticket.phase = "claimed"
        reason = "completed"
        try:
            operation()
        except BaseException:
            reason = "response_failed"
            raise
        finally:
            self._finish(ticket, reason)
        return True

    def close(self):
        self.active = False
        for ticket in tuple(self.pending()):
            self.discard(ticket, "close")
        for model, mp in self.snmp.message_processing_subsystems.items():
            for reference in tuple(mp._cache._Cache__stateReferenceIndex):
                self.discard(self._capture(model, reference), "close")
