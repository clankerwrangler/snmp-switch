"""PySNMP handles BER, USM cryptography and security clocks.

All operational reads use one immutable state and one current authorization
decision per PDU. Network dispatch never owns a second switch state.
"""
import asyncio
import ipaddress
import hashlib
from dataclasses import dataclass

from pyasn1.codec.ber import encoder, decoder

from pysnmp.carrier.asyncio.dgram import udp, udp6
from pysnmp.entity import config, engine as snmp_engine
from pysnmp.entity.rfc3413 import cmdrsp, context, ntforg
from pysnmp.proto import rfc1902 as a, rfc1905
from pysnmp.proto.api import v2c

from .mib import Projection, oid, plan_set, SetError
from .snmp_lifetime import InboundLifetime, UnsupportedLifetime, OwnershipError
from .storage import RollbackFailed, CommitUncertain


def wire_name(identifier):
    return hashlib.sha256(identifier.encode()).hexdigest()[:28]


def response_budget(args, whole_message):
    """Size a detached worst-case SET echo without consuming response state.

    Supported cryptography is the existing SHA-256/AES-CFB profile. Original
    community request IDs come from wire BER, not PySNMP's rewritten callback ID.
    """
    # These pinned layout imports belong only to the guarded replacement SET path.
    from pysnmp.proto.mpmod.rfc3412 import ScopedPDU, SNMPv3Message
    from pysnmp.proto.secmod.rfc3414.service import UsmSecurityParameters

    snmp, model, security_model, name, level, ctx_engine, ctx_name, version, request, scoped_max, reference = args
    result = v2c.apiPDU.get_response(request)
    original = v2c.apiPDU.get_varbinds(request)
    v2c.apiPDU.set_varbinds(result, original)
    v2c.apiPDU.set_error_status(result, 18)
    v2c.apiPDU.set_error_index(result, len(original))
    local = int(snmp.get_mib_builder().import_symbols(
        "__SNMP-FRAMEWORK-MIB", "snmpEngineMaxMessageSize")[0].syntax)
    if int(model) == 1:
        message = decoder.decode(whole_message, asn1Spec=v2c.Message())[0]
        wire_id = v2c.apiPDU.get_request_id(v2c.apiMessage.get_pdu(message))
        v2c.apiPDU.set_request_id(result, wire_id)
        v2c.apiMessage.set_pdu(message, result)
        return len(encoder.encode(message)) <= local and len(encoder.encode(result)) <= int(scoped_max)
    incoming = decoder.decode(whole_message, asn1Spec=SNMPv3Message())[0]
    incoming_usm = decoder.decode(incoming["msgSecurityParameters"].asOctets(), asn1Spec=UsmSecurityParameters())[0]
    scope = ScopedPDU()
    scope["contextEngineId"], scope["contextName"] = ctx_engine, ctx_name
    scope["data"].setComponentByType(result.tagSet, result)
    scope_bytes = encoder.encode(scope)
    usm = UsmSecurityParameters()
    usm["msgAuthoritativeEngineId"] = snmp.snmpEngineID
    # Future clock ticks cannot increase these maximum legal INTEGER widths.
    usm["msgAuthoritativeEngineBoots"] = usm["msgAuthoritativeEngineTime"] = 2147483647
    usm["msgUserName"] = incoming_usm["msgUserName"]
    usm["msgAuthenticationParameters"] = bytes(24 if int(level) > 1 else 0)
    usm["msgPrivacyParameters"] = bytes(8 if int(level) == 3 else 0)
    message = SNMPv3Message()
    message["msgVersion"] = 3
    message["msgGlobalData"]["msgID"] = incoming["msgGlobalData"]["msgID"]
    message["msgGlobalData"]["msgMaxSize"] = local
    message["msgGlobalData"]["msgFlags"] = bytes([3 if int(level) == 3 else 1 if int(level) == 2 else 0])
    message["msgGlobalData"]["msgSecurityModel"] = 3
    message["msgSecurityParameters"] = encoder.encode(usm)
    if int(level) == 3:
        # AES CFB preserves the encoded scoped-PDU length; no privacy dry run.
        message["msgData"]["encryptedPDU"] = bytes(len(scope_bytes))
    else:
        message["msgData"]["plaintext"] = scope
    maximum = min(local, int(incoming["msgGlobalData"]["msgMaxSize"]))
    return len(encoder.encode(message)) <= maximum and len(scope_bytes) <= int(scoped_max)


@dataclass(eq=False, repr=False)
class PendingSet:
    ticket: object
    args: tuple
    whole_message: bytes
    peer: object
    credential_id: str
    generation: str
    activation: str
    task: object = None


MAX_PENDING_SETS = 128


class Responder(cmdrsp.CommandResponderBase):
    SUPPORTED_PDU_TYPES = (v2c.GetRequestPDU.tagSet, v2c.GetNextRequestPDU.tagSet,
                           v2c.GetBulkRequestPDU.tagSet, v2c.SetRequestPDU.tagSet)

    def __init__(self, adapter, snmp, ctx):
        self.adapter = adapter
        super().__init__(snmp, ctx)

    def process_pdu(self, snmp, model, security_model, name, level, *rest):
        if rest[3].tagSet == v2c.SetRequestPDU.tagSet and self.adapter.inbound is not None:
            self.adapter.admit_set((snmp, model, security_model, name, level, *rest))
            return
        state = self.adapter.engine.state
        if not self.adapter.listening or not state.gate() or model not in (1, 3):
            return
        incoming = snmp.observer.get_execution_context("rfc3412.receiveMessage:request")
        peer = ipaddress.ip_address(incoming["transportAddress"][0].split("%")[0])
        cred = next((c for c in state.cfg.credentials.values() if
                     c.enabled and c.polling.enabled and
                     ((security_model == 2 and c.version == "2c" and wire_name(c.id) == str(name)) or
                      (security_model == 3 and c.version == "3" and c.username == str(name)))), None)
        if cred is None or (cred.polling.networks and not any(peer in ipaddress.ip_network(n) for n in cred.polling.networks)):
            return
        if cred.version == "3" and int(level) < {"noAuthNoPriv": 1, "authNoPriv": 2, "authPriv": 3}[cred.security_level]:
            return
        self.projection = Projection(state, state.cfg.views[cred.polling.view_id].includes)
        self.limit = state.cfg.snmp.max_varbinds
        super().process_pdu(snmp, model, security_model, name, level, *rest)

    def handle_management_operation(self, snmp, reference, context_name, pdu):
        incoming = v2c.apiPDU.get_varbinds(pdu)
        if context_name:
            self.send_varbinds(snmp, reference, "authorizationError", 1, incoming)
            return
        if len(incoming) > self.limit:
            self.send_varbinds(snmp, reference, "tooBig", 0, [])
            return
        if pdu.tagSet == v2c.SetRequestPDU.tagSet:
            self.send_varbinds(snmp, reference, "notWritable", 1 if incoming else 0, incoming)
            return
        if pdu.tagSet == v2c.GetRequestPDU.tagSet:
            result = [self.projection.get(n) for n, _ in incoming]
        elif pdu.tagSet == v2c.GetNextRequestPDU.tagSet:
            result = [self.projection.next(n) for n, _ in incoming]
        else:
            nonrepeat = min(max(0, int(v2c.apiBulkPDU.get_non_repeaters(pdu))), len(incoming))
            repeats = max(0, int(v2c.apiBulkPDU.get_max_repetitions(pdu)))
            result = [self.projection.next(n) for n, _ in incoming[:nonrepeat]]
            pending = incoming[nonrepeat:]
            for _ in range(min(repeats, self.limit)):
                if not pending or len(result)+len(pending) > self.limit:
                    break
                pending = [self.projection.next(n) for n, _ in pending]
                result.extend(pending)
                if all(v.tagSet == rfc1905.endOfMibView.tagSet for _, v in pending):
                    break
        self.send_varbinds(snmp, reference, 0, 0, result)


class SnmpAdapter:
    def __init__(self, engine, store):
        self.engine, self.store = engine, store
        self.snmp = None
        self.listening = False
        self.error = None
        self.binding = None
        self.configured = {}
        self.target_config = {}
        self.send_transports = {}
        self.listener = None
        self.listener_domain = None
        self.cold_sent = False
        self.io_lock = asyncio.Lock()
        self.boots = None
        self.engine_id = None
        self.inbound = None
        self.pending_sets = {}
        self.set_error = None

    def status(self):
        c = self.engine.state.cfg
        if not c.switch.identity.sys_object_id:
            reason = "identity_required"
        elif not c.snmp.enabled:
            reason = "disabled"
        elif self.error:
            reason = self.error
        elif not any(x.enabled and x.polling.enabled for x in c.credentials.values()):
            reason = "credentials_required"
        else:
            reason = "ready" if self.listening else "initializing"
        reading = any(x.enabled and x.polling.enabled for x in c.credentials.values())
        writing = any(x.enabled and x.writing.enabled for x in c.credentials.values())
        fault = self.engine.storage_fault
        set_ready = bool(self.listening and writing and self.inbound and not self.inbound.error and not fault)
        if not self.engine.state.gate():
            writing_reason = "identity_required" if not c.switch.identity.sys_object_id else "disabled"
        elif fault:
            writing_reason = fault
        elif self.set_error or (self.inbound and self.inbound.error):
            writing_reason = self.set_error or self.inbound.error
        elif not writing:
            writing_reason = "set_access_required"
        else:
            writing_reason = "ready" if set_ready else self.error or "initializing"
        return dict(ready=bool(self.listening and reading), reason=reason, listener_ready=self.listening,
                    writing_ready=set_ready, writing_reason=writing_reason,
                    notifications_ready=bool(self.snmp and self.engine.state.gate() and self.send_transports and not fault),
                    storage_status=self.engine.storage_status(),
                    engine_id=self.engine_id.hex() if self.engine_id else None, engine_boots=self.boots,
                    documentation_identity=c.switch.identity.sys_object_id == "1.3.6.1.4.1.32473.1")

    def _initialize(self):
        self.engine_id, self.boots = self.store.engine_boot()
        # Avoid PySNMP's optional temp-directory persistence; SQLite owns durability.
        self.snmp = snmp_engine.SnmpEngine(maxMessageSize=65507)
        try:
            self.inbound = InboundLifetime(self.snmp, lambda: (r.ticket for r in self.pending_sets.values()))
            self.set_error = None
        except UnsupportedLifetime:
            self.inbound = None
            self.set_error = "unsupported_pysnmp_lifetime"
        builder = self.snmp.get_mib_builder()
        engine_id, boots = builder.import_symbols("__SNMP-FRAMEWORK-MIB", "snmpEngineID", "snmpEngineBoots")
        engine_id.syntax = engine_id.syntax.clone(self.engine_id)
        boots.syntax = boots.syntax.clone(self.boots)
        self.snmp.snmpEngineID = engine_id.syntax
        ctx = context.SnmpContext(self.snmp)
        self.responder = Responder(self, self.snmp, ctx)
        self.originator = ntforg.NotificationOriginator()

    async def reconcile(self):
        async with self.io_lock:
            await self._reconcile()

    async def _reconcile(self):
        self._retire_stale_sets()
        if self.engine.storage_fault:
            return  # Keep existing read registrations/listener; no writes or sends.
        s = self.engine.state
        if not s.gate():
            self._unbind()
            self._close_senders()
            return
        if self.snmp is None:
            self._initialize()
        self.error = None
        current = {k: v.model_dump() for k, v in s.cfg.credentials.items() if v.enabled}
        if current != self.configured:
            self._close_senders()
            for k, c in self.configured.items():
                config.delete_vacm_user(self.snmp, 2 if c["version"] == "2c" else 3,
                    wire_name(k) if c["version"] == "2c" else c["username"], c["security_level"], notifySubTree=(1,3,6))
                if c["version"] == "2c":
                    config.delete_v1_system(self.snmp, wire_name(k))
                else:
                    config.delete_v3_user(self.snmp, c["username"])
            for k, c in current.items():
                if c["version"] == "2c":
                    config.add_v1_system(self.snmp, wire_name(k), c["community"], securityName=wire_name(k))
                else:
                    config.add_v3_user(self.snmp, c["username"],
                        authProtocol=config.USM_AUTH_HMAC192_SHA256 if c["security_level"] != "noAuthNoPriv" else config.USM_AUTH_NONE,
                        authKey=c["auth_key"], privProtocol=config.USM_PRIV_CFB128_AES if c["security_level"] == "authPriv" else config.USM_PRIV_NONE,
                        privKey=c["priv_key"])
                config.add_vacm_user(self.snmp, 2 if c["version"] == "2c" else 3,
                        wire_name(k) if c["version"] == "2c" else c["username"], c["security_level"], notifySubTree=(1,3,6))
            self.configured = current
        binding = (s.cfg.snmp.host, s.cfg.snmp.port)
        incoming = any(c.enabled and (c.polling.enabled or
                       (c.writing.enabled and self.inbound is not None and not self.inbound.error))
                       for c in s.cfg.credentials.values())
        if not incoming:
            self._unbind()
        elif not self.listening or self.binding != binding:
            self._unbind()
            module = udp6 if ":" in binding[0] else udp
            domain = module.DOMAIN_NAME
            transport = module.Udp6Transport() if module is udp6 else module.UdpTransport()
            try:
                transport.open_server_mode(binding)
                # Pinned PySNMP transport exposes completion of its asyncio bind task.
                await transport._lport
                config.add_transport(self.snmp, domain, transport)
                self.listener, self.listener_domain = transport, domain
                self.listening, self.binding = True, binding
            except Exception:
                transport.close_transport()
                self.error = "listener_bind_failed"
        targets = {k: t.model_dump() for k, t in s.cfg.targets.items() if t.enabled and s.cfg.credentials[t.credential_id].enabled}
        if targets != self.target_config:
            self._close_senders()
        for index, (tid, t) in enumerate(targets.items(), 1):
            if tid in self.send_transports:
                continue
            c = s.cfg.credentials[t["credential_id"]]
            module = udp6 if ":" in t["address"] else udp
            domain = module.DOMAIN_NAME + (100, index)
            transport = module.Udp6Transport() if module is udp6 else module.UdpTransport()
            try:
                transport.open_client_mode((t["source_address"] or ("::" if module is udp6 else "0.0.0.0"), 0))
                await transport._lport
                config.add_transport(self.snmp, domain, transport)
                config.add_target_parameters(self.snmp, wire_name(tid), wire_name(c.id) if c.version == "2c" else c.username,
                                             c.security_level, mpModel=1 if c.version == "2c" else 3)
                config.add_target_address(self.snmp, wire_name(tid), domain, (t["address"], t["port"]), wire_name(tid), tagList=wire_name(tid))
                config.add_notification_target(self.snmp, wire_name(tid), wire_name(tid), wire_name(tid), "trap")
                self.send_transports[tid] = (domain, transport)
            except Exception:
                transport.close_transport()
                self.error = "notification_configuration_failed"
        self.target_config = targets
        if not self.cold_sent and (self.listening or self.send_transports):
            self.cold_sent = True
            await self.engine.execute("coldStart")

    def _set_credential(self, args, peer, credential_id=None):
        snmp, model, security_model, name, level = args[:5]
        state = self.engine.state
        if (self.engine.storage_fault or snmp is not self.snmp or not self.listening or not state.gate() or
                (int(model), int(security_model)) not in ((1, 2), (3, 3))):
            return None
        for credential in state.cfg.credentials.values():
            if credential_id is not None and credential.id != credential_id:
                continue
            matches = ((security_model == 2 and credential.version == "2c" and wire_name(credential.id) == str(name)) or
                       (security_model == 3 and credential.version == "3" and credential.username == str(name)))
            if not credential.enabled or not matches:
                continue
            # The incoming authentication must still be the installed registration,
            # not a newly edited credential that reuses its security name.
            if self.configured.get(credential.id) != credential.model_dump():
                return None
            if int(level) < {"noAuthNoPriv": 1, "authNoPriv": 2, "authPriv": 3}[credential.security_level]:
                return None
            if credential.writing.networks and not any(peer in ipaddress.ip_network(n) for n in credential.writing.networks):
                return None
            return credential
        return None

    def _current_set(self, request):
        state = self.engine.state
        if (request.activation != state.activation or
                request.generation != state.credential_generations.get(request.credential_id)):
            return None
        return self._set_credential(request.args, request.peer, request.credential_id)

    def _cancel_set(self, request, reason):
        owner = request.ticket.owner
        if owner:
            owner.discard(request.ticket, reason)
        if request.task and not request.task.done():
            request.task.cancel()

    def _cancel_sets(self, reason):
        for request in tuple(self.pending_sets.values()):
            self._cancel_set(request, reason)

    def _retire_stale_sets(self):
        for request in tuple(self.pending_sets.values()):
            if not self._current_set(request):
                self._cancel_set(request, "revoked")

    def admit_set(self, args):
        owner = self.inbound
        if owner is None:
            return
        try:
            ticket = owner.capture(int(args[1]), args[-1])
        except OwnershipError:
            self.set_error = "inbound_response_ownership_lost"
            return
        if not owner.ready(ticket):
            return
        if owner.error:
            owner.discard(ticket, "ownership_error")
            return
        incoming = args[0].observer.get_execution_context("rfc3412.receiveMessage:request")
        try:
            peer = ipaddress.ip_address(incoming["transportAddress"][0].split("%")[0])
        except ValueError:
            owner.discard(ticket, "invalid_peer")
            return
        credential = self._set_credential(args, peer)
        if credential is None:
            owner.discard(ticket, "unauthorized_identity")
            return
        if len(self.pending_sets) >= MAX_PENDING_SETS:
            owner.discard(ticket, "overload")
            return
        state = self.engine.state
        request = PendingSet(ticket, args, bytes(incoming["wholeMsg"]), peer, credential.id,
                             state.credential_generations[credential.id], state.activation)
        self.pending_sets[ticket] = request
        request.task = asyncio.create_task(self._run_set(request))
        request.task.add_done_callback(lambda task: self._set_done(request, task))

    def _set_done(self, request, task):
        self.pending_sets.pop(request.ticket, None)
        if not task.cancelled() and task.exception() is not None:
            self.set_error = "set_processing_failed"
        request.args, request.whole_message, request.task = (), b"", None

    def _send_set(self, request, status, index, empty=False, information=None):
        args = request.args
        response = v2c.apiPDU.get_response(args[8])
        v2c.apiPDU.set_error_status(response, status)
        v2c.apiPDU.set_error_index(response, index)
        v2c.apiPDU.set_varbinds(response, [] if empty else v2c.apiPDU.get_varbinds(args[8]))
        # A REPORT is generated from the confirmed request, not a Response-PDU;
        # passing an unconfirmed response would trigger PySNMP's loop protection.
        outgoing = args[8] if information else response
        args[0].message_dispatcher.return_response_pdu(*args[:8], outgoing, *args[9:], information or {})

    async def _run_set(self, request):
        owner = request.ticket.owner
        if owner is None:
            return  # Expiry can retire the ticket before this task first runs.
        committed = False
        try:
            async with self.io_lock:
                async with self.engine.lock:
                    credential = self._current_set(request)
                    if credential is None or not owner.ready(request.ticket):
                        return
                    bindings = v2c.apiPDU.get_varbinds(request.args[8])
                    plan, information = None, None
                    status, index, empty = 0, 0, False
                    # Context errors use the protocol counter/report path, not a
                    # normal write-view authorization response.
                    if request.args[6]:
                        counter = self.snmp.get_mib_builder().import_symbols(
                            "__SNMP-TARGET-MIB", "snmpUnknownContexts")[0]
                        counter.syntax += 1
                        information = {"oid": counter.name, "val": counter.syntax}
                        status = "genErr"
                    elif (len(bindings) > self.engine.state.cfg.snmp.max_varbinds or
                          not response_budget(request.args, request.whole_message)):
                        status, empty = "tooBig", True
                    elif not credential.writing.enabled or credential.writing.view_id not in self.engine.state.cfg.views:
                        status = "authorizationError"
                    else:
                        try:
                            plan = plan_set(self.engine.state.cfg, bindings,
                                self.engine.state.cfg.views[credential.writing.view_id].includes)
                        except SetError as failure:
                            status, index = failure.status, failure.index

                    def commit_and_respond():
                        nonlocal committed, status, index
                        if plan is not None and plan.changed:
                            try:
                                self.engine.commit_set_locked(plan)
                            except RollbackFailed:
                                status, index = "undoFailed", 0
                                self.set_error = "storage_rollback_failed"
                            except CommitUncertain:
                                self.set_error = "storage_commit_unknown"
                                raise
                            except Exception as failure:
                                if not getattr(failure, "switchlab_rolled_back", False):
                                    raise
                                status, index = "commitFailed", plan.first_effective
                            else:
                                committed = True
                        self._send_set(request, status, index, empty, information)

                    # Current identity/view/generation, size and final candidate
                    # are checked. No await can split claim/commit/send/finalize.
                    owner.complete(request.ticket, commit_and_respond)
        except asyncio.CancelledError:
            raise
        except CommitUncertain:
            pass  # Diagnostic is explicit; neither rollback nor delivery is claimed.
        except Exception:
            self.set_error = "set_delivery_failed" if committed else "set_processing_failed"
        finally:
            owner.discard(request.ticket, "canceled_or_rejected")

    def _unbind(self):
        self._cancel_sets("listener_closed")
        self.listening = False
        if self.listener:
            config.delete_transport(self.snmp, self.listener_domain)
            self.listener.close_transport()
            self.listener = None
        self.binding = None

    def _close_senders(self):
        for tid, (domain, transport) in self.send_transports.items():
            config.delete_transport(self.snmp, domain)
            transport.close_transport()
            config.delete_target_address(self.snmp, wire_name(tid))
            config.delete_target_parameters(self.snmp, wire_name(tid))
            config.delete_notification_target(self.snmp, wire_name(tid), wire_name(tid))
        self.send_transports.clear()
        self.target_config = {}

    async def drain_one(self):
        async with self.io_lock:
            s = self.engine.state
            if self.engine.storage_fault or not s.gate() or not self.snmp or not s.outbox:
                return
            item = s.outbox[0]
            e, tid = item["event"], item["target_id"]
            status = "locally-failed"
            if tid in self.send_transports:
                fields = [(oid("1.3.6.1.2.1.1.3.0"), a.TimeTicks(e["uptime"])),
                          (oid("1.3.6.1.6.3.1.1.4.1.0"), a.ObjectIdentifier("1.3.6.1.6.3.1.1.5."+str({"coldStart":1,"linkDown":3,"linkUp":4}[e["kind"]])))]
                if e["kind"] != "coldStart":
                    fields.extend([(oid("1.3.6.1.2.1.2.2.1.1")+(e["if_index"],), a.Integer32(e["if_index"])),
                        (oid("1.3.6.1.2.1.2.2.1.7")+(e["if_index"],), a.Integer32(e["admin"])),
                        (oid("1.3.6.1.2.1.2.2.1.8")+(e["if_index"],), a.Integer32(e["before"] if e["kind"] == "linkDown" else e["after"]))])
                try:
                    # Synchronous send into an already-bound UDP transport while io_lock
                    # is held. Clearing identity must acquire this same lock.
                    failures = []
                    handle = self.originator.send_varbinds(self.snmp, wire_name(tid), None, b"", fields,
                        cbFun=lambda eng, handle, error, *rest: failures.append(error) if error else None)
                    status = "sent" if handle is not None and not failures else "locally-failed"
                except Exception:
                    status = "locally-failed"
            await self.engine.execute("notification-result", dict(notification_id=e["id"], target_id=tid, status=status, attempted=True))

    async def reboot(self):
        async with self.io_lock:
            self.close()
            self.cold_sent = False
            self.configured = {}
            await self._reconcile()

    def close(self):
        self._cancel_sets("closed")
        if self.inbound:
            self.inbound.close()
        self._unbind()
        self._close_senders()
        if self.snmp:
            self.snmp.close_dispatcher()
            self.snmp = None
        self.inbound = None
