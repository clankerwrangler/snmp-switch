"""PySNMP handles BER, USM cryptography and security clocks.

All operational reads use one immutable state and one current authorization
decision per PDU. Network dispatch never owns a second switch state.
"""
import asyncio
import ipaddress
import hashlib

from pysnmp.carrier.asyncio.dgram import udp, udp6
from pysnmp.entity import config, engine as snmp_engine
from pysnmp.entity.rfc3413 import cmdrsp, context, ntforg
from pysnmp.proto import rfc1902 as a, rfc1905
from pysnmp.proto.api import v2c

from .mib import Projection, oid


def wire_name(identifier):
    return hashlib.sha256(identifier.encode()).hexdigest()[:28]


class Responder(cmdrsp.CommandResponderBase):
    SUPPORTED_PDU_TYPES = (v2c.GetRequestPDU.tagSet, v2c.GetNextRequestPDU.tagSet,
                           v2c.GetBulkRequestPDU.tagSet, v2c.SetRequestPDU.tagSet)

    def __init__(self, adapter, snmp, ctx):
        self.adapter = adapter
        super().__init__(snmp, ctx)

    def process_pdu(self, snmp, model, security_model, name, level, *rest):
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
        return dict(ready=self.listening, reason=reason,
                    notifications_ready=bool(self.snmp and self.engine.state.gate() and self.send_transports),
                    engine_id=self.engine_id.hex() if self.engine_id else None, engine_boots=self.boots,
                    documentation_identity=c.switch.identity.sys_object_id == "1.3.6.1.4.1.32473.1")

    def _initialize(self):
        self.engine_id, self.boots = self.store.engine_boot()
        # Avoid PySNMP's optional temp-directory persistence; SQLite owns durability.
        self.snmp = snmp_engine.SnmpEngine(maxMessageSize=65507)
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
        polling = any(c.enabled and c.polling.enabled for c in s.cfg.credentials.values())
        if not polling:
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

    def _unbind(self):
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
            if not s.gate() or not self.snmp or not s.outbox:
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
        self._unbind()
        self._close_senders()
        if self.snmp:
            self.snmp.close_dispatcher()
            self.snmp = None
