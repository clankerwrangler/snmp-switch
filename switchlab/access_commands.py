"""RADIUS commands of the engine transaction: authentication, sessions,
accounting, CoA/Disconnect settings and their configuration records.

apply_access runs inside Engine._execute on the candidate Runtime `s`, exactly
like the engine's other commands; the engine commits or discards the result.
"""
from __future__ import annotations

from dataclasses import replace

from .access_state import AccessSession
from .common import event_resource_label, require
from .models import (AccountingOptions, DynamicOptions, DynamicSender, RadiusMaterial, RadiusOptions, RadiusServer,
                     SupplicantProfile, SupplicantTemplate, check_collection_limit, uid, update_options)
from .radius import AccessResult, RadiusError, access_attributes, authorization

ACCESS_ACTIONS = frozenset({
    "radius-dynamic", "dynamic-settings", "dynamic-sender-save", "dynamic-sender-delete",
    "accounting-settings", "accounting-target-save", "accounting-target-delete",
    "accounting-prune", "accounting-event", "accounting-result", "radius-shutdown",
    "radius-settings", "radius-server-save", "radius-server-delete",
    "radius-material-save", "radius-template-save", "radius-material-delete", "radius-template-delete",
    "source-supplicant-save", "source-authentication", "radius-session-action",
    "radius-begin", "radius-discover", "radius-pae-events", "radius-result",
})

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


def apply_access(engine, s, action, d):
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
        cfg.radius.dynamic_authorization = update_options(cfg.radius.dynamic_authorization, DynamicOptions, d)
        s.event(action);return
    if action == "dynamic-sender-save":
        previous = next((sender for sender in cfg.radius.dynamic_authorization.senders if sender.id==d.get("id")),None)
        fields = dict(d)
        if previous is not None and fields.get("secret")=="":fields.pop("secret")
        sender = DynamicSender.model_validate({**(previous.model_dump() if previous else {}),**fields})
        cfg.radius.dynamic_authorization.senders = [value for value in cfg.radius.dynamic_authorization.senders if value.id!=sender.id] + [sender]
        check_collection_limit(cfg.radius.dynamic_authorization, "senders", ("radius", "dynamic_authorization", "senders"))
        if sender.enabled:
            cfg.radius.dynamic_authorization.check_sender_addresses()
        s.event(action,resource_id=sender.id,resource_label=event_resource_label(sender));return {"id":sender.id}
    if action == "dynamic-sender-delete":
        sender = next((sender for sender in cfg.radius.dynamic_authorization.senders if sender.id==d["id"]),None)
        require(sender is not None,"Sender not found",404)
        cfg.radius.dynamic_authorization.senders = [sender for sender in cfg.radius.dynamic_authorization.senders if sender.id!=d["id"]]
        s.event(action,resource_id=d["id"],resource_label=event_resource_label(sender));return
    if action == "accounting-settings":
        require("targets" not in d, "Use accounting target operations", 422)
        cfg.radius.accounting = update_options(cfg.radius.accounting, AccountingOptions, d)
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
        check_collection_limit(cfg.radius.accounting, "targets", ("radius", "accounting", "targets"))
        s.event(action, resource_id=target.id, resource_label=event_resource_label(target))
        return {"id": target.id}
    if action == "accounting-target-delete":
        target = next((target for target in cfg.radius.accounting.targets if target.id == d["id"]), None)
        require(target is not None, "Accounting target not found", 404)
        cfg.radius.accounting.targets = [value for value in cfg.radius.accounting.targets if value.id != d["id"]]
        s.event(action, resource_id=d["id"], resource_label=event_resource_label(target))
        return
    if action == "accounting-prune":
        remaining = []
        for record in s.accounting_outbox:
            if engine.accounting.expired(record):
                s.accounting_drop("expired", record_id=record["id"])
            else:remaining.append(record)
        s.accounting_outbox = remaining
        return
    if action == "accounting-event":
        record = next((item for item in s.accounting_outbox if item["id"] == d["id"]), None)
        if record is None:return {"current": False}
        if d["phase"] == "attempting":
            record["status"] = "sending";record["attempts"] += 1
        s.event("accounting", status=d["phase"], record_id=record["id"], session_id=record["session_id"], target_id=d.get("target_id"), **({"server_label":d["server_label"]} if "server_label" in d else {}))
        return {"current": True}
    if action == "accounting-result":
        record = next((item for item in s.accounting_outbox if item["id"] == d["id"]), None)
        if record is None:return {"current": False}
        s.accounting_outbox = [item for item in s.accounting_outbox if item["id"] != record["id"]]
        if d["delivered"]:
            s.event("accounting", status="delivered", record_id=record["id"], session_id=record["session_id"], target_id=d["target_id"], **({"server_label":d["server_label"]} if "server_label" in d else {}))
        else:s.accounting_drop(d["reason"], record_id=record["id"], session_id=record["session_id"])
        return {"current": True}
    if action == "radius-shutdown":
        # Retired attempts make any late reply stale, so no grant follows Accounting-Off.
        for key in list(s.radius_attempts):
            s.retire_authentication(key)
            s.radius_status[key] = dict(status="invalidated", reason="application-shutdown")
        for key in list(s.radius_sessions):s.end_session(key, "application-shutdown")
        s.queue_accounting(8, reason="application-shutdown")
        return
    if action == "radius-settings":
        require(not {"servers", "materials", "templates", "accounting", "dynamic_authorization"} & d.keys(), "Use the RADIUS record operations", 422)
        cfg.radius = update_options(cfg.radius, RadiusOptions, d)
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
        check_collection_limit(cfg.radius, "servers", ("radius", "servers"))
        s.event(action, resource_id=server.id, resource_label=event_resource_label(server))
        return {"id": server.id}
    if action == "radius-server-delete":
        server = next((server for server in cfg.radius.servers if server.id == d["id"]), None)
        require(server is not None, "Server not found", 404)
        cfg.radius.servers = [value for value in cfg.radius.servers if value.id != d["id"]]
        s.event(action, resource_id=d["id"], resource_label=event_resource_label(server))
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
        family = "materials" if action == "radius-material-save" else "templates"
        check_collection_limit(cfg.radius, family, ("radius", family))
        if family == "templates":
            cfg.check_profile(record.profile)
        elif previous is not None and previous.kind != record.kind:
            cfg.check_material_dependents(record.id)
        s.event(action, resource_id=record.id, resource_label=event_resource_label(record))
        return {"id": record.id}
    if action in ("radius-material-delete", "radius-template-delete"):
        collection = cfg.radius.materials if action == "radius-material-delete" else cfg.radius.templates
        previous = get(collection, d["id"])
        del collection[d["id"]]
        if action == "radius-material-delete":
            cfg.check_material_dependents(d["id"])
        s.event(action, resource_id=d["id"], resource_label=event_resource_label(previous))
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
            cfg.check_profile(source.supplicant)
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
        require(not engine.closing, "RADIUS is shutting down", 503)
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
