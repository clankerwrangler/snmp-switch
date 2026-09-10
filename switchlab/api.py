import asyncio
import contextlib
import copy
import json
import os
import secrets
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import Field, ValidationError, create_model, model_validator

from .engine import CommandError, Engine
from .models import Configuration, Credential, CredentialAuth, AccessGroup, PollingAccess, WritingAccess, Endpoint, Identity, Record, SnmpSettings, Source, Switch, Target, View, RadiusSettings, RadiusServer, RadiusMaterial, SupplicantProfile, SupplicantTemplate, AccountingSettings, DynamicSettings, DynamicSender, initial_configuration
from .snmp import SnmpAdapter
from .storage import Store, StorageFault, RollbackFailed, CommitUncertain


class Revision(Record):
    expected_revision: int | None = Field(default=None, ge=0)
    expected_configuration_revision: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def revision_required(self):
        if self.expected_revision is None and self.expected_configuration_revision is None:
            raise ValueError("Supply expected_revision or expected_configuration_revision")
        return self


class Advance(Revision):
    duration_ms: int = Field(gt=0, le=86400000)


class Attachment(Revision):
    port_id: str


class Clone(Revision):
    preserve_macs: bool = False
    name: str | None = None


class Sources(Revision):
    sources: list[Source] = Field(max_length=4096)


class Clear(Revision):
    port_id: str | None = None
    vid: int | None = Field(default=None, ge=1, le=4094)


class VlanCreate(Revision):
    vid: int = Field(ge=1, le=4094)
    name: str = ""
    fdb_id: int | None = Field(default=None, ge=1, le=4294967295)


class VlanEdit(Revision):
    name: str


class Import(Revision):
    scenario: dict[str, Any]


class Login(Record):
    password: str = Field(min_length=1, max_length=1024, repr=False)


def patch_model(name, model, fields):
    return create_model(name, __base__=Revision, **{k: (model.model_fields[k].annotation | None, None) for k in fields})


from .models import Port

PortPatch = patch_model("PortPatch", Port, [k for k in Port.model_fields if k not in ("id", "bridge_port", "if_index")])
EndpointPatch = patch_model("EndpointPatch", Endpoint, ["name", "metadata", "active", "sources"])
SwitchPatch = patch_model("SwitchPatch", Switch, [k for k in Switch.model_fields if k not in ("id", "port_count")])
SnmpPatch = patch_model("SnmpPatch", SnmpSettings, list(SnmpSettings.model_fields))
class EndpointCreate(Endpoint, Revision):
    pass
# Credential updates merge write-only keys; validation occurs after merging in the engine.
PollingPatch = create_model("PollingPatch", __base__=Record, **{
    k: (PollingAccess.model_fields[k].annotation | None, None) for k in PollingAccess.model_fields
})
WritingPatch = create_model("WritingPatch", __base__=Record, **{
    k: (WritingAccess.model_fields[k].annotation | None, None) for k in WritingAccess.model_fields
})
CredentialWrite = create_model("CredentialWrite",
    __base__=patch_model("CredentialFields", Credential, list(Credential.model_fields)),
    polling=(PollingPatch | None, None), writing=(WritingPatch | None, None),
    group_id=(str | None, None), access_transfer=(Literal["keep", "none"] | None, None))
GroupWrite = create_model("GroupWrite",
    __base__=patch_model("GroupFields", AccessGroup, list(AccessGroup.model_fields)),
    polling=(PollingPatch | None, None), writing=(WritingPatch | None, None))
class ViewWrite(View, Revision):
    pass

class TargetWrite(Target, Revision):
    credential_id: str | None = None
    new_credential: CredentialAuth | None = None

    @model_validator(mode="after")
    def credential_choice(self):
        if (self.credential_id is None) == (self.new_credential is None):
            raise ValueError("Select an existing credential or create one, not both")
        return self


RadiusSettingsWrite = patch_model("RadiusSettingsWrite", RadiusSettings, [name for name in RadiusSettings.model_fields if name not in ("servers", "materials", "templates", "accounting", "dynamic_authorization")])
RadiusServerWrite = create_model("RadiusServerWrite", __base__=patch_model("RadiusServerFields", RadiusServer, list(RadiusServer.model_fields)),
    position=(int | None, Field(default=None, ge=0, le=15)))
AccountingSettingsWrite = patch_model("AccountingSettingsWrite", AccountingSettings, [name for name in AccountingSettings.model_fields if name != "targets"])
DynamicSettingsWrite = patch_model("DynamicSettingsWrite", DynamicSettings, [name for name in DynamicSettings.model_fields if name != "senders"])
DynamicSenderWrite = patch_model("DynamicSenderWrite", DynamicSender, list(DynamicSender.model_fields))
RadiusMaterialWrite = patch_model("RadiusMaterialWrite", RadiusMaterial, list(RadiusMaterial.model_fields))
SupplicantPatch = create_model("SupplicantPatch", __base__=Record, **{
    name: (field.annotation | None, None) for name,field in SupplicantProfile.model_fields.items()})
RadiusTemplateWrite = create_model("RadiusTemplateWrite", __base__=Revision,
    id=(str | None, None), label=(str | None, None), profile=(SupplicantPatch | None, None))


class SourceSupplicantWrite(Revision):
    source_id: str
    profile: SupplicantPatch | None = None
    template_id: str | None = None
    restart: bool = False


class SourceAuthentication(Revision):
    source_id: str
    action: Literal["restart", "reauthenticate"]


class SessionAuthentication(Revision):
    action: Literal["restart", "reauthenticate"]


def create_app(store=None, configuration=None):
    sessions = {}
    buckets = defaultdict(deque)
    password_hasher = PasswordHasher()

    @asynccontextmanager
    async def lifespan(app):
        nonlocal store
        owned = store is None
        if store is None:
            key_path = os.environ.get("SWITCHLAB_KEY_FILE", "secrets/config.key")
            if not Path(key_path).is_file():
                raise RuntimeError("Missing encryption key. Run python scripts/init.py before starting.")
            store = Store(os.environ.get("SWITCHLAB_DB", "data/switch.db"), Path(key_path).read_bytes().strip())
        task = adapter = None
        try:
            saved = store.load()
            cfg = saved or configuration or initial_configuration(int(os.environ.get("SWITCHLAB_PORT_COUNT", "24")))
            if saved is None and configuration is None:
                cfg.snmp = SnmpSettings(host=os.environ.get("SWITCHLAB_SNMP_DEFAULT_HOST") or cfg.snmp.host)
            if getattr(store, "startup_warning", None):
                app.state.startup_warning = store.startup_warning
            # An explicit overlay applies only to a fresh database, never to upgrades.
            overlay = os.environ.get("SWITCHLAB_CONFIG")
            if overlay and saved is None:
                raw = json.loads(Path(overlay).read_text())
                merged = cfg.model_dump(mode="json")
                if "identity" in raw:
                    merged["switch"]["identity"].update(raw["identity"])
                if "snmp" in raw:
                    merged["snmp"].update(raw["snmp"])
                try:
                    cfg = Configuration.model_validate(merged)
                except ValidationError:
                    # Repairable identity/setup failure must not make the UI unavailable.
                    app.state.startup_warning = "Invalid startup configuration; SNMP remains disabled. Repair settings."
            app.state.engine = Engine(cfg, store)
            adapter = app.state.adapter = SnmpAdapter(app.state.engine, store)
            await app.state.adapter.reconcile()
            await app.state.engine.reconcile_dynamic()
            app.state.background_error = None

            async def background():
                last = time.monotonic()
                while True:
                    await asyncio.sleep(0.1)
                    now = time.monotonic()
                    elapsed = int((now-last)*1000)
                    last = now
                    try:
                        await app.state.engine.reconcile_dynamic()
                        await app.state.engine.prune_dynamic()
                        await app.state.engine.service_authentication()
                        await app.state.engine.service_accounting()
                        if app.state.engine.storage_fault:
                            continue
                        await app.state.engine.continue_advance()
                        if not app.state.engine.state.cfg.paused:
                            await app.state.engine.execute("advance", {"duration_ms": max(1, min(elapsed, 60000)), "automatic": True})
                        await app.state.adapter.drain_one()
                        app.state.background_error = None
                    except Exception:
                        # Visible diagnostic, no unhandled task death or leaked request data.
                        app.state.background_error = "Background work failed; check storage and use a smaller simulation step."

            task = asyncio.create_task(background())
            yield
        finally:
            if task is not None:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            if hasattr(app.state, "engine"):
                await app.state.engine.close_dynamic()
                await app.state.engine.close_accounting()
                await app.state.engine.close_authentication()
            if adapter is not None:
                adapter.close()
            if owned:
                store.close()
                store = None

    app = FastAPI(title="Switch Lab API", version="1.0.0", lifespan=lifespan)

    @app.exception_handler(StorageFault)
    @app.exception_handler(RollbackFailed)
    @app.exception_handler(CommitUncertain)
    async def storage_error(request, exc):
        return JSONResponse({"detail": "Storage is faulted; this process serves its last confirmed snapshot. "
                             "Writes and trap sends require a successful restart from the saved database.",
                             "storage_status": app.state.engine.storage_status()}, status_code=503)

    @app.exception_handler(CommandError)
    async def command_error(request, exc):
        return JSONResponse({"detail": exc.message}, status_code=exc.status)

    @app.exception_handler(ValidationError)
    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        # Pydantic errors normally contain input values, which can include secrets.
        errors = [{"field": ".".join(map(str, e["loc"])), "message": e["msg"]} for e in exc.errors()]
        return JSONResponse({"detail": errors}, status_code=422)

    @app.middleware("http")
    async def security(request, call_next):
        path = request.url.path
        if path.startswith("/api/"):
            if not hasattr(app.state, "engine"):
                return JSONResponse({"detail": "Initializing"}, 503)
            if int(request.headers.get("content-length", "0")) > 8*1024*1024:
                return JSONResponse({"detail": "Request body too large"}, 413)
            body = await request.body()
            if len(body) > 8*1024*1024:
                return JSONResponse({"detail": "Request body too large"}, 413)
            now = time.monotonic()
            group = "auth" if path.startswith("/api/v1/auth/") else "api"
            bucket = buckets[(request.client.host if request.client else "local", group)]
            while bucket and bucket[0] < now-60:
                bucket.popleft()
            if len(bucket) >= (20 if group == "auth" and request.method == "POST" else 1200):
                return JSONResponse({"detail": "Rate limit exceeded"}, 429)
            if request.method != "GET" or group != "auth":
                bucket.append(now)
            if path not in ("/api/v1/auth/status", "/api/v1/auth/setup", "/api/v1/auth/login"):
                session = sessions.get(request.cookies.get("switchlab_session"))
                if not session or session["expires"] < now:
                    return JSONResponse({"detail": "Sign in required"}, 401)
                if request.method not in ("GET", "HEAD", "OPTIONS"):
                    if not secrets.compare_digest(request.headers.get("x-csrf-token", ""), session["csrf"]):
                        return JSONResponse({"detail": "CSRF token required"}, 403)
            if request.method not in ("GET", "HEAD", "OPTIONS"):
                origin = request.headers.get("origin")
                if origin and origin != str(request.base_url).rstrip("/"):
                    return JSONResponse({"detail": "Cross-origin write rejected"}, 403)
        response = await call_next(request)
        response.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "same-origin",
                                 "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'",
                                 "Cache-Control": "no-store" if path.startswith("/api/") else "no-cache"})
        return response

    @app.get("/healthz")
    async def health():
        return {"ready": hasattr(app.state, "engine")}

    @app.get("/api/v1/auth/status")
    async def auth_status(request: Request):
        session = sessions.get(request.cookies.get("switchlab_session"))
        active = session is not None and session["expires"] > time.monotonic()
        return {"setup_required": not bool(store.administrator_hash()), "authenticated": active,
                "csrf_token": session["csrf"] if active else None}

    def issue_session():
        now = time.monotonic()
        for k in list(sessions):
            if sessions[k]["expires"] < now:
                del sessions[k]
        if len(sessions) >= 20:
            sessions.pop(next(iter(sessions)))
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        sessions[token] = {"csrf": csrf, "expires": now+28800}
        response = JSONResponse({"csrf_token": csrf})
        response.set_cookie("switchlab_session", token, httponly=True, secure=os.environ.get("SWITCHLAB_SECURE_COOKIES") == "1", samesite="strict", max_age=28800)
        return response

    @app.post("/api/v1/auth/setup")
    async def setup(body: Login):
        if store.administrator_hash() or not store.create_administrator(password_hasher.hash(body.password)):
            raise HTTPException(409, "Administrator already configured")
        return issue_session()

    @app.post("/api/v1/auth/login")
    async def login(body: Login):
        saved = store.administrator_hash()
        try:
            if saved is None or not password_hasher.verify(saved, body.password):
                raise HTTPException(401, "Invalid credentials")
        except VerificationError:
            raise HTTPException(401, "Invalid credentials")
        return issue_session()

    @app.post("/api/v1/auth/logout")
    async def logout(request: Request):
        sessions.pop(request.cookies.get("switchlab_session"), None)
        response = JSONResponse({"signed_out": True})
        response.delete_cookie("switchlab_session")
        return response

    def mutation(method, path, model, action, transform=None):
        async def handler(request: Request, body):
            data = body.model_dump(exclude_unset=True)
            expected = data.pop("expected_revision", None)
            expected_config = data.pop("expected_configuration_revision", None)
            payload = transform(data, request.path_params) if transform else data
            adapter = app.state.adapter
            # The gate, reconfiguration and all send paths share this boundary.
            async with adapter.io_lock:
                previous = app.state.engine.state
                result = await app.state.engine.execute(action, payload, expected, request.headers.get("idempotency-key"), expected_config)
                if action == "reboot" and app.state.engine.state is not previous:
                    adapter.close()
                    adapter.configured = {}
                    adapter.cold_sent = False
                await adapter._reconcile()
                await app.state.engine.reconcile_dynamic()
            # Reconciliation may commit coldStart; return the current write revision.
            response = {**result, "revision": app.state.engine.state.revision, "configuration_revision": app.state.engine.state.configuration_revision}
            if action == "advance" and response.get("advance", {}).get("status") == "waiting":
                return JSONResponse(response, status_code=202)
            return response
        handler.__annotations__["body"] = model
        handler.__name__ = action + "_" + method + "_" + path.replace("/", "_")
        app.add_api_route("/api/v1"+path, handler, methods=[method], tags=[path.split("/")[1]])

    mutation("PATCH", "/radius/settings", RadiusSettingsWrite, "radius-settings")
    mutation("PATCH", "/radius/dynamic", DynamicSettingsWrite, "dynamic-settings")
    mutation("POST", "/radius/dynamic/senders", DynamicSenderWrite, "dynamic-sender-save")
    mutation("DELETE", "/radius/dynamic/senders/{id}", Revision, "dynamic-sender-delete", lambda d,p: {"id":p["id"]})
    mutation("PATCH", "/radius/accounting", AccountingSettingsWrite, "accounting-settings")
    mutation("POST", "/radius/accounting/targets", RadiusServerWrite, "accounting-target-save")
    mutation("DELETE", "/radius/accounting/targets/{id}", Revision, "accounting-target-delete", lambda d,p: {"id":p["id"]})
    mutation("POST", "/radius/sessions/{id}", SessionAuthentication, "radius-session-action", lambda d,p: {"id":p["id"], **d})
    mutation("POST", "/radius/servers", RadiusServerWrite, "radius-server-save")
    mutation("DELETE", "/radius/servers/{id}", Revision, "radius-server-delete", lambda d,p: {"id":p["id"]})
    mutation("POST", "/radius/materials", RadiusMaterialWrite, "radius-material-save")
    mutation("DELETE", "/radius/materials/{id}", Revision, "radius-material-delete", lambda d,p: {"id":p["id"]})
    mutation("POST", "/radius/templates", RadiusTemplateWrite, "radius-template-save")
    mutation("DELETE", "/radius/templates/{id}", Revision, "radius-template-delete", lambda d,p: {"id":p["id"]})
    mutation("POST", "/endpoints/{id}/supplicant", SourceSupplicantWrite, "source-supplicant-save", lambda d,p: {"id":p["id"], **d})
    mutation("POST", "/endpoints/{id}/authentication", SourceAuthentication, "source-authentication", lambda d,p: {"id":p["id"], **d})
    mutation("PATCH", "/switch", SwitchPatch, "switch-edit")
    mutation("PATCH", "/ports/{id}", PortPatch, "port-edit", lambda d,p: {"id":p["id"], "patch":d})
    mutation("POST", "/endpoints", EndpointCreate, "endpoint-create")
    mutation("PATCH", "/endpoints/{id}", EndpointPatch, "endpoint-edit", lambda d,p: {"id":p["id"], "patch":d})
    mutation("DELETE", "/endpoints/{id}", Revision, "endpoint-delete", lambda d,p: p)
    mutation("PUT", "/endpoints/{id}/sources", Sources, "endpoint-edit", lambda d,p: {"id":p["id"], "patch":d})
    mutation("PUT", "/endpoints/{id}/attachment", Attachment, "attach", lambda d,p: {**d, **p})
    mutation("DELETE", "/endpoints/{id}/attachment", Revision, "detach", lambda d,p: p)
    mutation("POST", "/endpoints/{id}/clone", Clone, "endpoint-clone", lambda d,p: {**d, **p})
    mutation("POST", "/vlans", VlanCreate, "vlan-create", lambda d,p: {k:v for k,v in d.items() if v is not None})
    mutation("PATCH", "/vlans/{vid}", VlanEdit, "vlan-edit", lambda d,p: {**d, "vid":int(p["vid"])})
    mutation("DELETE", "/vlans/{vid}", Revision, "vlan-delete", lambda d,p: {"vid":int(p["vid"])})
    mutation("POST", "/fdb/clear", Clear, "clear")
    for action in ("pause", "resume"):
        mutation("POST", "/clock/"+action, Revision, action)
    mutation("POST", "/clock/advance", Advance, "advance")
    mutation("POST", "/clock/advance/{id}/cancel", Revision, "advance-cancel", lambda d,p: {"id":p["id"]})
    mutation("POST", "/switch/save", Revision, "save-startup")
    mutation("POST", "/switch/reboot", Revision, "reboot")
    mutation("PATCH", "/snmp/settings", SnmpPatch, "snmp-settings")
    for route, model, prefix in (("snmp/credentials", CredentialWrite, "credential"), ("snmp/groups", GroupWrite, "group"), ("snmp/views", ViewWrite, "view"), ("notifications/targets", TargetWrite, "target")):
        mutation("POST", "/"+route, model, prefix+"-save")
        mutation("PUT", "/"+route+"/{id}", model, prefix+"-save", lambda d,p: {**d, **p})
        mutation("DELETE", "/"+route+"/{id}", Revision, prefix+"-delete", lambda d,p: p)
    mutation("POST", "/notifications/targets/{id}/test", Revision, "test-notification", lambda d,p: {"target_id":p["id"]})
    mutation("POST", "/scenarios/import", Import, "import", lambda d,p: d["scenario"])

    @app.get("/api/v1/state")
    async def state():
        return {**app.state.engine.snapshot(), "snmp_status": app.state.adapter.status(),
                "warning": ("Storage is faulted (" + app.state.engine.storage_fault + "). Showing the last confirmed snapshot; "
                            "writes and trap sends require a successful restart from the saved database."
                            if app.state.engine.storage_fault else
                            getattr(app.state, "startup_warning", None) or app.state.background_error)}

    @app.get("/api/v1/snmp/status")
    async def snmp_status():
        return app.state.adapter.status()

    @app.get("/api/v1/scenarios/export")
    async def export():
        return app.state.engine.export()

    @app.get("/api/v1/events")
    async def events(after: int = 0, limit: int = 200):
        s = app.state.engine.state
        return {"events": [e for e in s.events if e["id"] > after][:max(1,min(limit,2000))], "latest": s.event_id,
                "oldest": s.events[0]["id"] if s.events else 0}

    @app.get("/api/v1/events/stream")
    async def stream(request: Request, after: int = 0):
        async def generate():
            cursor = after
            while not await request.is_disconnected():
                session = sessions.get(request.cookies.get("switchlab_session"))
                if not session or session["expires"] < time.monotonic():
                    break
                batch = [e for e in app.state.engine.state.events if e["id"] > cursor]
                for event in batch:
                    yield f"id: {event['id']}\ndata: {json.dumps(event)}\n\n"
                    cursor = event["id"]
                if not batch:
                    yield ": keepalive\n\n"
                await asyncio.sleep(1)
        return StreamingResponse(generate(), media_type="text/event-stream")

    @app.get("/api/v1/vlans/{vid}/deletion-preview")
    async def preview(vid: int):
        s = app.state.engine.state
        if vid not in s.cfg.vlans:
            raise HTTPException(404, "VLAN not found")
        return {"vid": vid, "fallback_ports": [p.name for p in s.cfg.ports.values() if p.pvid == vid],
                "membership_ports": [p.name for p in s.cfg.ports.values() if vid in p.admitted], "revision": s.revision, "configuration_revision": s.configuration_revision}

    for family, key in (("switch","switch"), ("ports","ports"), ("endpoints","endpoints"), ("vlans","vlans"), ("fdb","fdb"),
                        ("snmp/settings","snmp"), ("snmp/credentials","credentials"), ("snmp/groups","groups"), ("snmp/views","views"), ("notifications/targets","targets")):
        def register_read(family, key):
            async def collection():
                snapshot = app.state.engine.snapshot()
                return {"revision": snapshot["revision"], "data": snapshot[key]}
            app.add_api_route("/api/v1/"+family, collection, methods=["GET"], name="read_"+key)
            if key in ("ports", "endpoints", "vlans"):
                async def item(id: str):
                    snapshot = app.state.engine.snapshot()
                    if id not in snapshot[key]:
                        raise HTTPException(404, "Resource not found")
                    return {"revision": snapshot["revision"], "data": snapshot[key][id]}
                app.add_api_route("/api/v1/"+family+"/{id}", item, methods=["GET"], name="read_one_"+key)
        register_read(family,key)

    static = Path(__file__).parent/"static"
    if static.is_dir():
        app.mount("/assets", StaticFiles(directory=static/"assets"), name="assets")
        @app.get("/", include_in_schema=False)
        async def index():
            return FileResponse(static/"index.html")
    return app


app = create_app()
