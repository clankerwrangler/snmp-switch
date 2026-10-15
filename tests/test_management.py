"""Local management RBAC: real API boundaries, policy durability and revocation."""
import asyncio
import json
import threading
from dataclasses import replace

import httpx
import pytest
from fastapi import Request
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from cryptography.fernet import Fernet

from switchlab.api import create_app
from switchlab.management import ACTION_PERMISSIONS, PUBLIC_ROUTES, ROLE_PERMISSIONS, Management, ViewerConflict
from switchlab.models import initial_configuration
from switchlab.storage import Store, StorageFault, CommitUncertain


ADMIN = "synthetic-local-admin"
VIEWER = "synthetic-local-viewer"


def app_client(store):
    cfg = initial_configuration(4)
    cfg.paused = True
    return TestClient(create_app(store, cfg))


def identity(client, provider="local-admin", password=ADMIN, setup=False):
    client.cookies.clear()
    response = client.post("/api/v1/auth/setup" if setup else "/api/v1/auth/login",
                           json={"password": password, **({} if setup else {"provider": provider})})
    assert response.status_code == 200, response.text
    return dict(client.cookies), response.json()["csrf_token"]


def use(client, credentials):
    client.cookies.clear()
    for name, value in credentials[0].items():
        client.cookies.set(name, value, domain="testserver.local", path="/")
    client.headers["X-CSRF-Token"] = credentials[1]


def configure(client, enabled=True, password=VIEWER):
    generation = client.get("/api/v1/management/viewer").json()["generation"]
    result = client.put("/api/v1/management/viewer", json={"expected_generation": generation, "enabled": enabled,
                        **({"password": password} if password is not None else {})})
    assert result.status_code == 200, result.text
    return result.json()


def initialized(client):
    admin = identity(client, setup=True)
    use(client, admin)
    configure(client)
    viewer = identity(client, "local-viewer", VIEWER)
    return admin, viewer


def test_complete_registered_route_matrix_and_default_deny(store):
    with app_client(store) as client:
        assert client.get("/api/v1/auth/status").json()["providers"] == ["local-admin"]
        admin, viewer = initialized(client)
        app = client.app
        routes = [(method, route.path) for route in app.routes if isinstance(route, APIRoute)
                  and route.path.startswith("/api/") for method in route.methods]
        matrix = app.state.route_permissions
        registered = {(method, path) for method, path, _, _ in matrix.entries}
        assert registered | PUBLIC_ROUTES == set(routes)
        assert len(registered) == len(matrix.entries)
        assert set(ACTION_PERMISSIONS.values()) == set(ROLE_PERMISSIONS["admin"]) - {"state:read", "scenario:export"}
        use(client, admin)
        snapshot = client.get("/api/v1/state").json()
        port = next(iter(snapshot["ports"]))
        before = snapshot["configuration_revision"]
        for credentials, role in [(None, "anonymous"), (viewer, "viewer"), (admin, "admin")]:
            if credentials:
                use(client, credentials)
            else:
                client.cookies.clear()
                client.headers.pop("X-CSRF-Token", None)
            for method, template in routes:
                if (method, template) in PUBLIC_ROUTES or template == "/api/v1/auth/logout":
                    continue
                path = template.replace("{id}", port if template.startswith("/api/v1/ports/") else "missing").replace("{vid}", "1")
                permission = matrix.required(method, path)
                assert permission is not None, (method, path)
                if path.endswith("/events/stream") and role != "anonymous":
                    # The actual streaming generator is exercised below; avoid an unbounded HTTP read.
                    assert app.state.management.permits(app.state.management.current(credentials[0]["switchlab_session"]), permission)
                    continue
                response = client.request(method, path, json={} if method != "GET" else None)
                if role == "anonymous":
                    assert response.status_code == 401, (method, path, response.text)
                elif role == "viewer" and permission not in ROLE_PERMISSIONS["viewer"]:
                    assert response.status_code == 403, (method, path, response.text)
                else:
                    assert response.status_code in (200, 404, 422), (role, method, path, response.text)
            assert client.get("/api/v1/not-classified").status_code == (401 if role == "anonymous" else 403)
            assert client.post("/api/v1/auth/status", json={}).status_code == (401 if role == "anonymous" else 403)
        # Adding an actual route without policy must not silently grant it.
        called = []
        async def unclassified():
            called.append(True)
            return {"unsafe": True}
        app.add_api_route("/api/v1/unclassified", unclassified, methods=["GET", "POST"])
        for credentials in (viewer, admin):
            use(client, credentials)
            assert client.get("/api/v1/unclassified").status_code == 403
            assert client.post("/api/v1/unclassified", json={}).status_code == 403
        assert not called
        use(client, admin)
        assert client.get("/api/v1/state").json()["configuration_revision"] == before


def test_viewer_login_role_projection_no_fallback_and_redaction(store):
    with app_client(store) as client:
        admin, viewer = initialized(client)
        use(client, viewer)
        status = client.get("/api/v1/auth/status").json()
        assert (status["provider"], status["role"], status["permissions"]) == ("local-viewer", "viewer", list(ROLE_PERMISSIONS["viewer"]))
        for path in ("state", "events", "scenarios/export"):
            response = client.get("/api/v1/" + path)
            assert response.status_code == 200
            for forbidden in (ADMIN, VIEWER, "password_hash", "$argon2", "management_viewer"):
                assert forbidden not in response.text
        assert client.post("/api/v1/auth/logout", json={}).status_code == 200
        assert not client.get("/api/v1/auth/status").json()["authenticated"]
        # A viewer password without the explicit viewer provider never selects it.
        assert client.post("/api/v1/auth/login", json={"password": VIEWER}).status_code == 401
        assert client.post("/api/v1/auth/login", json={"provider": "local-viewer", "password": ADMIN}).status_code == 401
        assert client.post("/api/v1/auth/login", json={"provider": "radius", "password": ADMIN}).status_code == 422
        assert client.post("/api/v1/auth/login", json={"provider": "local-viewer", "password": VIEWER, "role": "admin"}).status_code == 422
        response = client.post("/api/v1/auth/login", json={"password": ADMIN})
        assert response.status_code == 200 and response.json()["role"] == "admin"
        # Successful login rotates the caller's old token and CSRF.
        previous = client.cookies["switchlab_session"]
        previous_csrf = response.json()["csrf_token"]
        response = client.post("/api/v1/auth/login", json={"password": ADMIN})
        assert previous not in client.app.state.management.sessions
        assert client.cookies["switchlab_session"] != previous
        assert response.json()["csrf_token"] != previous_csrf
        assert "HttpOnly" in response.headers["set-cookie"] and "SameSite=strict" in response.headers["set-cookie"]


def test_viewer_management_validation_csrf_origin_and_generation(store):
    with app_client(store) as client:
        admin = identity(client, setup=True)
        use(client, admin)
        assert client.get("/api/v1/management/viewer").json() == {"enabled": False, "password_configured": False, "generation": 0}
        for extra in ({}, {"password": ""}, {"password": None}):
            response = client.put("/api/v1/management/viewer", json={"expected_generation": 0, "enabled": True, **extra})
            assert response.status_code == 422, response.text
        body = {"expected_generation": 0, "enabled": True, "password": VIEWER}
        assert client.put("/api/v1/management/viewer", json=body, headers={"X-CSRF-Token": "wrong"}).status_code == 403
        assert client.put("/api/v1/management/viewer", json=body, headers={"Origin": "https://other.invalid"}).status_code == 403
        result = configure(client)
        assert result == {"enabled": True, "password_configured": True, "generation": 1}
        assert client.put("/api/v1/management/viewer", json=body).status_code == 409
        assert store.viewer_policy().generation == 1
        viewer = identity(client, "local-viewer", VIEWER)
        use(client, admin)
        configure(client, password="synthetic-new-viewer")
        use(client, viewer)
        assert client.get("/api/v1/state").status_code == 401
        assert not client.get("/api/v1/auth/status").json()["authenticated"]
        assert client.post("/api/v1/auth/login", json={"provider": "local-viewer", "password": VIEWER}).status_code == 401
        renewed = identity(client, "local-viewer", "synthetic-new-viewer")
        use(client, admin)
        configure(client, enabled=False, password=None)
        use(client, renewed)
        assert client.get("/api/v1/state").status_code == 401
        assert client.get("/api/v1/auth/status").json()["providers"] == ["local-admin"]
        use(client, admin)
        assert client.get("/api/v1/state").status_code == 200
        # Local recovery and credential survive disable; only explicit enable restores viewer.
        configure(client, enabled=True, password=None)
        identity(client, "local-viewer", "synthetic-new-viewer")


@pytest.mark.parametrize("operation", ["disable", "rotate"])
def test_generation_change_during_real_password_verification_cannot_issue_session(store, monkeypatch, operation):
    with app_client(store) as client:
        admin, _ = initialized(client)
        app = client.app
        async def exercise():
            manager = app.state.management
            started = asyncio.Event()
            release = threading.Event()
            loop = asyncio.get_running_loop()
            verify = manager.hasher.verify
            def delayed(saved, password):
                loop.call_soon_threadsafe(started.set)
                assert release.wait(5)
                return verify(saved, password)
            from types import SimpleNamespace
            monkeypatch.setattr(manager, "hasher", SimpleNamespace(verify=delayed, hash=manager.hasher.hash))
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as remote:
                pending = asyncio.create_task(remote.post("/api/v1/auth/login", json={"provider": "local-viewer", "password": VIEWER}))
                try:
                    await asyncio.wait_for(started.wait(), 3)
                    current = store.viewer_policy()
                    response = await remote.put("/api/v1/management/viewer", headers={"X-CSRF-Token": admin[1], "Cookie": "switchlab_session="+admin[0]["switchlab_session"]},
                        json={"expected_generation": current.generation, "enabled": operation == "rotate", **({"password": "rotated-synthetic"} if operation == "rotate" else {})})
                    assert response.status_code == 200, response.text
                finally:
                    release.set()
                result = await asyncio.wait_for(pending, 5)
                assert result.status_code == 401 and "set-cookie" not in result.headers
        client.portal.call(exercise)


def test_queued_write_rechecks_logout_at_actual_io_boundary(store):
    with app_client(store) as client:
        admin, _ = initialized(client)
        app = client.app
        async def exercise():
            class Gate(asyncio.Lock):
                async def __aenter__(self):
                    waiting.set()
                    return await super().__aenter__()
            waiting = asyncio.Event()
            gate = app.state.adapter.io_lock = Gate()
            before = app.state.engine.state.configuration_revision
            await gate.acquire()
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver", cookies=admin[0], headers={"X-CSRF-Token": admin[1]}) as remote:
                pending = asyncio.create_task(remote.patch("/api/v1/switch", json={"expected_configuration_revision": before, "name": "must-not-apply"}))
                try:
                    await asyncio.wait_for(waiting.wait(), 3)
                    assert (await remote.post("/api/v1/auth/logout", json={})).status_code == 200
                finally:
                    gate.release()
                assert (await asyncio.wait_for(pending, 3)).status_code == 401
                assert app.state.engine.state.configuration_revision == before
                assert app.state.engine.state.cfg.switch.name != "must-not-apply"
        client.portal.call(exercise)


@pytest.mark.parametrize("reason", ["logout", "expiry", "policy", "fault"])
def test_actual_sse_generator_rechecks_each_yield(store, reason):
    with app_client(store) as client:
        admin, viewer = initialized(client)
        app = client.app
        use(client, admin)
        for name in ("first", "second"):
            revision = client.get("/api/v1/state").json()["configuration_revision"]
            assert client.patch("/api/v1/switch", json={"name": name, "expected_configuration_revision": revision}).status_code == 200
        endpoint = next(r.endpoint for r in app.routes if getattr(r, "path", None) == "/api/v1/events/stream")
        async def exercise():
            class StreamRequest:
                cookies = viewer[0]
                async def is_disconnected(self):
                    return False
            response = await endpoint(StreamRequest(), after=0)
            stream = response.body_iterator
            first = await anext(stream)
            assert "data:" in first
            manager = app.state.management
            token = viewer[0]["switchlab_session"]
            if reason == "logout":
                manager.sessions.pop(token)
            elif reason == "expiry":
                manager.sessions[token] = replace(manager.sessions[token], expires=0)
            elif reason == "policy":
                store.configure_viewer(store.viewer_policy().generation, False)
            else:
                store._fault("synthetic_storage_fault")
            with pytest.raises(StopAsyncIteration):
                await asyncio.wait_for(anext(stream), 2)
        client.portal.call(exercise)


def test_policy_encrypted_restart_independent_connection_and_fault_recovery(tmp_path):
    path = str(tmp_path / "management.db")
    key = Fernet.generate_key()
    store = Store(path, key)
    try:
        with app_client(store) as client:
            admin, viewer = initialized(client)
            raw = b"".join(bytes(row[0]) for row in store.db.execute("SELECT value FROM kv"))
            assert VIEWER.encode() not in raw and b"$argon2" not in raw
            assert VIEWER not in repr(store.viewer_policy()) and "$argon2" not in repr(store.viewer_policy())
            other = Store(path, key)
            try:
                assert other.viewer_policy().enabled
                other.configure_viewer(1, False)
                with pytest.raises(ViewerConflict):
                    store.configure_viewer(1, True)
                use(client, viewer)
                assert client.get("/api/v1/state").status_code == 401
            finally:
                other.close()
            store._fault("synthetic_storage_fault")
            use(client, admin)
            assert client.get("/api/v1/state").status_code == 200
            response = client.put("/api/v1/management/viewer", json={"expected_generation": 2, "enabled": False})
            assert response.status_code == 503
            identity(client, password=ADMIN)
    finally:
        store.close()
    reopened = Store(path, key)
    try:
        with app_client(reopened) as client:
            assert client.get("/api/v1/auth/status").json()["providers"] == ["local-admin"]
            identity(client, password=ADMIN)
            assert reopened.viewer_policy().generation == 2
            assert not reopened.viewer_policy().enabled
    finally:
        reopened.close()


def test_router_prefix_cannot_bypass_auth_permissions_csrf_or_default_deny(store):
    cfg = initial_configuration(2)
    cfg.paused = True
    app = create_app(store, cfg)
    called = []
    async def unclassified():
        called.append(True)
        return {"unsafe": True}
    app.add_api_route("/api/v1/unclassified", unclassified, methods=["GET", "POST"])
    with TestClient(app, root_path="/switchlab") as client:
        prefix = "/switchlab/api/v1"
        assert client.get("/switchlab-extra/api/v1/state").status_code == 404
        assert client.get("/switchlab-extra/api/v1/unclassified").status_code == 404
        for path in ("/state", "/management/viewer", "/unclassified"):
            assert client.get(prefix + path).status_code == 401
        response = client.post(prefix+"/auth/setup", json={"password": ADMIN}, headers={"Origin": "http://testserver"})
        assert response.status_code == 200, response.text
        admin = (dict(client.cookies), response.json()["csrf_token"])
        use(client, admin)
        assert client.get(prefix+"/state").status_code == 200
        assert client.get(prefix+"/management/viewer").status_code == 200
        assert client.get(prefix+"/unclassified").status_code == 403
        body = {"enabled": True, "password": VIEWER, "expected_generation": 0}
        assert client.put(prefix+"/management/viewer", json=body, headers={"X-CSRF-Token": "wrong"}).status_code == 403
        assert client.put(prefix+"/management/viewer", json=body, headers={"Origin": "https://other.invalid"}).status_code == 403
        assert client.put(prefix+"/management/viewer", json=body, headers={"Origin": "http://testserver"}).status_code == 200
        client.cookies.clear()
        response = client.post(prefix+"/auth/login", json={"provider": "local-viewer", "password": VIEWER})
        assert response.status_code == 200
        client.headers["X-CSRF-Token"] = response.json()["csrf_token"]
        assert client.get(prefix+"/state").status_code == 200
        assert client.get(prefix+"/management/viewer").status_code == 403
        assert client.get(prefix+"/unclassified").status_code == 403
        assert client.post(prefix+"/unclassified", json={}).status_code == 403
        revision = client.get(prefix+"/state").json()["configuration_revision"]
        assert client.post(prefix+"/clock/pause", json={"expected_configuration_revision": revision}).status_code == 403
        assert not called


@pytest.mark.asyncio
async def test_password_work_remains_bounded_across_repeated_request_cancellation(store):
    manager = Management(store)
    release = threading.Event()
    started = asyncio.Event()
    fifth_started = asyncio.Event()
    lock = threading.Lock()
    active = 0
    peak = 0
    count = 0
    loop = asyncio.get_running_loop()
    def slow():
        nonlocal active, peak, count
        with lock:
            active += 1
            count += 1
            peak = max(peak, active)
            if count == 4:
                loop.call_soon_threadsafe(started.set)
            if count == 5:
                loop.call_soon_threadsafe(fifth_started.set)
        try:
            assert release.wait(5)
            return "synthetic-hash"
        finally:
            with lock:
                active -= 1
    callers = [asyncio.create_task(manager.password_call(slow)) for _ in range(4)]
    fifth = None
    try:
        await asyncio.wait_for(started.wait(), 3)
        for caller in callers:
            caller.cancel()
            caller.cancel()
        await asyncio.gather(*callers, return_exceptions=True)
        assert len(manager.password_work) == 4
        fifth = asyncio.create_task(manager.password_call(slow))
        for _ in range(10):
            await asyncio.sleep(0)
        assert not fifth_started.is_set() and count == 4
        release.set()
        assert await asyncio.wait_for(fifth, 3) == "synthetic-hash"
        await manager.close()
        assert peak == 4 and active == 0 and not manager.password_work
        assert manager.password_slots._value == 4
    finally:
        release.set()
        await asyncio.gather(*callers, *([fifth] if fifth else []), return_exceptions=True)
        await manager.close()


def test_role_aware_session_capacity_preserves_admin_recovery(store):
    from switchlab.management import SessionCapacity
    manager = Management(store)
    admin_tokens = [manager.issue("local-admin", 0)[0] for _ in range(20)]
    with pytest.raises(SessionCapacity):
        manager.issue("local-viewer", 0)
    assert list(manager.sessions) == admin_tokens
    with pytest.raises(SessionCapacity):
        manager.issue("local-viewer", 0, previous_token=admin_tokens[0])
    assert list(manager.sessions) == admin_tokens
    new_admin = manager.issue("local-admin", 0)[0]
    assert admin_tokens[0] not in manager.sessions and len(manager.sessions) == 20
    assert new_admin in manager.sessions
    manager.sessions.pop(admin_tokens[1])
    viewer_token = manager.issue("local-viewer", 0)[0]
    preserved_admins = {key for key, value in manager.sessions.items() if value.provider == "local-admin"}
    replacement = manager.issue("local-viewer", 0)[0]
    assert viewer_token not in manager.sessions and len(manager.sessions) == 20
    assert preserved_admins.issubset(manager.sessions)
    manager.issue("local-admin", 0)
    assert replacement not in manager.sessions and preserved_admins.issubset(manager.sessions)
    assert len(manager.sessions) == 20


@pytest.mark.parametrize("stage", ["mid-write", "commit-before", "rollback", "commit-after", "commit-rolled-back"])
def test_viewer_policy_transaction_failure_and_restart(tmp_path, monkeypatch, stage):
    import sqlite3
    from test_snmp_lifetime import TransactionFault
    path, key = str(tmp_path / "viewer-recovery.db"), Fernet.generate_key()
    store = Store(path, key)
    cfg = initial_configuration(4)
    cfg.paused = True
    try:
        with TestClient(create_app(store, cfg), raise_server_exceptions=False) as client:
            admin, viewer = initialized(client)
            use(client, admin)
            confirmed = store.viewer_policy()
            connection, original_put = store.db, store.put
            def failed_put(name, value):
                original_put(name, value)
                if name == "management_viewer":
                    raise sqlite3.OperationalError("Synthetic viewer-policy write failure")
            with monkeypatch.context() as patcher:
                if stage == "mid-write":
                    patcher.setattr(store, "put", failed_put)
                else:
                    patcher.setattr(store, "db", TransactionFault(connection, stage))
                response = client.put("/api/v1/management/viewer", json={
                    "expected_generation": confirmed.generation, "enabled": False})
            uncertain = stage in ("rollback", "commit-after", "commit-rolled-back")
            assert response.status_code == (503 if uncertain else 500)
            assert store.viewer_policy() == confirmed
            assert client.get("/api/v1/management/viewer").json() == confirmed.public()
            use(client, viewer)
            assert client.get("/api/v1/state").status_code == (401 if uncertain else 200)
            use(client, admin)
            assert client.get("/api/v1/state").status_code == 200
            if uncertain:
                reason = "storage_rollback_failed" if stage == "rollback" else "storage_commit_unknown"
                assert store.fault_reason == reason
                assert client.put("/api/v1/management/viewer", json={
                    "expected_generation": confirmed.generation, "enabled": False}).status_code == 503
                assert client.get("/api/v1/auth/status").json()["providers"] == ["local-admin"]
                assert client.post("/api/v1/auth/login", json={"password": ADMIN}).status_code == 200
                assert client.post("/api/v1/auth/login", json={"provider": "local-viewer", "password": VIEWER}).status_code == 401
            else:
                assert store.fault_reason is None
                assert store.get("management_viewer") == confirmed.model_dump()
                # A known rollback preserves the live viewer and allows an explicit retry.
                assert client.put("/api/v1/management/viewer", json={
                    "expected_generation": confirmed.generation, "enabled": False}).status_code == 200
        store.close()
        store = Store(path, key)
        policy = store.viewer_policy()
        committed = stage in ("mid-write", "commit-before", "commit-after")
        assert policy.generation == confirmed.generation + int(committed)
        assert policy.enabled is not committed
        assert policy.password_hash == confirmed.password_hash
        assert store.fault_reason is None
        with app_client(store) as client:
            assert client.post("/api/v1/auth/login", json={"password": ADMIN}).status_code == 200
            assert client.post("/api/v1/auth/login", json={"provider": "local-viewer", "password": VIEWER}).status_code == (401 if committed else 200)
    finally:
        if not store.closed:
            store.close()
