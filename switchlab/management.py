"""Local management identity, permissions, and session lifetime ownership.

This policy is independent of simulated port authentication and scenario state.
No network identity provider is enabled by this module.
"""
import asyncio
import secrets
import time
from dataclasses import dataclass, field

from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
from pydantic import BaseModel, ConfigDict, Field, model_validator
from starlette.routing import compile_path


ROLE_PERMISSIONS = {
    "viewer": ("state:read", "scenario:export"),
    "admin": ("state:read", "scenario:export", "simulation:write", "configuration:write", "security:write"),
}
PROVIDER_ROLES = {"local-admin": "admin", "local-viewer": "viewer"}
PUBLIC_ROUTES = {("GET", "/api/v1/auth/status"), ("POST", "/api/v1/auth/setup"), ("POST", "/api/v1/auth/login")}
ACTION_PERMISSIONS = {
    **dict.fromkeys(("advance", "advance-cancel", "pause", "resume", "clear", "source-authentication", "radius-session-action", "test-notification"), "simulation:write"),
    **dict.fromkeys(("switch-edit", "port-create", "port-delete", "port-edit", "endpoint-create", "endpoint-edit", "endpoint-delete", "attach", "detach", "endpoint-clone", "vlan-create", "vlan-edit", "vlan-delete", "save-startup", "reboot", "import"), "configuration:write"),
    **dict.fromkeys(("radius-settings", "dynamic-settings", "dynamic-sender-save", "dynamic-sender-delete", "accounting-settings", "accounting-target-save", "accounting-target-delete", "radius-server-save", "radius-server-delete", "radius-material-save", "radius-material-delete", "radius-template-save", "radius-template-delete", "source-supplicant-save", "snmp-settings", "credential-save", "credential-delete", "group-save", "group-delete", "view-save", "view-delete", "target-save", "target-delete"), "security:write"),
}


class ViewerPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    enabled: bool = False
    password_hash: str | None = Field(default=None, repr=False)
    generation: int = Field(default=0, ge=0, le=9223372036854775807)

    @model_validator(mode="after")
    def configured(self):
        if self.enabled and not self.password_hash:
            raise ValueError("Set a viewer password before enabling access")
        return self

    def public(self):
        return {"enabled": self.enabled, "password_configured": bool(self.password_hash), "generation": self.generation}


class ViewerConflict(ValueError):
    pass


class SessionCapacity(RuntimeError):
    pass


class RoutePermissions:
    """Registered method/template matrix. Unclassified requests have no grant."""
    def __init__(self):
        self.entries = []

    def add(self, method, path, permission):
        if permission not in ROLE_PERMISSIONS["admin"] and permission != "session:logout":
            raise ValueError("Unknown management permission")
        self.entries.append((method, path, compile_path(path)[0], permission))

    def required(self, method, path):
        return next((permission for verb, _, pattern, permission in self.entries
                     if verb == method and pattern.fullmatch(path)), None)


@dataclass(frozen=True)
class Session:
    provider: str
    generation: int
    expires: float
    csrf: str = field(repr=False)

    @property
    def role(self):
        return PROVIDER_ROLES[self.provider]

    def public(self):
        return {"provider": self.provider, "role": self.role, "permissions": list(ROLE_PERMISSIONS[self.role])}


class Management:
    def __init__(self, store):
        self.store = store
        self.sessions = {}
        self.hasher = PasswordHasher()
        self.password_slots = asyncio.Semaphore(4)
        self.password_work = set()

    def current(self, token):
        session = self.sessions.get(token)
        if session is None:
            return None
        valid = session.expires > time.monotonic()
        if valid and session.provider == "local-viewer":
            policy = self.store.viewer_policy()
            valid = (not self.store.fault_reason and not self.store.closed and policy.enabled
                     and policy.generation == session.generation)
        if not valid:
            self.sessions.pop(token, None)
            return None
        return session

    def permits(self, session, permission):
        return session is not None and (permission == "session:logout" or permission in ROLE_PERMISSIONS[session.role])

    def providers(self):
        policy = self.store.viewer_policy()
        return ["local-admin"] + (["local-viewer"] if policy.enabled and not self.store.fault_reason and not self.store.closed else [])

    async def password_call(self, function, *args):
        await self.password_slots.acquire()
        try:
            worker = asyncio.create_task(asyncio.to_thread(function, *args))
        except BaseException:
            self.password_slots.release()
            raise
        self.password_work.add(worker)
        def completed(task):
            self.password_work.discard(task)
            self.password_slots.release()
            if not task.cancelled():
                task.exception()  # Retrieve abandoned failures without logging secret-bearing data.
        worker.add_done_callback(completed)
        # Request cancellation never releases the worker's permit or cancels it.
        return await asyncio.shield(worker)

    async def close(self):
        if self.password_work:
            await asyncio.shield(asyncio.gather(*self.password_work, return_exceptions=True))

    async def hash_password(self, password):
        return await self.password_call(self.hasher.hash, password)

    async def authenticate(self, provider, password):
        if provider == "local-admin":
            saved, generation = self.store.administrator_hash(), 0
        elif provider == "local-viewer":
            policy = self.store.viewer_policy()
            if not policy.enabled or self.store.fault_reason or self.store.closed:
                return None
            saved, generation = policy.password_hash, policy.generation
        else:
            return None
        if saved is None:
            return None
        try:
            verified = await self.password_call(self.hasher.verify, saved, password)
        except (VerificationError, InvalidHashError):
            return None
        if not verified:
            return None
        if provider == "local-viewer":
            current = self.store.viewer_policy()
            if (self.store.fault_reason or self.store.closed or not current.enabled
                    or current.generation != generation):
                return None
        return generation

    def issue(self, provider, generation, previous_token=None):
        now = time.monotonic()
        for token in list(self.sessions):
            if self.sessions[token].expires <= now:
                self.sessions.pop(token)
        previous = self.sessions.get(previous_token)
        replaceable = previous is not None and (provider == "local-admin" or previous.provider == "local-viewer")
        victim = None
        if len(self.sessions) - int(replaceable) >= 20:
            victim = next((key for key, value in self.sessions.items() if value.provider == "local-viewer"), None)
            if victim is None:
                if provider == "local-admin":
                    victim = next(iter(self.sessions))
                else:
                    # Rejected admission must not revoke even the caller's admin session.
                    raise SessionCapacity("Session capacity reached; try again later")
        if victim is not None:
            self.sessions.pop(victim)
        self.sessions.pop(previous_token, None)
        token = secrets.token_urlsafe(32)
        session = Session(provider, generation, now + 28800, secrets.token_urlsafe(32))
        self.sessions[token] = session
        return token, session

    def revoke_viewers(self):
        for token, session in list(self.sessions.items()):
            if session.provider == "local-viewer":
                self.sessions.pop(token, None)
