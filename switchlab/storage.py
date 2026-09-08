"""SQLite configuration transactions; encryption key lives outside the database."""
import json
import os
import sqlite3
from pathlib import Path

from cryptography.fernet import Fernet

from .models import Configuration, Identity
from pydantic import ValidationError


class Store:
    def __init__(self, path: str, key: bytes):
        self.cipher = Fernet(key)
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        # Commands remain serialized on the application's event loop. Disabling
        # thread affinity also permits lifespan handoff in ASGI test hosts.
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value BLOB NOT NULL)")
        self.db.execute("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, data TEXT NOT NULL)")
        self.db.commit()
        self.last_event = self.db.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0]

    def get(self, key, default=None):
        row = self.db.execute("SELECT value FROM kv WHERE key=?", (key,)).fetchone()
        return json.loads(self.cipher.decrypt(row[0])) if row else default

    def put(self, key, value):
        self.db.execute("INSERT OR REPLACE INTO kv VALUES (?, ?)", (key, self.cipher.encrypt(json.dumps(value).encode())))

    def load(self):
        raw = self.get("configuration")
        if raw:
            try:
                Identity.model_validate(raw["switch"]["identity"])
            except ValidationError:
                self.startup_warning = "Invalid saved identity was disabled. Configure a valid system object ID to enable SNMP."
                raw["switch"]["identity"] = Identity().model_dump()
        return Configuration.model_validate(raw) if raw else None

    def commit(self, state, idempotency, durable=True):
        with self.db:
            if durable:
                self.put("configuration", state.cfg.model_dump(mode="json"))
                self.put("configuration_revision", state.configuration_revision)
            self.put("revision", state.revision)
            self.put("idempotency", idempotency)
            self.put("outbox", state.outbox)
            self.db.executemany("INSERT INTO events VALUES (?, ?)", [(e["id"], json.dumps(e)) for e in state.events if e["id"] > self.last_event])
            self.db.execute("DELETE FROM events WHERE id < ?", (max(0, state.event_id - 2000),))
        self.last_event = state.event_id

    def events(self):
        return [json.loads(r[0]) for r in self.db.execute("SELECT data FROM events ORDER BY id")]

    def engine_boot(self):
        with self.db:
            identity = self.get("engine_identity")
            if identity is None:
                # RFC 3411: first bit clear, administratively unique 12-octet ID.
                identity = (bytes([0x40]) + os.urandom(11)).hex()
            boots = self.get("engine_boots", 0) + 1
            if boots >= 2147483647:
                raise RuntimeError("SNMP engine boot counter exhausted; replace engine identity administratively")
            self.put("engine_identity", identity)
            self.put("engine_boots", boots)
        return bytes.fromhex(identity), boots

    def close(self):
        self.db.close()
