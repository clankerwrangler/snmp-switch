from __future__ import annotations

import ipaddress
import re
import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from pysnmp.proto.rfc1902 import ObjectIdentifier


def uid() -> str:
    return str(uuid.uuid4())


def mac(value: str) -> str:
    if not (re.fullmatch(r"[0-9a-fA-F]{12}", value) or
            re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", value) or
            re.fullmatch(r"(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}", value) or
            re.fullmatch(r"[0-9a-fA-F]{4}(?:\.[0-9a-fA-F]{4}){2}", value)):
        raise ValueError("Use a six-octet unicast MAC address")
    raw = bytes.fromhex(re.sub(r"[:.\-]", "", value))
    if not any(raw) or raw[0] & 1:
        raise ValueError("Source MAC must be nonzero unicast")
    return raw.hex(":")


def numeric_oid(value: str | None) -> str | None:
    if value is None or not value.strip():
        return None
    value = value.strip()
    if not re.fullmatch(r"\d+(?:\.\d+)+", value):
        raise ValueError("Enter a full numeric OID")
    arcs = tuple(int(x) for x in value.split("."))
    if not 2 <= len(arcs) <= 128 or arcs[0] > 2 or (arcs[0] < 2 and arcs[1] > 39) or any(x > 4294967295 for x in arcs):
        raise ValueError("OID exceeds SMI limits")
    return str(ObjectIdentifier(arcs))


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_default=True)

    @model_validator(mode="after")
    def octet_limits(self):
        limits = {"sys_descr":255, "description":255, "contact":255, "location":255, "alias":64, "username":32}
        for key, limit in limits.items():
            value = getattr(self, key, None)
            if isinstance(value, str) and len(value.encode()) > limit:
                raise ValueError(f"{key} exceeds its {limit}-octet wire limit")
        if type(self).__name__ in ("Switch", "Port") and len(self.name.encode()) > 255:
            raise ValueError("name exceeds its 255-octet wire limit")
        return self


class Identity(Record):
    sys_descr: str = Field(default="Generic SNMP Switch Emulator", max_length=255)
    sys_object_id: str | None = None

    _oid = field_validator("sys_object_id")(numeric_oid)


class Switch(Record):
    id: str = Field(default_factory=uid)
    name: str = Field(default="Switch Lab", max_length=255)
    description: str = Field(default="Generic Ethernet switch management simulation", max_length=255)
    contact: str = Field(default="", max_length=255)
    location: str = Field(default="", max_length=255)
    identity: Identity = Field(default_factory=Identity)
    base_mac: str = "02:00:00:00:00:01"
    port_count: int = Field(default=24, ge=1, le=256)
    legacy_vlan: int = Field(default=1, ge=1, le=4094)
    aging_seconds: int = Field(default=300, ge=10, le=1000000)
    fdb_limit: int = Field(default=16384, ge=1, le=100000)
    endpoint_limit: int = Field(default=10000, ge=1, le=10000)
    source_limit: int = Field(default=40000, ge=1, le=40000)
    queue_limit: int = Field(default=1024, ge=1, le=10000)

    _mac = field_validator("base_mac")(mac)


class Port(Record):
    id: str = Field(default_factory=uid)
    bridge_port: int = Field(ge=1, le=65535)
    if_index: int = Field(ge=1, le=2147483647)
    name: str = Field(max_length=255)
    alias: str = Field(default="", max_length=64)
    admin_up: bool = True
    mode: Literal["direct", "shared"] = "direct"
    shared_partner: bool = False
    forced_down: bool = False
    speed: int = Field(default=1000000000, ge=1, le=400000000000)
    mtu: int = Field(default=1500, ge=64, le=9216)
    pvid: int = Field(default=1, ge=1, le=4094)
    admitted: list[int] = Field(default_factory=lambda: [1], max_length=4094)
    link_notifications: bool = True


class Vlan(Record):
    vid: int = Field(ge=1, le=4094)
    name: str = ""
    fdb_id: int = Field(ge=1, le=4294967295)

    @field_validator("name")
    @classmethod
    def valid_name(cls, v):
        if len(v.encode()) > 32:
            raise ValueError("VLAN name is limited to 32 UTF-8 octets")
        return v


class Source(Record):
    id: str = Field(default_factory=uid)
    mac: str
    tag: int | Literal["untagged"] = "untagged"
    initial_delay_ms: int = Field(default=1000, ge=1, le=86400000)
    interval_ms: int = Field(default=30000, ge=1, le=86400000)
    octets: int = Field(default=64, ge=64, le=9216)

    _mac = field_validator("mac")(mac)

    @field_validator("tag")
    @classmethod
    def tag_range(cls, value):
        if value != "untagged" and not 1 <= value <= 4094:
            raise ValueError("VID must be 1–4094, or untagged")
        return value


class Endpoint(Record):
    id: str = Field(default_factory=uid)
    name: str = Field(max_length=255, min_length=1)
    metadata: dict[str, str] = Field(default_factory=dict, max_length=30)
    active: bool = True
    sources: list[Source] = Field(default_factory=list, max_length=4096)
    revision: int = 0

    @model_validator(mode="after")
    def unique_sources(self):
        if len({s.id for s in self.sources}) != len(self.sources):
            raise ValueError("Source IDs must be unique within an endpoint")
        return self


class View(Record):
    id: str = Field(default_factory=uid)
    name: str = Field(max_length=80)
    includes: list[str] = Field(min_length=1, max_length=32)

    @field_validator("includes")
    @classmethod
    def validate_oids(cls, values):
        result = [numeric_oid(v) for v in values]
        if any(v is None for v in result):
            raise ValueError("View OIDs cannot be empty")
        return result


class Credential(Record):
    id: str = Field(default_factory=uid)
    label: str = Field(max_length=80)
    version: Literal["2c", "3"] = "2c"
    purpose: Literal["polling", "notification"] = "polling"
    enabled: bool = True
    view_id: str = "all"
    networks: list[str] = Field(default_factory=lambda: ["127.0.0.0/8", "::1/128"], max_length=32)
    username: str = Field(default="", max_length=32)
    security_level: Literal["noAuthNoPriv", "authNoPriv", "authPriv"] = "noAuthNoPriv"
    community: str | None = Field(default=None, max_length=255, repr=False)
    auth_key: str | None = Field(default=None, max_length=255, repr=False)
    priv_key: str | None = Field(default=None, max_length=255, repr=False)

    @field_validator("networks")
    @classmethod
    def cidrs(cls, values):
        if not values:
            raise ValueError("Provide at least one allowed network")
        return [str(ipaddress.ip_network(v, strict=False)) for v in values]

    @model_validator(mode="after")
    def security(self):
        if self.version == "2c" and not self.community:
            raise ValueError("A community is required")
        if self.version == "2c" and self.security_level != "noAuthNoPriv":
            raise ValueError("SNMPv2c uses noAuthNoPriv; select SNMPv3 for authentication/privacy")
        if self.version == "3":
            if not self.username:
                raise ValueError("A v3 username is required")
            if self.security_level != "noAuthNoPriv" and len(self.auth_key or "") < 8:
                raise ValueError("SHA-256 passphrase requires at least 8 characters")
            if self.security_level == "authPriv" and len(self.priv_key or "") < 8:
                raise ValueError("AES-128 passphrase requires at least 8 characters")
        return self


class Target(Record):
    id: str = Field(default_factory=uid)
    address: str
    port: int = Field(default=162, ge=1, le=65535)
    credential_id: str
    enabled: bool = True
    types: list[Literal["linkUp", "linkDown", "coldStart"]] = Field(default_factory=lambda: ["linkUp", "linkDown", "coldStart"])
    source_address: str | None = None

    @field_validator("address", "source_address")
    @classmethod
    def ip(cls, v):
        return str(ipaddress.ip_address(v)) if v else v


class SnmpSettings(Record):
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = Field(default=161, ge=1, le=65535)
    max_varbinds: int = Field(default=256, ge=1, le=1000)

    @field_validator("host")
    @classmethod
    def host_ip(cls, value):
        return str(ipaddress.ip_address(value))


class Configuration(Record):
    schema_version: Literal[1] = 1
    switch: Switch = Field(default_factory=Switch)
    ports: dict[str, Port] = Field(default_factory=dict)
    vlans: dict[int, Vlan] = Field(default_factory=lambda: {1: Vlan(vid=1, name="Default", fdb_id=1001)})
    endpoints: dict[str, Endpoint] = Field(default_factory=dict)
    attachments: dict[str, str] = Field(default_factory=dict)
    paused: bool = False
    snmp: SnmpSettings = Field(default_factory=SnmpSettings)
    views: dict[str, View] = Field(default_factory=lambda: {
        "all": View(id="all", name="All implemented objects", includes=["1.3.6.1.2.1"]),
        "interfaces": View(id="interfaces", name="Identity and interfaces", includes=["1.3.6.1.2.1.1", "1.3.6.1.2.1.2", "1.3.6.1.2.1.31"]),
    })
    credentials: dict[str, Credential] = Field(default_factory=dict)
    targets: dict[str, Target] = Field(default_factory=dict)

    @model_validator(mode="after")
    def references(self):
        if 1 not in self.vlans or self.switch.legacy_vlan not in self.vlans:
            raise ValueError("VLAN 1 and the legacy VLAN must exist")
        if len({v.fdb_id for v in self.vlans.values()}) != len(self.vlans):
            raise ValueError("FDB IDs must be distinct")
        if self.ports and len(self.ports) != self.switch.port_count:
            raise ValueError("Port count is fixed at initialization")
        for attr in ("if_index", "bridge_port"):
            if len({getattr(p, attr) for p in self.ports.values()}) != len(self.ports):
                raise ValueError("Port indexes must be unique")
        for key, p in self.ports.items():
            if key != p.id or p.pvid not in p.admitted or not set(p.admitted) <= set(self.vlans):
                raise ValueError("Every PVID must be admitted; all memberships must exist")
            if len(p.admitted) != len(set(p.admitted)):
                raise ValueError("Duplicate VLAN membership")
            if p.mode == "direct" and list(self.attachments.values()).count(key) > 1:
                raise ValueError("Direct ports accept one endpoint")
        if any(k != e.id for k, e in self.endpoints.items()) or any(k != v.vid for k, v in self.vlans.items()):
            raise ValueError("Record keys must match their IDs")
        if not set(self.attachments) <= set(self.endpoints) or not set(self.attachments.values()) <= set(self.ports):
            raise ValueError("Invalid attachment reference")
        for c in self.credentials.values():
            if c.view_id not in self.views:
                raise ValueError("Unknown read view")
        users = [(c.version, c.username if c.version == "3" else c.community) for c in self.credentials.values() if c.enabled]
        if len(users) != len(set(users)):
            raise ValueError("Enabled communities and usernames must be unique")
        for t in self.targets.values():
            c = self.credentials.get(t.credential_id)
            if c is None or c.purpose != "notification":
                raise ValueError("Targets require a separate notification credential")
            if t.source_address and ipaddress.ip_address(t.source_address).version != ipaddress.ip_address(t.address).version:
                raise ValueError("Target and source IP families must match")
        if len(self.credentials) > 100 or len(self.targets) > 100 or len(self.views) > 100:
            raise ValueError("At most 100 credentials, targets and views")
        return self


def initial_configuration(port_count: int = 24) -> Configuration:
    cfg = Configuration(switch=Switch(port_count=port_count))
    for n in range(1, port_count + 1):
        p = Port(bridge_port=n, if_index=100+n, name=f"Ethernet{n}")
        cfg.ports[p.id] = p
    return cfg
