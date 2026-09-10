from __future__ import annotations

import copy
import ipaddress
import re
import uuid
from typing import Annotated, Literal

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


def numeric_oid_prefix(value: str) -> str:
    value = value.strip()
    if not re.fullmatch(r"\d+(?:\.\d+)*", value):
        raise ValueError("Enter a numeric OID prefix")
    if "." not in value:
        root = int(value)
        if root > 2:
            raise ValueError("OID prefix root must be 0, 1, or 2")
        return str(root)
    return numeric_oid(value)


class Record(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_default=True)

    @model_validator(mode="after")
    def octet_limits(self):
        limits = {"sys_descr":255, "description":255, "contact":255, "location":255, "alias":64}
        if isinstance(self, CredentialAuth):
            limits["username"] = 32
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


class PortAuthentication(Record):
    control: Literal["force-authorized", "auto", "force-unauthorized"] = "force-authorized"
    method: Literal["dot1x", "mab", "dot1x-mab"] = "dot1x-mab"
    host_mode: Literal["single-host", "multi-auth", "multi-host"] = "single-host"
    fallback_no_supplicant: bool = True
    fallback_reject: bool = False


class SupplicantProfile(Record):
    method: Literal["tls", "peap"]
    identity: str = Field(min_length=1, max_length=1024)
    username: str = Field(default="", max_length=1024)
    password: str | None = Field(default=None, max_length=1024, repr=False)
    trust_id: str
    client_identity_id: str | None = None
    server_name: str = Field(min_length=1, max_length=253)

    @field_validator("identity", "username", "password")
    @classmethod
    def utf8_credentials(cls, value):
        if value is not None:
            try:
                value.encode("utf-8")
            except UnicodeError:
                raise ValueError("Supplicant text must be valid UTF-8") from None
        return value

    @field_validator("server_name")
    @classmethod
    def expected_name(cls, value):
        # One explicit DNS name, not a native-config fragment or a wildcard policy.
        value = value.encode("idna").decode("ascii").lower()
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", value) or any(not label or len(label)>63 for label in value.split(".")):
            raise ValueError("Enter the expected server DNS name")
        return value

    @model_validator(mode="after")
    def credentials(self):
        if self.method == "tls" and not self.client_identity_id:
            raise ValueError("Select a client certificate and key")
        if self.method == "peap" and (not self.username or not self.password):
            raise ValueError("PEAP requires an inner username and password")
        return self


class RadiusMaterial(Record):
    id: str = Field(default_factory=uid)
    label: str = Field(min_length=1, max_length=80)
    kind: Literal["ca", "client"]
    certificate: str = Field(min_length=1, max_length=262144, repr=False)
    private_key: str | None = Field(default=None, max_length=65536, repr=False)
    key_password: str | None = Field(default=None, max_length=1024, repr=False)

    @model_validator(mode="after")
    def valid_material(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        try:
            certificates = x509.load_pem_x509_certificates(self.certificate.encode())
            if not certificates:
                raise ValueError()
            if self.kind == "ca":
                if self.private_key or self.key_password or any(not c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca for c in certificates):
                    raise ValueError()
            else:
                key = serialization.load_pem_private_key((self.private_key or "").encode(), self.key_password.encode() if self.key_password else None)
                public = lambda k: k.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                if public(key.public_key()) != public(certificates[0].public_key()):
                    raise ValueError()
        except Exception:
            raise ValueError("Invalid certificate, key, or key password") from None
        return self


class SupplicantTemplate(Record):
    id: str = Field(default_factory=uid)
    label: str = Field(min_length=1, max_length=80)
    revision: int = Field(default=0, ge=0)
    profile: SupplicantProfile


class RadiusServer(Record):
    id: str = Field(default_factory=uid)
    label: str = Field(min_length=1, max_length=80)
    enabled: bool = True
    address: str
    port: int = Field(default=1812, ge=1, le=65535)
    secret: str = Field(min_length=1, max_length=1024, repr=False)
    source_address: str | None = None

    @field_validator("secret")
    @classmethod
    def secret_bytes(cls, value):
        try:
            valid = "\0" not in value and 1 <= len(value.encode("utf-8")) <= 4096
        except UnicodeError:
            valid = False
        if not valid:
            raise ValueError("Shared secret must be UTF-8 without NUL, at most 4096 octets")
        return value

    @field_validator("address", "source_address")
    @classmethod
    def addresses(cls, value):
        return str(ipaddress.ip_address(value)) if value is not None else None

    @model_validator(mode="after")
    def address_family(self):
        if self.source_address and ipaddress.ip_address(self.source_address).version != ipaddress.ip_address(self.address).version:
            raise ValueError("RADIUS source and destination address families must match")
        return self


class AccountingSettings(Record):
    enabled: bool = False
    targets: list[RadiusServer] = Field(default_factory=list, max_length=16)
    response_timeout_seconds: int = Field(default=3, ge=1, le=60)
    attempts: int = Field(default=3, ge=1, le=10)
    retry_backoff_seconds: int = Field(default=1, ge=0, le=30)
    interim_seconds: int | None = Field(default=None, ge=0, le=1000000)

    @field_validator("interim_seconds")
    @classmethod
    def interval(cls, value):
        if value is not None and 0 < value < 60:
            raise ValueError("Interim interval must be zero, absent, or at least 60 seconds")
        return value

    @model_validator(mode="after")
    def target_ids(self):
        if len({target.id for target in self.targets}) != len(self.targets):
            raise ValueError("Accounting target IDs must be distinct")
        return self


class DynamicSender(Record):
    id: str = Field(default_factory=uid)
    label: str = Field(min_length=1, max_length=80)
    enabled: bool = True
    address: str
    secret: str = Field(min_length=1, max_length=1024, repr=False)

    @field_validator("address")
    @classmethod
    def source_ip(cls, value):
        ip = ipaddress.ip_address(value)
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        return str(ip)

    @field_validator("secret")
    @classmethod
    def secret_bytes(cls, value):
        return RadiusServer.secret_bytes(value)


class DynamicSettings(Record):
    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = Field(default=3799, ge=1, le=65535)
    senders: list[DynamicSender] = Field(default_factory=list, max_length=64)

    @field_validator("host")
    @classmethod
    def bind_ip(cls, value):
        return str(ipaddress.ip_address(value))

    @model_validator(mode="after")
    def sender_ids(self):
        if len({sender.id for sender in self.senders}) != len(self.senders):
            raise ValueError("Dynamic sender IDs must be distinct")
        addresses = [sender.address for sender in self.senders if sender.enabled]
        if len(set(addresses)) != len(addresses):
            raise ValueError("Enabled dynamic sender IPs must be distinct")
        return self


class RadiusSettings(Record):
    accounting: AccountingSettings = Field(default_factory=AccountingSettings)
    dynamic_authorization: DynamicSettings = Field(default_factory=DynamicSettings)
    servers: list[RadiusServer] = Field(default_factory=list, max_length=16)
    materials: dict[str, RadiusMaterial] = Field(default_factory=dict, max_length=128)
    templates: dict[str, SupplicantTemplate] = Field(default_factory=dict, max_length=256)
    response_timeout_seconds: int = Field(default=3, ge=1, le=60)
    attempts: int = Field(default=3, ge=1, le=10)
    exchange_timeout_seconds: int = Field(default=60, ge=1, le=60)
    failed_cycle_retry_seconds: int = Field(default=60, ge=1, le=86400)
    discovery_seconds: int = Field(default=3, ge=1, le=3600)
    reauthentication_seconds: int = Field(default=0, ge=0, le=1000000)
    inactivity_seconds: int = Field(default=0, ge=0, le=1000000)
    nas_identifier: str | None = Field(default=None, max_length=253)
    nas_ip_address: str | None = None
    mab_case: Literal["lower", "upper"] = "lower"
    mab_separator: Literal["", ":", "-"] = ""
    station_case: Literal["lower", "upper"] = "upper"
    station_separator: Literal["", ":", "-"] = "-"

    @field_validator("nas_identifier")
    @classmethod
    def identifier_octets(cls, value):
        if value is not None:
            try:
                valid = 1 <= len(value.encode("utf-8")) <= 253
            except UnicodeError:
                valid = False
            if not valid:
                raise ValueError("NAS identifier must contain 1–253 UTF-8 octets")
        return value

    @field_validator("nas_ip_address")
    @classmethod
    def advertised_ipv4(cls, value):
        return str(ipaddress.IPv4Address(value)) if value is not None else None

    @model_validator(mode="after")
    def ids(self):
        if len({s.id for s in self.servers}) != len(self.servers):
            raise ValueError("RADIUS server IDs must be distinct")
        if any(key != value.id for collection in (self.materials, self.templates) for key, value in collection.items()):
            raise ValueError("RADIUS record keys must match IDs")
        return self


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
    untagged: list[int] = Field(default_factory=lambda: [1], max_length=4094)
    forbidden: list[int] = Field(default_factory=list, max_length=4094)
    link_notifications: bool = True
    authentication: PortAuthentication = Field(default_factory=PortAuthentication)

    @model_validator(mode="before")
    @classmethod
    def native_default(cls, value):
        # Saved ports without independent egress settings retain their native VLAN.
        if isinstance(value, dict) and "untagged" not in value:
            return {**value, "untagged": [value.get("pvid", 1)]}
        return value


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
    supplicant: SupplicantProfile | None = None

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
        return [numeric_oid_prefix(v) for v in values]


def default_views(*, legacy=False):
    views = {"all": View(id="all", name="All implemented objects" if legacy else "iso",
                         includes=["1.3.6.1.2.1"] if legacy else ["1"])}
    if not legacy:
        views["internet"] = View(id="internet", name="internet", includes=["1.3.6.1"])
    views["interfaces"] = View(id="interfaces", name="Identity and interfaces",
        includes=["1.3.6.1.2.1.1", "1.3.6.1.2.1.2", "1.3.6.1.2.1.31"])
    return views


class PollingAccess(Record):
    enabled: bool = False
    view_id: str = "all"
    networks: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("networks")
    @classmethod
    def cidrs(cls, values):
        return [str(ipaddress.ip_network(v, strict=False)) for v in values]


class WritingAccess(PollingAccess):
    view_id: str | None = None


SecurityLevel = Literal["noAuthNoPriv", "authNoPriv", "authPriv"]


class CredentialAuth(Record):
    label: str = Field(max_length=80)
    version: Literal["2c", "3"] = "2c"
    username: str = Field(default="", max_length=32)
    security_level: SecurityLevel = "noAuthNoPriv"
    community: str | None = Field(default=None, max_length=255, repr=False)
    auth_key: str | None = Field(default=None, max_length=255, repr=False)
    priv_key: str | None = Field(default=None, max_length=255, repr=False)

    @model_validator(mode="before")
    @classmethod
    def new_user_profile(cls, value):
        if isinstance(value, dict) and value.get("version") == "3" and "security_level" not in value:
            return {**value, "security_level": "authPriv"}
        return value

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


class Credential(CredentialAuth):
    id: str = Field(default_factory=uid)
    enabled: bool = True


class Community(Credential):
    version: Literal["2c"] = "2c"
    polling: PollingAccess = Field(default_factory=PollingAccess)
    writing: WritingAccess = Field(default_factory=WritingAccess)


class UsmUser(Credential):
    version: Literal["3"] = "3"
    security_level: SecurityLevel = "authPriv"
    group_id: str | None = None


class AccessGroup(Record):
    id: str = Field(default_factory=uid)
    label: str = Field(max_length=80)
    minimum_security_level: SecurityLevel = "authPriv"
    polling: PollingAccess = Field(default_factory=PollingAccess)
    writing: WritingAccess = Field(default_factory=WritingAccess)


class LegacyCredential(Credential):
    polling: PollingAccess = Field(default_factory=PollingAccess)
    writing: WritingAccess = Field(default_factory=WritingAccess)


def incoming_policy(cfg, credential):
    return credential if credential.version == "2c" else cfg.groups.get(credential.group_id)


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
    schema_version: Literal[4] = 4
    radius: RadiusSettings = Field(default_factory=RadiusSettings)
    switch: Switch = Field(default_factory=Switch)
    ports: dict[str, Port] = Field(default_factory=dict)
    vlans: dict[int, Vlan] = Field(default_factory=lambda: {1: Vlan(vid=1, name="Default", fdb_id=1001)})
    endpoints: dict[str, Endpoint] = Field(default_factory=dict)
    attachments: dict[str, str] = Field(default_factory=dict)
    paused: bool = False
    snmp: SnmpSettings = Field(default_factory=SnmpSettings)
    views: dict[str, View] = Field(default_factory=default_views)
    credentials: dict[str, Annotated[Community | UsmUser, Field(discriminator="version")]] = Field(default_factory=dict)
    groups: dict[str, AccessGroup] = Field(default_factory=dict)
    targets: dict[str, Target] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def migrate_credentials(cls, value):
        if not isinstance(value, dict):
            return value
        version = value.get("schema_version", 4)
        if type(version) is not int:
            raise ValueError("Configuration schema version must be an integer")
        if version not in (1, 2, 3):
            return value
        ports, endpoints = value.get("ports", {}), value.get("endpoints", {})
        if (not isinstance(ports, dict) or not isinstance(endpoints, dict) or
                any(not isinstance(p, dict) for p in ports.values()) or
                any(not isinstance(e, dict) or not isinstance(e.get("sources", []), list) or
                    any(not isinstance(src, dict) for src in e.get("sources", [])) for e in endpoints.values())):
            raise ValueError("Configuration ports, endpoints and sources have invalid shapes")
        if "radius" in value or any("authentication" in p for p in ports.values()) or any("supplicant" in src for e in endpoints.values() for src in e.get("sources", [])):
            raise ValueError("Legacy configuration cannot contain RADIUS security settings")
        if version == 3:
            raw = copy.deepcopy(value)
            raw["schema_version"] = 4
            return raw
        if "groups" in value:
            raise ValueError("Legacy configuration cannot contain schema 3 groups")
        raw = copy.deepcopy(value)
        if version == 1:
            credentials = raw.get("credentials", {})
            targets = raw.get("targets", {})
            if not isinstance(credentials, dict) or not isinstance(targets, dict):
                raise ValueError("Configuration credentials and targets must be objects")
            for credential in credentials.values():
                if not isinstance(credential, dict) or "polling" in credential:
                    raise ValueError("Schema 1 credentials cannot contain schema 2 polling access")
                if "writing" in credential:
                    raise ValueError("Schema 1 credentials cannot contain SET access")
                if credential.get("purpose", "polling") not in ("polling", "notification"):
                    raise ValueError("Invalid schema 1 credential purpose")
            for target in targets.values():
                if not isinstance(target, dict):
                    raise ValueError("Configuration targets must be objects")
                credential_id = target.get("credential_id")
                if not isinstance(credential_id, str):
                    raise ValueError("Schema 1 target credential ID must be a string")
                credential = credentials.get(credential_id)
                if credential is not None and credential.get("purpose", "polling") != "notification":
                    raise ValueError("Schema 1 targets require notification credentials")
            for credential in credentials.values():
                credential["polling"] = {
                    "enabled": credential.pop("purpose", "polling") == "polling",
                    "view_id": credential.pop("view_id", "all"),
                    "networks": credential.pop("networks", []),
                }
        credentials = raw.get("credentials", {})
        if not isinstance(credentials, dict):
            raise ValueError("Configuration credentials must be objects")
        groups = {}
        for cid, fields in credentials.items():
            if not isinstance(cid, str) or not isinstance(fields, dict):
                raise ValueError("Configuration credentials must have string keys and object values")
            legacy = LegacyCredential.model_validate({"security_level": "noAuthNoPriv", **fields})
            credential = legacy.model_dump()
            if legacy.version == "3":
                # The old schema has no groups; this injective ID needs no allocator.
                gid = "user-policy:" + cid.encode("utf-8").hex()
                groups[gid] = dict(id=gid, label=legacy.label,
                    minimum_security_level=legacy.security_level,
                    polling=credential.pop("polling"), writing=credential.pop("writing"))
                credential["group_id"] = gid
            credentials[cid] = credential
        raw.update(schema_version=4, groups=groups)
        return raw

    @field_validator("credentials", mode="before")
    @classmethod
    def community_version_default(cls, values):
        if isinstance(values, dict):
            return {key: {"version": "2c", **value} if isinstance(value, dict) else value
                    for key, value in values.items()}
        return values

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
            for field in ("admitted", "untagged", "forbidden"):
                memberships = getattr(p, field)
                if len(memberships) != len(set(memberships)):
                    raise ValueError("Duplicate VLAN membership")
                if not set(memberships) <= set(self.vlans):
                    raise ValueError("All VLAN memberships must exist")
            if not set(p.untagged) <= set(p.admitted) or set(p.forbidden) & set(p.admitted):
                raise ValueError("Untagged VLANs must be admitted; forbidden VLANs cannot be admitted")
            if p.mode == "direct" and list(self.attachments.values()).count(key) > 1:
                raise ValueError("Direct ports accept one endpoint")
        if any(k != e.id for k, e in self.endpoints.items()) or any(k != v.vid for k, v in self.vlans.items()):
            raise ValueError("Record keys must match their IDs")
        if not set(self.attachments) <= set(self.endpoints) or not set(self.attachments.values()) <= set(self.ports):
            raise ValueError("Invalid attachment reference")
        profiles = [t.profile for t in self.radius.templates.values()] + [src.supplicant for e in self.endpoints.values() for src in e.sources if src.supplicant is not None]
        for profile in profiles:
            trust = self.radius.materials.get(profile.trust_id)
            identity = self.radius.materials.get(profile.client_identity_id)
            if trust is None or trust.kind != "ca":
                raise ValueError("Select an existing RADIUS trust bundle")
            if profile.method == "tls" and (identity is None or identity.kind != "client"):
                raise ValueError("Select an existing client certificate and key")
            if profile.client_identity_id is not None and (identity is None or identity.kind != "client"):
                raise ValueError("Unknown client identity reference")
        for c in self.credentials.values():
            if c.version == "3" and c.group_id is not None and c.group_id not in self.groups:
                raise ValueError("Unknown SNMPv3 group")
        if any(key != group.id for key, group in self.groups.items()):
            raise ValueError("Group keys must match their IDs")
        policies = [c for c in self.credentials.values() if c.version == "2c"] + list(self.groups.values())
        for c in policies:
            if c.polling.enabled and c.polling.view_id not in self.views:
                raise ValueError("Unknown read view")
            if c.writing.enabled and c.writing.view_id not in self.views:
                raise ValueError("Select an existing write view")
        users = [(c.version, c.username if c.version == "3" else c.community) for c in self.credentials.values() if c.enabled]
        if len(users) != len(set(users)):
            raise ValueError("Enabled communities and usernames must be unique")
        for t in self.targets.values():
            c = self.credentials.get(t.credential_id)
            if c is None:
                raise ValueError("Unknown target credential")
            if t.source_address and ipaddress.ip_address(t.source_address).version != ipaddress.ip_address(t.address).version:
                raise ValueError("Target and source IP families must match")
        if any(len(collection) > 100 for collection in (self.credentials, self.groups, self.targets, self.views)):
            raise ValueError("At most 100 credentials, groups, targets and views")
        return self


def initial_configuration(port_count: int = 24) -> Configuration:
    cfg = Configuration(switch=Switch(port_count=port_count))
    for n in range(1, port_count + 1):
        p = Port(bridge_port=n, if_index=100+n, name=f"Ethernet{n}")
        cfg.ports[p.id] = p
    return cfg
