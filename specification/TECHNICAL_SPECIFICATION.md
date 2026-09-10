# SNMP Switch Emulator
## Technical specification · revision 4

**Date:** 2026-09-10

**Implementation target:** current application

**Scope:** application requirements and executable formal model

`Switch.tla` defines the core transition semantics; this document specifies the application and wire adapter around them. `docs/mib-coverage.csv` is the generated object manifest. [Current model contract](CURRENT_MODEL.md) and [current verification](CURRENT_VERIFICATION.md) describe the checked inputs and boundaries. Historical results remain in Git; new checker output stays local. These are design requirements, not implementation test results. See the [application README](../README.md) for installation and use, and the [application validation report](../docs/VALIDATION.md) for executed checks and their limits.

## 1. Purpose and boundaries

Build one configurable, vendor-neutral Ethernet-switch management simulation per deployment. An operator creates reusable endpoints, connects them to simulated ports, changes their source activity, and observes corresponding interface state, MAC learning, VLAN tables, and standard SNMP notifications.

There is no Ethernet forwarding, routing, real VLAN isolation, spanning-tree execution, host-interface EAPOL, DHCP, or reachability for endpoint IP addresses. Real networking includes HTTP, SNMP/notifications, RADIUS Access and accounting clients, and an independently enabled CoA/Disconnect listener. The [RADIUS contract and setup guide](docs/RADIUS.md) defines the selected access-policy and partial PAE profile; RADIUS does not authenticate web administrators. Endpoint addresses and names are simulation data. The agent must not expose the container host's interfaces as switch ports.

The first release includes a web UI, an automation API, SNMPv2c and SNMPv3 reads and authorized SET, standard link notifications, BRIDGE-MIB, Q-BRIDGE-MIB, read-only ENTITY-MIB, and conditional IEEE8021-PAE-MIB subsets, a persistent endpoint library, deterministic activity and aging, pause/manual advancement, and simulated reboot. Multiple switches, LLDP, vendor compatibility, and a graphical scenario timeline are deferred. No direct access to a NAC product is an acceptance prerequisite; no product-specific compatibility claim is permitted without testing that product.

### 1.1 Fixed decisions

| ID | Requirement |
|---|---|
| CORE-01 | One authoritative state engine drives the UI, SNMP views, and notification events. |
| CORE-02 | Only generic behavior and standard object/notification definitions are used. |
| EP-01 | An endpoint has a persistent ID independent of its MACs and attachment. |
| EP-02 | Each endpoint can contain several independently tagged MAC source entries. |
| EP-03 | Source MAC/tag edits are allowed while connected; edits do not implicitly flush learning or change carrier. |
| VLAN-01 | Port VLAN changes remove only learning invalidated by the change. |
| VLAN-02 | Deleting a native/PVID VLAN falls back affected ports to permanent VLAN 1. |
| TIME-01 | Automatic simulation time can pause; explicit advancement remains available. |
| BOOT-01 | Application restart preserves configuration and attachments but reboots operational state. |
| DEP-01 | Docker-first deployment, one administrator, private-lab defaults. |
| ID-01 | Public runtime defaults leave `identity.sys_object_id` unset. Operators supply the full advertised OID; no project-owned PEN is required to publish the application. |
| ID-02 | An explicitly selected isolated-development configuration uses `1.3.6.1.4.1.32473.1`. It is not a production fallback or an assigned operational identity. |
| ID-03 | An unset identity disables SNMP listening and notification sending, not the web UI, API, or simulation. An operator-selected identity does not enable vendor-specific behavior. |

### 1.2 Initial defaults, not fidelity claims

Defaults are 24 ports, VLAN 1, administrative enablement on, direct attachment mode, no endpoints attached, 1 Gbit/s configured port speed, a 300-second MAC age, a 1-second first-activity delay, a 30-second refresh interval, and automatic time advancement. The bridge aging range exposed on the wire follows its defined syntax; shortened TLC lifetimes are abstract test units, not wire values. [R1]

Numeric defaults can change without changing the behavioral contract. Port count is selected when initializing the switch and fixed thereafter in the first release. Endpoint and VLAN inventories remain editable at runtime. SNMP access starts unconfigured, not with an implicit `public` community. Public defaults set `identity.sys_object_id: null`; the identity setup gate in section 6.2 applies before any SNMP listener or notification sender starts.

## 2. State and identifiers

### 2.1 Configuration records

| Record | Required fields and rules |
|---|---|
| Switch | Stable UUID; name, description, contact, location; `identity.sys_descr`; nullable `identity.sys_object_id`; base MAC; listener binding and SNMP enablement; port count; selected legacy VLAN; aging configuration; limits; schema version. |
| Port | Stable internal ID, bridge-port number, `ifIndex`, name/alias, admin flag, direct/shared mode, shared-partner presence, forced-link-down flag, speed, MTU, PVID, independent admitted/untagged/forbidden VLAN sets, link-notification enablement; authentication control/method/host mode and explicit fallback choices. |
| VLAN | VID, name, FDB ID, management creation/change times. VLAN 1 always exists. |
| Endpoint | UUID, display name, optional metadata, active/silent setting, source entries, configuration revision. An attachment is stored separately. |
| Source entry | Stable source ID within an endpoint; unicast MAC; `untagged` or one explicit VID; activity timing; optional copied EAP supplicant settings. Empty endpoints are valid. |
| Attachment | Endpoint ID, port ID, attachment generation. One attachment per endpoint. |
| SNMPv2c community | Credential ID, label, enabled flag, protected community string; independent read/write permissions, views, and optional source networks. |
| SNMPv3 user | Credential ID, label, enabled flag, username, security level, protected keys, and optional group reference. |
| SNMPv3 group | ID, label, minimum security level, and shared independent read/write permissions, views, and optional source networks. |
| RADIUS settings | Ordered Access servers, protected trust/client materials, copied supplicant templates, NAS identity and timers; independent accounting targets and separately trusted dynamic senders. |
| Notification target | ID, address, UDP port, shared credential reference (which determines the version), enabled flag, notification types, and optional source binding. |

VIDs are 1–4094. Explicit endpoint tags may refer to an unconfigured VID. VLAN 0/priority-tagged frames and stacked tags are not implemented. Each port has independent admitted, untagged, and forbidden sets. All memberships refer to existing VLANs; untagged is a subset of admitted, forbidden is disjoint from admitted, and PVID is admitted. Zero or multiple untagged memberships are supported. A new port starts with its PVID untagged and no forbidden memberships. [R2]

MAC input accepts conventional hex notation and normalizes to six bytes. Multicast, broadcast, zero, and malformed source MACs are rejected. Duplicate unicast MACs between endpoints, between source entries, or between VLANs are allowed. Labels and endpoint metadata are not used to decide forwarding-table ownership.

Port numbers, bridge-port numbers, and `ifIndex` are distinct concepts. The initial allocator can use bridge ports 1…N and interface indexes 101…100+N. FDB IDs are stable and independent of the VID; the default mapping is `1000 + VID`. Persist or reproducibly derive these assignments. Never compact interface indexes after a rename. The bridge-port-to-interface relationship must use `dot1dBasePortIfIndex`. [R1]

### 2.2 Operational records

An FDB entry is keyed by `(fdb_id, mac)` and contains `bridge_port`, `last_seen_simulation_time`, and `expires_at`. There is at most one learned location for a key. The last accepted source activity wins when identical keys are observed on different ports. Distinct FDBs isolate identical MACs.

Operational state also includes scheduled activity, immutable pending jobs, simulated time, clock phase, real management uptime, interface counters/timestamps, a state revision, and notification queues. Saved endpoint instances are not FDB entries. Cached observations can outlive an attachment or the endpoint instance itself.

## 3. Endpoint and link lifecycle

### 3.1 Create, edit, clone, delete

Creating an endpoint saves a reusable object; it neither attaches nor learns by itself. Cloning copies its source layout and settings but generates a new endpoint ID, new source IDs, and new locally administered unicast MACs by default. An explicit preserve-MAC option enables duplication tests. Editing a supplicant template does not retroactively change copied profiles. Cloning can retain credential identity despite generating new MACs.

Replacing source entries while connected is an atomic configuration change. Existing learned rows remain unchanged, including their aging deadlines. Old source jobs are invalidated; new activity uses the edited configuration. Removing a source stops its refreshes but does not immediately erase its cached MAC. Another source may continue refreshing the same FDB/MAC key.

Deleting an attached instance returns a conflict; disconnect first. Deleting a detached instance removes its definition and invalidates remaining jobs, but does not remove cached entries behind a still-up shared link. Name and metadata edits have no link or learning side effects and need not restart activity.

### 3.2 Carrier and attachment rules

`operational_up = administrative_up AND carrier_present AND NOT forced_link_down`.

For a **direct** port, carrier is present when one endpoint is attached. A second attachment is rejected. For a **shared** port, carrier follows a separate persistent link-partner flag; attached endpoints may come and go without affecting that flag. Entering shared mode initially enables the partner. The UI must show this partner explicitly so an empty but up port is understandable.

The forced-down flag persists through connections, moves, edits, and restart. Attaching something does not repair a configured link fault. Returning a shared port to direct mode is rejected while more than one endpoint is attached. Changing mode can produce a real modeled link transition and therefore a notification.

Connect, disconnect, and move are atomic topology operations. Moving validates the destination before removing the old attachment. No observer may see an endpoint attached to two ports. An operational down transition flushes that port's dynamic learning and invalidates its activity jobs. A still-up shared port preserves cached learning after one source leaves. Administrative disablement preserves attachments.

Link establishment and source learning remain separate. Connecting a silent endpoint can produce `linkUp` with no learned MAC. No accepted activity occurs while a port is operationally down.

## 4. VLAN and FDB behavior

### 4.1 Admission and learning

On a force-authorized port, an untagged source uses the saved PVID and an explicitly tagged source uses its configured VID. Learning requires an up port and saved admission. Force-unauthorized blocks ingress without changing carrier. Auto requires a current client/shared authorization: inherited VLAN follows PVID, while an explicit grant permits untagged or matching-tag activity in its existing non-forbidden VID without rewriting saved membership. Otherwise the activity is recorded as rejected, without an FDB update. A VLAN is not created automatically by receiving simulated activity.

The first release uses independent VLAN learning. It does not share FDBs between VLANs. Learning follows accepted source activity, not a UI inventory edit; that distinction is consistent with the learned-address interpretation in BRIDGE-MIB. [R1]

| Command | Required result |
|---|---|
| Add membership | Preserve all existing entries and deadlines. |
| Remove membership | Remove only entries on that port in the removed VLAN/FDB. |
| Change PVID, retaining both VLANs | Preserve old entries. New untagged activity uses the new PVID. |
| Replace access VLAN | Remove old membership's entries and subsequently learn in the new VLAN. |
| Edit endpoint MAC/tag | Preserve existing entries. Apply the new source configuration to future activity. |
| Explicit clear | Remove entries in the requested port and/or VLAN scope; invalidate affected pending learning. |
| Age expiration | Remove expired dynamic entries without changing attachments or link state. |

Raw SNMP PVID SET changes ingress classification without changing untagged egress. For API `port-edit`, an actually changed PVID with omitted `untagged` uses `(old_untagged - {old_pvid}) union {new_pvid}`, including when the old PVID was not untagged. Explicit `untagged`, including an empty list, is exact. An omitted or unchanged PVID leaves the untagged set untouched. Final membership and forbidden constraints still apply.

These are emulator policies. They are not advertised as a universal flush policy implemented by all switches. A configuration change cannot manufacture a source observation or migrate an old row into another FDB.

### 4.2 Atomic VLAN deletion and fallback

Deleting VID `v` other than 1 performs one state transaction:

1. Remove `v` from the VLAN inventory and every port's admitted, untagged, and forbidden sets.
2. For each port whose PVID was `v`, use VLAN 1 unless the same SET supplies an explicit replacement PVID. Implicit fallback admits VLAN 1 and makes it untagged only if the deleted PVID was untagged. Explicit final bitmap assignments take precedence. Reject forbidden/membership conflicts instead of clearing restrictions. Preserve unrelated memberships.
3. Remove every dynamic entry in `v`'s FDB. Preserve other FDB entries and their deadlines.
4. Fall the selected legacy VLAN back to 1 if it was `v`.
5. Invalidate jobs based on affected port configurations and update relevant MIB row metadata.
6. Leave endpoint definitions, explicit tags, attachments, carrier, and admin flags unchanged.

VLAN 1 deletion is rejected. SNMP destroy of an absent row is a no-op, including its deletion counter, jobs, generations, and events. Untagged activity on fallback ports can subsequently learn in VLAN 1. Explicit activity tagged with deleted `v` remains configured but cannot learn there. Recreating `v` does not restore old membership or learning. The default FDB-ID mapping may be reused, but no outstanding pre-deletion job may become valid again.

### 4.3 Aging, capacity, and counters

Expiration uses simulated time. Refreshing a live entry resets its deadline. Changing the global age value recalculates deadlines from each entry's recorded last-seen time; already-expired entries are removed in that command. This runtime age-setting operation is an implementation requirement outside the current constant-age formal model.

Capacity must be explicit and visible. A proposed initial dynamic-entry limit is 16,384. When full, existing entries can still refresh or move, but a new key is rejected and a learning-capacity counter/event is incremented. Do not silently evict an unrelated row. Capacity and its counters are outside the current formal model and require implementation tests.

A source event represents one synthetic received unicast frame with a configured octet length. It updates input counters only if current job identity and physical state remain valid. VLAN rejection contributes to input discard accounting. Learning-capacity exhaustion is a learning failure, not automatically a frame discard. No simulated forwarding means output traffic counters remain zero unless a separately specified traffic model is added. Counters never advance because they are polled. Counter32 views wrap; Counter64 views use the same underlying totals. Boot/reset discontinuities must be reported consistently. [R3]

## 5. Time, scheduling, and obsolete jobs

### 5.1 Clock domains

| Clock | Purpose | Pause/reset behavior |
|---|---|---|
| Simulation | Source scheduling, FDB aging, access timers, discovery/cooldown, reauthentication, and accounting sampling | Pausable, manually advanceable; scenario reset can restart it. |
| RADIUS transport/replay | Real waits, retry/backoff, queue retention, and replay security | Not paused by simulation; timestamp validation uses real wall time and protected replay history. |
| Management uptime | `sysUpTime`, interface changes, VLAN creation/change filtering | Real monotonic elapsed time since management boot; not paused by the lab clock. |
| SNMPv3 engine time/boots | USM security timeliness | Library-managed real time plus durable engine boot state; never rewound by a scenario. |

Use deterministic scheduling, not random increments on reads. A source becomes due after its initial delay; recurring activity uses its interval. Silent endpoints retain definitions and attachments but schedule no accepted source activity. Intermittent behavior is represented by an interval exceeding the aging time; the TLC fixtures exercise shorter fixed intervals instead.

At each simulation deadline, expire independent access deadlines and FDB entries before same-time ordinary activity. Unresolved authentication is a causal boundary, not a guessed outcome. Within an equal-time batch, production ordering is stable by endpoint ID and source ID. The formal model explores alternative source-service orderings rather than relying on one tie-breaker. All due work must be completed or rejected before advancing past that deadline. A manual advance spanning many deadlines processes them chronologically; it does not jump directly to a final counter value.

Pausing acknowledges at an idle clock boundary. It stops automatic aging and source scheduling, not UI configuration, SNMP reads, real security time, or notification dispatch. Manual advancement is accepted only while paused. It can return a waiting operation at an unresolved authentication boundary; completion resumes toward the original target. Cancellation retains committed work and does not itself revoke grants. No activity service can permanently starve an eligible source when inputs stabilize and time continues.

### 5.2 Job validity and cancellation

A job captures the source MAC, effective VID, attachment, and identity generations at scheduling time. Production must identify at least the simulation epoch, endpoint incarnation/configuration, attachment session, source revision, and affected port configuration. The formal model combines endpoint/source/attachment invalidation into one endpoint token, with a separate port token and boot token.

Before committing an observation, revalidate the captured identities and current admission in the state engine. Reject obsolete work even when its old values happen to match current values after a move-away-and-back, edit-and-revert, VLAN delete/recreate, endpoint delete/recreate, or reboot. Task cancellation is an optimization, not the correctness boundary.

In `Switch.tla`, old jobs remain present until consumed. Finite equality tokens are chosen so that a token cannot be reused while an outstanding job could confuse it with a current identity. The application should use monotonically increasing generations or non-repeating IDs. The model does not prove an arbitrary UUID allocator or scheduler correct.

Relevant configuration commands invalidate pending observations and restart affected source delays. Already committed FDB entries are preserved unless a separate flush rule applies. Invalidating a source job is not permission to erase that source's historical learned rows.

## 6. SNMP adapter contract

### 6.1 Supported operations and access

Implement SNMPv2c and SNMPv3 `GET`, `GETNEXT`, and `GETBULK`, including correct ASN.1 types, scalar suffixes, numeric OID order, exceptions, and response limits. A PDU is evaluated against one coherent state snapshot and one authorization decision. Its projection captures scalar values and ASN.1 constructors, materializing selected ordinary cells only when read and reusing numeric table prefixes. Overlapping current-VLAN/TimeFilter rows retain their existing request-local construction. This request-local representation does not cache data or permissions across PDUs; uptime and TimeFilter wrap are sampled for each new projection. A walk consists of several requests and is not an atomic snapshot. Never expose `not-accessible` indexes as readable columns. [R4]

Resolve the accessible view before choosing a `GETNEXT`/bulk successor. Unknown credentials do not receive an unrestricted view. Missing objects and missing instances receive the appropriate protocol exceptions; unsupported subtrees must not be filled with invented zeros. Bounded bulk handling must preserve valid protocol behavior rather than truncate BER bytes or loop indefinitely. SET is limited to the ten objects and explicit writing permissions in section 6.5. MIB maximum access does not grant implementation access to other objects. [R4, R5]

### 6.2 Identity and object coverage

`docs/mib-coverage.csv` lists required switch objects, exact base OIDs, syntax, instance indexing, wire access, and value sources. Inclusion is an implementation target, not a statement that every group in the containing MIB is supported. Do not advertise full-module conformance or fabricate `sysORTable` capabilities.

#### 6.2.1 Operator-supplied identity

The public application uses a bring-your-own-identity policy. `identity.sys_object_id` is a nullable configuration field containing a **full numeric OID**, not a bare enterprise number. No project-owned Private Enterprise Number (PEN), registration, or embedded vendor identity is a prerequisite for publishing this application.

Public runtime defaults and public deployment examples use:

```yaml
identity:
  sys_descr: "Generic SNMP Switch Emulator"
  sys_object_id: null
```

The isolated-development override uses:

```yaml
identity:
  sys_object_id: "1.3.6.1.4.1.32473.1"
```

PEN 32473 is reserved for documentation, and RFC 5612 does not expect implementations to transmit it. Using this placeholder in isolated development is a deliberate test-policy departure, not a standards-approved operational allocation. The development configuration and UI must label it accordingly. It must never be selected automatically by a public build, missing configuration, or a guessed environment. [R15]

Validate a supplied value with the SNMP library's numeric OBJECT IDENTIFIER parser and SMI limits before saving it. Accept any syntactically valid numeric OID; do not require an enterprise-prefix match, registration lookup, ownership proof, or an allowlist. An empty form field maps to configuration `null`; malformed nonempty input is rejected without changing saved state. RFC 3418 describes the standard identity as an allocated value in the enterprises subtree. Accepting an arbitrary test value does not allocate that value or establish authority to use it. [R6]

The scalar instance `sysObjectID.0` is at `1.3.6.1.2.1.1.2.0`. Its configured **value** is a separate OID; do not append a scalar `.0` to that value. `null` is only a configuration sentinel, never a wire value. An empty string, ASN.1 NULL, omitted required identity, or an automatically substituted `0.0` is not an alternative identity strategy. [R6]

The value changes advertised identity only. It does not load a vendor profile, add proprietary objects, alter standard notification OIDs, or change simulation semantics. It is separate from the switch UUID and SNMPv3 engine identity; an identity edit must not regenerate either of them. Preserve operator configuration across restarts and upgrades. Public defaults must not overwrite a value already saved in a persistent volume.

#### 6.2.2 Identity setup gate

| Condition | Required behavior |
|---|---|
| Public first boot or saved identity is `null` | Start the UI, authenticated setup/API, and simulation normally. Keep the SNMP listener unbound and all notification sending disabled. Expose `identity_required` with a setup message. |
| Valid identity is saved | Allow SNMP activation once explicit enablement, credential/target configuration, and normal initialization checks pass. Identity alone must not create credentials or open access. |
| Nonempty malformed identity is submitted | Return a validation error and keep the prior value and running state. Invalid configuration loaded at startup keeps SNMP disabled and exposes a repairable error through setup. |
| Administrator clears identity | Quiesce SNMP reads/sends and discard unsent notification work with an audit reason before acknowledging the clear. Keep the simulation and UI available. |
| A valid identity is changed to another valid value | Publish it coherently to subsequent SNMP read snapshots. Preserve attachments, learned entries, and link state; do not trigger a simulated reboot or link flap. |

The gate also applies to notification test buttons and background sender tasks. Events occurring while disabled may appear in local history but must not accumulate a backlog for later SNMP replay. Already-transmitted packets cannot be recalled; acknowledgment of an identity clear means no further application send occurs under the previous activation. Coordinate in-flight work at the adapter boundary.

The SET and response models represent gate/activation invalidation abstractly. The nullable identity field, OID parsing, startup loading, and actual listener behavior still require implementation-level tests. [Setup and release guidance](docs/IDENTITY_SETUP.md) gives the development/public separation and test cases.

The adapter exposes configured physical switch ports only. Identity, interface counters, and bridge address are simulated values, not host OS data. First-release interface types are Ethernet and operational states are up/down; broader IF-MIB interface layering and inventory are not claimed.

### 6.3 BRIDGE and Q-BRIDGE projections

Q-BRIDGE exposes the full VLAN-aware FDB. Its index is the FDB ID followed by the fixed-length MAC index. BRIDGE exposes only the configured legacy VLAN's FDB, defaulting to VLAN 1. There is no community-string VLAN selection and no flattening of multiple VLANs into a conflicting MAC-only table. The UI and access summary must show the legacy scope explicitly.

Configured VLAN names and independent membership sets appear through the static table and the approved SET subset. The current egress-membership table adds active authorized client VLAN membership to configured membership and updates the affected change clock. Static membership, saved PVID, and current untagged membership remain configured values. Every configured VLAN is permanent and active in this release; dynamic VLAN registration is not implemented. [R2]

Serialize a `PortList` as bridge-port bits, most-significant bit first within each octet. Use a stable length sufficient for the highest bridge port. Do not use `ifIndex` as the bit position. FDB MAC indexes use six octet subidentifiers without an added length subidentifier. OID keys are integer sequences, never strings sorted lexically.

The formal projections contain sets and maps, not wire encodings. In particular, `IfTable` in the model is keyed by bridge port for convenient joins; the wire interface tables must instead be indexed by `ifIndex`.

### 6.4 VLAN current-table TimeFilter

The current-table index is `(TimeMark, VID)`. Maintain each row's management-clock creation/change metadata. A filter of zero selects the unfiltered current view; a positive filter selects rows whose current-epoch last-change time is greater than or equal to that filter, with current values rather than historical snapshots. A future cutoff yields no matching rows. Returned instance indexes retain the request's filter, not each row's last-change timestamp. Deleted rows are not returned as historical records. [R2, R7]

Implement the single-traversal behavior permitted by the updated TimeFilter guidance: after exhausting the relevant filtered rows, continue to the next accessible column/table rather than iterating endlessly over equivalent timestamp aliases. Test direct GET, GETNEXT starting inside a column, GETBULK repeaters, positive filters with no matches, zero filters, deletion, and uptime wrap. [R7]

Management-uptime wrap invalidates the previous filter epoch. Rebuild conceptual current rows and their timestamps in the new epoch from persistent VLAN configuration; do not delete that configuration or rewind USM security state. This adapter behavior is not represented by the VLAN-keyed TLA+ projection and needs separate wire tests.

### 6.5 Atomic SET

The writable columns are:

| Object | Base OID | Exact index / syntax |
|---|---|---|
| `ifAdminStatus` | `1.3.6.1.2.1.2.2.1.7` | `ifIndex`; INTEGER up(1)/down(2) |
| `dot1qVlanStaticName` | `1.3.6.1.2.1.17.7.1.4.3.1.1` | VID; UTF-8 OCTET STRING, 0–32 octets |
| `dot1qVlanStaticEgressPorts` | `1.3.6.1.2.1.17.7.1.4.3.1.2` | VID; PortList |
| `dot1qVlanForbiddenEgressPorts` | `1.3.6.1.2.1.17.7.1.4.3.1.3` | VID; PortList |
| `dot1qVlanStaticUntaggedPorts` | `1.3.6.1.2.1.17.7.1.4.3.1.4` | VID; PortList |
| `dot1qVlanStaticRowStatus` | `1.3.6.1.2.1.17.7.1.4.3.1.5` | VID; RowStatus INTEGER |
| `dot1qPvid` | `1.3.6.1.2.1.17.7.1.4.5.1.1` | bridgePort; Unsigned32/Gauge32 tag |
| `dot1xPaePortInitialize` | `1.0.8802.1.1.1.1.1.2.1.4` | ifIndex; TruthValue |
| `dot1xPaePortReauthenticate` | `1.0.8802.1.1.1.1.1.2.1.5` | ifIndex; TruthValue |
| `dot1xAuthAuthControlledPortControl` | `1.0.8802.1.1.1.1.2.1.1.6` | ifIndex; INTEGER forceUnauthorized(1)/auto(2)/forceAuthorized(3) |

`ifOperStatus` stays derived and read-only. The RFC-defined admin testing(3) value is unsupported under the permitted up/down profile, so SET returns `wrongValue`. VLAN indexes and PVIDs above 4095 are valid local-scope possibilities in the MIB but are unsupported by this global-VID-only product. [R2, R3]

A PortList uses bridge-port bits, not interface indexes. GET retains canonical width; SET accepts shorter zero-extended input and additional zero padding. A set bit for an absent port is `wrongValue`. Validate ASN.1 tags before converting values. Invalid UTF-8 is rejected without normalization. Identical decoded duplicate assignments coalesce; conflicting duplicates fail at the second original occurrence. Row look-ahead uses only the first row assignment, without bypassing validation of later bindings.

| Existing row | RowStatus SET | Result |
|---|---|---|
| Absent | 4 | Create active row; default empty name and bitmaps, filled by same-PDU assignments |
| Absent | 6 | Successful no-op |
| Absent | 1 or 2 | `inconsistentValue` |
| Absent | 5 | `wrongValue` |
| Present | 1 | Successful no-op |
| Present | 4 or 5 | `inconsistentValue` |
| Present | 2 | `wrongValue` |
| Present, not VLAN 1 | 6 | Delete with final-candidate fallback |
| VLAN 1 | 6 | `inconsistentValue` |
| Either | 3 or outside 1–6 | `wrongValue` |

Other columns of an absent row require explicit creation in the same PDU or fail `inconsistentName`. All assignments are validated against the final candidate, not OID-order-dependent intermediate states. Cross-field errors identify an actual participant in the violated relation; unrelated PVID changes and no-op row commands do not take its error index. Only effective creates/deletes invalidate tagged-source work.

Invalid authentication, registration, lifecycle, or source restrictions are dropped or handled by the existing security report path. For a valid current request, preflight the complete worst-case response before ordinary write authorization or binding processing. Insufficient budget or the varbind cap produces `tooBig`, index 0, with no bindings. Missing write grant produces `authorizationError`, index 0. Excluded objects produce `noAccess`; unsupported families produce `notWritable`; type, length, value, instance, row-state, and final-relation failures retain original 1-based positions. Responses otherwise echo the original request bindings, including createAndGo(4). [R4, R5, R17]

The adapter retains at most 128 pending SET requests outside PySNMP's base responder cache. It captures authenticated metadata and the original wire request ID, acquires `io_lock` then the engine lock, and rechecks current credential/group/view/source/security level and generation. Detached BER sizing does not consume MP/security state or run speculative encryption. A version/layout-checked per-engine lifetime owner ties each request to the original opaque MP/security records, including before admission. Existing expiry boundaries, cancellation, and close retire only exact owned state. There is no side response cache or independent timer.

After the final ready claim, one synchronous interval commits, publishes, materializes the public response, and finalizes its ticket without an await. A confirmed rollback returns `commitFailed` at the first effective assignment; an actual rollback failure returns `undoFailed`, index 0. Unconfirmed commit outcome is not labeled rollback. A committed configuration survives a subsequent response-delivery failure; there is no second effect or response attempt. Empty/no-op SET changes no engine state or idempotency data. Request IDs are not durable API idempotency keys. Section 9.1 defines storage-fault recovery.

### 6.6 Read-only ENTITY inventory

Let `E = 1.3.6.1.2.1.47` and `P = E.1.1.1.1`. Physical cells are `P.<column>.<physicalIndex>`. Chassis index 1 and port index `bridge_port + 1` are stable and independent of `ifIndex`, names, VLANs, and attachments. Only the emulated chassis and fixed ports appear. [R16]

| Physical columns | Syntax / value |
|---|---|
| 2 Descr | UTF-8 SnmpAdminString: saved switch description or `Emulated Ethernet port` |
| 3 VendorType | OBJECT IDENTIFIER `0.0`, unknown registration |
| 4 ContainedIn | Integer32: chassis 0, ports 1 |
| 5 Class | INTEGER: chassis(3), port(10) |
| 6 ParentRelPos | Integer32: chassis -1, ports' saved bridge-port number |
| 7 Name | UTF-8 saved switch/port name |
| 8–15 HardwareRev/FirmwareRev/SoftwareRev/SerialNum/MfgName/ModelName/Alias/AssetID | Empty strings for unavailable inventory; physical Alias is not the 64-octet IF-MIB alias |
| 16 IsFRU | TruthValue false(2) |
| 17 MfgDate | DateAndTime unknown sentinel: eight binary zero octets |
| 18 Uris | Canonical `urn:uuid:` from the saved entity UUID, or empty |
| 19 UUID | UUIDorZero: 16 network-order bytes from the same saved UUID, or empty |

Physical column 1 is an inaccessible index; RFC 6933 ends at column 19. Invalid UUID strings yield unknown values without rewriting or rejecting otherwise valid saved IDs. No manufacturer, serial, vendor registration, host inventory, or advertised management address is invented.

`E.1.3.2.1.2.<physicalPortIndex>.0` is a wildcard alias RowPointer to `ifIndex.<saved ifIndex>`. `E.1.3.3.1.1.1.<physicalPortIndex>` returns each direct chassis child index; this child index is readable. Filtering applies to the pointer object's OID and grants no dereference privilege. `E.1.4.1.0` is `entLastChangeTime`: actual projected-row changes update it in the engine transaction, no-op/irrelevant/rejected changes preserve it, management reboot resets it to zero, and uptime wrap does not reset it. Multiple changes in one centisecond may share its numeric value. [R16, R18]

Logical and LP tables, ENTITY writes, `entConfigChange`, and conformance registration are unsupported. The physical/mapping/general subset does not claim complete `entity4Compliance`, mapping-group support, or constrained-resource compliance. The generated manifest separately records normative maximum access, including ENTITY's writable declarations, and this implementation's read-only access.

### 6.7 Conditional PAE instrumentation

The selected 34 definitions use IEEE8021-PAE-MIB revision `200406220000Z` and existing ifIndex values. They are a partial profile, not complete conformance or real Ethernet EAPOL transport. Polling/writing views must explicitly include the IEEE subtree; existing MIB-II views are not broadened.

True action bindings coalesce per port. Initialize takes precedence over Reauthenticate, under the final candidate control mode, after all PDU validation. GET reports false after completion. Initialization does not reset counters. Auto/multi-auth omits ambiguous single-state, timer, and session cells. Exact internal EAP events drive aggregate counters; canceled/incomplete observation retains numeric history but omits counter/last-frame publication until management boot. Completed results are not observation loss. Current/last single-service session time is simulated centiseconds. Only exact PAE causes are exposed; egress counters, usernames, and unsupported mechanisms remain absent. See the [PAE profile](docs/RADIUS.md#pae-snmp-subset) and generated manifest for conditional value sources.

## 7. Credentials and notifications

### 7.1 Credentials

SNMPv2c communities own their incoming read/write policy. SNMPv3 users own USM identity, keys, global enablement, and a configured security level; one optional `group_id` selects their shared incoming policy. Groups own a minimum security level and independent read/write permissions, OID views, and optional source CIDRs. There are no per-user permission overrides. The groups are application-owned VACM-style policy, not a native VACM-table mirror or full VACM instrumentation. The existing internal notification mapping remains separate. [R8, R9, R10]

Stock PySNMP 7.1.29 accepts normal v3 management at the user's configured `noAuthNoPriv`, `authNoPriv`, or `authPriv` security level. A lower group minimum does not relax that protection requirement. After USM accepts the message, the application checks the group's minimum and policy; it adds no independent user floor. A user whose security level is below the selected group minimum can remain a member, but cannot use that group's incoming access. Discovery and REPORT exceptions are library behavior, not operational access at weaker protection. Authentication uses SHA-256 and privacy uses AES-128; the application does not implement cryptography.

New users default to `authPriv` with no group. New groups default to `authPriv` minimum and no incoming access. Communities and groups store `polling: {enabled, view_id, networks}` and `writing: {enabled, view_id, networks}`. Both permissions default disabled; read view defaults to `all`, write view to null, and both network lists to empty. Empty networks mean no source-IP restriction for that use. A nonempty list restricts only that operation. Enabled permissions require existing views, including in unused groups or globally disabled credentials. Inactive permissions retain missing view selections and source networks.

Credential-wide disablement stops reads, writes, and traps. Read-only access does not grant writes, write-only access does not grant reads, and target association grants neither. A v3 user without a group has no incoming access but can still serve independently enabled trap targets. Either incoming permission can hold the listener; outgoing trap transport is independent. One enabled credential identifies each community or v3 username in the single SNMP engine. Target-linked v3 traps retain the user's profile, keys, username, and local engine identity.

Configuration schema 4 has one `credentials` collection with version-specific community/user records and one `groups` collection. Group creation, editing, and deletion use the same revision-checked transaction as other configuration. Deletion rejects any member reference, including disabled users. Sparse updates preserve omitted permission fields and secrets. APIs return secret-presence flags, not secrets; stored configuration is encrypted with a separately stored key. Web authentication remains separate. Scenario schema 1 excludes credentials, groups, identity, notification destinations, RADIUS settings, port authentication, and supplicant profiles; import preserves destination security configuration.

Changing a saved credential's protocol requires fresh active protocol secrets and explicit incoming-access intent. `CredentialWrite.access_transfer` is request-only: `keep` copies the current saved policy and `none` denies incoming access. A v2c-to-v3 conversion also requires an explicit `security_level` and accepts an explicitly present `group_id` instead of `access_transfer`. `keep` creates one group with that profile as its minimum; a selected existing group or null uses that exact choice. A v3-to-v2c conversion requires `keep` or `none`; keeping access copies the selected group's policy into the community. Community protection has no USM minimum, so copied active permissions can become usable even if the old user could not meet its group minimum. Missing/conflicting intent and concurrent permission overrides are rejected. IDs, targets, other members, and retained groups are unchanged; a failed save publishes neither a conversion nor a new group. Fresh Add and inline target creation need no transfer intent and start with no incoming access.

Target forms select an existing version-compatible credential or create one atomically with the selected target. Other target associations remain unchanged. Deleting a target retains its credential; deleting a referenced credential is rejected.

Genuine group policy/minimum changes invalidate queued SET work for every member through the existing credential-generation owner. Membership changes, auth/global changes, selected-write-view definition changes, and activation changes also invalidate captured work, including remove/restore ABA. Label-only group edits, same-value saves, and unrelated changes preserve queued work. Current group/source/level/view checks still run at handling time. This queued-work invalidation is product lifecycle behavior, not an RFC VACM requirement; completed responses are not retroactively invalidated.

### 7.2 Notification semantics

Initial notification types are `linkUp`, `linkDown`, and one management `coldStart` on application boot. The TLA+ queue models link notifications only. There is no generic standard endpoint-connected/MAC-learned notification added by this project.

Capture interface identity, admin state, previous/new operational state, and management uptime when a transition commits. Do not reconstruct an old event from current tables during dispatch. For the standard link notification, encode the defined operational-state value: pre-down state for `linkDown`, entered state for `linkUp`. Add `sysUpTime.0` and `snmpTrapOID.0` in the required initial positions. [R3, R4]

Configure targets independently, with per-port link-notification enablement and per-target filters. Queue capacity is bounded; the default overflow policy preserves queued items and drops new excess items, increments a drop counter, and raises a visible warning. Configuration commits must not block on network delivery.

The event history distinguishes committed, queued, send-attempted/sent, locally failed, canceled-on-reboot, and dropped-on-overflow. A successful UDP send is not proof of receipt. Informs and their acknowledgment/retry behavior are deferred. [R4]

Application-level events may additionally report endpoint attachment, MAC learn/refresh/move/age, admission rejection, and invalidated work. Those are UI/API events, not extra SNMP traps. Ordinary source refreshes should be aggregated or hidden unless tracing is enabled, so the history remains usable.

## 8. Reboot, persistence, and scenario reset

Persist configuration, saved endpoints, source definitions, attachments, activity settings, clock mode, stable identities, and credentials. Persist the operator-selected `identity.sys_object_id`, including an intentionally unset value. Persist SNMP engine identity and boot state separately from lab snapshots. Increment/store engine boot state before the restarted listener is available, using the chosen SNMP library's supported lifecycle. Never restore it from a scenario export. [R8]

Application restart is a simulated switch reboot. End live access/accounting segments, clear FDB learning, reset counters and management uptime, invalidate every pre-boot job and authentication attempt, discard the old notification queue with an audit reason where possible, and restart source delays. Preserve admin state, VLANs, attachments, link-partner settings, forced faults, and active/silent settings. Reset simulation time to zero. Preserve paused/running mode; a paused restored lab relearns only after manual advancement or resume.

Restored topology is the boot baseline, not a fabricated sequence of physical disconnects/reconnects. Send one `coldStart` when the SNMP service becomes active after management initialization and the identity/setup gate passes. Suppress sending while the gate is closed; do not replay initialization or link events from the disabled period. Do not generate artificial link-down/link-up pairs solely because the process restarted. Port changes after initialization generate normal notifications. Initial `ifLastChange` is zero for interfaces already in their boot state.

Protected DAS replay decisions and the real-clock safety watermark survive graceful process restart; live grants do not. Accounting and dynamic requests use the same storage-health gates as existing mutations.

A scenario reset/import restores a selected saved lab baseline, clears learning, restarts simulation time and source deadlines, and uses a new simulation epoch. It preserves the live SNMP management engine and security clock. Actual topology differences can generate link events. This reset/import transaction is an application requirement not separately model-checked in this revision; `Reboot` checks the obsolete-work invalidation pattern, not import validation or crash recovery.

Exports are schema-versioned and omit secrets by default. Lab scenario imports/exports do not replace deployment identity, SNMP enablement, credentials, groups, or notification destinations; these are managed separately through protected settings. Imports validate the entire configuration and all cross-references before replacing any state. A malformed import leaves the previous lab intact. Factory reset and exact mid-timer crash resumption are deferred.

## 9. Architecture and transaction boundaries

Use a modular monolith: one asynchronous backend owns a serialized command processor, scheduler, SNMP adapter, notification dispatcher, persistence layer, and HTTP API. Suggested implementation stack is Python/asyncio, FastAPI, SQLite, a TypeScript UI, and PySNMP as the protocol-library candidate. Confirm dynamic tables, view traversal, and SNMPv3 boot behavior in a compatibility prototype before pinning the library version. PySNMP documents agent-side implementation hooks; library documentation does not establish application correctness. [R11]

Every mutating path enters the same command processor. Validate input and expected revision, construct the complete next state, perform required persistent writes, commit, publish an immutable read snapshot, then dispatch committed events. A persistence failure cannot leave half-applied VLAN fallback or emit a success notification for a rejected command. Do not allow the SNMP adapter to maintain a separate authoritative MAC table.

Use optimistic revision checks for UI/API writes. Multiple browser tabs still exist even with one administrator. Concurrent commands are linearized; background callbacks revalidate inside this boundary. SNMP readers retain a snapshot without holding the command lock during encoding or network I/O. Repeated requests may observe different revisions.

SQLite transactions cover durable configuration and event/outbox metadata where applicable. Operational cache state may remain in memory because restart semantics deliberately clear it. Audit/event storage needs bounded retention; do not turn per-source activity into unbounded database writes. A crash between a network send and recording its result may leave send status uncertain; do not promise exactly-once UDP notifications.

### 9.1 Uncertain storage and existing startup recovery

A confirmed rollback leaves the incarnation healthy. Only actual rollback failure or a COMMIT exception without a confirmed outcome latches a nonsecret storage-fault reason. The published Runtime remains the last confirmed snapshot; a connection-local candidate or a possibly committed value is not presented as confirmed state. Equality with the old value does not establish a successful rollback.

The Store and common engine transaction reject further configuration/runtime/storage mutations, including API, SET, clock/background work, setup, engine-boot helpers, and notification-result updates. Pending SETs cannot acquire effects, and queued traps are not sent when their durable result cannot be recorded. Existing authorized SNMP reads, UI/state/export, and read-only authentication remain available with explicit last-confirmed/storage-health labels. API mutations return 503; the initial SET retains its `undoFailed` or unknown/drop outcome. There is no in-place health clear or automatic retry.

Recovery closes the old connection/process and uses normal application startup: reopen the actual durable database, validate configuration, and load revisions, events, idempotency, outbox, and engine identity. A fresh successfully initialized incarnation resumes writes and sends. Failed close, unavailable/invalid loading, or persistent storage failure does not enable defaults as recovery. Existing management reboot semantics reset volatile learning/counters and cancel the prior outbox; no exact volatile-state restoration is claimed. There is no recovery endpoint, restart service, or new database/key.

## 10. API and UI contract

### 10.1 HTTP API

Version routes under `/api/v1`. UUIDs are opaque. Mutations accept an expected resource/state revision; multi-record operations return the resulting state revision and affected IDs. Sensitive fields are write-only. Define an OpenAPI schema during implementation and validate request bodies against it.

| Route family | Operations |
|---|---|
| `/state`, `/switch`, `/ports/{id}` | Snapshot, identity/settings, port configuration and link controls. |
| `/endpoints`, `/endpoints/{id}` | List/create/read/edit/delete; reject deletion while attached. |
| `/endpoints/{id}/sources` | Atomically replace the source list while preserving explicit source IDs. |
| `/endpoints/{id}/attachment` | PUT attaches/moves; DELETE detaches. Destination validation precedes any move. |
| `/endpoints/{id}/clone` | Clone with new MACs unless explicitly preserving them. |
| `/vlans`, `/vlans/{vid}` | List/create/name update/delete with atomic VLAN 1 fallback. |
| `/fdb`, `/fdb/clear` | Read learned state; clear an explicit scope. |
| `/clock/pause`, `/clock/resume`, `/clock/advance`, `/clock/advance/{id}/cancel` | Control simulated activity/access time and bounded waiting advancement. |
| `/radius/settings`, `/radius/servers`, `/radius/materials`, `/radius/templates` | Protected Access configuration and copied-profile inputs. |
| `/radius/accounting`, `/radius/accounting/targets`, `/radius/dynamic`, `/radius/dynamic/senders` | Independent collector and trusted-sender settings. |
| `/endpoints/{id}/supplicant`, `/endpoints/{id}/authentication`, `/radius/sessions/{id}` | Sparse supplicant save/copy and scoped restart/renewal. |
| `/switch/reboot` | Trigger the documented management restart procedure. |
| `/snmp/settings`, `/snmp/status` | Protected SNMP enablement/settings and effective readiness, including `identity_required` or configuration errors. The identity field is part of `/switch`. |
| `/snmp/credentials`, `/snmp/groups`, `/snmp/views`, `/notifications/targets` | Protected administration; test sends obey the identity gate. |
| `/events`, `/events/stream` | Cursor-based history and live updates. |
| `/scenarios/export`, `/scenarios/import` | Validated, versioned lab baselines without secrets. |

Return 401/403 for web authorization failures, 404 for unknown resources, 409 for stale revisions or state conflicts, 422 for invalid configuration, 429 for resource limits, and 503 before initialization completes. An unset identity is an expected setup state, not an application-wide 503; setup and simulation endpoints remain available. A malformed nonempty `identity.sys_object_id` submitted through the API returns 422. A rejected operation has no state or notification side effects. Support idempotency keys for retryable commands whose duplication would otherwise change state.

`POST /clock/advance` takes a positive duration in milliseconds and is allowed only while paused. Its response identifies the operation, reached time, target, and status. HTTP 202 means waiting for authentication; normal status reports completion, cancellation, interruption, or the same-time renewal guard. A source tag referencing an absent VLAN is valid endpoint configuration, not a 422 error. Deleting VLAN 1 and attaching a second endpoint to a direct port are conflicts.

### 10.2 Web UI

Provide a switch port grid, a reusable endpoint library with a source editor, a VLAN editor, distinct **SNMP**, **RADIUS**, and general **Settings** destinations, live interface/MAC address/VLAN tables, and an event history. General settings retain switch name/location/contact, base MAC, learning limits, and reboot; SNMP owns advertised identity, access, views, and notifications. Forms share the existing sparse, revision-checked commands. The compact **Simulation** header control reveals the current time and **Pause/Resume**, **+1s**, and **Advance…** controls. It closes on navigation; opening or closing it does not change clock mode. The port panel distinguishes admin state, carrier, forced-down state, **Port VLAN ID (PVID)** and independent **Allowed VLANs (configured)**, untagged, and forbidden sets, shared partner, attachments, and learned MAC count. Untouched Untagged VLANs preview the API PVID/untagged-membership update; a user-edited field is exact, including empty. The SNMP settings page has compact community, user, and group sections with ordinary Add/Edit/Delete controls. Community and group forms use one **Access** dropdown: **None (traps only)**, **Read**, **Read/write**, or **Write only**. Conditional fields preserve independent read/write views and networks. Mode changes retain drafts, but hidden final-inactive restriction edits are not submitted. User forms select a group alongside authentication and global enablement, and show security-level/minimum mismatches. Protocol changes require an explicit incoming-access choice without a preselected transfer. The service card shows one actual **Listener status**, its address/port, engine identity, and independent trap transport, not separate per-access status rows. The document title is **Switch Lab**. The full-width selected-port detail uses a compact link-status header, quieter interface/speed/learning metadata, grouped link and configured VLAN facts, attachments, and readable client rows. Effective authorization stays separate from saved VLAN policy and carrier. Existing source/session actions remain available; narrow layouts stack the same client fields without changing overview colors. The RADIUS page contains Access servers, certificates, templates, accounting, and dynamic authorization. CA/client certificate lists show separate template and copied-source reference counts. Bounded PEM file selection or paste is a local draft until Save; imports never implicitly select trust. Saved contents are not redisplayed; sparse replacement and reference validation remain in the existing material owner. Client rows provide on-demand allowlisted **Returned RADIUS attributes** and grouped history from existing bounded events. Missing, present, and invalid returned values are distinct from effective policy. Unclassified/private attributes expose presence/count only. Background refresh preserves disclosure, focus, scroll, and selection; accounting delivery status does not determine authorization. Endpoint profiles remain in the endpoint library; there is no parallel endpoint inventory.

The SNMP settings page labels the identity field **System object ID (`sysObjectID`)** and asks for a full numeric OID. Do not prefill it with a placeholder in the public UI. Explain that it changes advertised identity only. When unset, show **SNMP disabled: configure a system object ID** without hiding simulation controls. Warn when the documentation-only development placeholder is selected, including when an operator deliberately enters it in a public build. [R15]

The live FDB view shows MAC, VID, FDB ID, bridge port, joined `ifIndex`, last observation, and remaining simulated age. Cached entries without current endpoint instances remain visible; do not remove them merely because no library row can be joined.

Before VLAN deletion, show which ingress PVIDs fall back to 1 and which memberships disappear. The operation remains atomic regardless of the size of the preview. Show explicit invalid tagging/admission conditions without silently correcting them. Keep configured endpoint metadata visually distinct from switch-observed learning.

Optional SNMP request tracing shows manager, operation, OIDs, view/result, snapshot revision, and latency. Never display raw community/user secrets. Normal operation favors meaningful changes over a log entry for every routine MAC refresh.

## 11. Deployment and security boundaries

Ship one container and a Compose example with a persistent data volume. Run without privileged mode, host Docker socket access, or raw-packet capabilities. Default the SNMP query listener and host publication to UDP 161, with configurable alternatives using the same port on both sides. Container-scoped port permissions allow the nonroot process to bind 161 without additional capabilities. Serve the UI on a configurable HTTP port; bind local-only by default and document deliberate LAN exposure. [R12]

Require administrator setup, authenticated API mutations, protected sessions, CSRF protection for cookie-authenticated writes, and rate/size limits. HTTP traffic is unencrypted; HTTPS can be provided by a reverse proxy. The Secure session-cookie option requires HTTPS. SNMPv2c and unprotected v3 modes are identified as unencrypted.

Docker NAT can change observed source addresses. Reachability, notification source addresses, and source-CIDR matching depend on the deployment platform and routing; Linux host networking and Docker Desktop can differ. Advanced per-switch source-IP fidelity and multiple switch instances are later work. [R12]

Application readiness requires initialized storage, state, and a usable UI/API; a deliberately unset identity must not fail the container health check or cause a restart loop. Report SNMP readiness separately: it requires a valid configured identity, explicit enablement, completed configuration/security-engine initialization, and a bound listener. Gate notification readiness on identity and target configuration as well. Health checks and API diagnostics report actionable failures without exposing credentials. No performance target is claimed until measured. Exercise at least 24 ports, 1,000 endpoint instances, and 4,000 source entries as a proposed release load case, recording hardware, latency, memory, and scheduling behavior rather than declaring an unmeasured service level.

### 11.1 Development and public packaging

Keep the base defaults unset and load the development identity only through an explicitly selected development overlay or test fixture. The normal startup path must not select the development identity. The proposed identity fragments in `docs/config/` are documentation examples, not an implemented configuration loader.

Public images and deployment bundles must not bake in, copy as active configuration, auto-load, or supply environment defaults for the development overlay. Build from clean inputs and exclude saved lab volumes/databases and local settings. Do not remove or rewrite a user's persistent configuration during an upgrade. Source documentation and isolated test fixtures may mention the placeholder, but public quick-start instructions must begin with the unset public fragment and operator setup.

A clean-install release test must inspect the **effective** loaded configuration without overrides, confirm `sys_object_id` is null, and verify that neither polling nor notifications starts. Merely deleting the number from one sample file is insufficient. Release testing also supplies an operator OID explicitly and verifies that it is the advertised value. No PEN-registration check blocks publication.

## 12. Acceptance and formal-model traceability

| Behavior | Formal coverage | Required implementation test |
|---|---|---|
| Endpoint create/edit/delete, direct/shared attachment | Core actions; full small-state and scenario checks | API conflicts, ID persistence, live UI changes. |
| Live MAC/tag edits without flush/flap | LiveEdit and stale-job scenarios | External walk before/after accepted source activity. |
| VLAN removal and VLAN 1 fallback | VlanLifecycle, MultiSource, DeleteFallback, SelectiveAndPvid | All affected static/current/FDB OIDs agree in one PDU. |
| Obsolete callbacks and ABA races | Generation invariants and five targeted race families | Pause worker, mutate/revert, release old callback, assert no commit. |
| Active learning, aging, queue drain | Separate finite liveness fixtures with fairness | Scheduler timing, pause/manual advancement, backlog limits. |
| MIB joins | `MibOK` semantic projections | Numeric indexing, MAC encoding, bridge-port bitmaps, `ifIndex` joins. |
| Credentials | Current ReadAccess and SetTransactions bounded composition | Independent v2c/v3 clients; revoked queued request; restricted GETNEXT/BULK. |
| Development/public identity, setup gate | SET activation is abstractly modeled; concrete identity loading/parsing remains outside | Clean public default, explicit development overlay, typed OID response, validation, clearing, gated test sends, persistence, and unchanged generic behavior; see section 12.2. |
| Notifications | Link queue invariants/scenarios; drain liveness | Independent receiver checks PDU type, varbind order, values and timestamps. |
| Restart | `Reboot`, queued-work scenarios, and StorageOutcomes recovery | Process restart, persisted identities, USM boots, coldStart, relearning. |
| SET transaction/lifetime/storage health | SetTransactions, SetResponseLifecycle/Entry, StorageOutcomes | Actual BER, cache ownership, SQL exceptions, stale requests, and recovery. |
| ENTITY inventory | Stable core joins and EntityInventory snapshots/change clock | Exact OIDs/types/sentinels, UTF-8, UUIDs, filtering, no-op/wrap/reboot. |
| RADIUS authorization and dynamic requests | Separate RadiusAuthorization and RadiusDynamicAuthorization safety graphs | Real EAP/MAB, integrity, atomic selectors, replay/persistence, accounting ordering, causal time, PAE observations, and UI; no composition/refinement proof. |
| Wire protocol, TimeFilter, capacity, import, OS durability | Not proved by core TLA+ | Dedicated unit/integration/fault tests. |

Use Net-SNMP polling tools and `snmptrapd`, or equivalent independently implemented clients, for integration tests. Check good/bad credentials, view traversal, empty tables, nonidentical indexes, duplicate MACs across VLANs, absent VLAN tags, table edits during a walk, response limits, and reboot. A reference script can assert the end-to-end MAC → FDB → bridge port → interface join without access to a NAC product. [R13]

Model checking is finite and configuration-specific. The full-core fixture is intentionally small; focused fixtures and scripted traces cover larger combinations. Current SET checks compose bounded core and credential contracts; none is a formal refinement proof of the Python application. Passing TLC does not establish ASN.1 correctness, security implementation correctness, crash safety, unlimited-scale correctness, or NAC compatibility. Exact current configurations, outcomes, limits, and tool hashes are linked from `CURRENT_VERIFICATION.md`. Historical reports and evidence remain in Git with their original scope and measurements.

### 12.1 Integrated validation

Validate the serialized state engine against the model scenarios with automated tests. Check SNMP compatibility with the object manifest and an independent client/receiver. Verify that persistence, boot handling, API, and UI use the same state-engine commands, without a second simulation in the web layer. Include bounded-load, source-address, authorization, and failure tests.

An end-to-end acceptance workflow is: explicitly select the development identity or supply an operator OID, configure a credential and enable SNMP, walk interfaces/VLANs, attach an active endpoint, receive the appropriate link event, resolve its MAC to the correct interface, change its tag live, delete its native VLAN with fallback, and observe the documented cache behavior.

### 12.2 Identity acceptance tests

| ID | Required test |
|---|---|
| ID-T01 | A public image with a fresh volume and no overrides loads `null`; UI/API/simulation and application health work, while the listener and all notification/test sends remain disabled. |
| ID-T02 | Explicitly loading the isolated-development override supplies `1.3.6.1.4.1.32473.1` and displays its documentation-only warning. With other settings complete, an independent client reads that numeric value as OBJECT IDENTIFIER. |
| ID-T03 | Supplying a valid operator OID permits configured SNMP activation and round-trips that value through `sysObjectID.0`. No ownership lookup is required; syntactically valid non-enterprise test OIDs are not rejected merely for their prefix. |
| ID-T04 | Malformed nonempty input returns 422 without changing a running configuration. An intentionally blank form field saves `null`, not an empty string or ASN.1 NULL. |
| ID-T05 | Clearing identity during polling and notification activity safely quiesces the adapter, keeps simulation available, and prevents further application sends after acknowledgment. Restoring identity does not replay disabled-period events. |
| ID-T06 | Restarting or upgrading retains an operator value or an intentionally unset state. A lab scenario import does not replace the deployment identity. Changing the advertised OID does not reset the SNMPv3 engine identity. |
| ID-T07 | Changing identity does not change the supported MIB objects, trap definitions, link state, FDB, or endpoint behavior. A fresh public package cannot select the development value through hidden defaults. |

These are required application tests, not results of formal verification. The [application validation report](../docs/VALIDATION.md) records executed checks and their limits.

## References

The references define protocol/object semantics. Choices such as selective flushing, legacy VLAN scope, fallback, and live-edit cancellation are this project's documented policies.

- **[R1]** IETF RFC 4188, BRIDGE-MIB: https://www.rfc-editor.org/rfc/rfc4188.html
- **[R2]** IETF RFC 4363, Q-BRIDGE-MIB: https://www.rfc-editor.org/rfc/rfc4363.html
- **[R3]** IETF RFC 2863, IF-MIB and link notifications: https://www.rfc-editor.org/rfc/rfc2863.html
- **[R4]** IETF RFC 3416, SNMP protocol operations: https://www.rfc-editor.org/rfc/rfc3416.html
- **[R5]** IETF RFC 3415, view-based access control: https://www.rfc-editor.org/rfc/rfc3415.html
- **[R6]** IETF RFC 3418, SNMPv2-MIB: https://www.rfc-editor.org/rfc/rfc3418.html
- **[R7]** IETF RFC 4502, updated TimeFilter convention and traversal guidance: https://www.rfc-editor.org/rfc/rfc4502.html
- **[R8]** IETF RFC 3414, SNMPv3 USM: https://www.rfc-editor.org/rfc/rfc3414.html
- **[R9]** IETF RFC 7860, SHA-2 authentication: https://www.rfc-editor.org/rfc/rfc7860.html
- **[R10]** IETF RFC 3826, AES privacy: https://www.rfc-editor.org/rfc/rfc3826.html
- **[R11]** PySNMP, agent-side MIB implementations: https://docs.lextudio.com/pysnmp/v7.1/examples/v3arch/asyncio/agent/cmdrsp/agent-side-mib-implementations.html
- **[R12]** Docker, port publishing: https://docs.docker.com/engine/network/port-publishing/
- **[R13]** Net-SNMP manual index: https://www.net-snmp.org/docs/man/
- **[R14]** TLA+ tools: https://github.com/tlaplus/tlaplus
- **[R15]** IETF RFC 5612, documentation-only enterprise number 32473: https://www.rfc-editor.org/rfc/rfc5612.html

- **[R16]** IETF RFC 6933, ENTITY-MIB: https://www.rfc-editor.org/rfc/rfc6933.html
- **[R17]** IETF RFC 3413, command responder applications: https://www.rfc-editor.org/rfc/rfc3413.html
- **[R18]** IETF RFC 2579, RowStatus and TimeStamp conventions: https://www.rfc-editor.org/rfc/rfc2579.html
