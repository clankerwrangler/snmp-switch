# RADIUS access, accounting, and dynamic authorization

Switch Lab is a RADIUS/UDP NAS client, not a policy server. It uses real MAB,
EAP-TLS, and PEAP-MSCHAPv2 exchanges to authorize simulated ingress activity.
It does not forward Ethernet frames, transmit EAPOL on host interfaces, or use
RADIUS for web-administrator login. Link state remains independent of access.

## Configure access

1. Open **RADIUS**. Add an ordered authentication
   server with its IP address, UDP port (normally 1812), and shared secret.
   Leave **Local source IP address** blank for automatic source selection. An explicit
   address must exist in the application's network namespace—not just on the
   Docker host. This bind address is separate from the advertised NAS IPv4 identity.
2. For EAP, open **Certificates → Add certificate**. Choose CA trust or a client
   identity, then select PEM files or paste PEM text. TLS needs both a CA trust
   bundle and a client certificate with its matching private key. Save the
   certificates, then create a supplicant template or edit an endpoint's
   **Supplicant profiles** directly.
   Set the expected server DNS name. PEAP additionally needs an inner username
   and password. Certificate and server-name validation are required.
3. In **Switch overview**, select the port and **Configure port**. Choose
   **Auto (authentication required)**, the method, and host mode. Existing and new ports
   default to force-authorized; adding a server does not change their access.
4. Attach the endpoint. Inspect the selected port's client status, effective
   VLAN, session ID, counters, and timers. FDB learning still requires accepted
   ordinary activity; a successful authentication does not invent a data frame.
5. Choose **Save configuration** to retain switch Access, accounting, and dynamic-authorization settings across reboot/restart. Certificates, templates, copied source profiles, and physical connections persist automatically without saving unrelated switch policy.

**Force-authorized** uses configured VLAN admission. **Force-unauthorized** blocks
ordinary ingress without forcing the physical link down. **Auto (authentication required)** requires a
current authorization. **Single-host** permits one authenticated MAC;
**Multi-auth** gives each MAC its own service; **Multi-host** shares the authenticated owner's service with
other clients on that port. Duplicate sources with the same `(port, MAC)` must
have the same supplicant profile, or authentication is blocked as ambiguous.

MAB waits for ordinary source activity. The triggering frame is discarded,
not replayed after authorization. Optional no-supplicant fallback also waits
for activity. Optional **MAB fallback after RADIUS Access-Reject** can use the MAC already
observed from the represented EAP peer. Invalid integrity, missing helpers,
certificate failures, and unusable Access-Accept policy are not NAS Rejects.

Certificate lists separate CA trust from client identities and show references
to templates and copied source profiles. Labels and short record IDs distinguish
selections; importing alone does not select a certificate for any profile.
Certificate/chain inputs are limited to 256 KiB and keys to 64 KiB. Saved contents
are not displayed. Editing without replacement inputs retains them; canceling
discards the local draft. Referenced certificates cannot be deleted.

Template application and cloning copy settings; later template edits do not
change copies. A clone can retain the same credential identity even when its
MAC changes. Saving a profile affects future exchanges and invalidates obsolete
attempts without revoking an established grant. **Reauthenticate** retains valid
access while a renewal is pending; **Restart authentication** ends the selected client/shared
service and begins fresh authentication without a link bounce. Independent
idle/session expiry, administrative changes, or failed required renewal can
still end access. Late replies cannot restore an ended or replaced grant.

Expand **Returned RADIUS attributes** or **Authentication history** in a client row
for details. Client history shows the latest 20 matching retained events without
combining separate authentication attempts. The full Event history includes
accounting and supports category, subject, outcome, and text filters. Refresh preserves
open disclosures, focus, scroll, and selected port. **Port ID** shows the numeric
ifIndex; subjects use recorded public names/labels when available. Legacy lookups
are marked current, and removed subjects do not display internal keys. Accounting queue status is
separate from whether access is authorized.

Attribute detail reports the **RADIUS response** and only safely decoded
Service-Type, VLAN tunnel type/medium/numeric VID, Session-Timeout, Idle-Timeout,
Termination-Action, and accounting interval. It distinguishes absent, present,
and invalid values and never substitutes effective defaults. An Access-Accept
can still have failed local policy application. State, Class, Proxy-State,
User-Name, EAP, vendor key material, and other unclassified attributes show
presence/count only—not values, lengths, or server diagnostic text. No raw packet
history is retained for this feature or included in scenario exports.

An unset NAS-Identifier override uses the switch name. If that name does not
fit 1–253 UTF-8 octets, configure a representable override; the switch name itself
need not change. NAS-Port is the stable bridge-port number, while NAS-Port-Id
uses the port name. NAS identifiers describe the simulator, not its endpoints.

## Authorization and clocks

An absent VLAN assignment inherits the running **Port VLAN ID (PVID)**, shown as
**Port default (PVID)**. An explicit assignment is shown as **RADIUS-assigned**. An explicit assignment must
be one complete VLAN tunnel triple naming an existing, non-forbidden VID.
It permits untagged activity or a matching explicit tag for that service.
It never overwrites configured PVID, static membership, or untagged membership.
Current Q-BRIDGE egress membership includes active authorized VLAN membership;
static tables and the current untagged table retain their configured meaning.
Authorization cannot create VLANs or migrate old FDB observations.

The supported Access-Accept service type is absent or Framed(2). Unsupported
filtering, routing, IP assignment, framing, login, or tunnel controls cause a
local authorization error, not permissive access. Vendor attributes are limited
to structurally valid Microsoft MPPE key material handled by the EAP helper.
Class and State remain private protocol/session metadata. No egress policy or
counter is fabricated.

| Time domain | Uses |
|---|---|
| Simulation | Source activity, learning/aging, discovery and failed-cycle cooldown, session/idle limits, reauthentication, and interim sampling |
| Real elapsed time | Network waits/retries, target backoff, queue retention, and replay expiry |
| Real wall time | Dynamic-request Event-Timestamp validation and durable replay-safety watermark |
| Management uptime | SNMP uptime and MIB change timestamps |

Pausing simulation does not stop an already pending exchange or real network
security clocks. Manual advancement stops at an unresolved authentication
boundary and reports a waiting operation rather than guessing an outcome.
Completion continues toward the original target. Canceling advancement retains
committed work and does not itself revoke access or cancel an unrelated exchange.
At most 64 automatic renewals per subject may occur without simulation-time
progress; exceeding the guard ends that subject and reports failed advancement.
A zero timeout is immediately due, not a disabled timer.

Server Session-Timeout and Idle-Timeout override corresponding local defaults.
Termination-Action selects termination or renewal at the session limit. The
client row labels absolute deadlines **Session timeout at** and **Idle timeout at**,
in simulation time, rather than promising termination at a renewal deadline. Renewal
does not refresh true last data activity. Server reachability is separate from
client outcome: exhausted no-response cycles use bounded real-time backoff;
a valid Reject proves reachability without granting access. Recovery probing
requires an eligible client and does not generate synthetic MAB traffic.

## Accounting

Open **Accounting** on the RADIUS page. Add independent accounting servers
(normally UDP 1813), then enable accounting. Access-server configuration does not
implicitly create an accounting server. Accounting failure never changes access.

**Interim updates** selects a valid server interval, disabled updates, or a
local override of at least 60 simulated seconds. Invalid server interim data
produces a warning, not access denial. Start, cumulative Interim, and Stop
snapshots retain their generation times. Start omits duration/counters; Interim
omits a termination cause. Only observed ingress is reported. Unchanged renewal
retains the accounting segment; changed authorization begins a new segment.

Accounting has its own **RADIUS response timeout**, **Attempts per server** (total
attempts, not additional retries), and **Retry backoff base**. Defaults are
3 real seconds, 3 attempts, and a 1-second base. Limits are 1–60 seconds,
1–10 attempts, and 0–30 seconds. Retry ordinal times the base is capped at
30 seconds; the default delays remain 1 and 2 seconds. The policy is captured
with each queued generation. Genuine changes cancel old queued/in-flight work
visibly; no-op settings and unrelated Access edits preserve it. Connect,
response, backoff, failover, and promotion cannot extend the original
300-real-second retention horizon.

Only the head record of a session has active wire/retry ownership. A confirmed
response or counted permanent drop releases the next record. The queue holds at
most 1,024 records and 8 MiB, with 300 real seconds of retention from generation.
Configuration changes cancel queued work using the old accounting-server configuration.
Status reports queue length, drops, and bounded record summaries. UDP delivery
is not exactly once; accounting responses do not authorize clients.

## CoA and Disconnect

Open **Dynamic authorization clients (CoA / Disconnect)**. Choose
**Configure** in that card, then add separate dynamic authorization clients.
These clients send requests to Switch Lab; the listener defaults disabled.
Each client has an exact source IP and its own secret. Authentication/accounting
servers and SNMP credentials grant no incoming dynamic-authorization trust.
The strict profile requires one Message-Authenticator and one Event-Timestamp
within 300 real seconds. There is no legacy unauthenticated mode.

Every supplied NAS/session selector must match. At least one session selector
is required. Duplicate singleton selectors are rejected. A MAC selector on a
multi-host service names its authenticated owner, not a dependent client or FDB
row. All matched sessions change atomically or none do. Disconnect ends them;
CoA can change a complete VLAN assignment, Session-Timeout, Idle-Timeout, and
Termination-Action. Omitted policy remains unchanged. Authorize-Only and other
unsupported changes return a NAK, not an approximation.

A supplied session timeout starts at commit simulation time; an idle timeout
retains actual last admitted activity. Valid State and ordered Proxy-State are
echoed. Duplicate/empty State produces NAK404 with State omitted; this is the
selected malformed-input normalization. Framing/integrity failures drop before
semantic processing.

The bounded 4,096-entry replay owner retains decisions through the request's
full timestamp window, including accepted future skew. Duplicate authenticated
bytes replay the original result without affecting replacement sessions.
Unexpired entries are not evicted to admit new work. Sender removal/recreation
and secret rotation do not erase replay protection. Graceful restart retains
protected decisions, but never restores live grants. A real clock below the
durable safety watermark gates DAS only until it catches up; other healthy
application services remain available.

Compose does not publish the optional DAS listener. To receive requests from
outside the container network, deliberately add a UDP mapping for the selected
port (normally 3799), set the container bind address, and allow it through the
host firewall. Verify the source IP actually seen after NAT before configuring
sender trust. Outgoing Access and accounting require routing to their servers,
not a published ingress port. IPv6 deployment/NAT fidelity is not a tested claim.

## PAE SNMP subset

The generated [object manifest](mib-coverage.csv) contains 34 selected definitions
from IEEE8021-PAE-MIB revision `200406220000Z`, under `1.0.8802.1.1.1.1`.
Port instances use **ifIndex**, not bridge-port/NAS-Port. Fresh **iso** (`1`)
includes IEEE; **internet** (`1.3.6.1`) does not. The iso view retains internal
ID `all`. Existing saved views, including the historical MIB-II `all`, are not
broadened; explicitly edit their prefixes when IEEE access is wanted. Existing
access and response-size checks apply.

Only port control, Initialize, and Reauthenticate are writable. True action
bindings coalesce per port; Initialize takes precedence when both actions are
requested. The whole PDU is validated before effects, under its final control
mode. GET returns false for completed actions. Initialize does not reset PAE
counters. System control remains enabled/read-only and direction remains ingress
only. No EAPOL-Key transmission or full PAE conformance is claimed.

State/diagnostic counters derive from represented EAP events, not peer exit
status, MAB success, or server reachability. Auto/multi-auth omits ambiguous
single-state, timer, and session cells rather than selecting a client or claiming
an aggregate state. Port event counters aggregate actual internal EAPOL frames.
Protocol version and last-frame facts appear only when observed. If an EAP
attempt is retired before complete observation, accumulated counters and
last-frame cells are omitted until management boot; numeric history is retained,
not reset. Stale events and replies cannot publish state.

Session rows represent the current or last valid single/shared service. Duration
is simulated centiseconds modulo 2^32, not management uptime. Authentication
method means remote server, not an EAP/MAB method number. Only exactly
representable PAE termination causes appear. Usernames, egress session counts,
and unsupported timers are omitted.

## Runtime, storage, and troubleshooting

The default Docker image includes the pinned, patched wpa_supplicant 2.12 EAP
helper and matching receipt. Native EAP requires Linux and the managed executable
at `/usr/local/bin/eapol_test`, with `eapol_test.switchlab.json` beside it. A stock
binary does not implement the protected result interface. Python-only or Windows
native installations retain MAB and report EAP unavailable rather than silently
substituting another method. The Debian-based build procedure is
`runtime/eap/build.py`; its fresh work/output directories, build dependencies,
exact source/patch hashes, linkage checks, and installed runtime packages are
specified by the Dockerfile and `runtime/eap/source.json`.

Configuration schema 4 preserves older SNMP settings and migrates ports to
force-authorized without servers, sender trust, or secrets. Configuration and
private material use the existing encrypted Store. API/form reads expose
presence flags, never saved key, certificate, password, shared-secret, Class,
or State bytes. Blank secret fields preserve values in supported sparse edits.
Scenario schema 1 excludes RADIUS settings, port authentication, and supplicants;
import preserves destination deployment/security settings and does not save
logical switch changes to startup. Reboot restores saved switch policy over the
current durable lab, ends volatile grants, resets operational clocks/counters,
and invalidates old work. Accounting records retain their original horizons or
are canceled when restored target policy differs. DAS decisions, highwater,
USM identity/boots, and manager credentials are not restored from startup.
Reboot is not an exact mid-session recovery mechanism.

Use the RADIUS page and selected-port client status to distinguish no supplicant,
profile conflict, unusable policy, native capability failure, NAS rejection,
transport outage, and replay-clock gating. The [API schema](../../docs/openapi.json)
contains the revision-checked settings, source/session actions, and advancement
routes. [Validation](../../docs/VALIDATION.md) records actual tests and their limits.

MAB transport reasons identify the failing socket, bind, connect, send, receive,
or close stage with a fixed error category. For example,
`access_transport_bind_address_not_available` means the chosen local source
could not be bound; `access_transport_connect_unreachable` is an OS route error.
A receive-side `refused` can follow a send; it is not an authenticated Reject.
Unclassified OS errors use the stage-specific `failed` category. Reasons omit
raw OS text and addresses. `server-unavailable` reports no usable server response,
not proven delivery; `server-reject` requires a validated Access-Reject.

Protocol sources: [RFC 2865](https://www.rfc-editor.org/rfc/rfc2865.html),
[RFC 2866](https://www.rfc-editor.org/rfc/rfc2866.html),
[RFC 2869](https://www.rfc-editor.org/rfc/rfc2869.html),
[RFC 3579](https://www.rfc-editor.org/rfc/rfc3579.html),
[RFC 3580](https://www.rfc-editor.org/rfc/rfc3580.html), and
[RFC 5176](https://www.rfc-editor.org/rfc/rfc5176.html).
Generic host-mode, malformed-State, and unsupported-policy choices here are
product rules, not universal behavior of those standards.
