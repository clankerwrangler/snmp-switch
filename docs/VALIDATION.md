# Implementation validation

## Event history checks

Checked on 2026-09-11 against `19a4e79d`, using Python 3.12 and PySNMP 7.1.29.
The affected Engine/API and supported in-memory BER SET/lifetime selection passed
**313 tests in 38.57 s**, with 38 upstream warnings and **zero INET attempts**.
Sixteen new BER cases first reproduced the missing configuration effect; they now
check distinct operation, resource, and conditional link records under all four
existing security profiles. Records share the confirmed transaction revision;
unchanged SETs, API replay, failed validation, rollback, unknown publication, and
response delivery retain their existing boundaries. Typed port facts, field-only
other changes, five trap-gate combinations, attachment context, and retained IDs
across normal SQLite reload are covered. No UDP, native authentication, or
deployment performance claim follows from these tests. Two later v2c checks
passed in 0.63 s with zero INET attempts: the existing mixed IF/VLAN fixture
asserts every resource fact and common revision, and action-only Initialize
asserts operation/Access records without configuration or link effects.

The added finite EventHistory witness completed 15 prescribed cases with 161
generated/144 distinct states and all three temporal branches. Its negative
control published false operation/configuration/link records after a failed
commit and violated the event publication property. It does not replace actual
API replay, retention, field privacy, or trap-queue tests. Exact model inputs and
limits are in [current formal verification](../specification/CURRENT_VERIFICATION.md).

The packaged TypeScript/Vite build and full maintained synthetic browser passed;
the final browser completed in **63.835 s** with no page errors. A supported
in-memory BER SET first committed three actual operation/configuration/link
records into the fixture's encrypted database. The fresh app displayed those
same records without reapplying the SET. Filters, expanded typed details, recorded
subject navigation, 50-row paging, stable Follow/new-event behavior, and mobile
layout passed. Separate presentation samples cover accounting classification,
adjacent reversible groups, distinct unknown attempts/record identities, missing
historical fields, retention-window loss, and escaped/private-value omission.
These samples do not create backend authentication sessions.

The existing source/port, SNMP/RADIUS settings, sparse secrets, PEM click-time
snapshot/cancel, running/startup, and keyboard/focus/open/scroll checks remained
in the full flow. Earlier selector ambiguities and the first missing-effect
failures remain local evidence. The shared details grid was verified after its
visual correction. The browser used only synthetic state/certificates, prebound
loopback HTTP, disabled SNMP/unset identity, and prohibited UDP/external RADIUS.
Processes, socket, database, and synthetic key/material files were removed.
Private review images are not packaged; the README overview is unchanged.

## Recorded read, configuration, and UI checks

Checked on 2026-09-10 against `079aa9eb`, with Python 3.12 and PySNMP 7.1.29.
The final affected Engine, Store, API, MIB/PAE and named response-lifetime suite
passed **614 tests in 64.14 s**, with one actual-listener API case excluded,
46 upstream warnings and **zero INET attempts**. Input hashes remained unchanged
during the run. This is not a new native, UDP, independent-client or deployment run.

Automatic CI for `883dbc8f` passed 1,275 tests and 139 subtests but failed one
rollback fixture when independently sampled uptime crossed a centisecond boundary.
A controlled-clock reproduction changed only uptime (100 to 102 ticks). The fixture
now retains full storage/snapshot/event equality at fixed time and separately checks
100 ticks of clock progress. All 32 direct rollback/response-failure cases passed
in 5.62 s with zero INET attempts. Production clocks and rollback behavior are
unchanged; that failed CI run did not reach the runtime/LAN steps.

### Request-local reads

Synthetic 24-port states had four VLANs and either 24 or zero learned MACs.
The existing in-memory BER dispatcher exercised current v2c authorization,
GET/NEXT/BULK and response encoding/decoding. Numeric typed outputs, table
limits, row counts and PDU counts matched the retained baseline.

| Full-view workload, median unless noted | Before | Current |
|---|---:|---:|
| Projection construction, 24 learned MACs | 3.477 ms | 0.117 ms |
| Bridge-port table, 48 implemented cells, 49 GETNEXT PDUs | 260.291 ms | 64.923 ms |
| Same bridge table, two GETBULK PDUs | 19.065 ms | 11.073 ms |
| ifDescr, 24 cells, 25 GETNEXT PDUs | 145.608 ms | 47.633 ms |
| ifAlias, 24 cells, 25 GETNEXT PDUs | 127.060 ms | 40.271 ms |
| Q-BRIDGE FDB, 48 cells, 49 GETNEXT PDUs | 253.142 ms | 66.787 ms |
| Current VLAN, 20 cells, 21 GETNEXT PDUs | 106.185 ms | 29.612 ms |
| Static VLAN, 20 cells, 21 GETNEXT PDUs | 106.562 ms | 28.705 ms |
| PAE configuration, 216 cells, 217 GETNEXT PDUs | 1,156.969 ms | 369.528 ms |
| Prior IF/ifX workload, 648 cells, 675 GETNEXT PDUs, one replay | 3.578 s | 1.230 s |
| Same IF/ifX workload, 27 GETBULK PDUs, one replay | 275.846 ms | 178.617 ms |

Table walks used three samples and direct GETs five. A 96-binding request for
bridge columns 1–4 retained 48 implemented values and 48 absent-object results;
no unsupported column was invented. The zero-FDB control retained empty-table
successors, reducing its one-PDU FDB query from 4.592 to 1.235 ms. These are local
compute measurements, not deployment latency guarantees; network delay,
manager request patterns, and inventory size also affect response times.

Profiling 30 bridge PDUs attributed about 76% of baseline request time to
constructing all 1,977 ordinary cells per PDU. The current projection registers
complete column metadata first, builds only reached families, and constructs
selected ordinary ASN.1 values. It retains the captured Runtime, view and one
uptime/wrap sample; there is no cross-PDU cache. Request-local sorted TimeFilter
keys preserve global successor order across sparse, hidden and empty families.
A fixed-clock comparison covered 18 warm view/wrap cases; 20 additional cold
cases avoided diagnostic pre-materialization and included empty FDB, root views,
conditional PAE and unset identity. OID/tag/BER, exceptions, supported bases,
cutoffs, ordering and delayed old-publication reads matched. Earlier unchanged
ReadAccess and EntityReadConsistency evidence supplies the same abstract read
boundary, not a Python equivalence or performance proof.

### Running/startup and SET

The current tests cover logical apply/discard, revision-checked Save, persistent
physical edits without implicit startup Save, encrypted legacy migration and
normal close/reopen. They retain monotonic revisions, effect-scoped idempotency,
no repeated reboot, copied peer credentials/materials, accounting horizons and
revocation, DAS decisions/generations/highwater, and independent manager/USM data.
Fifteen Save/mixed/reboot and five migration fault cases distinguish actual write,
commit, failed rollback and unknown outcomes. Recovery uses ordinary SQLite close
with the failed transaction still open, not a fixture repair rollback.

A review reproduced nine missing nested fields being default-filled at split
load, including auto port control and restricted access filters. Complete stored
fragments now reject these omissions before publication while sparse API,
normalized legacy migration and genuinely new-port defaults retain their owners.
Both auto and force-unauthorized controls are covered. Original failures remain
local. The updated StorageOutcomes graph completed its temporal checks with
2,070,496 generated/172,689 distinct states; retained recovery and lifecycle
checks completed 120 recovery branches and identity plus five legacy-seed outcomes.
Four causal controls detected implicit/mixed autosave, hardware resurrection and
uncertain startup overwrite. Exact inputs, focused-slice correspondence and
limits are in [current formal verification](../specification/CURRENT_VERIFICATION.md).

Supported SET profiling used the same 135 actual BER PDUs per version of the
implementation: v2c memory/file SQLite and v3 authPriv memory, with 90 changed
transactions and 45 no-ops. Initial explicit Save was outside timing. All echoes,
status/revisions, running effects, unchanged startup and durable bookkeeping
checks passed; no Projection was built. File SQLite retained WAL/FULL settings.

| SET median | Original auto-persist | Startup split only | Current clone reuse |
|---|---:|---:|---:|
| v2c memory, admin change | 14.190 ms | 16.961 ms | 13.709 ms |
| v2c file, admin change | 16.588 ms | 17.600 ms | 16.708 ms |
| v2c memory, three-binding VLAN write | 15.788 ms | 17.654 ms | 14.689 ms |
| v2c file, three-binding VLAN write | 17.555 ms | 18.384 ms | 16.573 ms |

Running-only configuration is not zero disk I/O or itself a speed improvement.
For SET alone, Runtime cloning no longer deep-copies the old cfg that is immediately
replaced by a separately deep-copied plan candidate. Candidate isolation, full
validation, all other Runtime copies, commit/fault/response ownership and non-SET
paths remain. Five profiled memory SETs fell from 0.224 to 0.174 s, with cumulative
deepcopy cost falling from 0.132 to 0.093 s. No-op processing is unchanged. Alias,
old lazy-read, copy/validation/Store failure, no-op and stale-plan regressions pass.
These small no-contention samples do not establish a universal SET latency target.

### Packaged interface

TypeScript 5.9.3 and Vite 7.1.12 built the packaged assets. The full maintained
synthetic browser passed in **53.820 s**: root-prefix views and preserved references,
RADIUS five-card layout/compact header actions and keyboard disclosures, one global
Save/dirty marker, Apply versus durable-lab Save, actual stale Save rejection,
reboot discard with lab/login retention, and existing source/port actions.
PEM file/paste, pre-read size checks, sparse replacement, reference errors,
click-time certificate/key snapshots and cancellation remain covered. Selected-port
returned attributes/history, escaped labels, focus/open/scroll, and mobile frame
geometry pass without changing carrier colors or hiding information. The first
run found an ambiguous Add Server test locator; scoping it to authentication servers
preserved all assertions. No application behavior was changed for that fixture fix.

The browser kept SNMP disabled/identity unset, prohibited UDP/external RADIUS,
and used only disposable certificates and state. Children, socket, database and
keys were removed. Desktop RADIUS and mobile overview inspection images are local;
the mobile image is not a RADIUS-route capture. Responsive RADIUS geometry and
narrow-screen overflow checks are maintained in the browser. The existing README
1680 × 1296 viewport overview remains representative and unchanged. No extra
presentation-model run or screenshot-only CSS was introduced. Deeper native and
wire evidence below belongs to its recorded earlier inputs. Current runtime/LAN
caller fixtures now explicitly Save only where their restart assertions require
it; those updated network fixtures were source/parse checked, not executed locally.

The focused MAB method/transport tests passed 30 cases in 0.24 s with zero INET
attempts. Injected socket-stage errors first reproduced 12 lost-diagnostic failures
alongside six passing controls. The correction reports only fixed stage/category
reasons; it preserves explicit source binding, strict reply validation, retries,
cancellation, current-attempt ownership, and no-grant behavior. Fake socket checks
are not NAC reachability or Docker-route verification.

## Recorded RADIUS integration checks

Executed on 2026-09-10. Results are separate source checkpoints, not one combined
end-to-end run. They precede the settings/port presentation changes described above.

| Check | Actual result |
|---|---|
| Earlier engine/API/MIB/dispatcher integration checkpoint | 972 passed; 80 subtests passed; 14 skipped and one real-listener API case deselected; 110.63 s; 151 upstream warnings |
| Final scope: changed controller/API/engine/MIB regression selection | 372 passed; one real-listener API case deselected; 19.09 s; INET0 |
| Maintained full browser flow (`tests/ui-smoke.cjs`) | Passed in 39.387 s; existing flow plus RADIUS settings, copied profiles, safe attributes and grouped history; no page errors/screenshots or mobile overflow |
| Changed native helper callers | Nine private-input/cancellation/capability/incremental cases passed in 0.18 s, INET0; synthetic child scripts, not a native EAP/crypto matrix rerun |
| Current Docker test selection | Source/collection check includes 26 native-channel and 109 codec cases; eight wire cases include the new independent PAE walk/bulk/action case; collection creates no sockets |
| Final shutdown and capacity follow-up | 56 passed in 2.00 s, INET0; includes actual SQLite rollback during close, retained replay ownership, full-cache denial/cached replay, and accounting record/byte bounds |
| Network boundary for that selection | AF_INET/AF_INET6 creation prohibited; zero attempts; native/codec modules and the UDP wire module not rerun |
| PAE observations/actions | Fourteen focused cases; current/last sessions, exact types/indexes, conditional omission, atomic actions, stale events, completion versus retirement, and reboot |
| Incremental native-channel decoder | Three pure Python cases passed in 0.08 s, INET0; fragmented literal EAP metadata does not authorize without a complete NAS result; no native process or crypto rerun |
| PAE application responder | Four cases across v2c and all v3 security profiles; real BER/USM with an in-memory transport; explicit IEEE view, final-PDU validation, action echo and GET completion |
| Manifest and API | 129 definitions: 123 readable, ten writable, six inaccessible indexes; deterministic manifest and regenerated OpenAPI |
| Current UI | TypeScript/Vite build passed; packaged assets match the tested build |
| Current headless Chromium forms | Passed in 6.852 s; accounting/DAS plus existing RADIUS forms, sparse secrets, independent destinations, timer precedence, retained grants, desktop/mobile; no page errors or screenshots |

The browser used synthetic authorization, disabled SNMP/identity, disabled
accounting/DAS, a prebound ephemeral loopback HTTP socket, exact-origin requests,
and guards against UDP/native authentication. It did not perform a RADIUS or PAE
wire test. Browser/app processes exited, the socket closed, and the synthetic
database/key were removed. Earlier browser checkpoints cover selected-port
presentation and pending/canceled advancement through the same API/DOM owners.

Three focused regressions first reproduced a PAE observation defect: Initialize,
plain Reauthenticate, and independent session expiry could retire an unfinished
EAP capture while still publishing aggregate counters as exact. The shared
retirement path now preserves numeric history, omits incomplete observations
until management boot, and rejects late events/results. Completed Accept/Reject
consumption remains precise. The correction's initial 12-case and 247-case
integration logs passed before the larger selection. The independent-expiry
regression installs a due policy directly; it is not native timing evidence.

The final shutdown check reproduced a queued DAS handler deleting its reservation
before `close_dynamic` could persist a tombstone. Handlers now retain reservations
during closure; the existing close owner persists retirement before draining and
removing them. A failed SQL retirement keeps the reservation for retry. The
corrected focused selection followed the 972-case checkpoint; the counts are
not additive. Cache-capacity tests prefill valid-shaped records rather than
sending thousands of datagrams. No current-image wire claim follows from them.

The final scope completes independently configurable accounting timeout/attempts/
backoff, captured delivery policy and the absolute original retention horizon.
Focused tests cover timeout while connecting, receiving, or backing off; a policy
change retires old queued/in-flight ownership without changing grants. A new
combined host-mode regression covers raced single-host ownership, per-client
VLAN/tag admission, membership references, API/SNMP baseline changes, selective
VLAN deletion, and shared-service accounting.

The maintained browser takes a disposable CA/client certificate through
`SWITCHLAB_TEST_RADIUS_CA_FILE` and its matching encrypted key through
`SWITCHLAB_TEST_RADIUS_KEY_FILE`, alongside its existing URL/password/browser
inputs. The synthetic key password is fixed in the test, never an operator key. The bounded local runner generated that certificate/key pair using the existing
test fixture and removed both afterward. It kept all RADIUS destinations/listeners
disabled, prohibited external authentication/UDP, and used synthetic response
presentation only for simultaneous successful/pending/failed client rows.
The actual authenticated API test separately verifies returned-versus-effective
attributes, absent/present/invalid values, private-value omission, and bounded
event history. The browser checks actual refresh completion before asserting
open disclosure, focus, selected port, and unchanged scroll.

The existing Docker CI runs Python tests, clean-runtime checks, and its isolated
ordinary LAN/SNMP flow; it does not run an external RADIUS server or the browser.
Automatic CI for `345c522` passed 1,148 tests and 139 subtests, both image builds,
and the existing runtime/LAN checks. The independent PAE UDP test was included
there, not run through a new local listener.
Current native EAP-to-PAE event/UDP integration is established by the separate
controlled current-image fixture below, not the local no-network checks.
RADIUS deployment source/NAT paths remain separate. Earlier controlled
RADIUS fixture evidence remains separate; no additional listener or live-service
execution is implied.

### Current production-image fixture

A current production-stage image, built from 37 frozen application/UI/native
inputs, completed the controlled fixture in **28.569 s** with the packaged
helper and no application-source mount or helper override. Independent
puresnmp 2.0.1 read IEEE cells after real EAP-TLS and PEAP-MSCHAPv2 exchanges:
TLS had 8 received/9 transmitted internal EAPOL frames; PEAP had 11/12. Typed
state/backend/controlled status, identity-response diagnostics, silent-session
ingress counters, and session cells agreed with the Engine. The wire assertions
check ASN.1 tags and declared response lengths, not process-exit or MPPE status.

With the task-only Access server paused, an actual unfinished TLS renewal
advanced its observed counters to 9/10. Initialize under final unauthorized
control then exposed `noSuchInstance` for potentially incomplete aggregates,
retained the last valid session, preserved the unrelated PEAP grant, and allowed
no late grant after the server resumed. A fresh successful exchange did not
restore precision; management boot started a new observable counter epoch.
Private numeric-history preservation and adversarial scheduling variants remain
covered by the focused Engine tests rather than a private wire inspection.

The same run exercised current MAB/accounting/DAS integration, configured
accounting retry policy, three chronological collector samples, cancellation of
old queued configuration, real generation-based `Acct-Delay-Time` of 3 seconds,
and cached Disconnect replay after graceful app close/restart and replacement
authentication. Full 300-second expiry is covered by the focused remaining-time
tests, not claimed from a wire case bounded to 60 seconds. There were 29 trusted
sender datagrams, including 11 SNMP requests with declared responses of 89–455
octets, plus one untrusted-source negative packet. No private packets, keys,
community, or raw opaque values were exported.

All 16 preexisting containers were unchanged. Every fixture container, private
network/volume, and synthetic credential was removed. The listener was bound
only inside the isolated fixture at its approved address/UDP 11610; no host port
was published. The original broader Net-SNMP/USM and deployment LAN/NAT cases
remain normal CI or separate deployment scope.

Three maintained regressions also passed with their existing owners (11 tests,
INET0): populated encrypted schema-3 Store close/reload and durable migration,
same-port duplicate-source removal retaining its grant, and idle expiration
releasing a single-host slot for the next eligible subject. Earlier fixture-only
TimeTicks conversion, exception-sentinel re-encoding, and post-restart readiness
failures are retained locally; no application change was made to fit them.

### Earlier real protocol checkpoints

The pinned wpa_supplicant 2.12 helper includes upstream Message-Authenticator
length fix `aa02cfa569477f67f3915c8b9a83d1a7ca93693d` and the protected managed
result patches in `runtime/eap/`. Its prerequisite had 15 passing channel,
correlation, integrity, backpressure, and cancellation checks, followed by real
TLS 1.2 EAP-TLS and PEAP-MSCHAPv2 exchanges with isolated FreeRADIUS 3.2.10.
Wrong server name, untrusted CA/client, wrong password, and expired-server
negative cases passed. Authenticated NAS results and ordered attributes remain
separate from peer/key success and process exit. The stock pending-request-loss
hypothesis was disproved; actual stock 2.12 retains the pending request.

A default nonroot production-stage image separately completed EAP-TLS/PEAP with
the installed helper, matching receipt, and runtime libraries, without application
source mounts or a compiler. Actual requests checked default NAS-Identifier with
no synthetic loopback NAS-IP, explicit identifier with no NAS-IP, and explicit
advertised IPv4. A later production-stage checkpoint completed real MAB,
a silent TLS session, independent accounting, and CoA/Disconnect in 19.953 s.
It covered all-match VLAN changes, atomic NAK, selector contradictions, State
and Proxy-State, invalid/untrusted/stale drops, immediate zero timeout, cached
duplicates against replacement sessions, sender-secret ABA, chronological
cumulative interims, a delayed collector, idle expiry, and graceful Stop/Off.
All task fixture objects and synthetic secrets were removed; existing services
were unchanged and no ports were published.

These real image checkpoints precede the latest PAE projection, observation
retirement, and service-form changes. They do not prove current PAE wire/event
completeness, full EAP/PAE conformance, TLS 1.3, NAC-product compatibility, LAN/NAT
source fidelity, or every crash/power-loss interleaving. The RADIUS models ran
before implementation and remain separate finite safety abstractions, not
composition or implementation-refinement proofs. See the
[formal report](../specification/CURRENT_VERIFICATION.md) and
[RADIUS behavior](../specification/docs/RADIUS.md).

## Recorded users and groups checks

Executed locally on 2026-09-08 with the pinned Python 3.12 environment and unchanged PySNMP 7.1.29:

| Check | Actual result |
|---|---|
| API, engine, MIB, dispatcher/lifetime, and storage recovery | 734 passed; one real-listener API case excluded; 150 upstream warnings; 107.98 s |
| Network boundary | AF_INET/AF_INET6 creation prohibited; zero attempted network sockets |
| Stock-USM normal profile matrix | All nine suite/requested-level cases checked: three matching profiles accepted; six mismatches rejected with counter increments; three actual unsupported-level REPORTs decoded |
| UI build | TypeScript 5.9.3 and Vite 7.1.12 passed; CSS and third-party notices unchanged |
| Actual headless Chromium browser | Passed in 24.427 s; desktop/mobile layouts; no screenshots or page errors |

The implementation checks cover encrypted schema loading, independent community/group permissions, sparse saves, explicit protocol-conversion intent, atomic rejection and SQLite rollback, shared-group generation changes, queued ABA revocation, and unchanged response/storage owners. The original lower-level-USM probe failed three cases; it remains failed evidence. The selected product behavior retains stock USM protection requirements and applies group minimum only after actual security-model acceptance.

The browser exercised the single Access form, all four modes, hidden drafts, shared users/groups, profile mismatch, explicit conversion choices, missing views, literal labels, validation/revision errors, one listener status, and the exact Switch Lab title. Existing trap, endpoint-disconnect, VLAN, authentication, and mobile flows also passed. Its synthetic instance kept identity unset and SNMP disabled, used prebound ephemeral loopback HTTP and exact-origin requests, then closed its processes/socket and removed its database/key.

The focused grouped-access models ran before implementation; the [formal report](../specification/CURRENT_VERIFICATION.md) records separate checkpoints and corrections, not a combined catalog run. Independent wire/Net-SNMP fixtures are prepared for the existing Docker CI and have not been executed for this change locally.

## Recorded ENTITY and SET checks

These measurements describe the earlier ENTITY/SET implementation, before the users/groups change. Executed locally on 2026-09-08 with the pinned Python 3.12 environment and PySNMP 7.1.29:

| Check | Actual result |
|---|---|
| API, engine, MIB planner/projection, response lifetime, and storage recovery | 649 passed; one real-listener API case excluded; 137 upstream warnings; 97.38 s |
| Network boundary for those tests | AF_INET/AF_INET6 creation prohibited; real BER/security serialization uses in-memory transport sinks |
| MIB manifest | Generator reproduces 95 definitions exactly; 89 readable, seven writable, six inaccessible indexes; complete projection/writer equality checks pass |
| UI | TypeScript 5.9.3 and Vite 7.1.12 build passes; CSS and third-party notices unchanged |
| Actual headless Chromium browser | Passed in 33.026 s; 1440 px desktop and 390 px mobile; no screenshots or page errors |

The browser uses synthetic state with SNMP disabled and identity unset, a prebound ephemeral `127.0.0.1` HTTP listener, and exact-origin requests. It covers independent SET access and optional CIDRs, explicit/missing views, secret-free forms, literal HTML-like labels, independent admitted/untagged/forbidden sets, native-PVID preview, empty untagged membership, atomic errors, and the existing endpoint-disconnect, trap, authentication, and mobile flows. Browser/app processes exit, the HTTP socket closes, and synthetic database/key files are removed.

The backend checks cover all seven typed SET objects, final-candidate and original-index rules, no-op preservation, actual SQLite rollback, current authorization/generation checks, queued revocation/expiry, and commit-versus-response delivery. Storage tests distinguish actual failed rollback from both possible no-active-transaction unknown outcomes. Faulted API/SET/background/setup/boot/send paths remain blocked while reads use the last confirmed snapshot; two normal fresh startups reload actual durable data and restore writes and serialized notifications.

Separate prerequisite evidence covers 2,230 fresh BER responses across v2c and all three v3 security levels, original request-ID widths, peer minimum size 484, and response-budget boundaries. The pinned inbound-lifetime correction retains its reproduced stock expiry failure and late-association counterexample; successful corrected tests do not erase those failures. No local SNMP wire listener or Net-SNMP command was run for this change. The existing Docker suite contains the independent wire/restart/receiver checks.

The current model checks ran before their corresponding implementation changes. [Current formal verification](../specification/CURRENT_VERIFICATION.md) identifies exact inputs, separate runs, bounded proofs, and negative controls. Neither those models nor in-memory protocol tests prove OS durability or independent-client wire compatibility.

## Recorded baseline application validation

The following measurements and descriptions retain the scope of the original application run; they are not measurements of the ENTITY/SET implementation.

Executed on 2026-09-08. These results concern the application. The TLC reports under `specification/` cover the formal models and were not rerun during application validation; they are not implementation proof.

### Automated checks

| Check | Result |
|---|---|
| Python state engine, MIB, API, wire and independent Net-SNMP suite | 56 tests |
| TypeScript strict checking and production UI build | Passed |
| Browser workflow in headless Microsoft Edge, 1440px desktop and 390px mobile | Passed; no page errors or mobile horizontal overflow |
| Public Docker runtime build | Passed |
| Clean runtime image: setup health and simulation with unset identity | Passed |
| Operator OID round-trip, clearing identity, process restart, persisted USM ID/boots | Passed |
| 24 ports / 1,000 endpoints / 4,000 sources | All 4,000 entries learned; 44,000 scheduled observations processed |

Engine tests exercise direct/shared carrier, forced faults, move validation, connected deletion conflicts, multi-source live edits, historical cache retention, selective membership removal, PVID changes, VLAN 1 fallback, absent tags, duplicate MAC moves and VLAN isolation, pause/manual time, chronological expiration, capacity counters, durable restart, scenario validation, persistence failures and idempotency. Seven late-job tests cover edit, attachment, port, VLAN, instance, reboot and explicit-clear invalidation.

MIB tests compare every definition in the 72-row object manifest with implemented access: 68 readable object definitions and four non-readable indexes. They verify ASN.1 types, scalar exceptions, interface/bridge joins, fixed six-octet MAC indexes, PortList bit order, counters, restricted traversal, TimeFilter single traversal and uptime wrap.

Wire tests use independent **puresnmp/x690** for v2c reads, walks, bulk requests, SET rejection, credential/CIDR rejection, rotation, v3 discovery and trap decoding. **Net-SNMP** independently verifies v3 noAuthNoPriv, SHA-256 authNoPriv and SHA-256/AES-128 authPriv, numeric identity values including `2.999.123`, reboot timeliness, TimeFilter, live MAC edits, VLAN fallback and authenticated/encrypted trap reception with `snmptrapd`. PySNMP manager tests additionally check USM state across reboot.

The x690 decoder used by puresnmp mishandles an OID whose combined first two arcs need a multi-byte encoding. Its interoperability fixtures therefore use `1.3.999.123`; independent Net-SNMP tests cover `2.999.123` and pass. The agent accepts valid numeric OIDs regardless of enterprise prefix.

Browser checks create the administrator, pause time, create and attach an endpoint, advance activity, inspect its learned MAC, edit a port, open settings and verify the mobile layout. Screenshots are in `screenshots/`.

The clean-image check uses the actual public runtime image, temporary data, and an isolated network namespace. It verifies null effective identity, working health/setup/simulation, operator identity on the wire, process-restart persistence, USM boot increments, listener shutdown after clearing identity, and persistence of the unset state. It confirms the development overlay is absent from the runtime image.

### Measured load case

One run in Docker Desktop's Linux/WSL2 environment:

| Measurement | Result |
|---|---|
| CPU exposed to container | AMD Ryzen 5 7500F, 12 logical CPUs |
| Memory exposed to container | 16,214,664 KiB |
| Kernel / runtime | Linux 6.18.33.2-microsoft-standard-WSL2; Python 3.13.15 |
| Scenario | 24 shared ports, 1,000 endpoints, four sources each |
| Processed activity | 44,000 observations across 11 equal-time source batches |
| Learned FDB entries | 4,000 |
| Batch duration, median / maximum | 124.95 ms / 141.38 ms |
| Full MIB projection | 91.23 ms; 20,816 ordinary instances, plus filtered VLAN instances |
| Process maximum resident memory | 69,720 KiB |

This measures the in-memory engine and projection, excluding SQLite, HTTP, UI, and network latency. It is not a full-deployment throughput or latency guarantee. Reproduce with `docker run --rm switchlab-test python scripts/load_case.py`.

### Boundaries

- NAC-product integration and vendor compatibility were not tested.
- These runs tested Docker's isolated loopback networking and native Windows localhost. They did not cover published-port NAT behavior, LAN source-CIDR matching, IPv6 deployment paths, or notification source addresses on a deployment network.
- Fault tests inject failed persistence and verify atomic application state. They do not exhaustively simulate filesystem/power-loss failures.
- UDP send acknowledgment is local only. A send/record crash window may leave delivery uncertain; exactly-once notifications are not promised.
- Imports require the same stable port inventory. Mid-timer recovery is intentionally a reboot, and scenario import does not rewind the management/security engine.
- Test runs emit upstream deprecation warnings from Starlette/httpx integration and PySNMP's cryptography CFB import. The tested encrypted operations pass with the pinned versions.
- The formal state machines were not composed with, or formally refined into, this implementation. This test suite is evidence for the exercised behavior, not a proof over every input or scale.
