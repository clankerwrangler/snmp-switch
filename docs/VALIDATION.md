# Implementation validation

On 2026-09-10, the separate SNMP/RADIUS/general settings, certificate file/paste
forms, and redesigned selected-port detail passed the maintained headless browser
flow in 48.584 s with native scrollbars visible. It covered sparse general/SNMP
edits, draft-only file selection, size checks before reads, invalid input, sparse
certificate/key replacement,
reference and stale-revision errors, cancel-during-read isolation, all existing
port/session controls, and keyboard/mobile/refresh behavior. Two held-read
regressions first reproduced a Save combining an earlier certificate with a later
key selection. Save now captures both PEM drafts and scalar/revision fields before
reading either file; both exact-payload regressions pass. The earlier dialog-close
correction clears the current form synchronously without affecting a later dialog.
Original failures remain local. A document scrollbar gutter now keeps the shared
main/header/sidebar/page frame stable across long and short routes. The maintained
regression first failed on a 15 px width change; wide-layout measurements also
showed a 7.5 px page shift. Desktop, wide, and mobile navigation checks now pass
without hiding scrollbars or adding per-page offsets. TypeScript/Vite passed;
the packaged JavaScript contents are unchanged.

The synthetic instance kept SNMP disabled and identity unset, prohibited UDP and
external RADIUS, and used only generated certificate/key inputs. Its processes,
loopback socket, database, and keys were removed. The README overview is a
1680 × 1393 viewport capture of a separate synthetic eight-port lab with one attached endpoint and learned address. It includes the
complete selected-port panel, waits for the toast to finish, and uses no stitched
full-page capture or screenshot-only styling. Other inspection screenshots remain
local. The unchanged `ScenarioPauseManual` check completed
with 15 generated/14 distinct states and an empty queue before UI implementation;
navigation and local drafts remain presentation stutters, not a new model.

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
