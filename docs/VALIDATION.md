# Implementation validation

## Current users and groups checks

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

The focused grouped-access models ran before implementation; the [formal report](../specification/CURRENT_VERIFICATION.md) records separate checkpoints and corrections, not a combined 51-config run. Independent wire/Net-SNMP fixtures are prepared for the existing Docker CI and have not been executed for this change locally.

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
| Python state engine, MIB, API, wire and independent Net-SNMP suite | 56 tests; final output in `test-results.txt` |
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
