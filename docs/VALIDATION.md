# Implementation validation

Executed on 2026-09-08. These results concern the application. The TLC reports under `specification/` cover the formal models and were not rerun during application validation; they are not implementation proof.

## Automated checks

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

## Measured load case

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

## Boundaries

- No NAC-product integration or vendor compatibility was tested or claimed.
- Docker's isolated loopback networking and native Windows localhost were tested. Published-port NAT behavior, LAN source-CIDR policy, IPv6 deployment paths and chosen notification source addresses must be checked on the actual network.
- Fault tests inject failed persistence and verify atomic application state. They do not exhaustively simulate filesystem/power-loss failures.
- UDP send acknowledgment is local only. A send/record crash window may leave delivery uncertain; exactly-once notifications are not promised.
- Imports require the same stable port inventory. Mid-timer recovery is intentionally a reboot, and scenario import does not rewind the management/security engine.
- Test runs emit upstream deprecation warnings from Starlette/httpx integration and PySNMP's cryptography CFB import. The tested encrypted operations pass with the pinned versions.
- The formal state machines were not composed with, or formally refined into, this implementation. This test suite is evidence for the exercised behavior, not a proof over every input or scale.
