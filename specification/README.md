# SNMP Switch Emulator: model and technical specification

This directory contains the current TLA+ contract, bounded TLC configurations, behavioral negative controls, and application requirements for one vendor-neutral switch-management emulator. There is no Ethernet forwarding. Original project material uses the [MIT License](../LICENSE); external tools and standards retain their terms.

## Start here

- [Application README](../README.md): installation, essential configuration, and documentation links.
- [Technical specification](TECHNICAL_SPECIFICATION.md): state, VLAN/SET/ENTITY behavior, API/UI, and storage recovery.
- [Current model contract](CURRENT_MODEL.md): model ownership, selected profiles, finite bounds, and implementation boundaries.
- [Current verification](CURRENT_VERIFICATION.md): exact checked inputs, outcomes, negative controls, and preserved failures.
- [Object manifest](docs/mib-coverage.csv): 95 definitions, comprising 89 readable objects (seven writable) and six inaccessible indexes. Maximum MIB access and implemented access are separate.
- [Identity setup](docs/IDENTITY_SETUP.md): explicit identity configuration and public defaults.
- [Historical verification](VERIFICATION.md): original revision-2 evidence, with its original scope and measurements.

## Current contract

One state engine owns endpoints, stable ports, VLANs, learned addresses, generations, and notification events. Endpoints have editable MAC/tag sources and independent attachments. Direct/shared carrier behavior, selective flushing, deterministic source activity and aging, pause/manual advancement, and reboot semantics remain explicit.

Ports have independent admitted, untagged, and forbidden VLAN sets. Raw SNMP PVID changes ingress classification only; the API's native-PVID convenience is modeled separately. Seven SET objects use simultaneous final-candidate validation and one transaction. Polling and writing grants are independent and default-denied, while reusable credentials can also serve trap destinations.

The read-only ENTITY subset contains emulated chassis/port inventory, stable interface pointers, direct containment, and an actual-row-change timestamp. It does not invent host devices or implement logical tables, inventory SET, or ENTITY notifications.

SET models include original-position errors, current authorization and generation invalidation, exact response-record ownership, expiry/cancellation, commit versus delivery outcomes, and fault-only storage recovery through existing startup. The concrete BER, USM, SQLite, API, and browser boundaries still require implementation tests.

## Run the checks

Use Python, a Java runtime suitable for the selected official TLA+ tools, and `tla2tools.jar`. The JAR is not bundled. Tool versions and integrity evidence are recorded in the current verification report.

```powershell
python .\run_tlc.py --jar C:\tools\tla2tools.jar --timeout 600
```

```sh
python3 ./run_tlc.py --jar /path/to/tla2tools.jar --timeout 600
```

For selected configurations:

```sh
python3 ./run_tlc.py --jar /path/to/tla2tools.jar --models SetResponseEntry StorageRecovery
```

The normal catalog contains 48 configurations. Current verification joins the original and affected runs; it does not claim one combined 48-configuration rerun. The normal SET graph uses the checked equality quotient and its source/certificate guard. The retained unreduced timeout remains incomplete, not a pass. A timeout or parse failure is not a successful negative control.

```sh
python3 ./tests/check_mutations.py --jar /path/to/tla2tools.jar
```

Mutation checks use temporary copies. Current verification also retains the targeted lifetime, entry-association, and storage-recovery counterexamples. Historical logs describe the exact inputs recorded with each run.

## Main owners

| File | Role |
|---|---|
| `Switch.tla` | Core state, VLAN sets, stable ENTITY joins, invariants, and source progress |
| `ReadAccess.tla` | Shared credentials and independent polling/writing/target references |
| `SetTransactions.tla` | Final-candidate SET, original-position errors, authorization, and generations |
| `EntityInventory.tla` | Inventory snapshots and change-clock behavior |
| `SetResponseLifecycle.tla`, `SetResponseEntry.tla` | Original response ownership, stage-aware finalization, and pre-admission association |
| `StorageOutcomes.tla` | Confirmed/uncertain durability, faulted mutation/send gates, and existing-startup recovery |
| `configs/*.cfg` | Finite graph and scripted scenario selections |
| `run_tlc.py` | Bounded runner and current replacement/certificate checks |
| `docs/make_mib_manifest.py` | Canonical object-manifest generator |

Model checking is finite and configuration-specific. Semantic sets/maps do not prove ASN.1 encoding, cryptography, OS durability, unlimited-scale behavior, or NAC-product compatibility. The implementation has not been formally refined from these models. The current verification report identifies the exact assumptions and remaining boundaries.
