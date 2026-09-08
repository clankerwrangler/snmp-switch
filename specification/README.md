# SNMP Switch Emulator: model and technical specification

A vendor-neutral switch-management emulator design with reusable endpoints, BRIDGE-MIB/Q-BRIDGE-MIB views, and standard notifications. No Ethernet forwarding is implemented or required.

This directory contains an executable TLA+ model, TLC configurations, targeted scenarios, and application requirements. For installation and use, see the [application README](../README.md).

Documentation revision **2.1** defines identity configuration and first-run setup. The identity gate is outside the verification scope of the revision-2 `.tla` and `.cfg` files.

## Start here

- [Technical specification](TECHNICAL_SPECIFICATION.md): behavior, data structures, wire protocol, API/UI, persistence, deployment, and acceptance tests.
- [Identity setup and release policy](docs/IDENTITY_SETUP.md): development placeholder, unset public default, operator setup, and release checks.
- [Verification report](VERIFICATION.md): actual TLC results, finite bounds, and exclusions.
- [Core model](Switch.tla): state transitions and semantic MIB projections.
- [Object manifest](docs/mib-coverage.csv): 72 first-release object/index definitions. This is a target manifest, not a full-MIB conformance claim.

## Identity policy

Public defaults leave `identity.sys_object_id` unset. The web UI and simulation remain available, but SNMP listening and notifications stay disabled until the operator supplies a valid full numeric OID and completes normal SNMP setup. No project-owned enterprise-number registration is required to publish the application.

Isolated development explicitly loads `1.3.6.1.4.1.32473.1`. This is a documentation-only placeholder, not an assigned operational identity; the public runtime must not inherit it. Any syntactically valid operator OID is accepted without ownership checks. Changing it changes advertised identity only, not supported MIBs or behavior.

The [setup guide](docs/IDENTITY_SETUP.md) and its cited standards distinguish the deliberate development exception from standards-conforming identification. Public defaults stay null in the source configuration; a development overlay supplies the placeholder only when explicitly selected.

## Endpoint and VLAN behavior

Endpoint definitions are mutable, with multiple MAC/tag sources per instance. They can be edited while attached. Historical learned rows survive edits and age normally.

VLAN membership changes flush only invalidated entries. Deleting a VLAN falls native ports back to VLAN 1, preserves unrelated memberships and learning, and leaves explicit endpoint tags unchanged. VLAN 1 cannot be deleted.

The model also includes runtime endpoint/VLAN lifecycle, direct/shared link modes, persistent forced-down state, source scheduling, pause/manual ticks, reboot invalidation, and late callbacks that survive cancellation. Generation tokens prevent old activity becoming valid after values change and later return to their original values.

The source, interface, VLAN, and FDB views have one state owner. No vendor profile, vendor trap, or vendor community-indexing behavior is included.

## Run the checks

Requirements: Python 3.10 or later, a Java runtime suitable for the selected TLA+ tools, and the official `tla2tools.jar`. The recorded run used OpenJDK 21 and the tool version identified in the verification report. No third-party Python packages are required.

Obtain the tools from the [official TLA+ project](https://github.com/tlaplus/tlaplus). The JAR is not bundled. Pass its actual path:

```powershell
python .\run_tlc.py --jar C:\tools\tla2tools.jar --timeout 600
```

On Linux:

```sh
python3 ./run_tlc.py --jar /path/to/tla2tools.jar --timeout 600
```

Run only selected configurations:

```powershell
python .\run_tlc.py --jar C:\tools\tla2tools.jar --models VlanLifecycle ScenarioDeleteFallback ScenarioAttachmentABA
```

Check the intentional defect variants:

```powershell
python .\tests\check_mutations.py --jar C:\tools\tla2tools.jar
```

Mutation checks operate on temporary copies. Success means the intentionally broken copies were rejected by behavioral checks; a parse failure or timeout does not count as detecting a defect.

The verification report records the revision-2 model checks. Every new checker run records fresh logs and JSON outcomes; after edits, use those new results rather than treating the bundled report as evidence for changed inputs. A timeout is incomplete, never a pass. Increase the timeout or use a focused configuration when needed. `states/` is disposable local TLC scratch. The `run_tlc.py` runner uses one worker and a fixed seed; symmetry reduction is not used for liveness.

## Model organization

| File | Role |
|---|---|
| `Switch.tla` | Core state machine, invariants, source validity, and conditional progress properties. |
| `ReadAccess.tla` | Separate abstraction of configurable credentials and handling-time read authorization. |
| `TestSwitch.tla` | Small fixture initial states and restricted transition families. |
| `Scenarios.tla` | Sixteen scripted traces using actual core actions and explicit checkpoints. |
| `configs/*.cfg` | Twenty-five executed finite TLC configurations. |
| `make_configs.py` | Rebuild the general fixture configurations. |
| `tests/make_scenarios.py` | Rebuild scenario module and configurations. |
| `tests/check_mutations.py` | Three deliberately defective copies and behavioral rejection checks. |
| `run_tlc.py` | Portable TLC runner with per-model outcome logs. |
| `docs/make_mib_manifest.py` | Rebuild the CSV object manifest. |
| `docs/example-endpoint.json` | Illustrative endpoint payload with untagged and tagged sources. |
| `docs/IDENTITY_SETUP.md` | Development/public identity policy and setup behavior. |
| `docs/config/*.yaml` | Proposed identity fragments, not a working application configuration format. |
| `DOCUMENTATION_CHANGES.md` | Revision-2.1 change summary and verification boundaries. |

The generators are development conveniences, not prerequisites for running the checked-in configurations. `ReadAccess.cfg` is maintained directly. The example JSON is a proposed API payload, not a presently executable importer format.

## Formal boundaries

The model uses finite endpoint/source slots for runtime objects, short aging countdowns instead of absolute timestamps, equality generations instead of an unbounded ID allocator, and one semantic notification queue. Some fixtures restrict which action families may occur. These bounds are listed in the verification report.

MIB operators represent semantic sets/maps, not ASN.1 encoders. Index objects are not necessarily readable columns; the object manifest distinguishes them. The current VLAN table's TimeFilter semantics, notification encoding, counters, persistence transactions, import/reset behavior, capacity, and SNMPv3 cryptography require implementation-level tests.

`ReadAccess.tla` is not formally composed with `Switch.tla`. Successful finite model checking does not prove application correctness, cover every possible system size, or establish NAC-product compatibility.

## Initial implementation scope

One switch, Docker-first, one web administrator, multiple read credentials, direct/shared ports, an editable endpoint library, live tables, deterministic source activity and aging, standard notifications, and controlled restart behavior. Public release uses operator-supplied `sysObjectID` configuration rather than requiring a project-owned allocation. Identity setup and release behavior require application-level tests; the model-checking results do not cover them.
