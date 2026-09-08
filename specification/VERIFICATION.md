# Verification report

**Revision 2 · checked 2026-09-07**

This historical report retains its original scope. Referenced `logs/` files are
local output and are no longer tracked in the current tree. Inspect the original
files with `git show 2c1c84d6:specification/logs/verification.json` or another
recorded path at that commit. See [current verification](CURRENT_VERIFICATION.md)
for the maintained suite and its results.

**Documentation revision 2.1:** the recorded TLC run covers the revision-2 formal models and configurations. The operator-supplied identity policy, public/development separation, readiness behavior, and SNMP identity gate are application requirements outside those models. The recorded run does not verify them.

## Outcome

The actual TLA+ specifications were parsed/semantically checked with SANY and checked by TLC. All **25 configurations passed** in the final run. Sixteen are scripted scenario configurations; nine are general/focused state-space or liveness configurations, including the separate credential model.

The recorded totals are **9,957,236 generated states** and **659,899 distinct states summed across configurations**. All completed searches had zero states remaining on the queue. These are per-run sums with overlapping abstractions, not the number of unique states of one combined full-scale system. Generated-state counts include repeats and are not a count of distinct behaviors or an exhaustive check of production-sized inputs.

Three mutation checks successfully rejected deliberately broken copies: accepting an obsolete job, flushing the whole port on a VLAN edit, and omitting VLAN 1 admission during fallback. Their logs intentionally contain invariant failures. The model without these mutations passes.

Python reference-checker counts from earlier revisions are not evidence for these TLC results.

## Toolchain and reproducibility

- Tool: `TLC2 Version 2026.08.21.155922 (rev: 9787e65)`.
- Java: OpenJDK 21.0.11 on Linux amd64, as recorded by TLC.
- TLC JAR SHA-256: `eabd140a70f49eb9305a3bd3f3df944eddf87e5a90d329789085f8953a80533a`.
- One worker; seed 20260907; fingerprint index 0; no symmetry reduction.
- The runtime was obtained from the official `tlaplus/vscode-tlaplus` workflow artifact 9492902073, run 32638245725, containing the VS Code extension's `extension/tools/tla2tools.jar`.
- Source workflow: https://github.com/tlaplus/vscode-tlaplus/actions/runs/32638245725
- Exact commands, counts, and log paths are in `logs/result-*.json` and `logs/verification.json`. The latter also records hashes of every checked `.tla`/`.cfg` file.

The runtime binary is not bundled. Use the official tools distribution and the `run_tlc.py` runner to reproduce checks. Tool versions can change state exploration order or diagnostics; compare outcomes and the checked inputs, not just runtime duration. TLC uses state fingerprints; the usual fingerprint-collision caveat is not a proof of a defect or a guarantee of collision-free exhaustive storage.

## Executed configurations

| Configuration | Result | Generated states | Distinct states |
|---|---|---:|---:|
| ActiveLiveness | PASS | 24 | 15 |
| AgingLiveness | PASS | 6 | 5 |
| LiveEditRace | PASS | 81,313 | 10,164 |
| MultiSource | PASS | 12,333 | 1,694 |
| ReadAccess | PASS | 3,435,528 | 95,744 |
| ScenarioAttachmentABA | PASS | 15 | 14 |
| ScenarioDeleteFallback | PASS | 27 | 25 |
| ScenarioDuplicateMacMove | PASS | 14 | 13 |
| ScenarioDuplicateMacVlans | PASS | 16 | 14 |
| ScenarioFaultAndDirect | PASS | 20 | 19 |
| ScenarioInstanceABA | PASS | 14 | 13 |
| ScenarioLiveEdit | PASS | 22 | 20 |
| ScenarioPauseManual | PASS | 15 | 14 |
| ScenarioPortABA | PASS | 15 | 13 |
| ScenarioReboot | PASS | 13 | 12 |
| ScenarioSelectiveAndPvid | PASS | 24 | 22 |
| ScenarioSharedCache | PASS | 27 | 24 |
| ScenarioStaleEdit | PASS | 14 | 13 |
| ScenarioTrapOverflow | PASS | 8 | 6 |
| ScenarioUnknownTag | PASS | 19 | 18 |
| ScenarioVlanABA | PASS | 20 | 17 |
| SharedPort | PASS | 213,281 | 34,450 |
| Smoke | PASS | 6,210,325 | 516,960 |
| TrapDrainLiveness | PASS | 22 | 14 |
| VlanLifecycle | PASS | 4,121 | 596 |

## Bounds and action restrictions

| Configuration | Bounds and scope |
|---|---|
| Smoke | Full Next; 1 port, 1 endpoint, 1 source slot, 1 MAC, VLAN 1; queue capacity 0. |
| VlanLifecycle | VLAN + activity actions; 1 port, 1 endpoint, 1 source, 1 MAC, VLANs 1/10; queue 1. |
| LiveEditRace | Edit/move/reboot/activity actions; 2 ports, 1 endpoint/source, 2 MACs, VLAN 1; queue 1. |
| MultiSource | VLAN + activity actions; 1 port, 1 endpoint, 2 sources, 1 MAC, VLANs 1/10; queue 1. |
| SharedPort | Shared attach/detach/partner/fault + activity; 1 port, 2 endpoints, 1 source each, 1 MAC, VLAN 1; queue 1. |
| ActiveLiveness | Stable active inputs; 1 port/endpoint, 2 source slots, 1 MAC, VLAN 1; fair source service. |
| AgingLiveness | Silent inputs with a prelearned entry; 1 port/endpoint/source/MAC, VLAN 1; fair time. |
| TrapDrainLiveness | Stable links with one queued event; 1 port/endpoint/source/MAC, VLAN 1; fair dispatch. |
| ReadAccess | 2 credentials, 2 opaque secrets, 2 views, 2 snapshots; one pending request; fair handling. |

The full-core `Smoke` fixture exercises **all action families**, but has only VLAN 1 and no queued-notification capacity. This keeps the unrestricted finite graph tractable. Other configurations exercise VLAN lifecycle, nonzero queues, multiple ports, multiple endpoints, and multiple sources, but they do not collectively constitute an unrestricted two-port/multi-VLAN proof.

Every scripted scenario uses two available ports, two endpoint IDs, three source slots per endpoint, three MAC symbols, and VID universe {1,10,20,30}. Most scenarios use only part of that universe. Queue capacity is 8 except the overflow scenario, which uses 1. Scenarios restrict execution to their stated command sequences and checkpoints; they are not arbitrary-interleaving exhaustive runs.

In switch configurations, aging is two abstract ticks, refresh and initial delay are one tick. Token pool size is the number of possible source slots plus two. Current and still-referenced tokens are excluded from reuse. The model does not use modulo generation counters that could silently wrap into a live job's identity.

## Checked properties

The switch safety checks are `TypeOK`, `InventoryOK`, `FdbOK`, `JobsOK`, `MibOK`, and `TrapsOK`. `LearningHasSource` and `StaleJobCannotCommit` constrain transitions. They cover legal references, permanent VLAN 1, selective FDB legality, nonobsolete job identity, semantic table joins, bounded event structure, and valid learning provenance.

The three dedicated liveness fixtures check `StableSourcesProgress`, `SilentEventuallyAgesOut`, and `QuietLinksDrain` under the configured fairness and stable-input assumptions. Manual time need not advance on its own. Infinite configuration churn is not promised to make progress. These restricted fixtures do not establish every liveness property for the complete unconstrained action system.

The sixteen scenarios contain 241 scripted command steps. They exercise live MAC/tag changes, VLAN deletion/fallback, selective removal/PVID changes, invalidation after edit/move/configuration/VLAN/instance reuse, reboot, shared-link caching, forced-down persistence, direct-port behavior, manual clock progression, duplicate-MAC isolation/movement, unknown tags, and queue overflow. Terminal states explicitly stutter, and scenario completion is checked so a disabled scripted step cannot pass vacuously.

`ReadAccess` checks handling-time authorization, allowed view intersection, coherent snapshot identity, and fair completion. Secrets and snapshots are opaque symbols. It is a separate model, not a composition with the switch state machine.

## What this does not establish

This report covers formal models, not the SNMP agent, web UI, database transaction layer, or Docker application. Application test results are recorded separately in the [application validation report](../docs/VALIDATION.md). These TLC checks do not test ASN.1 encoding, actual GETNEXT/GETBULK traversal, TimeFilter alias handling, per-target delivery, port notification suppression, v3 security protocol, cryptography, host source address, counter arithmetic, FDB capacity policy, real scheduler, crash recovery, import transaction, or NAC integration.

The core collapses several application identities into endpoint/port/boot tokens, models one pending job per source slot, and uses countdowns rather than absolute time. Names, metadata, source cloning, independently variable source periods, wire types, and real security time are outside it. FDBs use independent VLAN learning only; one PVID equals one untagged egress VLAN per port. Read/write permissions beyond the read-access abstraction and SNMP SET are not modeled.

There is no theorem proving all cardinalities, no implementation refinement proof, and no proof that the separate switch/access models compose. These limits are deliberate and visible; implementation acceptance tests remain required.

## Development attempts and final evidence

An earlier unrestricted smoke attempt with queue capacity 1 exceeded its runner limit and was not treated as a pass. The final unrestricted fixture uses capacity 0, and focused/scenario fixtures separately test nonzero queues. Intermediate parser/configuration defects were corrected before the final run. Only final per-configuration logs and the explicitly labeled mutation logs are included as evidence.

`logs/sany-final.log` records the standalone final semantic checks. `logs/runner-final.log` records the full final TLC invocation sequence. All formal input hashes in this report were captured after that run, with no intervening changes to the checked modules/configurations.
