# Current finite model verification

The 58-configuration normal catalog is supported by separate completed checks,
not one combined 58-config run. All passing graphs below finished with zero
queued states; scripted checks include completion assertions. Counts overlap
across configurations. These results concern the [models](CURRENT_MODEL.md), not
application, wire, or operating-system correctness.

## SNMP protocol selection follow-up (2026-10-20)

Before protocol-field, registration, and compatibility edits, `SnmpSecurity`
completed **6,051 generated / 3,459 distinct states**. Existing `GroupOwnership`
(**32/24**) and `GroupQueuedSet` (**378/324**) also passed unchanged. All queues
were empty and temporal checks completed.

The response-size edit was initially applied under an abstract contract that
left BER sizing to implementation tests. It was restored before the concrete
sizing refinement, then reapplied only after the final refinement passed.
That final graph completed **236,739 generated / 120,099 distinct states**, depth
7, with an empty queue and complete temporal checking. A provisional arithmetic
check omitted DES's full block when the plaintext was aligned; the final model
and implementation use the pinned cipher's mandatory 1..8 padding octets.
Two intermediate parse/semantic failures are failures, not passing checks.

The graph checks 72 selected profiles, inactive key/protocol suppression,
opaque matching credentials, unchanged policy, selection persistence, and
response budget arithmetic at 15 scope lengths and adjacent byte budgets.
It does not prove cryptography, full BER encoding, SQLite, or a refinement of
Python. Actual GET/SET/notification, malformed input, redaction, and storage
compatibility checks remain application obligations.

Reproduce from the repository root:

```sh
python specification/run_tlc.py --jar /path/to/tla2tools-1.7.4.jar --models SnmpSecurity GroupOwnership GroupQueuedSet --output specification/logs/snmp-security-1
```

Three task-local source-overlay controls produced TLC invariant counterexamples:
inactive key registration failed `InactiveMaterialAbsent`; fixed SHA-256 digest
sizing and omitted full-block DES padding each failed `BudgetBoundary` (exit 12).
The overlays and results are under `model-runs/snmp-security-controls/` in the
durable scratch evidence root identified next.
These controls are not additions to the maintained mutation catalog.

These are separate completed checks, not a whole-catalog run. The normal catalog
now contains 58 configurations. Local receipts for this checkpoint are
`/workspace/.scratch/snmpv3-backend-evidence/model-runs/snmp-security-before/verification.json`
and `model-runs/snmp-sizing-des-before/verification.json` under the same evidence
root. Exact initial/final inputs, source overlays, logs, and raw test output are
retained there outside the temporary worktree. Local ignored logs are not
required to reproduce the checks.

## Local management access follow-up (2026-10-15)

`ManagementAccess` checks authenticated/current-generation local issuance,
viewer read-only permissions, queued-token execution rechecks, logout/expiry,
stream revocation, independent administrator recovery, and a finite route-relative
API boundary. The initial graph completed before product implementation
(22,361 generated / 3,695 distinct states). The final routing refinement completed
**593,101 generated / 36,950 distinct states**, depth 14, with zero queued states.
The first provisional routing fix preceded that concrete refinement; those lines
were restored, the refinement checked, and the final fix reapplied. The earlier
abstract result is not relabeled as prior proof of concrete path handling.

`ManagementResources` completed before the worker/capacity corrections:
**3,002 generated / 475 distinct states**, depth 10, with zero queued states.
The normal runner reproduced both final counts with unchanged model inputs.
Its finite two-slot/three-worker graph retains worker ownership after request
cancellation; its two-session graph prevents viewer admission from evicting an
administrator. Concrete limits, token replacement, and fault handling remain
application obligations. Neither graph establishes liveness or a Python refinement.

Local source-overlay controls produced actual invariant counterexamples for
omitted execution rechecks (`WritesAuthorized`), raw-path routing classification
(`RoutingBoundary`), request-count-based worker admission (`BoundedWork`), and
FIFO viewer eviction (`AdminRecovery`). Early model construction/parse errors
are retained failures, not successful behavioral controls. These four overlays
are task-local evidence, not entries in the existing reusable mutation catalog.

Reproduce the current two graphs from the repository root:

```sh
python specification/run_tlc.py --jar /path/to/tla2tools-1.7.4.jar --models ManagementAccess ManagementResources --output specification/logs/management-1
```

This is a two-configuration follow-up, not a combined 57-configuration run.
Framework path spelling, real lock/worker ownership, API policy persistence,
redaction, and browser recovery are covered separately in
[implementation validation](../docs/VALIDATION.md#local-management-access).

## Snapshot count follow-up (2026-10-15)

`SnapshotCounts` checks one-pass aggregation over three optional FDB rows and two
ports, including source changes and detached published counts. Before the
implementation change, TLC completed **4,547,502 generated / 158,895 distinct
states**, depth 7, with no error. The normal runner reproduced the result.
Removing the count increment fails `PartialCounts`; this negative control is not
a timeout or parse failure. TLC 2.19 (`tla2tools-1.7.4.jar`) and Java 21 were used.

```sh
python specification/run_tlc.py --jar /path/to/tla2tools-1.7.4.jar --models SnapshotCounts
```

Run from the repository root. This finite aggregation check does not replace
API serialization, redaction, or runtime tests. Application measurements and
checks are in [implementation validation](../docs/VALIDATION.md#snapshot-read-cost).

## Port inventory follow-up (2026-09-16)

Existing core, ENTITY, storage, and SET owners now cover live/issued port identity,
add/delete, survivor preservation, zero ports, immutable reads, affected obsolete
jobs, and queued SET rejection after deletion and fresh allocation. Storage adds
add/remove to its existing commit/recovery relation, preserving unrelated saved
and running policy. No catalog entry or independent inventory subsystem was added.

| Completed check | Generated / distinct states |
| --- | ---: |
| `Smoke` | 8,187,877 / 750,240 |
| `EntityInventory`, `EntitySparse` (each) | 108,033 / 3,072 |
| `EntityReadConsistency` | 687,457 / 14,400 |
| `EntityLifecycle` | 35 / 31 |
| `StorageRecovery` (200 branches) | 5,000 / 4,800 |
| `StartupLifecycle` | 34 / 28 |
| `SetBitmapPorts` | 21 / 20 |
| `SetTokenEquivalence` | 1,026 / 513 |
| `SetTransactionsEquality` | 6,708,324 / 526,688 |

All queues completed; the equality graph finished temporal checking in 355.513 s.
Its earlier 180-second timeout remains incomplete. An initial storage parse error
and mistaken config selector were corrected before the model-first checkpoint;
neither counts as a pass. Inputs remained unchanged within the completed checks.
After the core/ENTITY runs, the sole core edit names their unchanged initial set
`InitialLivePorts == Ports`; only the later bitmap scenario overrides it. Storage
checks use their independent module; SET checks and controls use final inputs.
Four existing negative controls produced behavioral counterexamples: obsolete-job
acceptance, wrong ENTITY alias, removed-hardware resurrection, and storage-fault
gate removal. This is not a whole-catalog run or a composed/refinement proof.
Independent numeric allocator bounds/migration, concrete RADIUS cleanup, HTTP,
BER, and form lifetimes remain [application obligations](../docs/VALIDATION.md#port-inventory).

Reproduce from `specification/` with the existing tools:

```sh
python3 run_tlc.py --jar /path/to/tla2tools.jar --models Smoke EntityInventory EntitySparse EntityReadConsistency EntityLifecycle StorageRecovery StartupLifecycle SetBitmapPorts SetTokenEquivalence SetTransactionsEquality --timeout 600 --output logs/port-inventory
python3 tests/check_mutations.py --jar /path/to/tla2tools.jar --mutations accept_obsolete_job entity_alias_uses_bridge_port startup_resurrects_hardware storage_fault_gate_removed --output logs/port-inventory-controls
```

## Integrated ownership follow-up (2026-09-16)

Before product edits, the existing checks passed: `RadiusDynamicAuthorization`
(8,106/5,826 generated/distinct states), `AccessLifecycle` (72/70),
`GroupOwnership` (32/24), `GroupQueuedSet` (378/324), and `StorageRecovery`
(3,000/2,880). All queues completed; inputs remained unchanged during the batch.
The model edits clarify correspondence only: unused CoA planner fields have no
abstract effect; family-owned checks preserve valid-state transitions; local
form cancellation stutters before a revision-checked command is dispatched.
No transition, invariant, state variable, or catalog entry was added or removed.

Concrete idle expiry, normalized identity uniqueness, bounds, and DOM form/file
lifetimes remain application-test obligations, not new TLC proofs. This was not
a whole-catalog or negative-control rerun. See [implementation validation](../docs/VALIDATION.md#integrated-ownership)
for those separate results. Reproduce this checkpoint from `specification/`:

```sh
python3 run_tlc.py --jar /path/to/tla2tools.jar --models RadiusDynamicAuthorization AccessLifecycle GroupOwnership GroupQueuedSet StorageRecovery --output logs/ownership
```

## Operation-scoped validation follow-up (2026-09-15)

The scoped SET legality predicate retains the valid-prestate equivalence invariant.
Six focused configurations passed before product changes: `SetAtomicMixed` (29/28),
`SetVlanFallback` (23/22), `SetBitmapPorts` (15/14), `SetRowStatus` (47/46),
`SetAbsentDestroy` (10/9), and the extended `AccessLifecycle` (72/70).
Numbers are generated/distinct states; all queues and temporal checks completed.

The integrated rerun then passed `SetTransactionsEquality` (6,708,324/526,688),
`ReadAccess` (3,435,528/95,744), `WriteAccess` (87,553/3,420),
`SharedAccessRelationships` (1,677,391/36,465), `SetIndependentViews` (26/25),
and `SetAuthorization` (58/57). The SET graph retains its previous reachable-state
counts and complete temporal check with the new equivalence invariant. Model
inputs remained unchanged during both batches. This is not a new whole-catalog
run or a Python refinement proof.

Five selected behavioral controls produced actual counterexamples: omitted
scoped port relationships, disabled target references ignored on deletion,
capability auditing on a resource projection, unauthorized SET, and failed-SET
prefix publication. The three new controls belong to the maintained twenty-control
catalog; the other fifteen were not rerun for this follow-up. Opaque capability
values establish observation ownership only, not executable-integrity correctness.
See [implementation validation](../docs/VALIDATION.md#operation-scoped-validation)
for typed-input, cryptographic, alias, persistence, and API evidence.

Reproduce the affected checks with the existing runner and tools below:

```sh
python3 run_tlc.py --jar /path/to/tla2tools.jar --models SetAtomicMixed SetVlanFallback SetBitmapPorts SetRowStatus SetAbsentDestroy AccessLifecycle --output logs/validation-focused
python3 run_tlc.py --jar /path/to/tla2tools.jar --models SetTransactionsEquality ReadAccess WriteAccess SharedAccessRelationships SetIndependentViews SetAuthorization --output logs/validation-integrated
python3 tests/check_mutations.py --jar /path/to/tla2tools.jar --mutations skip_affected_port_relations ignore_disabled_target_reference audit_resource_projection allow_unauthorized_set publish_failed_set_prefix --output logs/validation-controls
```

## Earlier recorded outcomes

| Check | Actual result | Generated / distinct states |
| --- | --- | ---: |
| Core/access/ENTITY/SET matrix, including the original 25 configs | 40 PASS | 12,271,969 / 710,685 |
| SET graph under the certified token view | PASS; full temporal check; 349.003 s | 6,708,324 / 526,688 |
| Token-allocation certificate | PASS | 1,026 / 513 |
| VIEW/fair-handle compatibility fixture | PASS; full temporal check | 524 / 11 |
| Response lifecycle graph | PASS; full temporal check | 210,495 / 23,175 |
| Response reuse and transaction-integration traces | PASS | 109 / 90; 115 / 101 |
| EventHistory: 15 prescribed cases | PASS; full temporal check; 2.800 s | 161 / 144 |
| Entry-association trace | PASS; all 240 branches complete | 2,640 / 2,400 |
| Running/startup storage graph | PASS; full temporal check; 113.542 s | 2,070,496 / 172,689 |
| Storage recovery: 120 branches | PASS; full temporal check; 2.198 s | 3,000 / 2,880 |
| Startup identity and five legacy-seeding outcomes | PASS; full temporal check; 1.032 s | 34 / 28 |
| Group normalized ownership: eight cases | PASS; full temporal check; 1.952 s | 32 / 24 |
| Group queued SET/current boundary: 54 cases | PASS; full temporal check; 2.346 s | 378 / 324 |
| RADIUS authorization | PASS; finite safety check; 1.275 s | 16,753 / 1,356 |
| RADIUS dynamic requests | PASS; finite safety check; 1.242 s | 8,106 / 5,826 |
| Unreduced SET graph | **INCOMPLETE**; timeout at 1,800.158 s | 32,429,244 / 4,501,741; 1,690,258 still queued |

The response checks were rechecked with insertion ownership and retained their
counts. The group checks retain normalized migration isolation, atomic saves,
all 23 shared-policy stale/stable categories for both credentials, and four
current-boundary denials for each. Detailed schema/conversion/form and security
input cross-products were intentionally retired. Existing engine, API, browser,
and wire tests cover those implementation details; they are not an equivalent
formal proof. Earlier results remain in Git with their original scope.

The storage graph distinguishes running policy from durable lab/startup and
retains both actual outcomes of an unknown commit. Recovery and startup traces
were checked separately; later changes only remove duplicate witnesses in the
unused general-graph wrappers, leaving their action/property slices unchanged.
The general graph preserves the same successors and weak fairness. Earlier
storage timeouts remain incomplete, including one with an empty BFS queue but
unfinished final temporal checking; they are not the completed result above.

The EventHistory check completed all three temporal branches. Its separate
record-batch properties extend unchanged SET/core/response actions and the pure
storage outcome relation; prior checks are not relabeled as event-history proof.
Earlier response receipts retain their unchanged action/config slices rather
than claiming a rerun at the extended module hash. The initial fixture precedence
error failed before any initial state; its original source and failure remain
local alongside the completed corrected check.

SANY, generator byte-for-byte round-trip, and five small runner-routing/guard
cases passed at their recorded checkpoints. These are supporting checks, not
additional application-model graphs.

Behavioral negative controls detected stale-job acceptance, excessive FDB
flushing, broken VLAN fallback, unauthorized/partial SET, wrong ENTITY pointers,
captured-token reuse, response leaks/foreign cleanup, stale durable overwrite,
migration sharing, incomplete shared-member revocation, and failed conversion
prefix publication. Actual counterexamples also drove response diagnostics,
entry-association, error-index, no-op deletion, and selected-target corrections.
The twenty reusable controls in `tests/check_mutations.py` run against current
sources. The three grouped controls reach actual second-member stale success,
cross-user policy modification, and rejected-save prefix publication. Other historical control definitions and exact inputs are in Git.
The three RADIUS controls detect a stale reply installing a grant, a duplicate
changing cached ACK to NAK, and partial CoA effects under a NAK. The duplicate
counterexample does not demonstrate replacement-session revocation. Both RADIUS
checks are separate safety graphs, without fairness or a composition proof;
causal scheduling and persistent replay remain application boundaries.
The storage controls detect logical autosave, mixed-lab autosave, removed-hardware
resurrection, and overwrite after an unconfirmed Save. The last counterexample
uses a local focused config checking `UnconfirmedDurableSurvives` so it can reach
the overwrite after the earlier forbidden edit; the maintained fault-gate control
uses the full recovery config. Correct configs retain every assertion.
The event control produced a TLC13 `EventFailedPublication` counterexample in
2.597 s: `commitFailed` retained the entire core state and empty durable history,
but published false operation/configuration/link records for an unchanged port.
It uses the same full EventHistory config, not a weakened control-only assertion.
Parsing failures, construction errors, interrupted searches, and timeouts remain
failures or incomplete results; they do not count as detected behavioral defects.

## Why the SET view preserves the checked behavior

`SetTransactionsEquality.cfg` retains `TransactionSpec`, all 31 requests,
constants, assertions, and weak fairness. `CanonicalSetView` changes only the
names of independent registration and activation tokens. Each pending capture
is represented as current or stale. Switch/access state, response, gate, full
request metadata, core boot/job tokens, secrets, operations, budgets, and
persistence choices stay exact.

`SetTokenEquivalence` checks all 513 current/captured assignments and 4,104
changed-writer-subset/restart cases with the actual `Fresh`, `UsedRegistration`,
and `UsedActivation` operators. Three tokens suffice because each owner excludes
at most its current token and one pending capture. It checks update, capture,
completion, and projection idempotence. Deliberate captured-token reuse violates
`TransitionCongruence`.

The dependency argument covers future steps in both directions, not just the
initial reply. Submit captures current comparisons; genuine access/lifecycle
changes make affected captures stale; no-ops preserve them. Matching non-token
inputs determine the same affected writers and handling branch. Candidate
validation and switch mutation do not inspect normalized token names. Fresh
choices remain available even though numeric `CHOOSE` need not commute with
renaming. Rejection preserves the actual complete state. The same rules cover
shared-view revoke/restore and reboot helpers checked by focused scenarios.

Handle is enabled exactly when a PDU is pending and always clears it, so it
cannot become stuttering under the view. Handle enabledness and occurrence,
`WF_allvars(HandleSet)`, and request completion are preserved. The compatibility
fixture checks TLC's VIEW/liveness combination separately from the completed
transaction graph. Changes to token dependencies, rejection frames, or fairness
require this argument and its affected checks to be revisited.

## Tools and running checks

Recorded current runs used Temurin JRE 21.0.12.1+1 and official
[TLA+ tools v1.7.4](https://github.com/tlaplus/tlaplus/releases/tag/v1.7.4)
(TLC 2.19, August 8, 2024). Tools are not bundled. The JAR's recorded local SHA256
is `936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88`;
its publisher supplied SHA-1 `bee4a54f3ee3d4afc347c3240ec2d9e93b075104`,
not that SHA256 or a signature. The Linux x64 JRE archive's publisher SHA256 is
`2413149700df0f7d440500a84a8f764c535f21e5a5e87d38328b64eec2c5b500`.

From `specification/`, use a fresh local output name:

```sh
python3 run_tlc.py --java /path/to/java --jar /path/to/tla2tools.jar --output logs/run-1
python3 tests/check_mutations.py --java /path/to/java --jar /path/to/tla2tools.jar --output logs/mutations-1
```

On Windows, use `python` and the paths to `java.exe` and the JAR. To check only
affected fixtures, select their config stems, for example:

```sh
python3 run_tlc.py --java /path/to/java --jar /path/to/tla2tools.jar --models RadiusAuthorization RadiusDynamicAuthorization --timeout 120 --batch-timeout 300 --heap 1g --max-state-mib 2048 --min-free-mib 20480 --output logs/radius-1
```

The runner uses one worker, seed 20260907, fingerprint index 0, and no symmetry.
Defaults are 600 seconds per config, 3,600 seconds per batch, and a 2 GiB heap.
The recorded quotient run also used an 8 GiB state cap and a 20 GiB free-space
reserve. Resource limits and timeouts are incomplete outcomes with nonzero exit;
existing output is not overwritten. Both token replacement configs are required
for normal discovery. Local receipts record actual input/tool hashes, commands,
counts, log hashes, and outcomes.

The unreduced diagnostic remains explicitly selectable; its earlier timeout is
not superseded by a claim that it passed:

```sh
python3 run_tlc.py --java /path/to/java --jar /path/to/tla2tools.jar --models SetTransactions --timeout 1800 --batch-timeout 1800 --output logs/unreduced-1
```

Both checker entry points regenerate four scenario modules and 32 configs with
`make_configs.py` and the three existing `tests/make_*scenarios.py` generators.
These outputs are ignored; edit their generators, not the generated files.
Before invoking SANY or TLC directly, prepare the inputs without running Java:

```sh
python3 run_tlc.py --prepare-only
```

## Local output and Git history

`logs/` is ignored local output, not an input to current checks. A fresh checkout
needs only the tracked models/configs/generators plus Java and the TLA+ JAR;
the runners prepare generated inputs automatically.
Use `--mutations NAME ...` to select affected negative controls; otherwise all
twenty run. Parsing errors and timeouts are not behavioral detection.
Do not add generated logs, receipts, states, or historical source overlays to
commits. Git retains the previously committed evidence and detailed report;
there is no separate archive or version index. For an exact historical result,
inspect the report and its referenced receipt at the same commit:

```sh
git show 2c1c84d6:specification/CURRENT_VERIFICATION.md
git show 2c1c84d6:specification/logs/current/2026-09-08/runs/set-token-equality/verification.json
```

For historical counterexample replay, use a detached worktree at that commit
and follow its report's source-overlay instructions. Keep the recorded inputs
and FAIL/PASS/INCOMPLETE distinction; do not substitute current model bytes for
an old receipt. Current regression scenarios and reusable mutation controls do
not depend on those historical overlays. See [application validation](../docs/VALIDATION.md)
for real USM, wire, storage, API, and browser checks and their limits.
