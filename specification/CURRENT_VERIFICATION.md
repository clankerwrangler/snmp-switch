# Current finite model verification

## Results and scope

The normal suite now has 48 configurations. Evidence consists of the earlier
42-config checkpoint, the three-config response-lifecycle refinement, the
entry-association trace with three affected response checks, and two independent
storage checks. The original checkpoint contains 40 core/access/ENTITY/SET graphs
and traces, one token allocator certificate, and the same 31-request SET graph
under a certified token-equality view. No combined 48-config rerun is claimed.
Every passing graph reports zero queued states. These finite results are not an
application refinement proof or a substitute for wire and persistence tests.

The checks extend the application model at commit
`d75c960ccd66d99413e9287aae557ae32b47440b`. New ENTITY and SET contracts were
modeled before application implementation. `CURRENT_MODEL.md` describes the
state/action correspondence and the remaining implementation boundaries.

The evidence root for paths in this report is `logs/current/2026-09-08/`.

| Check | Actual result | Receipt |
| --- | --- | --- |
| Core/access/ENTITY/SET matrix, including the original 25 configs | 40 PASS; 12,271,969 generated, 710,685 distinct | `runs/current-matrix/verification.json` |
| SET transaction graph under the certified view | PASS in 349.003 s; 6,708,324 generated, 526,688 distinct; depth 13; complete temporal check | `runs/set-token-equality/verification.json` |
| Finite token certificate | PASS; 1,026 generated, 513 distinct; all affected-writer subsets and activation-change flags | `runs/token-certificate-final/verification.json` |
| Captured-token reuse mutation | DETECTED; `TransitionCongruence` violation, TLC exit 12 | `runs/token-certificate-mutation-final/verification.json` |
| VIEW and fair-handle compatibility fixture | PASS; 524 generated, 11 distinct; complete temporal check | `runs/token-view-compatibility-final/verification.json` |
| Original three and added three behavioral mutation controls | All six DETECTED | `runs/current-mutations/verification.json` |
| Scenario generator round-trip | PASS; generated formal bytes unchanged | `generator-final-verification.json` |
| SANY | Nine current modules passed, followed by the new token module | `sany-final-current.log`, `sany-token-final-verification.json` |
| Unreduced SET graph | INCOMPLETE: timeout after 1,800.158 s | `runs/set-long-current/verification.json` |
| Normal/diagnostic runner routing and missing-replacement guards | Five tiny-fixture cases PASS in 4.681 s | `runs/runner-normal-routing/routing-verification.json` |

The 41 behavior graphs/traces total 18,980,293 generated and 1,237,373 distinct
states. These are sums across overlapping checks, not one combined state space.
The certificate and compatibility fixture are additional checks. TLC uses
64-bit fingerprints; the raw logs retain TLC's reported collision estimates.

The 40 checks, six mutation controls, and generator run predate the independent
token and response additions. Every model/config dependency of those original
checks still has the same hash. The added token
module has its own semantic check, finite certificate, mutation, compatibility,
and complete graph evidence. Later runner-selection and documentation changes
do not change those formal inputs. Their tiny routing fixtures verify the new
runner path without claiming another application-model run.

## Token-equality certificate

`SetTransactionsEquality.cfg` uses the unchanged `TransactionSpec`, constants,
invariants, action properties, and weak fairness. It adds `VIEW
CanonicalSetView`; it does not reduce the 31 request forms.

The view retains exact switch state, access state, result, gate, and request
metadata. Only the numeric names of the two independent lifecycle token owners
are normalized. Current registrations and activation map to one token. A
captured token maps to that token exactly when it equals its current owner;
otherwise it maps to a distinct stale token. Core job generations, boot state,
boot capture, secrets, view contents, operations, budgets, and persistence choices
remain unchanged.

Two concrete states are related when their complete canonical views agree.
The finite certificate checks all current and captured token combinations:

- No pending PDU: `3^2 * 3 = 27` assignments.
- A pending PDU: `3^2 * 3 * 2 * 3 * 3 = 486` assignments.
- Total: 513 initial assignments and 4,104 affected-subset/restart cases.

`ChangedRegistrations` and `ChangedActivation` call the inherited actual
`Fresh`, `UsedRegistration`, and `UsedActivation` operators. Each owner excludes
at most its current token and one pending capture, leaving a fresh member of
its three-token domain. The certificate checks current-to-stale and
already-stale changes, capture, completion, and projection idempotence.

The mutation removes the pending capture from `UsedRegistration`. TLC finds
current readerA token 0 with captured token 1; a new generation can reuse 1 and
make stale work current. `TransitionCongruence` rejects that update. The recorded
FAIL is the intended behavioral detection, not a parsing error or a timeout.

## Future transitions and liveness

The relation concerns future pending transitions, not only immediate responses.
Matching non-token action parameters have matching enabledness and successors:

- `SubmitSet` sees the same absence of a pending PDU, preserves the same complete
  request, resets the same result, and captures two current token comparisons.
- `SetWriting`/`SetWriteView` and `Rotate` make the same access changes. Their
  affected writer set depends on non-token data. Genuine changes make that
  writer's capture stale; same-value and unrelated changes preserve it.
- `SetGate` makes the same gate change and invalidates the captured activation.
  Repeated change/restore cycles cannot make an old capture current.
- `HandleSet` sees the same gate, boot, secret, lifecycle comparisons, current
  grants, response budget, and exact varbind sequence. It selects the same
  rejection or complete-candidate branch. `Candidate`, `AffectedEndpoints`,
  `AffectedPorts`, and `Mutate` do not read the normalized token names. The
  resulting switch/access state and response agree, and completion clears the
  same pending PDU.

These actions form `TransactionNext`. The local certificate and token dependency
review establish matching steps in both directions. Concrete fresh choices
always exist. Numeric `CHOOSE` results need not commute with a permutation;
their checked equality observations are sufficient for this relation.

The same token-owner rules cover `Grant`, `ChangeView`, and `RemoveCredential`:
the exact non-token configuration determines affected consumers, including both
writers of a shared view. `SetReboot` invokes the unchanged core reboot and
invalidates captured activation. Thus rotation, shared-view removal/restoration,
and repeated reboot preserve stale rejection. Separate scenarios check those
additional helpers. The two lifecycle owners never compare their tokens with
one another or with a core job token.

The six core invariants and two core transition properties see exact switch
states and transitions. Successful atomicity sees the same candidate, FDB, and
access state; successful authorization sees the same credential/view decisions
and token comparisons. Every actual rejection preserves both concrete token
owners and the remaining state. This unchanged-state argument applies to the
actual reject branches, not arbitrary transitions that modify hidden tokens.
Changes to those branches or token dependencies require the certificate and
relation argument to be checked again.

`HandleSet` is enabled exactly when a PDU exists, and each handle clears it.
A handle cannot disappear as a stuttering step under the view. Related states
therefore agree on handle enabledness and occurrence, preserving
`WF_allvars(HandleSet)` and `SetRequestsComplete`. No fairness condition or
assertion is removed. Independent dependency and final-module reviews found no
concrete mismatch in this bounded relation.

The compatibility fixture uses the actual handle action and its weak fairness.
It explicitly stutters only after completion; that branch is disabled while a
PDU is pending and cannot conceal a stuck request. Its complete temporal check
establishes tool compatibility, not the arbitrary transaction result. The latter
has its own completed 526,688-state graph.

## Response-lifecycle refinement

The original response refinement kept every earlier checked TLA/config/generator
byte unchanged and did not add resource caches to the arbitrary SET graph.
Its final three-config batch completed in 7.939 seconds, using one worker,
1 GiB heap, a 120-second per-config bound, and a 360-second batch bound.

| New check | Actual result | Receipt |
| --- | --- | --- |
| Resource lifecycle graph | PASS; 210,495 generated, 23,175 distinct; full temporal check | `runs/response-final/verification.json` |
| Nineteen identity/reuse/diagnostic cases | PASS; 109 generated, 90 distinct; completed traces | `runs/response-final/verification.json` |
| Fourteen actual transaction-boundary cases | PASS; 115 generated, 101 distinct; completed traces and full `s` preservation | `runs/response-final/verification.json` |
| Expiry omits security cleanup | DETECTED; `TerminalOwnership` violation, TLC exit 12 | `runs/response-mutation-expiry_leaves_security/verification.json` |
| Cleanup uses only the numeric reference | DETECTED; `CleanupPreservesForeign` action-property violation, TLC exit 13 | `runs/response-mutation-cleanup_by_numeric_ref/verification.json` |
| Eight queued ownership-loss paths before correction | FAIL as expected; all eight observations lack the required diagnostic, TLC exit 12 | `runs/response-eight-losses-repro/verification.json` |
| The same eight paths after correction | PASS; 26 generated, 25 distinct; full temporal check | `runs/response-eight-losses-fixed/verification.json` |

The eight paths are missing or foreign security state followed by each of
cancel, expiry, revoke, and close. The old finalizer classified them as ordinary
cancellation. The corrected finalizer reports an ownership failure whenever the
queued ticket still owns MP state but does not own its associated security state,
regardless of the terminal trigger. It preserves a replacement security record
and performs no send or configuration effect. `QueuedOwnershipLossReported`
checks the action relation; the nineteen-case trace exercises the alternate
paths rather than reaching errors only through `RejectNotReady`.

The resource graph covers normal, error, tooBig, no-op, and rolled-back commit
failure responses. It distinguishes failure before MP take, after MP take but
before security consumption, and after consumption during encoding or transport.
There is one terminal consume/discard per ticket, no duplicate release, no late
send from a terminal ticket, and no cleanup of a same-number foreign replacement.
`ProgressAvailable` checks enabled progress for every nonterminal phase;
`TicketCompletes` is checked under explicit weak fairness. Fairness does not
assume that a disabled or stuck claimed ticket completes.

The claim relation uses the existing `HandleSet` and compares `didCommit` with
the actual `Configuration(s') # Configuration(s)`. The immutable scenario
observation then holds the full resulting `s` through each materialization and
finalization step. Successful commit followed by response failure retains the
committed admin/generation/event state and the original transaction result;
it is not rewritten as a rolled-back `commitFailed`. Protocol and commit-failure
responses can consume a ready ticket without committing configuration.

The concrete record/owner identities are opaque. `Close` represents retirement
of the modeled admitted ticket; the later B entry is a foreign reuse witness,
not another admitted transaction product. Actual draining of all admitted
engine tickets, the existing expiry timer, library cache layout, no-await/lock
boundaries, and response delivery remain implementation tests. A successful
synchronous send is not a UDP delivery acknowledgment.

The diagnostic witness module/config and pre-correction lifecycle source are in
`response-fixtures/`. They reproduce the correction without changing the normal
config catalog. Exact per-run input and log hashes distinguish failing,
corrected, and deliberately mutated sources. Construction-only initial failures
and intermediate working copies remain separate from these completed claims.

## Entry-association refinement

The earlier resource model starts with a captured ticket. It does not establish
that a later numeric lookup recovers an unadmitted entry's original security
record. The entry refinement adds insertion-time ownership and reuses the
existing lifecycle through an explicit transfer projection. Only
`SetResponseLifecycle.tla` changes among prior sources: its cleanup expression
is extracted as `DiscardState`, and entry operators use that same expression.
The existing scenarios, configurations, assertions, and action families remain.

| Current check | Actual result | Receipt |
| --- | --- | --- |
| Affected resource graph | PASS; 210,495 generated, 23,175 distinct; full temporal check | `runs/entry-initial/result-SetResponseLifecycle.json` |
| Existing nineteen reuse cases | PASS; 109 generated, 90 distinct; completed traces | `runs/entry-initial/result-SetResponseReuse.json` |
| Existing fourteen transaction-boundary cases | PASS; 115 generated, 101 distinct; complete temporal check | `runs/entry-initial/result-SetResponseIntegration.json` |
| New 240-branch entry trace | PASS; 2,640 generated, 2,400 distinct; complete temporal check | `runs/entry-final/verification.json` |
| Late-capture cleanup mutation | DETECTED; `EntryForeignSafe` action violation, TLC exit 13 | `runs/entry-mutation-late-capture/verification.json` |

`entry-refinement-verification.json` joins exact loaded-module/config hashes,
commands, log hashes, process identities, and outcomes. All four completed
checks have empty queues. The three existing checks retain their prior counts.
They do not import `SetResponseEntry.tla`, whose later parsing correction is the
only input difference between that initial batch and the final entry check.
Their checked dependencies match the current source exactly.

The initial overall batch remains FAIL because the new entry fixture had a
square-bracket membership parse ambiguity. `runs/entry-fixed/` preserves the
unsuccessful first syntax correction. Parenthesizing the antecedent fixes the
fixture without changing its assertion or intended behavior. The corrected
trace passes in `runs/entry-ready/` and again in `runs/entry-final/` after the
causal mutation check. The initial three passing results are not a claim that
the entire initial batch passed.

The mutation replaces the cleanup view's stored association with a nonmissing
live lookup. Its actual counterexample inserts A with witness SecA, loses SecA,
allocates SecB under the same integer, and then closes the unadmitted entry.
Cleanup deletes B once and omits the required diagnostic. The unchanged entry
configuration detects this action failure; removing the mutation restores the
passing result. `entry-fixtures/` contains the two construction-failure fixture
versions and the exact mutated lifecycle source. `entry-mutation-definition.json`
records the source substitution and hashes.

Insertion and security loss/reuse preserve the original witness. A valid delayed
admission preserves both observed cache entries and transfers ownership without
a mirror; subsequent steps invoke the existing lifecycle. Expiry/close with a
valid witness use the same cleanup expression. Missing, foreign-lifetime, or
foreign-security-owner witnesses have no valid admitted projection: cleanup
reports failure, removes the exact MP entry, and preserves unknown security.
A stored missing identity cannot later become a grant to B. Completion, foreign
and outgoing preservation, readiness before effects, and no-await/commit checks
are nonvacuous on the finite trace. `CURRENT_MODEL.md` describes this relation.

The runs use one worker, 1 GiB heap, 120-second per-config bounds, an 8 GiB state
cap, and a 20 GiB free-space reserve. Total actual run time including the two
construction failures, mutation, and reversal confirmation is 13.399 seconds,
within the 600-second task bound; processes are reaped. No arbitrary SET/read/core/
token graph is rerun. Original receipts stay unchanged.

Actual insertion hooks, opaque nonexpanding representation, report/discovery and
named-key serializer compatibility, BER, cache layout, and timer/locking behavior
remain runtime checks. Insertion of a stock v3 report is not application
admission. Pre-admission report serialization failures after stock MP pop remain
outside this entry/admitted-response claim.

## Storage outcome and recovery refinement

This independent refinement leaves every earlier model, configuration, and
assertion unchanged. It separates published, actual durable, and uncommitted
transaction values instead of treating an unconfirmed outcome as rollback.
The same unknown health/drop result covers actual old or candidate durable
bytes. Writes remain blocked in both cases until successful close and validated
new-incarnation startup, including when publication equals the actual durable value.

| Check | Actual result | Receipt |
| --- | --- | --- |
| Final storage graph | PASS; 1,105,000 generated, 25,313 distinct; full temporal check | `runs/storage-final/verification.json` |
| Forty recovery branches | PASS; 960 generated, 920 distinct; all 22-step traces complete | `runs/storage-final/verification.json` |
| Continued writes after an unconfirmed outcome | DETECTED; old-durable branch violates `RecoveryAssertions`, TLC exit 12 | `runs/storage-mutation-continue-after-unknown/verification.json` |
| Stale publication overwrites committed data | DETECTED; committed-candidate branch violates `RecoveryAssertions`, TLC exit 12 | `runs/storage-mutation-stale-overwrite/verification.json` |

`storage-refinement-verification.json` joins exact source/log hashes, commands,
process identities, and outcomes. `StorageOutcomes.tla` SHA256 is
`1d149f16d4aa55c5b1ea2bd3bb47502cdda76ec525a80747456e6cf1f7d0023a`.
The final graph and trace have empty queues. The forty initial trace branches
retain the earlier thirty-two and add eight old-durable unknown combinations
across four work kinds and two handling stages. Both physical unknown outcomes
use the same health gate; a diagnostic read cannot establish confirmed health.

The checked paths preserve confirmed-rollback capability, block later API/SET/
background/send effects after uncertainty, and distinguish an open failed
rollback from a closed unconfirmed commit. Failed close and unavailable/invalid
load cannot heal the gate or install defaults. Successful restart loads actual
durable state, resets an abstract volatile marker, and excludes queued captured
incarnations. The trace retains old work across two restarts, checks its drop,
and completes new work, writes, and sends afterward.

The arbitrary graph has no retained read-snapshot product. The focused trace
actually exercises labeled confirmed reads and separate diagnostic observations.
Its assertions compare the first outcome, actual durable value, and every
failed-close/load checkpoint. Graph recovery liveness explicitly assumes an
external successful restart and available valid storage. Neither fairness nor
trace completion describes an automatic application retry or repair mechanism.

The broad mutation removes the commitUnknown health restriction. Its first
counterexample chooses the physically old outcome and demonstrates prohibited
continued mutation. The causal control activates that bypass only for the
committed-but-unconfirmed physical case, retaining all forty inputs and every
configuration/assertion. Its trace commits primary=TRUE without publishing,
reads both observations without recovery, and then writes secondary=TRUE from
the old publication, resetting durable primary to FALSE. This is actual modeled
loss of committed data, not a parsing/type failure or a reduced positive check.
The two source substitutions and hashes are in
`storage-mutation-definition.json` and `storage-causal-mutation-definition.json`.

Construction failures in `runs/storage-initial/` and `runs/storage-fixed/`
retain incompletely framed Handle and Open successors. Explicit parentheses
attach their written shared frames to every branch. `runs/storage-ready/`
passes the superseded candidate-only unknown domain (500,648/20,849 and 768/736);
it does not supply final old-or-candidate coverage. `storage-fixtures/` retains
those three source versions and both deliberate mutants. All raw failures and
superseded results keep their original input hashes and statuses.

Total actual model time across construction, superseded-domain, final, and
mutation runs is 35.046 seconds. Each configuration has a 120-second bound;
execution stays within the 360-second task budget with one worker, 1 GiB heap,
an 8 GiB state cap, a 20 GiB free-space reserve, and reaped processes. No earlier
graph is rerun. Actual SQLite and OS failure semantics, complete storage/Runtime
footprints, every mutator/send entry point, read labeling, validated process
startup, and subsequent error rendering remain application verification
boundaries. The earlier confirmed-rollback SET abstraction and response-ticket
model retain their original scopes.

## Failure provenance

The unreduced token-name graph remains available as an explicit diagnostic.
Its 1,800-second run last reported 32,429,244 generated, 4,501,741 distinct,
and 1,690,258 queued states at depth 10. It did not finish, so its receipt stays
FAIL/TIMEOUT. This is a model-checking timeout, not an application execution
failure. The quotient pass does not rewrite it.

The earlier 600.113-second timeout in `runs/final/` used its recorded older
input hashes. `runs/integrated-first/` records an intentional interruption of an
older graph. The selected raw logs, result files, and original batch summaries
are retained as provenance. Repeated passing logs from those older batches are
not included in this current evidence set and do not supply current claims.

`runs/set-reboot-aba-repro/`, `runs/review-counterexamples/`, and
`runs/review-fixed/` retain concrete failing and corrected traces for stale reboot
captures, error-index participation, absent-destroy effects, and response-budget
ordering. Their input hashes identify the relevant model version. Historical
revision-2 reports and raw evidence outside this current subtree remain unchanged.

## Reproduction and tool identity

Use the normal commands in `CURRENT_MODEL.md`. The runner selects the 48 normal
configurations by default, requires both token replacement configs, and keeps
explicit diagnostic selection available. Its defaults are 600 seconds per
configuration and 3,600 seconds per batch. Missing replacements fail before
creating output or starting TLC. The earlier routing receipt checks default selection,
the default bounds, both missing-config cases, and explicit diagnostic selection
even when a replacement is missing. Those tests use the bundled harmless tiny
fixtures, not the switch application.

`toolchain-receipt.json` records task-local Temurin 21.0.12.1+1 and official
TLC v1.7.4, whose banner is TLC2 2.19 of August 8, 2024. The JRE bytes match the
publisher SHA256. The exact TLC asset matches its publisher SHA-1 and expected
size over the recorded official HTTPS release path; its independently computed
SHA256 is a local content identifier, not a publisher signature or SHA256.

The complete quotient run used one worker, fixed seed 20260907/fingerprint 0,
2 GiB heap, a 600-second deadline, an 8 GiB state cap, and a 20 GiB free-space
reserve. Its process completed and was reaped. Raw receipts retain exact commands,
input/tool/runner hashes, Java version, elapsed time, counts, and log hashes.
No binary, download archive, cache, or TLC state/checkpoint is included here.

Actual ASN.1/BER/OID behavior, UUID/sentinel encoding, per-PDU snapshot binding,
CIDRs/security levels, dispatcher ownership and response encoding, SQLite
rollback/durability, and complete API/revision/event/idempotency effects remain
implementation-level verification boundaries.
