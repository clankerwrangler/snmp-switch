# Current formal model and application traceability

The core, ENTITY, SET, response-lifetime, and storage models retain their checked
relations and evidence from the application checkpoint
`d75c960ccd66d99413e9287aae557ae32b47440b` and its subsequent refinements. The
grouped-access relation uses unchanged dependencies from application baseline
`ea5047605260e0806d0e8f00406755c97094eb9e` and describes the schema-3 contract
before its application integration checks. Finite TLC results concern these
models, not an application refinement proof.

## State ownership

| Model | Scope |
| --- | --- |
| `Switch.tla` | Existing endpoint, link, VLAN, FDB, generation, and link-event state; independent untagged/forbidden memberships; fixed ENTITY topology and interface joins. |
| `ReadAccess.tla` | Shared credentials, independent read/write access, named view contents and references, target references, atomic inline creation, and handling-time reads. Secrets and snapshots are opaque. |
| `GroupedAccess.tla`, `GroupedAccessScenarios.tla` | Canonical community/user/group policy, legacy normalization, explicit protocol conversion, sparse form submissions, and shared-generation invalidation through the existing access/SET owners. |
| `SetTransactions.tla` | A named instance of `ReadAccess` and the same `Switch` state. One complete candidate commits through `Mutate`; failures preserve modeled switch/access state. No second FDB or credential store exists. |
| `SetTokenEquivalence.tla` | A finite allocator certificate and equality-only TLC view for registration/activation tokens. The inherited transaction specification and every request remain unchanged. |
| `SetResponseLifecycle.tla`, `SetResponseScenarios.tla`, `SetResponseEntry.tla` | Original MP/security association before admission, exact response-ticket ownership, cache consumption/discard stages, and focused integration with the existing transaction commit boundary. |
| `StorageOutcomes.tla` | Last confirmed publication, actual durable outcome, temporary storage-health gate, and externally triggered validated restart with stale-work rejection. |
| `EntityInventory.tla` | ENTITY-visible labels, an abstract management clock, change timestamps, and immutable selected-object observations. Physical, alias, and IF selections are independent. |
| `TestSwitch.tla`, `Scenarios.tla` | Existing focused initial states and core traces, plus explicit-tag lifecycle invalidation. |
| `AccessScenarios.tla`, `EntityScenarios.tla`, `SetScenarios.tla` | Scripted integration traces using the owning models' actions, with checkpoints and required completion. |

## Current code to model

| Application owner | Formal relationship |
| --- | --- |
| `models.Configuration.references` | `InventoryOK`, `VlanConfigLegal`, and `ReadAccess!ReferencesOK`: permanent VLAN 1, fixed references, admitted PVID, unique interface/FDB joins, and credential/view/target references. |
| Credential/group validation, normalization, and save commands | `ConfigValid`, `Migrate`, `Convert`, `FormPolicy`, and `Publish`: one canonical incoming-policy owner, exact saved-policy transfer, sparse final-active restrictions, and revision-checked atomic candidates. These are intended schema-3 relations until implementation tests establish the call sites. |
| `Engine.execute`, `Store.commit` | Atomic publication is an abstract transition. SET rejection and rolled-back persistence failure leave the modeled state unchanged. Actual SQLite rollback, revisions, event history, idempotency, and crash outcomes require implementation tests. |
| `Runtime.valid`, `schedule`, `observe` | `ValidJob`, `QueueActivity`, `ApplyActivity`, `JobsOK`, `LearningHasSource`, and `StaleJobCannotCommit`. VLAN creation/deletion now also invalidates explicitly tagged endpoints, including inadmitted tags. |
| `Runtime.advance`, `expire`, `reset_operational` | Abstract ticks, due-work draining, expiration, and reboot. Existing fair source, aging, and link-queue progress fixtures remain. |
| `mib.Projection` | IF/BRIDGE/Q-BRIDGE/ENTITY semantic maps. Numeric OIDs, ASN.1 types, bit ordering, TimeFilter, UUID bytes, and unknown-value sentinels are adapter checks, not modeled encoders. |
| `Responder` and adapter lifecycle | Existing read authorization and immutable per-PDU snapshots; asynchronous SET capture/recheck/commit. Registration and activation tokens prevent queued obsolete work from becoming current after changes are reversed. |

## Communities and incoming management groups

`GroupedAccess` stores version-specific credentials and groups in one canonical
configuration. A v2c community owns read/write policy; a v3 user owns an optional
group reference and opaque authentication material. `PolicyOf` resolves the
current group policy into the unchanged `ReadAccess`/`SetTransactions` instance.
There is no copied effective per-user policy or second token history.

A group's minimum incoming security level is distinct from the user's configured
protection profile. `StockUsmAccepted` represents stock PySNMP normal-management
acceptance at that profile, conditional on opaque authentication success. A lower
group minimum does not relax the user's protection requirement. The application
checks group policy after stock USM accepts the request; it does not implement a
second per-user floor. Discovery/REPORT exceptions are library behavior, not
ordinary lower-level management capability. No group or Access=None denies
incoming access without changing target-linked notification authorization. Fresh users have no group; fresh users and groups
use authPriv, and fresh groups have no access. Inline creation updates only its
explicit selected target; every unrelated target reference and enable bit stays
unchanged. Active group views must exist,
even without enabled members; inactive selections and filters remain stored.
Any member, including a disabled user, prevents group deletion.

Legacy normalization preserves IDs, opaque key material, enablement, old incoming
minimum, policy, target references, and metadata. Each old v3 user receives a
distinct deterministic group slot; equal policies are not merged. Explicit
protocol conversion requires request-only `access_transfer=keep|none` or, for
v2c-to-v3 only, an exclusive explicit nullable group selection. Missing/conflicting
intent and simultaneous policy overrides reject. Keep copies current saved
policy, not a hidden draft. Group creation and credential conversion publish
atomically; other groups and members remain unchanged. Fresh/same-version saves
reject transfer intent, and no transfer flag is persisted.

The four access selections preserve all read/write enabled pairs. `FormPolicy`
changes enabled bits independently and applies dirty restrictions only to
final-active sections. Unchanged or secret-only saves preserve existing
restrictions; inactive draft changes do not replace hidden saved values.

Real group policy/minimum, membership, user authentication/global state, and
selected shared write-view changes renew every affected credential's existing
registration token. The allocator excludes the pending capture, so remove/restore
cannot revive old work. Label-only, same-value, and unrelated changes preserve
queued work. Current group, source, level, and view checks still apply at handling;
the trace invokes the unchanged `SubmitSet` and `HandleSet` actions.

This is a VACM-style application incoming-policy subset, not full native VACM
instrumentation. Actual USM authentication/REPORT behavior, schema parsing/import
validation, sparse field presence, CIDR parsing, identifier encoding, secrets, storage, and browser
drafts remain implementation checks. The schema1 relation abstracts parsed
purpose/view/filter fields rather than replacing its existing input validator.
Title, labels, and the actual listener status remain browser assertions.

## SET contract represented here

The seven writable objects are `ifAdminStatus`, static VLAN name/egress/forbidden/
untagged/RowStatus, and `dot1qPvid`. Admin remains up/down; testing(3) is a valid RFC
2863 enumeration that this permitted product profile does not implement.

Static VLANs remain active-only. RowStatus creates with 4, reads active as 1, and
destroys with 6. The RFC-permitted unsupported 2/5 cases retain their existing-row
versus absent-row distinction. Destroying absent rows is a no-op even inside a
mixed successful PDU. VLAN 1 remains permanent.

Raw SET PVID changes ingress classification only. Untagged memberships may be
empty or multiple, remain a subset of admitted memberships, and do not overlap
forbidden membership through admitted ports. All memberships reference configured
VLANs. The native-PVID API convenience changes an omitted untagged set to
`(old_untagged - {old_pvid}) union {new_pvid}` only when PVID actually changes.
Unchanged PVID preserves the set; explicit untagged input is exact.

Deletion removes only effective deleted VLANs. Fallback supplies VLAN 1 only when
an affected PVID has no explicit replacement. It adds untagged VLAN 1 only when
the removed native VLAN was untagged. Explicit final assignments win over
fallback defaults; final contradictions reject rather than silently clearing a
forbidden bit. Configuration is validated as one final candidate, not in OID order.

Per-varbind symbolic decoding errors retain original positions. Final relational
conflicts select an actual participating assignment; unrelated valid PVID writes
and row no-ops do not become error-index 1. Identical duplicates coalesce in effect;
conflicting duplicates reject at the second occurrence. Response budget rejection
precedes normal access/varbind responses, after stale authentication/lifecycle
work is excluded. Exact BER feasibility and security-library drop/report behavior
remain implementation boundaries.

A response belongs to the single modeled PDU. It stays observable after completion
and resets to `none` when the next PDU is submitted. This avoids carrying unrelated
previous-response history through the next request's state space.

Writing is disabled by default and is independent of polling and target use.
Selected write-view changes invalidate every affected queued writer, including a
shared-view remove/restore sequence. This retained-revocation rule is an explicit
product lifecycle choice, not a requirement to remember past VACM decisions in
RFC 3415. Same-value and unrelated view saves preserve that writer's generation.
Current write grants are still checked when handling the PDU.

`SetReboot` advances the adapter activation token while retaining the pending PDU
for late rejection. It also invokes the unchanged core reboot semantics. The
activation allocator excludes the pending PDU's token, so two reboots cannot make
an old PDU current even when the finite core boot token is reused.

## Response resource lifecycle

`SetResponseLifecycle` models one admitted inbound response ticket with opaque
engine, MP-owner/record, and security-owner/record identities. Numeric references
may be reused. Ready requires both exact records and current lifecycle gates;
foreign records under reused numbers do not grant ownership. Terminal completion
clears the ticket's identity references and occurs once.

The synchronous claimed interval takes MP state, consumes security state, and
then encodes/sends or fails. Cancel, revoke, close, expiry, and cache replacement
cannot interleave that no-await interval. The expiry action represents the
existing MP-cache due-removal boundary, not another clock. Before MP take,
cleanup owns both records; after MP take, it owns only the remaining security
record; after security consumption, it must not release either record again.
Foreign and outgoing notification state remain unchanged by ticket cleanup.

A queued owned MP record with missing or different security state is an ownership
failure regardless of whether expiry, cancel, revoke, close, or a handling
attempt discovers it. Expected absence after actual consumption is different.
The checked traces cover both cancellation/expiry orders, late callbacks, numeric
MP/security reuse, and engine/owner mismatch.

`SetResponseScenarios` calls the existing `HandleSet` only at the claim boundary.
Its immutable test observation freezes the complete resulting `s`; subsequent
materialization/finalization steps preserve that state. A committed change stays
committed when response preparation, encoding, or transport fails. Rolled-back
commit failure and delivery failure are distinct. `sent` means the synchronous
transport operation returned, not that a UDP peer acknowledged delivery.

The model uses one ticket and a later foreign replacement witness, not an
unrestricted cache or request product. Actual PySNMP layouts, identity checks,
method binding, expiry hooks, locks, task bounds, BER/USM, and transport behavior
remain implementation tests.

### Original association before admission

`SetResponseEntry` adds the earlier insertion boundary. The canonical MP record
stores an immutable opaque witness of its original lifetime, security owner, and
security-record identity. Insertion is not application admission and creates no
SET effects. A missing security identity at insertion stays unknown even if a
new record later occupies its numeric reference.

Late admission copies that witness, not the current lookup. The checked
projection transfers the exact observed MP/security entries into the existing
lifecycle owner without cache removals or a remaining mirror. For unadmitted
expiry or close, the same `DiscardState` expression used by admitted cleanup
checks the original association. Security loss/reuse cannot redefine ownership.
Missing or foreign-owner witnesses report failure, retire the exact MP entry,
and preserve unknown security instead of adopting a replacement.

The focused trace covers delayed admission, original expiry, and close across
normal, lost/reused security, a stored missing identity, missing/foreign witness,
and wrong-engine cases. All branches complete; foreign/outgoing state, current
readiness before effects, and the existing admitted-stage checks remain. The
A/B records represent an original identity and a same-number replacement.
Foreign-witness cases use another lifetime or security owner, not arbitrary
trusted-memory corruption.

The insertion hook also encounters stock v3 report/error entries, which are not
application admission. Opaque nonexpanding `repr`, no secret copying, exact
pinned method shapes, named-key response compatibility, report/discovery/BER,
and real timer/locking behavior remain application checks. This refinement does
not cover every pre-admission report serialization failure after stock MP pop.

## Storage outcome and recovery

`StorageOutcomes` separates the last confirmed publication from actual durable
state and an optional open transaction candidate. A confirmed rollback preserves
both publication and storage and leaves normal capability available. Failed
rollback retains the open candidate, reports the initial SET `undoFailed(0)`, and
blocks later mutation and notification effects. An unconfirmed outcome with no
active transaction keeps the same faulted health whether actual durable bytes
are old or candidate. The initial SET response is dropped, not reported as
rollback. Publication stays old even when a candidate is already durable.

The health gate applies before API/SET mutations, background effects, and queued
notification sends. A plausible read or equality between publication and actual
durable state cannot clear the fault. Labeled reads expose only the last
confirmed Runtime; a diagnostic storage observation is not a confirmed read.
These read observations are exercised by the focused recovery trace, not by the
arbitrary storage graph. Existing read authorization remains separate.

Recovery requires successful process close and a new incarnation with a valid
load of actual durable state. Closing an uncommitted failed-rollback transaction
retains old durable bytes. Failed close, unavailable load, or invalid load does
not restore writes or substitute defaults. A valid reopen loads old or candidate
as actually stored, resets an abstract volatile marker, and excludes any captured
work token from the fresh incarnation. Two-restart traces reject old queued work
and then demonstrate new work, writes, and sends. Eventual recovery assumes an
external successful restart and available valid storage, not an automatic loop.

The two Boolean data fields are four opaque versions used to observe a lost
update, not SQL or application schema. A later unrelated edit from stale
publication must not overwrite an already committed field. Other mutable Runtime
state and notification sends have finite effect markers. The existing SET
persistence-failure abstraction concerns confirmed rollback; unknown storage
outcomes are not reclassified into that branch. Response-ticket ownership,
authorization, BER, SQLite/OS durability, validated startup, every actual
Store/Engine mutation entry point, and notification transport gating remain
implementation boundaries.

## ENTITY scope

Exactly one chassis and the fixed switch ports form the physical inventory.
Chassis index is 1; port index is bridge port plus 1. The chassis is the sole root,
with parent 0/class 3/position -1. Ports have parent 1/class 10 and their saved
bridge-port position. Direct containment and wildcard alias pointers join to the
same saved `ifIndex` used by BRIDGE-MIB. Endpoint and VLAN records never add rows.

The timestamp changes only for an actual projected label/description change,
stays unchanged for no-ops, rejected persistence, unrelated work, and clock wrap,
and resets to zero on management reboot. Multiple changes in one abstract tick
may have the same timestamp. The metadata graph checks clock behavior; it does
not include reads. `EntityReadConsistency` has reachable reads and label changes.
The lifecycle trace also checks alias-only and IF-only selections: a visible
RowPointer does not authorize its target IF-MIB instance or physical row.

The model uses opaque stable identity tokens. UUID parsing, invalid-ID unknown
fallbacks, byte/URN encoding, every physical column type/sentinel, exact OID-prefix
permissions, and real per-PDU adapter binding remain implementation tests.
No ENTITY writes, logical/LP inventory, conformance registration, or entity-change
notifications are included.

## Finite matrix

The original 25 configuration cardinalities and action families remain. Their
six core safety checks and two transition properties remain; `MibOK` also checks
fixed ENTITY joins. The three original conditional liveness fixtures remain.

Additional configurations are:

- `ScenarioTagLifecycle`: explicit-tag create/delete invalidation while the tag
  remains inadmitted; the original two-port/six-source-slot scenario universe.
- `SharedAccessRelationships`: two credentials/targets/views, one opaque secret
  and snapshot; arbitrary reference, enablement, deletion, and inline outcomes.
- `AccessLifecycle`: two credentials/targets/views/secrets; a completed read and
  shared-target lifecycle trace, including failed inline persistence.
- `WriteAccess`: one credential/view/target/snapshot, two secrets; independent
  access/reference transitions and fair read completion.
- `EntityInventory` and `EntitySparse`: two ports, two labels, a four-value
  management clock. The sparse fixture uses bridge ports 1/65535 and ifIndexes
  2147483647/7. Neither fixture adds read transitions to the clock graph.
- `EntityReadConsistency`: two ports and two labels; independently selected
  physical/alias/IF objects and reachable immutable reads/name changes.
- `EntityLifecycle`: nineteen completed steps for change/no-op/rejection,
  snapshot retention, wrap, unrelated configuration, reboot, and alias visibility.
- `SetTransactions`: one port/endpoint/source/MAC, VLAN universe 1/10, queue 1,
  two credentials/secrets/views, one snapshot/target, three equality tokens, and
  one pending PDU. Its 31 request forms contain zero to two commands drawn from
  admin up/down, PVID 1, a read-only object, and a symbolic wrong-type command.
  Write enablement, secrets, and activation may change while requests wait.
- `SetTransactionsEquality` checks that same transaction specification under
  `CanonicalSetView`. Only two opaque lifecycle token identities are normalized;
  current-versus-stale captures, all 31 requests, and all other state remain.
- `SetTokenEquivalence` checks all 513 current/captured token assignments and
  all affected-credential subsets/activation changes. The certificate and
  future-step/fairness argument are described in `CURRENT_VERIFICATION.md`.
- The seven `Set*` scenarios use the same commit/authorization actions with
  VLANs 1/10/20 and up to four varbinds. `SetBitmapPorts` and `SetAbsentDestroy`
  use two ports; the others use one. They cover simultaneous candidates, source
  invalidation and FDB cleanup, RowStatus/errors/duplicates, native fallback,
  two-reboot and credential ABA, independently selected/shared views, and
  non-effects of absent destroy within a real mixed change.

The original response-lifecycle refinement adds three independent configurations:

- `SetResponseLifecycle`: one admitted ticket, fixed numeric MP/security slots,
  opaque A/B record identities and owner incarnations, five response kinds, and
  explicit synchronous ownership stages. Fair progress and enabledness checks
  cover queued and claimed completion.
- `SetResponseReuse`: nineteen completed cases, including all eight missing or
  mismatched security states followed by cancel, expiry, revoke, or close.
- `SetResponseIntegration`: fourteen completed cases using the actual
  `HandleSet` action and full semantic-state observations across response failure.

The entry refinement adds `SetResponseEntry`: 240 scripted initial branches
(three admission/expiry/close routes, eight ownership conditions, five response
kinds, and two outgoing-state values). Each branch completes nine steps. The
three existing response checks also run against the extended lifecycle owner;
no resource product is added to the arbitrary SET graph.

The storage refinement adds two independent configurations:

- `StorageOutcomes`: four opaque persisted values, three incarnation tokens,
  one queued item ranging over four work kinds, known/unknown storage outcomes,
  and failed/successful close/load transitions. Recovery progress is conditional
  on external restart and valid storage availability.
- `StorageRecovery`: forty completed 22-step branches, including eight
  old-durable unconfirmed cases, confirmed reads and diagnostic observations,
  every modeled blocked-effect family, failed startup, two restarts, and resumed
  operation. The configured first effective assignment index is 2.

The grouped-access relation adds three independent scripted configurations:

- `GroupMigrationConversion`: 2,332 fixtures for legacy normalization, defaults,
  explicit keep/none/group conversion, invalid/stale/failed saves, and references.
- `GroupAccessForms`: 2,112 fixtures covering all four initial access modes,
  mode changes, unchanged/secret-only saves, independent restrictions, missing
  inactive views, hidden drafts, cancellation, and atomic rejection.
- `GroupQueuedSet`: 5,276 fixtures for all three levels, stock-USM/group-floor/source
  checks, shared policy/membership/view ABA, same-value and unrelated saves, and
  completed outcomes through the existing transaction action.

These fixtures use two credentials, three group slots, two named views and the
no-view marker, two opaque key bundles, two source classes and empty/A-only/B-only
filters, two targets, one pending PDU, and three existing token values. The SET
witness retains one port/endpoint/source/MAC and VLANs 1/10. The scripts complete
two, four, or five transitions with revisions in 0–8. No TLC state constraint,
VIEW, or arbitrary SET cross product is added.

These focused graphs and scripted traces are not an unrestricted multi-port,
multi-VLAN, multi-request system proof. Actual source CIDRs/security levels,
cryptography, complete wire parsing, response encoding, pending-task cancellation,
SQLite durability/undo failure, counters, capacity, and full event history remain
explicit implementation-level obligations. A timeout or interrupted frontier is
incomplete, never a pass.

## Reproduction and evidence

`run_tlc.py` reads the `TLC_MODULE` comment in each configuration. Its normal
suite has 51 configurations: the previous 40 core/access/ENTITY/SET traces and
graphs, the token certificate, the proved token-view graph, three response-lifecycle
checks, the entry-association trace, two storage checks, and three grouped-access
checks. Evidence consists of the earlier 42 checks and separate response, entry,
storage, and grouped-access checkpoints. The entry checkpoint rechecks three
affected response configs; storage and grouped access leave earlier checked inputs
unchanged. No combined 51-config run is claimed.
The unreduced
`SetTransactions` configuration is an explicit diagnostic, not part of normal
selection. Missing either replacement configuration fails normal selection
before starting TLC; it does not silently omit transaction verification.

The runner uses one worker, fixed seed 20260907/fingerprint 0, no symmetry,
a default 600-second per-config deadline, a 3,600-second batch deadline, and a
fresh output directory. Positive explicit timeouts remain available. It records
every formal input hash, tool hash, command, Java version, count, and outcome.
Optional state-storage and free-space limits terminate an incomplete run with
`RESOURCE_LIMIT`; deadlines produce `TIMEOUT`. Existing output is never
overwritten. The Java child is reaped on timeout or resource failure.

Run the normal suite from `specification/`:

```sh
python run_tlc.py --java /path/to/java --jar /path/to/tla2tools.jar --output logs/current/run-1
python tests/check_mutations.py --java /path/to/java --jar /path/to/tla2tools.jar --output logs/current/mutations-1
```

Use a new output name for each run. The checked tool versions, current results,
quotient justification, and incomplete reference runs are recorded in
`CURRENT_VERIFICATION.md` and `logs/current/2026-09-08/`.

The explicit unreduced diagnostic remains available:

```sh
python run_tlc.py --java /path/to/java --jar /path/to/tla2tools.jar --models SetTransactions --timeout 1800 --batch-timeout 1800 --output logs/current/diagnostic-1
```

This explores token names without the proved equality view. Its recorded
1,800-second run is incomplete, not a pass. `--checkpoint-minutes 1` requests
regular TLC checkpoints; resumption requires matching model/config/tool inputs.
A checkpoint or partial frontier is not a completed verification result.

`tests/check_mutations.py` uses temporary model copies and separate output.
The original three defects and three new unauthorized/partial-SET/alias defects
must produce behavioral violations. Parse failures and timeouts do not count
as detection. The separate token-certificate reuse defect is recorded with its
exact mutated input hash. Scenario generators reproduce checked-in inputs;
`ReadAccess`, shared-access, token-proof, and other direct fixture configurations
remain maintained directly.

Historical `logs/verification.json`, its raw logs, and the revision-2 report are
preserved. Current results use a separate directory. No historical hash or result
is rewritten to match newer inputs.
