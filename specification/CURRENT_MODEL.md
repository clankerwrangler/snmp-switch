# Current formal model

The TLA+ models describe bounded state transitions and invariants for Switch Lab.
They are not a formal refinement proof of the Python application. See the
[technical specification](TECHNICAL_SPECIFICATION.md) for application behavior,
[verification report](CURRENT_VERIFICATION.md) for recorded results and commands,
and [application validation](../docs/VALIDATION.md) for implementation tests.

## Owners and checked relationships

| Model | State and properties | Application boundary |
| --- | --- | --- |
| `Switch.tla` | Endpoint/port/VLAN references, independent VLAN learning, legal FDB entries, generation-checked activity, link events, and fixed ENTITY joins | Runtime scheduling, invalidation, port/VLAN edits, and MIB projection |
| `ReadAccess.tla` | Shared credential/view/target references, independent read/write grants, current read authorization, coherent snapshots, and atomic inline creation | Authentication, source filtering, credential saves, and per-PDU reads |
| `SetTransactions.tla` | Existing switch/access state; simultaneous candidate validation, original error positions, atomic commit/rejection, and stale queued-request denial | SET planner and engine transaction |
| `GroupedAccess.tla` | Canonical communities/users/groups, policy projection into the existing access/SET owners, exact migration/conversion, sparse saves, and shared-generation invalidation | Schema loading, group/credential commands, and incoming authorization |
| `EntityInventory.tla` | Fixed physical/alias/interface identity, independent filtered snapshots, and actual-row-change timestamps | Read-only ENTITY projection and management uptime |
| `SetResponseLifecycle.tla`, `SetResponseEntry.tla` | Original MP/security record association, exact ownership through admission, consumption/discard, expiry, reuse, and response failure | Pinned response-lifetime integration |
| `StorageOutcomes.tla` | Published versus durable state, failed rollback/unknown commit, faulted effect gates, and validated new-incarnation recovery | Store/Engine failure and startup paths |
| `SetTokenEquivalence.tla` | Finite token-allocation certificate and equality-only view of the unchanged SET graph | Model-checking reduction, not application behavior |
| `TestSwitch.tla` and the `*Scenarios.tla` modules | Focused initial states, action sequences, independent expected outcomes, and required completion | Regression fixtures, not another state owner |

Core safety includes `TypeOK`, `InventoryOK`, `FdbOK`, `JobsOK`, `MibOK`, and
`TrapsOK`; transition properties require valid learning provenance and prevent
stale jobs from committing. Creation/deletion of a VLAN invalidates explicitly
tagged source work even when the tag is not admitted. Restricted liveness
fixtures require source refresh, aging, and notification draining under their
stated stable-input and service-fairness assumptions.

SET uses one complete candidate and the existing `Mutate` action. Raw PVID writes
do not rewrite untagged membership; the API native-VLAN convenience is separate.
The model covers Boolean admin status, active-only VLAN rows, independent
admitted/untagged/forbidden sets, effective deletion, duplicates, original-position
errors, and response-budget ordering. Rejection and confirmed rollback preserve
state. Current authorization and captured registration/activation are rechecked;
revocation followed by restoration, rotation, or repeated reboot cannot revive an
old request. Same-value and unrelated changes preserve its generation.

Grouped access resolves a v3 user's optional group without a copied per-user
policy. No group denies incoming access without changing target-linked traps.
Stock-USM normal-management acceptance is opaque authentication at the configured
user protection profile; the group minimum applies afterward. A lower group
minimum does not enable a weaker normal request. This is not a second application
floor, and discovery/REPORT exceptions are outside that relation.

Migration retains saved identities, secrets, restrictions, and targets, with a
distinct group per old v3 user. Protocol conversion requires explicit incoming
access intent and, for v2c-to-v3, an explicit new profile. Group creation and user
conversion publish together or neither does. Four-mode form submissions preserve
unchanged and final-inactive restrictions; they do not model DOM interactions.
Inline creation changes only its selected target. Shared policy/minimum/view and
membership changes invalidate every affected queued writer; label-only and
same-value edits do not.

ENTITY has one chassis and fixed ports, with physical index `bridge_port + 1`
and alias pointers to saved `ifIndex` values. No endpoints or VLANs add physical
rows. Visible label/description changes update the timestamp; no-ops, rejection,
unrelated work, and clock wrap preserve it, while management reboot clears it.
Clock-only graphs do not check reads: separate reachable-read and lifecycle
fixtures check immutable observations and alias-only access without permission
to read the pointer target.

Response ownership uses opaque owner/record identities, not numeric references
alone. The original security association is captured at MP insertion, before
application admission. Later loss/reuse cannot authorize foreign cleanup.
Missing ownership is diagnostic. The claimed commit/materialization interval
cannot interleave with cancellation or expiry; cleanup depends on whether MP
and security state have actually been consumed. The integration trace invokes
`HandleSet` at claim and preserves its complete resulting switch state through
response failure. Committed configuration is not rolled back by failed delivery.
Pre-admission REPORT failures after stock MP consumption remain outside this
claim.

Storage uncertainty is a separate small graph. Failed rollback or an unknown
commit outcome blocks later API/SET/background/send effects, including when the
actual durable value still equals the publication. Reads retain the confirmed
publication. Only successful close and validated durable loading in a new
incarnation restore operation; failed close/load cannot install defaults or heal
the fault. Recovery liveness assumes an external restart and available valid
storage, not an automatic retry loop. Old queued work stays stale across repeated
restarts.

## Finite scope

`configs/` is the executable source of bounds, selected actions, invariants, and
fairness. There are 51 normal configurations and one explicit unreduced SET
diagnostic. The normal suite contains both general finite graphs and scripted
traces; these do not collectively prove an unrestricted production-sized system.

| Family | Representative bounds and restrictions |
| --- | --- |
| Core | Full `Smoke`: one port/endpoint/source/MAC, VLAN 1, queue 0. Focused graphs separately cover nonzero queues, multiple ports/endpoints/sources, VLAN lifecycle, and conditional liveness. |
| Core scenarios | Two ports/endpoints, three source slots each, three MACs, VLANs 1/10/20/30; queue 8 except overflow queue 1; prescribed sequences with completion assertions. |
| Access | Up to two credentials/views/targets/secrets, opaque snapshots, one pending read; separate reference and authorization fixtures. |
| ENTITY | Two fixed ports, two labels, four-value clock; sparse port/index fixture and independent physical/alias/IF selections. |
| SET graph | One port/endpoint/source/MAC, VLANs 1/10, two credentials/secrets/views, three tokens, one pending PDU, all 31 selected request forms. |
| SET scenarios | Seven scripted cases, VLANs 1/10/20, up to four varbinds; bitmap/absent-destroy cases use two ports. |
| Response | One ticket plus foreign replacement identities; lifecycle graph, 19 reuse/diagnostic traces, 14 transaction traces, and 240 insertion-boundary branches. |
| Storage | Four opaque durable values, three incarnation tokens, one queued item/four work kinds; graph and 40 recovery branches. |
| Groups | Two credentials, three groups, two views plus no-view, two opaque key bundles, three security levels, two source classes, two targets, one pending PDU. The three scripts have 2,332 migration/conversion, 2,112 form, and 5,276 access/queued fixtures. |

Generation tokens are not reused while captured by outstanding work. Abstract
ticks/countdowns replace wall-clock time. The certified SET view normalizes only
registration/activation token names; it retains current-versus-stale equality,
all requests, all other state, every assertion, and handle fairness.

ASN.1/BER/OID/UUID encoding, cryptography, actual USM acceptance, CIDR parsing,
cache layouts, locks/timers, SQL/OS durability, complete event/idempotency history,
HTTP/DOM behavior, and capacity limits require implementation tests. Successful
UDP send is not delivery acknowledgment. Finite TLC checks use fingerprints and
are not a theorem for arbitrary cardinalities or an implementation proof.
