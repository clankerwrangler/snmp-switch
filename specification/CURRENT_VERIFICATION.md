# Current finite model verification

The 52-configuration normal catalog is supported by separate completed checks,
not one combined 52-config run. All passing graphs below finished with zero
queued states; scripted checks include completion assertions. Counts overlap
across configurations. These results concern the [models](CURRENT_MODEL.md), not
application, wire, or operating-system correctness.

## Recorded outcomes

| Check | Actual result | Generated / distinct states |
| --- | --- | ---: |
| Core/access/ENTITY/SET matrix, including the original 25 configs | 40 PASS | 12,271,969 / 710,685 |
| SET graph under the certified token view | PASS; full temporal check; 349.003 s | 6,708,324 / 526,688 |
| Token-allocation certificate | PASS | 1,026 / 513 |
| VIEW/fair-handle compatibility fixture | PASS; full temporal check | 524 / 11 |
| Response lifecycle graph | PASS; full temporal check | 210,495 / 23,175 |
| Response reuse and transaction-integration traces | PASS | 109 / 90; 115 / 101 |
| Entry-association trace | PASS; all 240 branches complete | 2,640 / 2,400 |
| Storage graph and 40 recovery branches | PASS; full temporal checks | 1,105,000 / 25,313; 960 / 920 |
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

SANY, generator byte-for-byte round-trip, and five small runner-routing/guard
cases passed at their recorded checkpoints. These are supporting checks, not
additional application-model graphs.

Behavioral negative controls detected stale-job acceptance, excessive FDB
flushing, broken VLAN fallback, unauthorized/partial SET, wrong ENTITY pointers,
captured-token reuse, response leaks/foreign cleanup, stale durable overwrite,
migration sharing, incomplete shared-member revocation, and failed conversion
prefix publication. Actual counterexamples also drove response diagnostics,
entry-association, error-index, no-op deletion, and selected-target corrections.
The twelve reusable controls in `tests/check_mutations.py` run against current
sources. The three grouped controls reach actual second-member stale success,
cross-user policy modification, and rejected-save prefix publication. Other historical control definitions and exact inputs are in Git.
The three RADIUS controls detect a stale reply installing a grant, a duplicate
changing cached ACK to NAK, and partial CoA effects under a NAK. The duplicate
counterexample does not demonstrate replacement-session revocation. Both RADIUS
checks are separate safety graphs, without fairness or a composition proof;
causal scheduling and persistent replay remain application boundaries.
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
twelve run. Parsing errors and timeouts are not behavioral detection.
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
