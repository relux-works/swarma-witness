# WC1 independent custodian protocol proposal v1

**Proposal only.** This document specifies G17/G18/G19 obligations, not an
accepted wire codec, qualified provider, serving constructor or activation.
[Closed interfaces](../custodian/contract.go), G07/G10 and every native/time,
storage, disclosure, exclusion and recovery gate remain closed. No code changes
are supplied. The [local S3 contract](storage-v1.md) and
[WC1 QT-2c profiles](witness-qt2c-profile.md) retain their stricter requirements.

## 1. Roles, independence and scope

The selected M0 direction is one synchronous independent G17 custodian, a second
WC1 witness on a separate VPS, plus **separately enforced lifetime exclusion**.
It serves the shared custody dependency for Keymaker bootstrap/enrollment, the
broker's timeconf rollback witness and D5, and later the user-manager's PC2 floor
and A3d-2 base. A common provider of custody does not merge those scopes or give
one consumer another's authority. Registry Q10 requires its own consumer review.

Production placement uses a different provider and account. Prototype placement
may use the same provider in a separate project and account, **without a shared
API token**. The second witness has independent administration, signing keys,
epochs, transport identities/pins, deployment and recovery credentials and
retained recovery anchors. No first-witness key or administrative credential is
shared, copied or used to derive the second witness's. Neither side's ordinary
service credential administers the other. G10/G11 require protected independent
initial pins and separately authorized pin transitions; certificate possession
or role syntax alone is insufficient. See [role boundaries](policy-v1.md) and
[transport identity rules](tls-profile.md).

Separate accounts do not remove common-provider outages, privileged control-plane
failures, shared software defects, common administrators/automation or coordinated
backup rollback. Cross-provider placement does not cure shared administration.
Neither placement qualifies latestness, retention, latency or exclusion.

Record/control custody retains exactly the existing seven-field tuple:
`service, chain, stream, seq, record_hash, receipt_hash, control_hash`.
Its chains remain records or controls; **audits is not a tuple chain**. Independent
audit/archive acknowledgment remains separate under G14/G15. The original
record's `control_hash` is immutable; current control is checked separately.
Consumer use/outcome, time settlement and floor custody need explicitly reviewed
bindings; they are not automatically covered by this record tuple.

## 2. Grounded interfaces and wire boundary

The existing local `Provider` declares `ReadFresh`, `VerifyFresh`, `Confirm` and
`VerifyConfirmation`. `Request` carries a tuple and a 32-byte challenge;
`Transition` carries previous/next tuples and original transaction identity;
`Evidence.Original` is opaque provider material. These are Go obligations, not
accepted network objects. In particular, `Confirm` has no complete original-bundle
argument and `Request` alone does not enroll provider identity/epoch or prove
current control. An adapter must obtain a protected authenticated complete bundle
and enrolled expectations through a separately accepted typed contract. Opaque
bytes do not authorize arbitrary provider data or a hidden accepting path.

[wire-v1](wire-v1.md) already fixes closed WS records, receipts, heads, controls,
canonical bytes, domains and bounds; [tls-profile](tls-profile.md) fixes the
proposed G11 transport preimages and pinned mTLS predicates. Reuse only those
forms in their existing roles. A WS signed head can supply original WS evidence;
it is not itself a new custodian confirmation, an exclusion lease or proof that
the second witness is independently current. TLS authentication grants neither
custody authority nor bootstrap/rotation authority.

This proposal selects **no new JSON members, methods, endpoints, signature domains,
error codes or TLS operation fields**. A future versioned custody envelope must
bind provider identity/epoch, exact source service/chain/stream, exact previous
and next tuples, original transaction identity and exact evidence digest. These
are semantic requirements, **not a field list or an accepted preimage**. Its
original-evidence bundle and verification rules, transport principal/ACL,
limits, error precedence and continuity signatures require joint review before
an adapter. It must not extend the closed WS tuple or silently repurpose admin,
append or latest as a custodian method.

Existing WS transport ceilings remain ceilings for those objects, not permission
to fit a custody bundle into an unrelated carrier: frame 65536 bytes, line 8192,
receipt 4096, head 32768, proof page 45056; other structural caps still apply.
Complete custody evidence and any bounded multipart retrieval need their own
accepted aggregate bounds. Refuse incomplete/oversized ancestry before work;
never truncate or replace originals by digests to fit.

## 3. Confirm: independent compare-previous retention

Before accepting a transition the custodian must (resolve an occupied-position
exact repeat under step 5 before attempting a new advancement):

1. Authenticate the enrolled source, writer authority, independent provider
   identity/epoch and exact protected scope. Authorize before existence lookup.
   Freeze the original transaction, previous/next tuple and original evidence.
2. Validate an independently authenticated **original-evidence bundle**: exact
   bounded record/control bytes, original receipts, applicable historical key,
   binding and control ancestry, and authorized genesis where relevant. Verify
   signatures, canonical bytes, hashes, sequence, immediate predecessor and
   consumer pairing under the appropriate existing contracts. A digest,
   copied database, requester validity bit or signature from only the custodian
   is insufficient. The primary's transfer is a claim to verify, never authority
   to replace the custodian's own history, pins or recovery premise.
3. For a new advancement, compare the claimed previous tuple to the custodian's
   **own independently retained authoritative predecessor**, including all seven fields and scope.
   The requester does not choose the expected state. Retain exact current
   control independently of the historical record control. A higher sequence
   with a valid signature cannot select a new baseline.
4. Atomically compare previous and durably retain the exact successor, original
   transaction/evidence and original confirmation before acknowledging. Qualify
   complete file/namespace durability, monotone ancestry and no partial authority;
   an S3 local root or rename alone does not establish independent retention.
   A distinct concurrent loser cannot commit a second successor at the position.
5. At an occupied position, changed bytes, predecessor, evidence or transaction
   refuse. An **exact repeat recovers the original confirmation**, without a new
   receipt, timestamp, transition or use. Match the retained original previous
   and next tuples, transaction and complete evidence; do not compare an old
   previous tuple to today's later head or rewind it to retry a CAS. Original
   acknowledgment does not waive current authorization, exclusion, control or
   release checks. Capacity exhaustion
   refuses without deleting acknowledged history or resetting sequence.

The caller retains its exact durable prepare **before** asking for confirmation.
After confirmation and separate audit/archive acknowledgment, it revalidates and
publishes under its qualified R endpoint; response exposure additionally requires
X. This follows [S3 publication order](storage-v1.md#immutable-format-and-publication).
Confirmation is not local publication, time qualification, consumer commit or
permission to send. A confirmed successor may exist while the primary remains
prepared/held; recovery must resolve that exact original occurrence.

## 4. ReadFresh and current control

The caller generates a fresh unpredictable challenge under a qualified
post-restore entropy/continuity premise; retries cannot reuse a response as a
fresh read. `ReadFresh` must bind that exact challenge, exact authorized scope,
protected provider identity/epoch, authoritative retained record and **current
control**. Return independently verifiable original records/receipts and required
ancestry, authenticating the response under protected provider pins and key/control
continuity. An authenticated channel plus cached signed bytes is not freshness.

The consumer verifies the challenge and scope it independently expected, current
provider epoch/pins and control, original record/control signatures and ancestry,
exact predecessor/head and complete bounded proof. Compare current control
separately: never rewrite an old receipt's historical `control_hash` to make it
look current. Equal sequence/digest, a recent timestamp, local checksum or a
requester-supplied expected tuple cannot replace this comparison. A fresh record
read paired with stale/missing control refuses. Missing originals, unexpected
provider/epoch or conflicting/behind/ahead state holds the affected operation.

Freshness is tied to this original attempt and its remaining deadline. The
consumer retains owned evidence, challenge association, enrolled pins/epoch,
exact read set, reservation and original operation/deadlines through final
revalidation and any effect. A fresh read is not a lease: continuous G18 exclusion
and exact local rechecks must bridge the unlocked interval to publication,
signing and release, including prepared responses. No periodic, cached, local
or absent-provider authority fallback is permitted.

## 5. Uncertainty, restore and continuity

| Event | Required result and retained evidence |
| --- | --- |
| Disagreement, outage or unverifiable evidence before possible work | Refuse; retain the original attempt/evidence and close dependent authority. No older-head success or alternative provider chosen by the requester. |
| Timeout/lost reply after possible confirmation | Outcome unknown: hold the original transaction/position, reconcile exact originals and custodian state. A client timeout does not cancel a possible durable confirmation or allocate a new ID/receipt. |
| Confirmed remotely, primary not yet published | Recover only the matching durable original prepare and authenticated confirmation, under authorized recovery and current fences. Never regenerate a receipt or silently publish an older root. |
| Primary restored/behind | Establish independent current custodian head/control and exact complete surviving originals, reconcile all pending/outcome/audit/use state. Missing bytes hold; a higher counter alone cannot reconstruct them. |
| Custodian restored/behind | Its restored database cannot assert latestness. First establish its true current position from independent retained recovery anchors/evidence outside both relevant restore domains. Primary transfer alone cannot authorize catch-up; dependent paths hold until exact continuity is proved. |
| Custodian ahead or either side conflicting | Hold affected authority; reconcile exact predecessor and acknowledged outcomes using independent originals. Do not pick the larger sequence or reset the other side. |
| Joint loss or compromise of independent evidence | No recovery guarantee. Remain closed; no recreated lineage, implicit first use or automatic mode downgrade. |

Genesis, rotation and migration require explicit independently authorized
continuity and protected pin/epoch transitions, binding predecessor and all
retained acknowledged state. Missing state, restored files, a new process/epoch,
or a new key is never authority for a new lineage. Retain original confirmations,
unknown attempts, complete records/receipts/control/key ancestry and independent
recovery anchors outside the primary's administration/restore domain. Qualify
custodian restore detection against its own external continuity premise as well;
being off-node is insufficient. Recovery needs G19 approval and G18 fencing of
old executors before any new authority. No recovery runbook is supplied here.

The dependency graph must be finite and acyclic, terminating in independently
qualified nonrollback/latestness custody. Two witnesses recursively confirming
each other's uncommitted state do not establish that root. Their time sources,
original readers, use custody, audit/archive and exclusion dependencies must be
included. The concrete trust root and either-side/joint-loss recovery remain
owner/qualification questions, not an assumed third recursive witness.

Local failure mappings retain existing boundaries: absent/unqualified record
custody is `storage_unavailable`; unknown append/control work is `outcome_unknown`
and held; unaccepted exclusion/recovery defaults are `profile_unavailable`.
Do not expose arbitrary backend errors or invent a confirmation-specific code.
Mixed-failure precedence and complete provider-to-WS mapping remain open G21
work before serving; the table specifies authority/state invariants regardless
of diagnostic precedence. See [closed defaults](../custodian/contract.go).

## 6. G18 lifetime exclusion and consumer admission

G17 compare-previous is not G18. A separately qualified enforcer must prevent a
revoked, old, paused, partitioned, restored or cloned instance from **actual
writes, signatures and releases**, including already prepared responses and
delegated/in-flight effects, throughout the serving lifetime and unlocked calls.
A heartbeat, local flock, successful CAS or cached lease cannot supply this.

The custodian must either provide accepted independently enforced ownership
continuity or require and validate such authority from a separate enforcer.
Its concrete issuer, proof, revocation propagation, effect handles and recovery
integration are open; no lease wire form is selected. Existing `Exclusion.Check`
is only an obligation/closed default: a point check cannot implement lifetime
fencing. Custodian confirmation must not silently grant or renew ownership.

Before admitting work and at each publication/signing/release boundary, the
consumer must establish the current independently enrolled ownership epoch and
instance authority, unchanged exact scope/head/control and reservation, and
live enforcement through the complete endpoint. Revocation or uncertainty
closes all dependent effects, retained results and asynchronous completions.
Replacement cannot open until old executors and delegated effects are proven
unable to act; a resumed process cannot continue an old final act from a saved
confirmation/use. Preserve independently current Epoch, per-process Run and
original use revision as distinct identities. Provider confirmation cannot
recall an already emitted signature, so downstream effect boundaries must also
honor their accepted revocation/ownership checks. Emergency stop must not wait
for locks, a provider reply or that dependency graph to complete.

## 7. Consumer bindings and budgets

The following are required adapter properties, not implementations or expanded
wire scopes. One custodian retains separately authenticated consumer namespaces;
no cross-consumer sequence, control, transaction or epoch substitution is allowed.

| Consumer | Protected inputs and retained association | Boundary / missing binding |
| --- | --- | --- |
| WC1 / registry Q10 | Exact service/record/control predecessor and successor, original transaction and bundle, independent current control/pins, audit archive ack, reservation and original deadline; retain original confirmations and complete S3 P/R/X outcomes. | External confirm/read/archive/signing precede final G/S/A/L admission; exact recheck under gates, then sole m, pure verification, durable burn and bounded endpoint. Q10 still needs registry-owner acceptance; record custody is not registry truth or audit custody. |
| Keymaker bootstrap and A/P | Complete master-epoch/public name/index/tombstone and allocator history, purpose-1 binding/results, purpose-6 original B0–B5 occurrence/stage/association/policy/activation outcome, audit, root and deployment floor and exact generation/read-set authority. Retain intent, originals, confirmation, commit/resolution and original retry result. Secret master/key bytes never enter WC1 evidence. | Connect the accepted Keymaker intent → local commit → acknowledged resolution → use contract to the full inventory and root/release. No live B0–B5 adapter, full-use custody or finite bootstrap budget is supplied. A/P bindings cannot stand in for E-I/E-C consumption. |
| Keymaker enrollment E-I/E-C | Exact independently confirmed issue/reload occurrence, original start/D, approval/ledger generation, high-water/registry/pin/config and invalidation predecessors, candidate epoch and original approval expiry; retain burn/held/committed outcomes and full handover evidence. | E-I durable issue/publication and E-C invalidation → unlocked preparation → exact final admission → consume/use/swap remain distinct. Unknown state never reissues an approval or opens authority. Independent custody must survive coherent restore of ledger, use and candidate together. |
| Broker timeconf RollbackWitness | Exact `WitnessHead` generation/digest and settlement ancestry, retained originals, W/holds/in-flight and operation/challenge association under independently protected provider binding; current confirmed head and original deadlines. | Existing `Read` / `CompareAndSwap(old,next)` requires fresh authenticated read, exact durable CAS and no reuse/wrap. OriginalReader validates originals separately. Full uint64 generation cannot be cast/truncated into WS safe-integer seq. Mapping/namespace/envelope remain unaccepted; no automatic WS tuple extension. |
| Broker D5; later user-manager PC2 floor / A3d-2 | Exact owning root/floor/cut/debt/attempt/use/outcome and current ownership continuity under each accepted consumer contract; retain authoritative originals across restore. | Shared custodian direction does not close D5 or define those consumer formats. Manual recovery is not D5 closure. Joint PC2 live spend-cut/base binding, concrete scopes and acceptance remain prerequisites; no RPC under F. |

Consumer source contracts: Keymaker [witness integration](https://github.com/relux-works/swarma-keymaker/blob/1cb18bc28580f946bba4643d509853e3374d58cd/spec/keymaker-witness.md#L47-L68)
and [station bootstrap](https://github.com/relux-works/swarma-keymaker/blob/79b37d2d0a6fbacae1174ec97c8f07d09681fe00/spec/keymaker-station-caller.md#L262-L321);
Keymaker [QT-2c proposal at 6023815](https://github.com/relux-works/swarma-keymaker/blob/60238159b0adf9aa6883f9cd661b5903077fb362/spec/keymaker-qt2c-profile.md#L344-L450);
broker [RollbackWitness](https://github.com/relux-works/swarma-credential-broker/blob/8709e215a1b6bc7f42094a14e4a5620e2baed290/timeconf/settlement_linux.go#L15-L38),
[settlement order](https://github.com/relux-works/swarma-credential-broker/blob/8709e215a1b6bc7f42094a14e4a5620e2baed290/docs/qualified-time-api.md#L109-L154)
and [handoff custody boundary](https://github.com/relux-works/swarma-credential-broker/blob/8709e215a1b6bc7f42094a14e4a5620e2baed290/docs/time-handoff.md#L215-L230).
These pins identify reviewed inputs, not activation approvals or dependency bumps.

The broker's current settlement session uses a local exclusive flock while
calling `Read`/`CompareAndSwap`. Inserting network traffic into that held section
would violate the final-lock rule. A future adapter needs separately reviewed
unlocked preparation/reservation and exact revalidation/publication ordering,
while retaining the independently current head and exclusion. The existing
interface does not by itself provide that handover or an accepting remote path.

### Timing assumptions and call envelope

The following arithmetic is hypothetical and **unmeasured**, not an SLA or a
qualified worst-case f. Same-region RTT r=10 ms; cross-provider EU r=60 ms;
remote verification/durability per call <=20 ms; cold connection 2r+20 ms;
all other work <=100 ms per modeled boundary. Three sequential successful
exchanges model fresh record, current control and confirmation; real operations
must pay their actual count. For N successes and K boundaries, time is
`2r+20 + N*(r+20) + K*100 + loss`, plus earlier elapsed time. The EU loss case
adds one 250 ms timeout, 25 ms backoff and 140 ms reconnect, total 415 ms; the
successful exact retry is already counted in N. Further loss refuses in this
model. All connection/RPC/retry limits are clipped to the remaining original
budget and endpoint reserve. A timeout cannot fence a late writer.

| Modeled span (ms) | Same region | EU | EU with one loss/retry |
| --- | --- | --- | --- |
| One boundary, N=3, K=1 | 230 | 480 | 895 |
| Two boundaries, N=6, K=2 | 420 | 820 | 1235 |
| Four boundaries, N=12, K=4 | 800 | 1500 | 1915 |

These share one cold connection and at most one modeled loss. They are not a
PC2 step count. Never double-charge one mutation's confirmation to both P/R,
but never omit a genuinely separate read, confirmation, archive or time call.

| Original budget | Arithmetic verdict / condition |
| --- | --- |
| WC1 P/R/X <=5000 ms, stricter accept/caller limits | Conditional fit for the modeled spans; charge the complete TLS/header/body/P/custody/R/X work against the original intersected deadlines. R/X do not start a fresh 5 s. Native commit/send bounds remain undefined/refuse. |
| WC1 TLS handshake-start+3000 ms, accept-start+5000 ms | Conditional fit for 230/480/895 only with full original-accept propagation and reserve for TLS/time work; no callback-created replacement timer. |
| Keymaker A/P and registration R-S/R-X native <=2000 ms | Conditional fit for modeled work; enclosing original <=250 ms generation windows can veto it. Standalone root/helper budgets remain undefined/refuse. |
| Any actual <=250 ms reader/PC2 step containing one remote boundary | Same-region 230 leaves only 20 ms; EU 480 and loss 895 **do not fit**. Owner budget question unless already permitted unlocked preparation can move work before this subwindow without losing currentness or enclosing clocks. |
| Keymaker E-I <=60000 ms, whole E-C <=10000 ms (6023815 proposal) | Conditional fit for modeled custody, not qualified or activated. E-I includes human/config/inspection/output/publication from original entry; E-C includes serialization, load, preparation, consume/use/swap. Load gets only its remaining original 10 s subdeadline. Shorter native/reader/approval limits still win. |
| Q7 / K3-G6 | Conditional for bounded native <=2000 ms; any <=250 ms intersection still vetoes EU/loss. Fresh-evidence lifetimes and 64-publication count are not execution budgets; standalone re-anchor remains undefined/refuse. |
| PC2 1000 ms from original pre-binding | One modeled boundary conditional; four-boundary 800 conditional same-region, 1500/1915 **do not fit** EU/loss. Actual call count and pre-binding authority contract remain open. |
| PC2 send-start+2000 ms observation | Conditional for bounded actual work; four-boundary loss leaves only 85 ms for earlier/unmodeled work. No new timer at binding/commit/retry. |
| Broker timeconf whole request <=10000 ms or stricter enrolled/caller budget | Conditional only with bounded settlement/history/original/witness work, collection, drain and teardown in the same original deadline. This ceiling is not a ten-second custody allowance. |
| Serial 201-head inventory under WC1 5000 ms | Reads alone 6070/16220 ms same-region/EU: **does not fit**. No admission at this workload under these assumptions. |

The original analysis's unspecified enrollment budgets are superseded here by
the **proposed** complete E-I/E-C numbers at 6023815; these still supply no native
enforcement or activation. [A/P](https://github.com/relux-works/swarma-keymaker/blob/60238159b0adf9aa6883f9cd661b5903077fb362/spec/keymaker-qt2c-profile.md#L98-L128)
and [PC2 original limits](https://github.com/relux-works/swarma-keymaker/blob/1cb18bc28580f946bba4643d509853e3374d58cd/spec/keymaker-pc2-anchors.md#L390-L416)
remain intersections, never interchangeable allowances.

Before adapter acceptance specify a **bounded call/inventory envelope** per
operation: affected and other required streams/control, retained originals and
ancestry bytes/depth, exact sequential calls, connection work, retries and each
local endpoint reserve. Preflight must include the full protected inventory:
today `service.checkIndependent` serially checks retained stream heads plus
control. With 201 reads, `(2r+20)+201*(r+20)` already exceeds 5 s. Refuse before
new work if the qualified envelope or complete evidence cannot fit; do not omit
unaddressed streams, prune history or assume parallelism/batching. Any alternative
complete snapshot/batch protocol requires independent review; none is selected.
A deployment admission cap may limit accepted workload without deleting retained
history. Concrete limits, aggregate custody bytes and enforced latency remain
open, so **this proposal admits no production workload**.

All external calls happen **before final locks**, not inside F or WC1 terminal
gates. Keep original pre-binding/send/accept/command starts across preparation,
reconnects and all phases. A separately reviewed post-local-commit pre-release
confirmation may withhold authority until complete; it cannot retroactively
supply missing pre-binding authority or renew a deadline. Under final admission,
compare exact protected predecessor/read set/epoch and unused revision, take
sole m, verify purely, burn durably and enforce the complete endpoint. Apply
`m-s+f+epsilon<=T` and `m+f+epsilon<D`, original uncertainty <=1.5 s or stricter,
with no extra clock/provider read. Equality at D refuses. A valid arithmetic
example is neither native enforcement nor protection from a paused executor.

## 8. PENDING paired requirements and remaining decisions

[Custodian requirements in the storage inventory](storage-tests.md#pending-qualification-specifications)
are PENDING specifications, not executable/skipped passing tests. Each pairs
valid exact behavior with forbidden outcomes and a proposed narrowing control.
Existing storage and G16 tests remain unchanged; none qualifies this protocol.
Linux and macOS need independent native evidence for every admitted tuple. Linux
may activate only after its own full qualification; macOS stays closed until its
own qualifies. Proposal parity transfers no native evidence between platforms.

| Property | Owner / acceptance still required |
| --- | --- |
| Independent second witness, keys/epochs/pins and placement | Owner + WC1: concrete administration/pins/nonrollback root and prototype risk acceptance. |
| Exact durable compare-previous and original repeat | WC1: authenticated original-bundle contract, independent retention and complete crash/concurrency proof. |
| Challenge-bound retained head and separate current control | WC1 + consumer: fresh verification, authorized disclosure, owned bounded evidence and exact final read set. |
| Ambiguity/restore/continuity | Owner + WC1: either-side/joint-loss runbook, independent anchors and authorized genesis/rotation/migration; no reset. |
| Lifetime exclusion through write/sign/release | Owner + WC1 + consumer: actual-effect enforcer and replacement/restore protocol, not a point check. |
| Complete Keymaker/bootstrap/enrollment and broker mappings | Respective consumers + WC1: exact inventories/namespaces/use outcomes; no WS extension implied. Registry owns Q10; user-manager owns later PC2/A3d-2 acceptance. |
| Original deadlines and bounded inventory/calls | Consumer + owner: measured/enforced envelopes, 201-head and 250/1000 ms non-fit decisions; no restarted clocks. |
| Wire/error precedence and trust graph | WC1 + consumer + owner: exact versioned envelope/limits/ACL/continuity, finite acyclic custody/time root. G14/G15 remain separate. |

These are open acceptance and qualification questions in
[the gate register](../UNRESOLVED_QUESTIONS.md), not reasons to weaken the contract.
No manual recovery, periodic replication, local equality or new-lineage fallback
closes M0 custody or D5. Serving and activation remain unavailable.
