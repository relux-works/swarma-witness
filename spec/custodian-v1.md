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

Each adapter must select an authenticated **versioned consumer/profile** and
exact service/chain/stream binding, authorization, original-evidence contract and
protected verification dispatch. Admission, exact repeat, historical verification
and recovery use the **same accepted lineage/profile contract** and historically
applicable authorization, with current effect/release checks still required.
Keep each history and its calling credentials separate. None falls through a
Keymaker-only or broker-only decoder; unsupported or unenrolled profiles refuse
**before intent or disclosure**. Purpose-3 fields, broker generations and shared
M0 digests are not universal custody semantics.

Today [Append](../service/append.go) calls `records.DecodeKeymaker` both on new
admission and exact repeat (:100 and :62 at the proposal base); it cannot admit a
registry profile. [Checkpoint wrapper decoding](../records/checkpoint.go) is not
verification: its `Verify` remains closed. Later owner-registry enrollment needs
a separately accepted adapter and consistent protected dispatch at all four
paths, its own evidence/authorization contract and refreshed workload/qualification
envelope. It preserves existing profiles and closed WS objects. A syntactically
valid provisioned binding enables none of this. These are required future code
changes, not changes implemented by this documentation proposal.

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

Call the primary witness W1 and the independent custodian W2. The consumer's
independent bridge may originate the unpredictable challenge, or use an accepted
purpose-separated derivation from its fresh request. A challenge chosen solely
by W1 does not prove freshness independently of W1. W1 may relay W2 originals
only through an accepted delivery binding: independently verify W1 wrappers,
original receipts and complete record/control/intent proofs **and** W2 original
confirmations/fresh reads, against separate identities, pins, epochs and historical
authorization. A fresh W1 wrapper around old W2 evidence or W1's assertion that
custody succeeded is insufficient. Direct W2 retrieval is additional budgeted
work; no ad hoc member is added to closed WS responses.

The authoritative record and current control must form **one consistent view**:
an accepted linearization point within the read, or an equivalently qualified
multi-read protocol with explicit race/retry/refusal rules. Individually fresh
but mutually inconsistent reads refuse. For example, observe R0, then commit R1,
then change control to C1: a returned R0/C1 pair is not current. This does not
require R0's historical `control_hash` to equal C1; original record policy stays
immutable. Retain complete owned evidence and protected complete-read timing.
The concrete delivery/coherent-view protocol remains an acceptance gate.

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
| Committed confirmation, reply lost / primary not yet published | Recover only the original independently verified committed outcome and matching durable prepare, under authorized recovery and current fences. Retain exact confirmation/originals; never regenerate a receipt, silently publish an older root or send late success to an expired caller. Without that committed evidence the outcome stays unknown. |
| In flight or unknown, including delayed confirmation | Retain the original transaction/position and fence until resolved. An old-head/predecessor read, timeout or empty lookup never proves non-commit: a delayed writer may still commit. A later completion resolves only that occurrence, never late success or a replacement identity. |
| Authenticated confirmed final non-commit | Accept only independently verifiable terminal evidence bound to the exact original transaction, previous/next tuples, complete evidence and ownership epoch, with qualified exclusion of every in-flight/old executor from later committing that occurrence. Retain that final outcome and all burns/floors; no inferred cancellation, replacement ID, reused burn or renewed original deadline. Any permissible further action follows separately authorized exact recovery. |
| Primary restored/behind | Establish independent current custodian head/control and exact complete surviving originals, reconcile all pending/outcome/audit/use state. Missing bytes hold; a higher counter alone cannot reconstruct them. |
| Custodian restored/behind | Its restored database cannot assert latestness. First establish its true current position from independent retained recovery anchors/evidence outside both relevant restore domains. Primary transfer alone cannot authorize catch-up; dependent paths hold until exact continuity is proved. |
| Custodian ahead or either side conflicting | Hold affected authority; reconcile exact predecessor and acknowledged outcomes using independent originals. Do not pick the larger sequence or reset the other side. |
| Joint loss or compromise of independent evidence | No recovery guarantee. Remain closed; no recreated lineage, implicit first use or automatic mode downgrade. |

The future provider protocol must distinguish **committed-original**,
**pending/unknown** and **terminal non-commit** evidence before a consumer resolves
uncertainty; absent that accepted distinction, it stays held. These are semantic
outcomes, not new wire members or error codes. Final non-commit of a confirmation
also does not prove that unrelated local/consumer effects did not happen.

Terminal non-commit requires either a durable authenticated terminal disposition
of that exact occurrence, or a completed authenticated epoch/fence transition
whose retained resolution both establishes non-commit and disables every remaining
effect of the old occurrence. Merely changing epoch or stopping one worker cannot
settle an already committed or unresolved transaction. Once terminal non-commit
is established, **late arrival or retry can never convert it into committed**.
Committed recovery preserves the original fixed bytes and grants no late consumer
act. Without this qualified terminal proof or committed original, stay held;
the resolution encoding and enforcement mechanism remain joint acceptance gates.

The first authoritative checkpoint of each separately enrolled broker scope
requires **explicit operator-approved genesis**, bound to the protected broker
installation identity and scope. Empty/missing state is never fresh-start
authority, including after restore. No production genesis path is supplied.

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
confirmation/use. Preserve independently current Epoch, private per-attempt Run
bound to preparation, and original use revision as distinct identities. If the
old-instance fence needs a process incarnation identity, bind it separately;
never overload Run. Provider confirmation cannot
recall an already emitted signature, so downstream effect boundaries must also
honor their accepted revocation/ownership checks. Emergency stop must not wait
for locks, a provider reply or that dependency graph to complete.

Apply these fences independently to W1, W2, the broker writer and every enrolled
registry writer/bridge/publisher. A restored broker clone cannot write time W,
holds or D5 acknowledged-head/start-fence state. Delayed delegated confirmation
and prepared response release remain covered; another consumer's fence is not
proof of exclusion for these actors.

The joint broker/enforcer binding must cover installation, **both broker scope
identities**, ownership Epoch, private per-attempt Run bound to preparation,
original use/transaction revision and protected effect handles.
The custodian validates that authority **before
confirmation and before release**; enforcement must continuously cover broker
W/hold/D5 writes, local pointer publication and material release through their
complete endpoints. Revocation propagation, delegated/in-flight effects, old-instance
exclusion before replacement and recovery all use that same authority. A successful
CAS, point check, cached receipt or timer cannot supply it. Emergency stop remains
independent. The concrete binding/enforcer is unaccepted, not implemented here.

## 7. Consumer bindings and budgets

The following are required adapter properties, not implementations or expanded
wire scopes. One custodian retains separately authenticated consumer namespaces;
no cross-consumer sequence, control, transaction or epoch substitution is allowed.

| Consumer | Protected inputs and retained association | Boundary / missing binding |
| --- | --- | --- |
| WC1 | Exact service/record/control predecessor and successor, original transaction and bundle, independent current control/pins, audit archive ack, reservation and original deadline; retain original confirmations and complete S3 P/R/X outcomes. | External confirm/read/archive/signing precede final G/S/A/L admission; exact recheck under gates, then sole m, pure verification, durable burn and bounded endpoint. This is WC1 P/R/X, not registry C/V/F; record custody is not registry truth or audit custody. |
| owner-registry (awaiting separate enrollment) | The independent registry bridge verifies and retains all eight checkpoint projection fields, exact checkpoint/candidate and complete W1/W2/control/intent originals; only then derives the closed six-field JournalWitness by omitting checkpoint_time and candidate_digest. | The custodian does not perform that adapter or attest C's physical durability. Advancing-anchor verification, pre-intent genesis/historical verification and same-registry-sequence/head checkpoint_id fork detection remain registry prerequisites. No fabricated witness fact enables pre-intent verification. Registry C/V/F and their uses stay distinct from WC1 P/R/X and remain closed. |
| Keymaker bootstrap and A/P | Complete master-epoch/public name/index/tombstone and allocator history, purpose-1 binding/results, purpose-6 original B0–B5 occurrence/stage/association/policy/activation outcome, audit, root and deployment floor and exact generation/read-set authority. Retain intent, originals, confirmation, commit/resolution and original retry result. Secret master/key bytes never enter WC1 evidence. | Connect the accepted Keymaker intent → local commit → acknowledged resolution → use contract to the full inventory and root/release. No live B0–B5 adapter, full-use custody or finite bootstrap budget is supplied. A/P bindings cannot stand in for E-I/E-C consumption. |
| Keymaker enrollment E-I/E-C | Exact independently confirmed issue/reload occurrence, original start/D, approval/ledger generation, high-water/registry/pin/config and invalidation predecessors, candidate epoch and original approval expiry; retain burn/held/committed outcomes and full handover evidence. | E-I durable issue/publication and E-C invalidation → unlocked preparation → exact final admission → consume/use/swap remain distinct. Unknown state never reissues an approval or opens authority. Independent custody must survive coherent restore of ledger, use and candidate together. |
| Broker timeconf RollbackWitness (separate enrollment) | Scope includes protected broker installation identity, purpose, history identity and its own credentials/ACLs, plus exact time-settlement lineage: WitnessHead generation/digest, settlement ancestry, originals, consumed W, holds/in-flight and operation/challenge association; current confirmed head and original deadlines. | Fresh authenticated read and exact-predecessor durable commit before final locks, no generation reuse/wrap; OriginalReader validates originals separately. Full uint64 generation cannot be cast/truncated into WS safe-integer seq. Mapping/namespace/envelope remain unaccepted; no automatic WS tuple extension. |
| Broker D5 (separate enrollment) | Separately retain the store's acknowledged head and start fence: the acknowledged owning store/root inventory, durable restore/start fence, reconciliation result and reopen authority, bound to the broker installation identity, purpose, history identity, its own credentials/ACLs and exact original transition. Every supported start/recovery path checks these with admission closed. Its history/enrollment is separate from timeconf settlement. | Same locally checkable exact-predecessor/outcome and G18 broker-writer obligations; manual recovery is not D5 closure. D5 mapping/authority/genesis and native qualification remain open. |
| User-manager PC2 floor / A3d-2 (later separate enrollment) | Exact owning root, floor, cut, debt, attempt, use/outcome and current ownership continuity under its accepted consumer contract; retain authoritative originals across restore. | Shared custodian direction does not define these formats. Joint PC2 live spend-cut/base binding, concrete scopes and acceptance remain prerequisites; no RPC under F. |

The two broker enrollments cannot substitute history, credential, genesis approval
or original transaction for each other. Each needs an explicit operator-approved
first checkpoint; replacement/migration must preserve acknowledged ancestry,
maximum W, holds and pending outcomes. A matching D5 digest alone is no start or
reopen authority. These are joint broker binding gates: today's closed WS profiles
are Keymaker, registrar and owner-registry; a broker cannot masquerade as one.

A joint typed broker contract must specify versioned broker profiles and custody
envelope, canonical bytes/signature domains, complete original-bundle closure,
request/response correlation, authorized principals, size/depth/history limits
and error/outcome mapping. Confirmation verification uses **owned immutable bytes
and independently enrolled expectations**, with no hidden remote lookup under
locks. Begin and final settlement are distinct durable transitions with stable,
phase-specific original retry identities; one confirmation cannot cover both.
Preserve the full uint64 generation domain. The broker's time challenge is
**32 hex characters (16 bytes)**, while the custody challenge is **32 bytes**:
use separate fresh nonces with an explicit original-request association; **never
pad, truncate or equate them**. These are required properties, not new fields,
preimages or an accepting adapter. Native evidence and joint contract acceptance
must precede enrollment or production use.

For registry Q18 option (i), immutable witnessed content is separate from later
atomic completion/use metadata under a versioned **non-circular composite root**.
The selected custody service must accommodate separately approved completion,
visibility and use namespaces with **their own independent rollback authority**,
exact predecessor acknowledgments, retention, authorized genesis/migration and
recovery. Record custody and Keymaker/broker acceptance do not protect those
metadata. Approve atomic content/completion/use coupling and bridge authentication
before registry activation. Never add completion fields to frozen content/closed
witness records, add a remote step under final locks, or let a later acknowledgment
retroactively supply missing act/use protection. The schema and those bindings
remain open. See the pinned [registry bridge and eight-to-six contract](https://github.com/relux-works/swarma-owner-registry/blob/79d92d6521fd984e46b35238f848b7ff954a3ef0/design/owner-registry.md#L834-L919)
and [Q18 boundary](https://github.com/relux-works/swarma-owner-registry/blob/79d92d6521fd984e46b35238f848b7ff954a3ef0/design/owner-registry.md#L1533-L1547).

Consumer source contracts: Keymaker [witness integration](https://github.com/relux-works/swarma-keymaker/blob/1cb18bc28580f946bba4643d509853e3374d58cd/spec/keymaker-witness.md#L47-L68)
and [station bootstrap](https://github.com/relux-works/swarma-keymaker/blob/79b37d2d0a6fbacae1174ec97c8f07d09681fe00/spec/keymaker-station-caller.md#L262-L321);
Keymaker [QT-2c proposal at 6023815](https://github.com/relux-works/swarma-keymaker/blob/60238159b0adf9aa6883f9cd661b5903077fb362/spec/keymaker-qt2c-profile.md#L344-L450);
broker [RollbackWitness](https://github.com/relux-works/swarma-credential-broker/blob/8709e215a1b6bc7f42094a14e4a5620e2baed290/timeconf/settlement_linux.go#L15-L38),
[settlement order](https://github.com/relux-works/swarma-credential-broker/blob/8709e215a1b6bc7f42094a14e4a5620e2baed290/docs/qualified-time-api.md#L109-L154)
and [handoff custody boundary](https://github.com/relux-works/swarma-credential-broker/blob/8709e215a1b6bc7f42094a14e4a5620e2baed290/docs/time-handoff.md#L215-L230).
Broker [current reserve/deadline checks](https://github.com/relux-works/swarma-credential-broker/blob/8b45a165fa528395da5f8b098ac722427c90dce5/timeconf/consume_linux.go#L137-L158),
[uncertainty and reserve](https://github.com/relux-works/swarma-credential-broker/blob/8b45a165fa528395da5f8b098ac722427c90dce5/timeconf/consume_linux.go#L285-L295),
[challenge encoding](https://github.com/relux-works/swarma-credential-broker/blob/8b45a165fa528395da5f8b098ac722427c90dce5/timeconf/receipt.go#L103-L110)
and [shared uncertainty cap](https://github.com/relux-works/swarma-credential-broker/blob/8b45a165fa528395da5f8b098ac722427c90dce5/timeconf/policy.go#L23-L32)
constrain the later joint binding. These pins identify reviewed inputs, not
activation approvals or dependency bumps.

The broker's current settlement session uses a local exclusive flock while
calling `Read`/`CompareAndSwap`. Inserting network traffic into that held section
would violate the final-lock rule. A future adapter needs separately reviewed
unlocked preparation/reservation and exact revalidation/publication ordering,
while retaining the independently current head and exclusion. The existing
interface does not by itself provide that handover or an accepting remote path.
For each broker scope, the accepted contract must provide **exact-predecessor
commit before final locks**, followed by a protected, locally checkable outcome
as fixed authenticated bytes bound to the original transition and ownership.
No under-lock read/confirm/poll may be needed to validate that outcome. Specify
a ready finite per-operation budget; **backward-time tolerance is zero**, not a
grace period inferred from uncertainty allowance. Retain the three §5 outcomes
and broker-writer fence; an old-head read never reopens admission.

### Broker operation envelopes: open joint gates

Each row needs its own reviewed finite envelope. For every row specify original
start/exclusive D and tighter caller limits; challenge age and original-request
association; complete ancestry bytes/depth; **actual** remote RPC count, current
control and original retrieval; authentication, cold connections and retries;
local durability, drain, handoff and teardown reserve; final T/f/epsilon and the
endpoint that enforces them. No row below supplies missing numeric limits. Unknown
bounds refuse, including at restore/start before opening admission.

| Broker operation | Required operation-specific inventory / still-open bound |
| --- | --- |
| Initial enrollment | Separate approved genesis and full initial originals for each scope; current head/control and exact confirmation as required by the accepted protocol. RPC/page counts, age, depth, durability and reserve limits are joint inputs; no empty-as-genesis shortcut. |
| Ordinary time consumption | One witness Read plus **two distinct Confirm operations: begin and final settlement**, plus all actual current-control/original retrieval, collection, local publication and drain. Three operations are a lower bound, not the hypothetical three-call boundary's one-confirmation path. Phase retry identities and complete call/age/ancestry/reserve bounds remain open. |
| Exact-outcome recovery | Resolve only the original transaction/phase under §5, with complete original outcome, current scope/control and fence evidence. Unknown outcomes remain held. Retrieval/resolution calls, age, depth and local reconciliation reserve need joint bounds; no new caller deadline or late act. |
| D5 current-head / start check | Verify owning root inventory, acknowledged head, durable start fence, reconciliation result and reopen authority on every supported path. Current control/original reads and all age/depth/call/reserve bounds need joint acceptance; head equality alone cannot open. |
| D5 acknowledged advance | Exact predecessor, durable independent acknowledgment and owning local inventory/publication under continuous G18. Count every required read/confirmation/original/control exchange and its local durability reserve; D5 must not borrow the time-settlement envelope. |
| Restore / reopen | Both scopes' retained ancestry, maximum W, holds/pending outcomes, independent anchors, authorized reconciliation/reopen and exclusion of all old effects. Bound complete retrieval/control/fencing work and each local endpoint before reopening; no reset or recovery-created time allowance. |

For each time-qualified path, broker code requires **reserve >= budget + handoff**
and **measured uncertainty + reserve <= MaxUncertainty <= 1.5 s** (or stricter
policy). The enclosing consumption budget includes collection, custody, local
durability, drain and teardown, and is intersected with the original caller D.
A nominal 10 s request ceiling therefore **does not fit as a general custody
allowance**; no broker-specific fit is established by either arithmetic table.
Non-time D5/start/recovery paths also need an accepted finite bound and enforcing
endpoint; any time component must satisfy these same stricter intersections.
Zero backward tolerance is a separate detect-and-hold rule, not zero latency or
permission to widen uncertainty.

A reviewed reserve/prepare and handover must run outside final locks, preserving
local durability order and exact final head/epoch/use revalidation/publication.
Do not insert a network provider into flock-held RollbackWitness calls. Retain
one qualified suspend-aware clock read after full final admission and a pure
local verifier, with no hidden provider call. All six operation envelopes, wire
bindings and native endpoints remain joint acceptance gates; no accepting adapter is supplied.

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

| Hypothetical shared-connection span (ms) | Same region | EU | EU with one loss/retry |
| --- | --- | --- | --- |
| One boundary, N=3, K=1 | 230 | 480 | 895 |
| Two boundaries, N=6, K=2 | 420 | 820 | 1235 |
| Four boundaries, N=12, K=4 | 800 | 1500 | 1915 |

The table assumes one shared cold connection and at most one modeled loss.
That is a **hypothetical future custody transport**, not the existing
[one-request-per-connection TLS profile](tls-profile.md), which has
`one_request:true` and `resumption:false`. No connection-reuse optimization is
accepted. If each exchange uses that cold profile, charge setup **per exchange**:
`N*(3r+40)+K*100`, before earlier/unmodeled work or loss.

| Cold one-request profile (ms) | Same region | EU | EU with one loss/retry |
| --- | --- | --- | --- |
| One boundary, N=3, K=1 | 310 | 760 | 1035 |
| Two boundaries, N=6, K=2 | 620 | 1520 | 1795 |
| Four boundaries, N=12, K=4 | 1240 | 3040 | 3315 |

For this cold model the failed call consumes the same full 250 ms timeout plus
25 ms backoff. The successful retry's setup is already included in its per-call
cost, so add 275 ms, not a second 140 ms reconnect; other failure traces must
charge their actual failed setup/work once. No retry is owed if remaining budget
cannot cover it and all mandatory work. Both models remain unmeasured. Accepting
a concrete custody transport/reuse decision and the complete actual call inventory
is an owner/consumer prerequisite; neither table qualifies registry C/V/F or
claims three calls cover its attempt. Figures in the verdict table distinguish
these models. They are not a PC2 step count. Never double-charge one mutation's
confirmation to both P/R, but never omit a genuinely separate read, confirmation,
archive or time call.

| Original budget | Arithmetic verdict / condition |
| --- | --- |
| WC1 P/R/X <=5000 ms, stricter accept/caller limits | Conditional fit for the modeled spans; charge the complete TLS/header/body/P/custody/R/X work against the original intersected deadlines. R/X do not start a fresh 5 s. Native commit/send bounds remain undefined/refuse. |
| WC1 TLS handshake-start+3000 ms, accept-start+5000 ms | One cold boundary 310/760/1035 is a conditional arithmetic fit only with full original-accept propagation and reserve for TLS/time work; no callback-created replacement timer. Shared-connection values require a future accepted transport. |
| Keymaker A/P and registration R-S/R-X native <=2000 ms | One cold boundary may fit arithmetically; four cold EU boundaries 3040/3315 do not. Original <=250 ms generation windows independently veto all modeled cold boundaries. Standalone root/helper budgets remain undefined/refuse. |
| Any actual <=250 ms reader/PC2 step containing one remote boundary | Cold 310/760/1035 **do not fit**, even same-region. Hypothetical shared same-region 230 leaves only 20 ms; shared EU/loss also do not fit. Owner budget/transport question unless already permitted unlocked preparation moves work before the subwindow without losing currentness or enclosing clocks. |
| Keymaker E-I <=60000 ms, whole E-C <=10000 ms (6023815 proposal) | Conditional fit for modeled custody, not qualified or activated. E-I includes human/config/inspection/output/publication from original entry; E-C includes serialization, load, preparation, consume/use/swap. Load gets only its remaining original 10 s subdeadline. Shorter native/reader/approval limits still win. |
| Q7 / K3-G6 | Conditional for bounded native <=2000 ms; any <=250 ms intersection vetoes all modeled cold boundaries and shared EU/loss. Fresh-evidence lifetimes and 64-publication count are not execution budgets; standalone re-anchor remains undefined/refuse. |
| PC2 1000 ms from original pre-binding | One cold 310/760 is conditional; cold loss 1035 and four cold 1240/3040/3315 **do not fit**. Shared four-boundary 800 is conditional same-region only under a future accepted transport; 1500/1915 do not fit. Actual call count and pre-binding authority contract remain open. |
| PC2 send-start+2000 ms observation | Four cold same-region 1240 is conditional; cold EU 3040/3315 do not fit. Hypothetical shared four-boundary loss 1915 leaves only 85 ms for earlier/unmodeled work. No new timer at binding/commit/retry. |
| Broker timeconf nominal request ceiling <=10000 ms | **No general fit.** reserve >= budget + handoff and measured uncertainty + reserve <= MaxUncertainty <=1500 ms (or stricter) dominate. The six broker operation envelopes above remain unbounded/unaccepted; custody, collection, local durability, drain and teardown must all fit original D and those inequalities. |
| Serial 201-head inventory under WC1 5000 ms | Reads alone 14070/44220 ms cold same-region/EU; hypothetical shared 6070/16220: **neither fits**. No admission at this workload under these assumptions. |

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
control. With 201 reads, cold `201*(3r+40)` or hypothetical shared
`(2r+20)+201*(r+20)` already exceeds 5 s. Refuse before
new work if the qualified envelope or complete evidence cannot fit; do not omit
unaddressed streams, prune history or assume parallelism/batching. Any alternative
complete snapshot/batch protocol requires independent review; none is selected.
A deployment admission cap may limit accepted workload without deleting retained
history. Concrete limits, aggregate custody bytes and enforced latency remain
open, so **this proposal admits no production workload**.

**Q21 is one shared open rule for WC1 and all consumers.** Define each operation's
exact fresh record-head set and current-control coverage, coherent-view/race
rules and finite streams/calls/pages/bytes/serialized-work envelope across the
complete attempt. Existing **all-populated-stream plus current-control checking
stays mandatory** until an accepted replacement demonstrates **equivalent rollback
and cross-stream/control protection**. A qualified full-inventory cap is valid.
Each consumer must have its own explicitly qualified finite envelope under that
rule. Enrollment, profile/control changes and inventory growth are admitted
against **every affected consumer's envelope** before invalidating an existing
bound. Refuse excess without dropping comparisons, truncating history or losing
startup/restore, audit or exclusion obligations. A changed protocol/envelope needs
review and qualification; one consumer's passing model cannot qualify another.

Before starting **and before every retry/reconnect**, compare remaining original
exclusive D to the next exchange plus **all uncompleted mandatory work**: setup,
transfer, heads/control, exact confirmation, separate audit acknowledgment,
complete proof pages/originals, time/settlement/signer/exclusion, bridge verification,
durability and every remaining window's f, epsilon and reserve. Unknown bounds
do not fit. Stage limits are maxima within the same attempt, never additive
allowances. Charge nested work once; never reuse another window's reserve or
compare different hosts' absolute monotonic values. Insufficient budget refuses
further authority and fences unknown outcomes; exact recovery cannot reopen the
expired caller.

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
| Challenge-bound retained head and separate current control | WC1 + consumer: bridge-originated challenge, independently authenticated W1/W2 delivery, one coherent record/control view, authorized disclosure, owned bounded evidence and exact final read set. |
| Ambiguity/restore/continuity | Owner + WC1: either-side/joint-loss runbook, independent anchors and authorized genesis/rotation/migration; no reset. |
| Lifetime exclusion through write/sign/release | Owner + WC1 + consumer: actual-effect enforcer and replacement/restore protocol, not a point check. |
| Complete consumer mappings and profile dispatch | Respective consumers + WC1: authenticated versioned dispatch across admission/repeat/history/recovery; separate Keymaker, broker timeconf/D5 and later registry/user-manager scopes. Registry owns eight-to-six, anchor/fork and Q18 completion/visibility/use authority; no WS extension implied. |
| Original deadlines and bounded inventory/calls | Consumer + owner: shared Q21 rule, per-consumer measured/enforced envelopes and growth admission for all affected consumers, accepted transport, cold-profile 201-head and 250/1000 ms non-fit decisions; no restarted clocks. |
| Wire/error precedence and trust graph | WC1 + consumer + owner: exact versioned envelope/limits/ACL/continuity, finite acyclic custody/time root. G14/G15 remain separate. |

These are open acceptance and qualification questions in
[the gate register](../UNRESOLVED_QUESTIONS.md), not reasons to weaken the contract.
No manual recovery, periodic replication, local equality or new-lineage fallback
closes M0 custody or D5. Serving and activation remain unavailable.
