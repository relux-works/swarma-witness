# WC1 QT-2c window profiles

Status: **proposal requiring contract and owner review; unimplemented and
unqualified on Linux and macOS**. Acceptance of these profiles is a prerequisite
for a G16 codec or adapter, not activation. S1/S2, G07/G10 and record-key rotation
stay closed. No listener, time provider, use store, custodian, archive or
exclusion backend is supplied. This document changes no closed WS request,
receipt, head, audit line, control record, custodian tuple or provider receipt.

There are four distinct consuming windows: **P** local prepare/audit, **R**
post-custodian root publication, **X** actual response release, and **TLS** peer
validation/admission. A private checked result, prepared success audit or durable
root never authorizes another window's act. The proposed names and transitions
below are WC1-owned; they do not reuse another consumer's use format.

## Source pins and interpretation

References such as `H:110–122` mean file and line numbers at the pinned revision
in this table. S3 storage, lock and phase choices described here remain proposals;
there is no S3 storage implementation to cite as a qualified mechanism.

| Name | Immutable source |
| --- | --- |
| Schema | [Broker seven-group schema](https://github.com/relux-works/swarma-credential-broker/blob/7294b7aea68a8e0757437075efa3a6e318a18e51/docs/time-window-profile.md), especially lines 15–89 |
| Handoff | [Broker handoff, including N1–N3 and named controls](https://github.com/relux-works/swarma-credential-broker/blob/7294b7aea68a8e0757437075efa3a6e318a18e51/docs/time-handoff.md) |
| Mac | [Mandatory macOS binding](https://github.com/relux-works/swarma-credential-broker/blob/7294b7aea68a8e0757437075efa3a6e318a18e51/docs/time-handoff-macos.md) |
| API mapping | [Broker Run/Epoch and native-operation mapping](https://github.com/relux-works/swarma-credential-broker/blob/b38aeda82fb563503960836c771bcc94e8103810/docs/time-handoff-api.md), especially lines 85–102; mapping reference only, no dependency or activation change |
| Release rule | [Required durability before success](https://github.com/relux-works/swarma-credential-broker/blob/b38aeda82fb563503960836c771bcc94e8103810/docs/time-handoff.md#L148-L155) |
| Transition alphabet | [Broker enrolled-ID alphabet](https://github.com/relux-works/swarma-credential-broker/blob/b38aeda82fb563503960836c771bcc94e8103810/timeconf/receipt.go#L103) and [handoff transition-version validation](https://github.com/relux-works/swarma-credential-broker/blob/b38aeda82fb563503960836c771bcc94e8103810/timeconf/handoff_linux.go#L158) |
| WS | [Conditional service contract](https://github.com/relux-works/swarma-keymaker/blob/b232f6aec52e9327daffd8e889b52ed0ebd2fd3f/spec/witness-service.md), especially lines 181–243, 473–544 and 598–616 |
| H | [S2 transport predicates](https://github.com/relux-works/swarma-witness/blob/c18d70040d11a6a03078df1e61c1bf3aa0dae85a/transport/handler.go) |
| TLS | [S2 qualified-time interface and TLS predicates](https://github.com/relux-works/swarma-witness/blob/c18d70040d11a6a03078df1e61c1bf3aa0dae85a/transport/tls.go) |
| Policy | [S2 transport/policy contract](https://github.com/relux-works/swarma-witness/blob/c18d70040d11a6a03078df1e61c1bf3aa0dae85a/spec/policy-v1.md), lines 100–111 |
| Registry | [Owner-registry QT-2c design, sections 9.1 and Q18–Q20](https://github.com/relux-works/swarma-owner-registry/blob/cf3e35db73c82055552fe896b62e0a4ff2a43794/design/owner-registry.md) |

The accepted consumer examples provide documentation structure, not WC1 budgets,
locks or semantics: [Keymaker profiles](https://github.com/relux-works/swarma-keymaker/blob/4b9aebbaa74598b95ff0b071ae5218a7aa89c57c/spec/keymaker-qt2c-profile.md)
and [user-manager profiles](https://github.com/relux-works/swarma-user-manager/blob/b8fa8c0eafd7c1ced23b9a98371fac02ab9360be/spec/requalification-time-windows.md).
WC1 does not inherit their 250 ms, 1000 ms or 2000 ms windows.

## Shared requirements, version 1

Every group below incorporates these requirements. They are documentation
semantics, not an implemented codec or interchangeable cross-consumer record.

**Identity and staging.** Protected enrollment fixes the native profile, machine,
consumer, purpose, authority/adapter/policy and independent continuity scope.
Propose native identity codec `witness-window-intent/1` for P/R/X, with canonical
CCJ-1 bytes B under the existing native operation recipe:
SHA-256 of ASCII `qualified-time/consumer-operation/1`, NUL, uint32-BE length of
profile, profile, uint32-BE length of B, then B. B is at most 65536 bytes; its
closed encoding, field bounds and vectors require joint review before use.
The required semantic inputs are service, protected authority generation/live
incarnation, original retained operation identity, authenticated principal and
method, exact original canonical argument digest, existing signing purpose,
phase/slot, expected predecessor root/control/audit/use revisions, frozen
candidate objects and original deadline tuple. No caller chooses enrollment or
expected state. TLS retains its own existing codec below.

Each operation owner durably fixes its authorized phase/slot set before
preparation. Request ID is correlation, not a new deduplication contract. A retry
of an append position binds its original exact bytes and predecessor; an audited
lookup is a distinct authorized operation and cannot append/sign the record
again. A live incarnation authenticates the executor but cannot create unused
slots after restart. Keys below use a stable independently protected service
lineage and original operation ID, not the current process incarnation.
Original operation IDs and allocated slots never repeat within that lineage;
revision exhaustion refuses without wrap, reset or deletion of tombstones.

The graph is original protected intent → already frozen content/arguments and
expected predecessors → fresh receipt/settlement/original closure → private H →
use/completion/outcome. Original issuance/signing, including any qualified `at`
used in a frozen audit, finishes outside final locks before the revalidation
handoff. Revalidation cannot retime or re-sign those bytes. If issuance and
revalidation cannot be staged without a cycle, that path refuses pending its
own reviewed issuance binding. Neither H, m nor a completion digest containing H
is an input to the operation digest or frozen content manifest. Later use-owned
references bind that immutable content without editing it. TLS, record/control,
audit and time-provider keys/purposes remain separate.

**Timing and reserve.** All windows use s for their own receipt's original
elapsed observation, require no extra pre-lock capture, and set p=s. m is exactly
one fixed qualified suspend-aware read outside the pure check, after every
initial admission. No native c/n has a second meaning. Retain original boot,
clock/domain, start, exclusive absolute D, original UTC deadline and every
original budget plus the conservative mapping identity in protected intent.
Use checked signed-64 integer nanoseconds, round elapsed bounds up and exclusive
deadlines down; reject overflow, nonrepresentability, boot/domain mismatch and
unqualified mapping. A receipt lacking this tuple cannot invent it. Require:

```
m >= p >= s; T > 0; f > 0; epsilon >= 0
m - s + f + epsilon <= T
m + f + epsilon < D
```

T is fixed from s through the entire window endpoint, not a remainder beginning
at m. D is the earliest of all actually applicable original deadlines. A fresh
phase, page, challenge, retry, reconnect or recovery never renews any start,
D, T or reserve. `undefined` means a missing specified budget/input and refuses;
`pending qualification` means a specified limit without native proof and also
refuses. No unspecified f/T/epsilon becomes zero or unlimited.

Authenticate the original settlement reserve and error/rate rule before W
advances. Original source uncertainty plus reserve must fit total delta <=1.5 s
or stricter protected policy. Cover all elapsed preparation/admission since s
and the complete residual endpoint once; T includes already charged error, not
a second charge. Preserve original O, delta and [L,U], U<A and
L>max(prior provider W, imported J), plus stricter locked consumer floors and
certificate/authority expiry. Do not shift O, shrink delta, enlarge reserve or
transfer one window's reserve to another. Coarse projections, if used, must also
pass the original nanosecond predicates; provider W is not a consumer admission
watermark. Each window settles independently within the original attempt.

**Authenticity.** Option (d) is a trusted single process on one host: a qualified
protected original reader authenticates full eleven-fact receipt, exact original
source/settlement/record closure, confirmed acknowledgment, current independent
witness checkpoint and complete ancestry before final locks. Dedicated
`chrony-nts-authdata`, verified NTS association, source confidence, W/holds and
in-flight continuity remain required. Pin installed reader/validator/qualification
and checked descriptor/object identities; a digest, structural decode, opaque Go
value, nonce or boot UUID is not that authority. Retain immutable disjoint owned
bytes and qualify live custody/invalidation through completion for hold/step,
policy/authority change, lost originals and competing executor. A copied snapshot
cannot discover an otherwise unobserved revocation. Crossing process/host trust
boundaries needs a separately accepted authenticated delivery profile, never a
borrowed key or requester-chosen validator.

The original-reader closure is bounded before allocation: <=64 objects, <=8 MiB
aggregate, depth<=16, no cycles, each object<=8 MiB, receipt<=65536 bytes, including
all ancestry/backend witness material (Handoff:202–212). Missing, excessive or
unauthenticated originals return no bundle; never truncate. These limits do not
enlarge any WS wire cap. Proposed S3 immutable segment/index<=1 MiB, journal
entry<=64 KiB, root marker<=4096 bytes and audit line<=4096 bytes must include
all use/outcome references and precharged temporary copies. WS:534–544 further
bounds frames65536, lines8192 including LF, receipts4096, streams1024,
operations16, history100 GiB, audit1 GiB and reserve16 MiB. A complete closure
that cannot fit refuses; exact file-count/workload profiles remain undefined.

**Final protocol.** Proposed final order is admission/config gate **G** → affected
stream gates **S** in lexical order → global audit gate **A** → local storage/
persistence gate **L**. Modes are exclusive for mutation; stream-free TLS takes
G then L with S/A absent. An outer lifetime authority fence **E** is continuously
effective, including across unlocked RPC phases; it is not a local flock. A
bounded protected reservation serializes a pending global audit tail across
unlocked custody/archive calls; pending work blocks competing tail allocation.
Reservation acquisition and all provider, witness, original-reader, archive,
custodian and signer work precede final admission. No RPC or lock upgrade under
terminal gates. Stop acquires none of these gates and waits on no indirect holder.

`VerifyWindow` itself is pure: no clock, file or network I/O. Under the terminal
gates, allow exactly the one fixed qualified read m outside `VerifyWindow`, plus
the bounded local burn, act and durability steps of that window. Forbid any extra
clock read and any external provider, original-reader, signing, custodian or
archive work under those gates. The permitted local act includes X's specified
response write; it does not permit external qualification or custody work.

Under the named full final chain, complete initial persistence **and** consuming
use/CAS admission; select exact current protected head, epoch and unused revision
before m. Even nonwaiting initial admission after m is forbidden. Then capture
m once; pure `VerifyWindow` takes bounded owned preparation, independently
expected intent/boot/deadline, locked read set/use revision/floors and m. It does
no clock read, callback, I/O, provider access, traversal or mutation and returns
only a candidate/refusal. Serialize the durable burn under retained admission
before any separable act. Keep the final chain through the local endpoint or
fenced failure. If a later completion reentry is necessary it needs a reviewed
continuously retained outer fence, the same original f/D and no new read; this
proposal grants no initial admission exception. Retire the checked preparation
on any final-lock release, failed check, expiry, changed boot, run or epoch, or
invalidation (N3). At most one live candidate per logical slot is admitted.

**Consumer-owned use.** Propose semantic transition **`WC1TimeUse/1`**, carried in
the next reviewed version of the owning S3 transaction, not an independent
acknowledged side ledger. Its exact bytes, genesis/migration, retention/capacity,
independent custody and recovery bindings still require review. Existing WS
audit fields and the proposed frozen content segment are not spare storage for
H. Propose retaining exact H/envelope reference and authenticated original
closure references in use-owned metadata linked to the frozen content; no H is
required inside that content or any closed WS wire object. Those references
must be bounded, retained and independently authenticated, not just hashed.

**Protected transition mapping.** Proposed mapping version
`witness-transition-map:1` has exactly one reviewed entry:
native `WC1TimeUse/1` ↔ enrolled `WC1TimeUse:1`. The native name labels WC1's
owning transaction semantics; the enrolled value is the broker-facing
`transition_version`. The protected enrollment fixes this exact case-sensitive
pair and mapping version for all four windows. At preparation, derive
`WindowExpected.TransitionVersion` and handoff metadata `TransitionVersion` from
that entry; at encoding, supply the identical enrolled `WC1TimeUse:1` to
`EncodeHandoff`, never the native slash-bearing name. Decoding/verification must
match the same protected entry and expected value before use. The inverse
mapping accepts only that exact enrolled literal. No generic slash substitution,
caller-selected mapping, version inference or fallback is permitted. Missing or
changed mapping, literal `WC1TimeUse/1` in the broker field and wrong version
`WC1TimeUse:2` refuse; syntactic acceptance of another enrolled ID is insufficient.
The mapping neither creates a new logical slot nor changes any broker/WS codec.

The future native transition retains the exact stable logical tuple below
alongside the broker `Operation` digest binding the live epoch and native read
set. Broker `Run` is a private per-attempt nonce; `Epoch` is the independently
enrolled live-writer fence, compared separately with the locked epoch (API
mapping:85–102). Re-derive `Operation` from protected locked state before m and
compare the full native predecessor and unused revision at consumption. A changed
`Operation` digest after replacement or a read-set change is never a new unused
WC1 slot; an API `UseKey` containing that digest cannot replace the stable tuple
and retained burns. This is a future codec/adapter obligation, not an accepting
mapping or a change to any closed provider/WS record.

For each key below, compare exact predecessor and independently proven
`unused(v)` under the final chain. `unused(v) -> burned(v+1, exact intent)` is
durable before the separable act. Then only that still-live fenced admission
may make its one act attempt within f/D. `burned -> committed(exact outcome)`
requires all authoritative local durability/recovery bindings; incomplete or
unknown authority becomes `held`, still burned. Each window also requires its
full endpoint. For X, the committed outcome is **release authority before send**,
not a claim of delivery; its distinct send bound and later accounting are below.
No fresh H, challenge, run or epoch, failed act, missing file or restored root makes
it unused. Provider W, holds and associations were settled earlier and never
refund. An atomic act/use alternative requires a demonstrated transaction, not
two files and one rename. Keep exact outcomes and tombstones after cleanup.
Internal use persistence is part of the owning transaction, not a recursive WS
audit operation. A separate ledger needs an explicit owner decision.

**Refusals and enforcement.** `handoff_unqualified` is an internal activation
reason mapping to existing `profile_unavailable`; clean expiry maps to
`deadline_exceeded`, missing continuity/durability to `storage_unavailable`, and
uncertain irreversible append/control to `outcome_unknown` with the scope held.
During TLS close without an application frame. Preserve existing authorization
and mixed-failure precedence; no template label creates a WS error member.
A finite enforced f or deadline-honoring act must cover verification, burn,
GC/preemption, contention, faults, pause/suspend, every file and namespace
barrier, readback, outcome and necessary cleanup. Timer cancellation, an average
latency, full flush or post-effect check cannot prevent late effects. No WC1
window currently has this proof: all remain `handoff_unqualified`.

## Window P: local prepare and audit

### 1. Versioned identity and dependency graph

Proposed profile `state-witness-prepare:1`, phase P, one fixed prepare slot per
retained append/control operation or independently authorized audit-only lookup.
Use `witness-window-intent/1` with exact record/action/lookup arguments and frozen
record, original receipt/control and audit candidate inventory. Independently
expect service lineage, principal/ACL generation, E epoch, original transaction,
prior service root, affected record/control tuples, global audit tail, reservation
and unused use revision. Read-only/retry lookup is not another record append.
Freeze candidate signing/issuance first; graph and no-H-cycle rule above apply.

### 2. Canonical timing meanings

s=P receipt observation, p=s, m=sole final read after G/S/A/L and use admission.
T_P runs from s through complete durable P prepare/use outcome. Inherit the
original <=5000 ms-or-stricter attempt from WS:527–532 and accept-relative <=5 s,
caller timeout 1–5000 ms from H:110–122/Policy:100–106. TLS/header/body consumed
time is not recovered. Standalone audit, startup or offline job budget is
**undefined/refuse** until its owning original operation specifies one.

### 3. Uncertainty coverage

P has its own authentic pre-settled reserve covering original elapsed preparation,
P burn, segment/journal durability and complete outcome. Preserve original audit
`at` and receipt bytes; a new observation cannot upgrade unknown time to success.
All shared interval/cap/floor checks apply. P reserve is spent here, not saved
for custody, R or X.

### 4. Preparation authenticity and bounded ownership

Authenticate originals as above; authorize before existence lookup. Protected
owned inputs include exact frozen audit/candidate bytes, ACL/control heads,
reserved audit successor and capacity charge. Original loading, path/descriptor
validation, signing and provider calls finish with G/S/A/L released. Bound all
objects by the shared caps; a pending audit reservation never authorizes a second
tail. Its currentness must be rechecked under final gates.

### 5. Final admission, durable use and recovery

Hold E; acquire G→S→A→L exclusively (S empty for global audit-only work), admit
persistence/use CAS and exact unused P revision, read m once, check purely,
then burn. Proposed key is `(service_lineage, original_operation_id, P, 1)`;
home is the retained owning prepare transaction/use metadata, linked to exact
audit frame and candidate manifest. Before act, fully persist its burn intent.
Act is full-write, file-sync, checked close, immutable same-filesystem install,
all changed parent-directory syncs, complete prepare journal and P outcome/use
commit/readback. No partial segment is a prepare. Keep journal evidence; no
deletion is required for acknowledgment. File/namespace failures hold the exact
candidate and burn. This endpoint is local preparation, **not** committed WS
head or released success. Release final gates before custody/archive RPCs.
Every shared crash row below applies to these exact P files and audit tail.

### 6. Enforcement and per-platform qualification

| Platform | Clock/boot, same act and qualification |
| --- | --- |
| Linux | One `CLOCK_BOOTTIME` m after P admission; protected boot UUID and retained original D. Checked file/parent sync through P burn, immutable segments, journal and outcome. T_P, f_P, epsilon_P, reserve/rate and maximum file/work counts are undefined; OS/filesystem/device proof absent. `handoff_unqualified`. |
| macOS | One `mach_continuous_time` m after identical P admission; protected `kern.bootsessionuuid`, qualified checked timebase/mapping. Checked `F_FULLFSYNC` on P burn/segment/journal/outcome files **plus separately qualified namespace durability** for create/rename and all changed parents; same full prepare/use act, not just file visibility. Mandatory native sources and representation gap below apply. Bounds/proof undefined; `handoff_unqualified`. |

### 7. Paired controls and composition

`WC1PrepareEndpoint`: on-time exact candidate and complete barriers commit one
P outcome; paired failures at every burn/write/sync/close/rename/parent/outcome
cut retain burn, forbid root/success exposure and hold uncertainty. Plant skipped
parent sync and require crash-reopen/use linkage assertion to fail. Apply all
shared named controls below. After P, custody and audit archive run unlocked;
R requires new evidence/reserve/use within the same original attempt. A bridge's
acknowledged intent is obtained only after R and X, never from P.

## Window R: post-custodian root publication

### 1. Versioned identity and dependency graph

Proposed profile `state-witness-publication:1`, phase R, fixed publication slot
of the same original transaction. `witness-window-intent/1` binds exact prepared
content/audit manifest, P outcome, original predecessor root/record/control/audit
tails and exact authenticated custodian/archive confirmations. For append or
control, require WS's exact seven-field previous→next custody tuple; an audit-only
transaction instead requires its separately accepted audit archive contract.
Expect protected reservation, current policy/E epoch and unused R revision.
Content → confirmation → fresh R evidence → use/outcome/root is acyclic; no R H
is inserted into frozen content or the closed custodian tuple.

### 2. Canonical timing meanings

s=R receipt observation after external confirmation, p=s, m=sole post-admission
read. T_R covers s through all resolution/use and service-root durability.
Use the **same original** WS:527–532 and H:110–122 deadlines, intersecting caller
remaining budget; confirmation time was already charged. No fresh 5 s begins
after custody. A standalone recovery/root-publication job budget is
**undefined/refuse**, not inherited from an expired network request.

### 3. Uncertainty coverage

New R settlement/challenge/reserve covers elapsed R preparation and all local
publication barriers once. Preserve O/delta/U<A/L>max(W,J), stricter authority
floors and original artifact issuance; do not reuse P's receipt/reserve or
advance timestamps. External confirmation does not prove time qualification.

### 4. Preparation authenticity and bounded ownership

With final gates released, validate exact retained P bytes and authentic original
closure, fresh custodian confirmation/currentness and independent audit archive
acknowledgment. The audit acknowledgment is not `chain:audits` in WS's closed
tuple. Bound complete confirmation/ancestry and content/use closure; no cached
digest-only acknowledgment or requester supplied expected root. A qualified live
reservation/fence must prevent competing changes until final recheck.

### 5. Final admission, durable use and recovery

Under E and G→S→A→L, select current exact predecessor, reservation, confirmation
and unused R revision **and admit initial persistence/use CAS before m**. Read
once, pure check, burn. Key `(service_lineage, original_operation_id, R, 1)`;
home is the owning resolution/root transaction's retained use/outcome. Persist
burn before any separable authoritative root effect. Fully persist resolution/
use-owned metadata, write/sync/check-close root temp, same-filesystem root rename,
sync changed directories, read back exact linked root/outcome and satisfy all
required namespace/use completion barriers before authority opens, strictly
before D. One rename is not an atomic multi-file commit. Retain exact immutable
evidence; no cleanup deletion is required to acknowledge. Root-visible but
outcome/durability unknown stays held, including after crash; no old-root fallback
or re-signing. Shared crash cuts apply. R grants only committed local state;
later delivery requires X.

### 6. Enforcement and per-platform qualification

| Platform | Clock/boot, same act and qualification |
| --- | --- |
| Linux | One post-R-admission `CLOCK_BOOTTIME` m, protected boot and original D; complete resolution/use/root file sync, checked close, rename and directory/readback endpoint. No root commit implementation or enforced f_R; T_R, epsilon_R, reserve/rate and workload counts undefined. `handoff_unqualified`. |
| macOS | One post-R-admission `mach_continuous_time` m, protected `kern.bootsessionuuid`, checked native timebase/original-D mapping. `F_FULLFSYNC` on all resolution/use/root files plus separate same-volume rename and parent namespace qualification; same complete root/use act including readback. Native source/representation restrictions below apply; all bounds unqualified/undefined, so `handoff_unqualified`. |

### 7. Paired controls and composition

`WC1RootEndpoint`: exact P/custody/audit/predecessor on-time commits one root/use;
wrong tuple, lost confirmation, changed locked root/audit revision or pause at
each root/use barrier cannot publish success. Plant omitted use/root-directory
barrier and require no-early-authority/crash assertion to fail. Shared controls
apply. Registry C/V cannot consume R's result or H: its intent and resolution
acknowledgments each need their own complete WC1 transactions and X releases.

## Window X: actual response release

### 1. Versioned identity and dependency graph

Proposed profile `state-witness-release:1`, phase X, one original authorized
response-exposure slot. `witness-window-intent/1` binds authenticated connection/
principal, exact method/arguments and final canonical HTTP/WS response bytes,
committed root/R outcome, audit/archive result, current control/key generation,
E epoch and unused X revision. Latest includes its exact fresh client challenge,
complete proof and current heads. Receipt retry binds the exact original receipt,
not another signature. Frozen response → fresh X evidence → release-use/outcome
has no H cycle. Request IDs, reconnects and lost replies allocate no extra slot.

### 2. Canonical timing meanings

s=X observation, p=s, m=sole read after release persistence/use admission and all
final gates. T_X spans s through the durable pre-send release/use commit and
actual complete frame write; all required authority readback/barriers precede
the first response byte. Separately specify positive enforced bounds
`f_X_commit` from m through that durable commit and `f_X_send` from commit
completion through the complete actual send, including any intervening pause
and required transport completion. Require checked
`f_X_commit + f_X_send <= f_X`, with the shared T_X/original-D inequalities and
epsilon charged once. There is no second clock read or new allowance at commit.
Both component bounds are currently **undefined/refuse**. Inherit
original WS:527–532 and H:110–122 accept/caller limits, without restarting after
R; `f_X_send` is inside that budget, not a post-commit extension. Independently authorized
re-exposure/offline output job and its original budget are **undefined/refuse**.

### 3. Uncertainty coverage

X obtains its own original settlement reserve for preparation, burn, durable
pre-send release/use commit and complete send; all shared interval/floor/authority and retained
issuance predicates apply to the exact response. TLS/P/R reserves, audit `at`
and stored receipt age are not X evidence. Delayed/blocked writes cannot silently
consume a new reserve or enlarge D/T.

### 4. Preparation authenticity and bounded ownership

Authenticate the original closure and exact committed R/audit/response bytes
outside final gates. Revalidate current authorized peer, generation, exclusion
and complete latest/proof evidence independently of requester claims. Fully
precharge the response (frame<=65536; proof page<=45056 canonical bytes and the
outer carrier bounds in WS:534–554), use/outcome files and completion work.
No streaming callback, provider RPC, on-demand signing or lazy page construction
under final gates. One request/connection; partial transport state is owned and
cannot be transferred to another live release candidate.

### 5. Final admission, durable use and recovery

Propose E plus G→S→A→L and exclusive ownership of the already reserved connection
writer; acquire/admit **all** release and use/CAS exclusions and exact unused X
revision before m. The connection reservation is taken before G, never acquired
by a callback under L. Pure check follows the single read, then durable burn.
Key `(service_lineage, original_operation_id, X, 1)`; home is the owning response
transaction's retained release intent/outcome, linked to exact committed R/audit
and frozen frame bytes. The exact X ordering is:

1. Durably burn the stable X key under retained admission. A burn is not yet a
   completed release/use authorization; an ambiguous burn forbids any send.
2. Commit **`XReleaseCommitted`**, the owning transaction's immutable durable
   release/use authority. It binds that burned key/revision, exact H/original
   references, frame bytes/digest/length, peer/connection, original deadline,
   live epoch, committed R/audit/archive evidence and exact predecessor. Finish
   every required write, sync, checked close, namespace barrier, readback and
   independently protected recovery/use binding **before any response byte**.
   Only this completed local transition supplies release authority; a prepare,
   R/audit result or burn alone cannot. Any failure/unknown completion holds the
   scope, preserves the burn and sends nothing. Commit means release-authorized,
   not delivered.
3. Only the still-live admitted executor may make its one bounded send attempt,
   with the full chain/current fence retained. Enforce `f_X_send` and the same
   original exclusive D/current epoch through the complete authoritative frame;
   no renewed deadline, extra read or recovery dispatch. The full X endpoint is
   durable `XReleaseCommitted` followed by this timely actual send. No mandatory
   authority or recovery durability remains after the frame leaves. Local commit
   and socket delivery are not atomic; a failed/partial/unknown send retains the
   committed burn and uncertain delivery, never an unused slot.
4. Any later delivery accounting is a separate **non-authoritative delivery
   note**, not release/use completion, required success evidence or another
   authorization. It cannot overwrite/delete `XReleaseCommitted`, its retained
   bindings or the burn. Failure or crash of that note's write, sync or readback
   leaves the prior authority committed and delivery accounting unknown; it
   never refunds use or permits resend. Its own maintenance budget/protocol is
   undefined and grants no automatic late job under the expired request.

Recovery retrieves exact committed authority/status only, with delivery unknown
where necessary; it never re-sends, even if no byte was delivered. A new exposure
occurrence needs separately reviewed authorization and slot semantics, not a
fresh H. Every shared crash row applies; a prefix may have escaped after step 2.
This preserves existing authoritative WS success semantics. If any required
authority/durability binding cannot precede send, or either bound/current-epoch
enforcement is unqualified, **X is unavailable** (`handoff_unqualified`); this
proposal introduces no peer-side deferred-success protocol and does not weaken
success semantics. The new transaction and send enforcement are not implemented.

### 6. Enforcement and per-platform qualification

| Platform | Clock/boot, same act and qualification |
| --- | --- |
| Linux | One `CLOCK_BOOTTIME` m after complete X admission, protected boot/original D; durable burn → complete durable/read-back `XReleaseCommitted` → one bounded actual send; any later delivery note is non-authoritative. All required file/namespace/use bindings precede response bytes. H:98–107 only builds bytes and H:140–144 has no serving dispatcher. `f_X_commit`, `f_X_send`, total f_X/T_X/epsilon_X, reserve/rate and workload enforcement are undefined/unqualified. X unavailable: `handoff_unqualified`. |
| macOS | One post-X-admission `mach_continuous_time` m and protected `kern.bootsessionuuid`; checked timebase/original-D conversion. Checked `F_FULLFSYNC` on burn/release-use files plus separately qualified namespace/readback barriers complete `XReleaseCommitted` **before any response byte**, followed by the same one bounded actual send. Later delivery accounting cannot invalidate the committed authority or authorize resend. Native source/representation restrictions below apply. Flush is not a socket deadline/fence; both component bounds and enforcement missing. X unavailable: `handoff_unqualified`. |

### 7. Paired controls and composition

`WC1ReleaseEndpoint`: complete durable `XReleaseCommitted` precedes every response
byte, then one timely bounded send, versus failure/unknown burn or any required
pre-send write/sync/readback (no send), post-commit pause, partial write, epoch
revocation and lost reply (burn remains, no recovery resend). Plant release on
R/audit/burn alone or move required use completion after send; the
no-success-before-durable-authority assertion must fail. Removing current
epoch/deadline enforcement must fail the late/duplicate-exposure assertion.

`WC1ReleasePostSendAccounting`: on **both Linux and macOS**, pair a complete
timely frame followed by successful delivery-note accounting with that same
complete frame followed by write failure, sync failure, readback failure or
crash of the proposed completion/accounting record. Assert authority/use and all
required recovery bindings were already durable before the first byte and remain
unchanged; accounting may be unknown, but the stable key stays burned and reopen
never re-sends. No client success depends on the failed later record. Plant the
old send-before-required-use-completion ordering; this paired control must fail
the durable-authority assertion. These are future native controls, not executed
platform qualification. Shared controls apply. A received complete X response still
does not supply registry C/V time or its protected read-completion fact.

## Window TLS: peer validation and admission

### 1. Versioned identity and dependency graph

Keep native profile **`state-witness-tls:1`** and exact operation
`{v:1,service,role,principal_id,peer_spki,chain_digest,tls_policy_digest,
connection_id,config_generation}` (TLS:159–191; [TLS codec](tls-profile.md)).
Exact presented DER order, protected pins/anchors/full CRLs and policy digest
are frozen before time preparation. Independently expect those values plus
original accept/connection identity, current config/CRL floors, E epoch and unused
TLS revision. Protected association to original deadline/use state does not add
fields to this closed operation body. Connection ID and time-provider challenge
are distinct; neither time H nor m enters its digest. A new connection attempt
does not reset an enclosing original reconciliation budget.

### 2. Canonical timing meanings

s=TLS observation, p=s, m=sole final read after peer-admission persistence/use
and config gates. T_TLS spans s through complete durable peer-admission/use
commit before application access. Keep original handshake start+3 s and
accept start+5 s (Policy:100–106/H:110–122), intersecting known stricter enclosing
caller limits without creating a fresh stage allowance. TLS:437 creates a new
3 s background callback context today; it does **not** establish propagation of
the original accept/attempt deadline. The accepted-socket runtime integration
must supply that tuple; absent it this path refuses.

### 3. Uncertainty coverage

Own fresh settlement reserve covers validation/preparation and all peer-admission
use durability, not a later application request. Preserve TLS:193–201's original
interval, <=1.5 s uncertainty cap, authority/floor predicates and TLS:319–348's
L>=NotBefore/U<NotAfter for every certificate including root plus qualified CRL
validity/floors. Failed TLS never refunds provider W/holds. TLS reserve cannot
pay for P/R/X or a registry window.

### 4. Preparation authenticity and bounded ownership

The full shared original-reader/current witness authentication is mandatory;
`QualifiedTime.Consume` (TLS:132–157,257) is an interface obligation, not an
implemented reader/handoff or durable WC1 use store. Stage Consume, parsing,
path/CRL verification and randomness with final config/use gates released.
Retain exact owned DER reparsed from protected bytes (TLS:443–480), checked
enrollment and current generation. Presented certificates<=4, each<=8192 bytes,
total<=32768; CRLs<=3, each<=65536, entries<=1024, bounded path work
(TLS:39–129,268–348). Plus the shared complete-original closure caps. OS random
bytes alone do not qualify post-restore challenge/incarnation freshness.

### 5. Final admission, durable use and recovery

Propose E, exclusive connection reservation, then G→L; S/A absent, with
connection/config/CRL and persistence/use-CAS admissions and exact unused TLS
revision selected before m. Read once; pure check compares prepared results,
current protected read set and interval; then burn. Proposed key
`(service_lineage, original_connection_attempt_id, TLS, 1)` is allocated by the
protected accept owner before time preparation, never by H or a reused restored
connection nonce. Home is a **new version of the owning retained connection
admission transaction** in the common S3 transaction facility; S2 has none.
Persist burn before any separable peer-admission effect. Commit exact qualified
peer/config/use outcome with all file/namespace/readback barriers before opening
application authority, strictly before D. TLS wire progress is not that commit;
any authority-bearing handshake release also needs inclusion in the enforced
endpoint, not an unprofiled callback exception. Missing runtime binding remains
closed. Crash/unknown validation or durability closes the connection and keeps
burn; recovery does not reopen it. Normal application operations require P/R/X.

### 6. Enforcement and per-platform qualification

| Platform | Clock/boot, same act and qualification |
| --- | --- |
| Linux | One `CLOCK_BOOTTIME` m after TLS use/config admission; protected boot and original accept/handshake/enclosing D. Complete durable peer-admission/use act before application access. Current predicates/config supply no connection-use transaction or enforced f_TLS; T_TLS, epsilon_TLS, reserve/rate, exact durable workload and runtime deadline propagation are undefined. `handoff_unqualified`. |
| macOS | One post-admission `mach_continuous_time` m, protected `kern.bootsessionuuid`, checked timebase/original-D mapping. Checked `F_FULLFSYNC` on connection burn/admission/outcome files **and separately qualified namespace durability**; same durable peer-admission/use act and application gate. No Linux receipt relabeling; native sources below apply. Darwin provider/receipt/runtime and enforced act/storage bounds absent: `handoff_unqualified`. |

### 7. Paired controls and composition

`WC1TLSAdmissionEndpoint`: valid pin/role/chain/CRL, original deadline and complete
durable use commits one peer admission; wrong original connection, changed config/
CRL floor, post-read pause, restored nonce or missing use durability closes with
no application admission. Plant application access on a pure ValidateTLS return
and require no-early-admission assertion to fail. Retain S2 test names, including
`TestTLSHandshakeChoiceBeforeTime` and `TestReviewTLSExactEdges`; they prove pure
predicates, not this future endpoint. All shared controls apply. Successful TLS
does not authenticate time for a WS operation or extend its original budget.

## Native platform requirements, version 1

The per-window rows above incorporate the same primary source baseline. These
are API semantics/research pins, **not qualification of an installed OS/device**.
Linux requires its selected suspend-aware `CLOCK_BOOTTIME`, protected canonical
boot UUID, descriptor/owner/path protection and checked file/directory durability;
no Go ordinary monotonic timestamp or Linux awake-only clock is a substitute.

On macOS select `mach_continuous_time` explicitly, not `mach_absolute_time` or
uptime. Apple's pinned [Mach declaration](https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/osfmk/mach/mach_time.h#L60-L64)
specifies sleep advancement. Load `mach_timebase_info` before final admission,
pin its ratio and qualify checked conservative tick/ns conversion, rate/error,
suspend/hibernate and wake-through-D. Read and validate protected nonzero canonical
`kern.bootsessionuuid` before locks, using the pinned [XNU read-only declaration](https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/kern/kern_sysctl.c#L2869-L2871).
Neither identifier proves VM-restore uniqueness, original continuity or exclusion.

The pinned [F_FULLFSYNC declaration](https://github.com/apple-oss-distributions/xnu/blob/8d741a5de7ff4191bf97d57b9f54c2f6d4a15585/bsd/sys/fcntl.h#L299)
and Apple's archived [fcntl manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fcntl.2.html)
describe a file/device full-flush request. Require checked `F_FULLFSYNC` for
written durable files on the exact qualified target, no silent fsync or other
fallback. Device behavior and APFS support are not established by an archived
support list. Namespace persistence requires separate proof for directory
descriptors, create/rename/unlink, newly created directories and both changed
parents as applicable. Never assume directory F_FULLFSYNC is supported or enough.
Apple's [rename manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/rename.2.html)
does not establish a complete multi-file/use transaction or a deadline guarantee.
Unsupported/failed/unproved directory barriers refuse and hold unknown durability.

Each P/R/X/TLS target must qualify its identical act/use endpoint, protected
descriptors, exclusions, live epoch/deadline enforcement, readback and cleanup.
Full flush supplies no finite f by itself. Qualification includes GC/preemption,
page faults, scheduling, suspend, storage stalls/power loss and stale executor
resumption; emergency stop remains independent of the entire dependency graph.
The time provider's witness cannot depend on WC1 append/audit in order to qualify
the time those paths require. All accepting original-reader/witness, entropy,
custody and act implementations remain absent or unqualified.

Current closed Linux receipts accept `CLOCK_BOOTTIME` only. Proposed Darwin
`MACH_CONTINUOUS_TIME/ns` needs a separately reviewed platform version, native
provider, receipt validator and authenticated boot/deadline mapping (Mac:41–49).
Never relabel or translate a Linux receipt as Darwin authority. Linux evidence
cannot qualify macOS, nor vice versa; each of the four rows must be accepted.

## Crash cuts for each owning transition

These rules apply independently to **P prepare**, **R root**, **X release** and
**TLS admission**, with the distinct keys/homes/endpoints above. They are proposed
recovery semantics, not permission for an expired original execution to resume.

| Cut | Required disposition for that window |
| --- | --- |
| Before burn | No window act/use write. Retire old preparation. Reprepare only if independent current history proves the same original slot unused and its original constraints still permit it. Missing/torn state is not unused. |
| Burn write/sync/ack unknown | No act. Retain exact intent and fence. A fresh H cannot resolve uncertainty or skip the slot. |
| Burn durable, act absent | Keep burn forever for this logical key. No recovery redispatch, even if P bytes, R root, X frame or TLS admission never happened. Availability may be lost. |
| Partial act or any required authority file/namespace/readback/outcome ambiguity | Preserve exact old/new bytes, use and evidence; hold. P is not prepared, R not acknowledged, TLS cannot open application authority. X sends nothing if required pre-send authority is uncertain; after XReleaseCommitted, delivery may be partial/unknown but that committed burn remains. No rollback-to-unused or fabricated completion. |
| Act appears complete, required use/authority outcome not proven | Not an accepted committed state. Hold each owning scope; readable file/root, sent bytes or a verified peer cannot replace durable linked use. A full X frame without prior XReleaseCommitted is forbidden, not repairable by later accounting. |
| X frame delivered, later delivery-note write/sync/readback fails or crashes | Keep prior durable XReleaseCommitted and all required authority/recovery bindings unchanged. Delivery accounting may remain unknown; no authority completion was deferred. Key remains burned and recovery never re-sends, on both OSes. |
| Full endpoint, acknowledgment lost | Recover exact original outcome/status only. No second prepare/publication/write/admission. An authorized lookup/re-exposure is separately scoped and never resets this burn. |
| Known late act | Retain burn/evidence and hold. Withheld response or late completion does not repair the forbidden effect or authorize automatic late publication. |
| Restored consumer use/root, intact provider W (N1) | Independent consumer use/currentness authority must detect rollback; provider W alone cannot. Before burn, a fresh interval may pass time only if history and original unused authority survive; after burn every H refuses. |
| Pause/restore after burn before act, replacement executor (N2) | Effect-enforcing current epoch/deadline or proven exclusion must prevent the old P/R/X/TLS executor acting after D/replacement. Burn-time checks alone are insufficient. |
| Changed run/epoch/challenge (N3) | Retire live prepared entry; logical key and original D persist. A new incarnation cannot allocate a replacement slot for a burned key. |

Independent consumer use/completion rollback authority is an open owner item.
Record/control custody and an audit archive acknowledgment do not automatically
authenticate this new metadata. Its home must establish independently current
exact root/use ancestry and old-writer exclusion; an unbound sidecar is not enough.

## Future paired controls, version 1

**Specified only; not executed or implemented by this documentation.** Apply each
row to P/R/X/TLS with its actual endpoint, nearby qualified timely control, exact
provider/use/act post-state and native platform fixture. Arithmetic examples
alone cannot qualify a late-effect or storage property. A plant is killed only
by its named intended assertion, not setup failure or a skipped test.

| Future control | Negative and nearby positive; narrowing plant |
| --- | --- |
| `WC1WindowAdmissionOrder` | Initial persistence/use admission or unused/head/epoch selection after m forbids burn/act; valid control admits every gate first. Move admission after m and require the ordering assertion to fail (`HandoffUseAdmissionOrder`). |
| `WC1WindowStaleCapture` | Pause pre-entry past original D; actual final read refuses without burn/act. Same owned bytes timely may pass time only with enforcement. Remove/move m and require stale-admission assertion to fail. |
| `WC1WindowPostReadPause` | Pause/suspend after timely m or burn past D/revocation; forbid late act, not merely late success. Timely full endpoint commits once. Remove effect enforcement and require native late-effect assertion to fail (`HandoffLateRun`, N2). |
| `WC1WindowDoubleUse` | Two pure checks of unused v plus competing burns or H2 for a burned key accept at most one act. Distinct independently authorized key is the valid control. Remove predecessor CAS or key by H/run and require duplicate-act assertion to fail. |
| `WC1WindowTransitionVersion` | The exact protected witness-transition-map:1 pair maps native WC1TimeUse/1 to enrolled WC1TimeUse:1 identically at preparation/expected metadata and encoding, and matches on decode. This is the positive version predicate with otherwise valid input. Literal slash WC1TimeUse/1 in transition_version, wrong WC1TimeUse:2, unknown mapping or preparation/encoding mismatch refuses before bundle/use/act; an alphabet-valid wrong version is still wrong. Plant generic slash replacement or omitted exact version comparison and require mapping/version assertion to fail. |
| `WC1WindowBindingAndOriginals` | Wrong service/principal/operation/candidate, boot/start/D/mapping, held provider, missing original or excessive ancestry gives no bundle/burn/act. Exact protected bounded originals/read set is the valid control. Plant requester-derived expectations or truncated ancestry and require binding/provenance assertion to fail. |
| `WC1WindowReserveAndEquality` | Overflow, growing T/reserve, m-s+f+epsilon>T, m+f+epsilon=D or U=A refuses with no burn/act. Nearby representable interior values may pass time predicates. Plant inclusive D/A or refreshed reserve and require strict-bound assertion to fail. No shared illustrative 250 ms value is a WC1 budget. |
| `WC1WindowN1Recovery` | With J=140, original [199,201] settled to W=201: intact history rejects [170,172] by interval; missing/restored history independently rejects [210,212] by continuity. With complete history [210,212] may pass provider time for a still-unused slot within its original D; after burn it still refuses this key. Plant W reset to J, omitted consumer-use custody or fresh-H slot and require the corresponding interval/continuity/replay assertion to fail. |
| `WC1WindowCrashOutcome` | Exercise every owning crash row; unknown/restore/lost ack never refunds W/use or redispatches. Exact durable outcome retrieval is the positive, not another act. Plant missing retained burn/outcome linkage and require restart-replay assertion to fail. |
| `WC1WindowNativeParity` | Awake-only clock, boot/domain substitution, overflow, unsupported full flush, unknown namespace recovery or suspend through D never qualifies. Native timely continuous-clock/full-endpoint fixture is the control. Plant uptime substitution/ignored directory barrier and require suspend/crash-durability assertion to fail (`HandoffMacParity`). |
| `WC1WindowPurityAndStop` | `VerifyWindow` itself is pure: no clock, file or network I/O, callback, provider or signing work. Under the terminal gates, allow exactly the one fixed qualified read m outside `VerifyWindow`, plus the bounded local burn, act and durability steps of that window. Forbid any extra clock read and any external provider, original-reader, signing, custodian or archive work under those gates. Stop must not wait on these gates, a provider/storage holder or a dependency cycle. Positive control: complete all final exclusions and initial persistence/use-CAS admission, select the exact current head/epoch/unused revision, take sole m outside the pure verifier, run the pure check, durably burn, perform the bounded local act and every durability/readback/outcome barrier, and reach the full endpoint strictly before original D while admission remains held and stop remains independent. Preserve original T/f/epsilon/reserve; this trace requires qualified enforcement, not merely favorable arithmetic. Negative controls insert an extra clock read, external provider/original-reader/signing/custodian/archive work under the gates, or any clock/I/O inside `VerifyWindow`; each must fail its named purity/gate assertion before burn/act. Plant the former blanket terminal clock/I/O ban and require the complete positive trace to fail; plant an extra read, external provider call under L or stop dependency and require the corresponding structural/stop assertion to fail. |
| `WC1WindowBridgeBudget` | Retry/page/R/X/reconnect cannot refresh the original operation D or reuse another window's evidence/reserve; WC1 H cannot authorize registry C/V/F. Timely distinct windows within original local budgets are the control. Plant per-phase timeout reset or shared H and require deadline/isolation assertion to fail. |

## Registry bridge composition and remaining inputs

The registry order stays: exact witness intent acknowledged → fresh registry C
handoff and atomic content/completion/use commit → independent bridge verification
of that exact commit → matching witness resolution acknowledgment and required
fresh challenged complete read → fresh registry V visibility/use commit. Registry
F publish/revalidation has its own window/use. Each WC1 request in that sequence
has P/R/X and TLS as applicable, with distinct evidence, reserves, keys and local
clock/deadline domains. No registry mutex/final lock spans provider or witness
RPCs; WC1 releases its final gates for all custody/archive/provider calls.
When any parent window encloses work, its original T/reserve/f must cover the
whole nested span, without reusing another settlement or capture.

E3 whole-attempt accounting: each side retains its original local start/D; bound
each delegated timeout by the registry attempt's remaining original budget and
WC1's own <=5 s-or-stricter remaining limit. Handshake/header/body caps intersect
that same original deadline. Never compare different hosts' absolute monotonic
timestamps or treat a timeout_ms field as proof of unseen end-to-end transit.
G20 must qualify propagation, transit, reconnect and complete durable/release
endpoints; no fresh phase or retry allowance is created. WC1 supplies no protected
read-completion time fact for registry `WitnessReadAt`: TLS time, audit `at`, a
checkpoint timestamp and an original receipt are not substitutes. No WS head or
consumer witness record gains a field here.

| Unresolved input | Responsible decision and closed behavior |
| --- | --- |
| T/f/epsilon/reserve/rate for P/R/X/TLS; maximum complete files/work | Platform/storage/transport and time owners must supply finite workload-specific qualifications and an enforcing act/fence, including separate f_X_commit and f_X_send inside X's original budget. All are undefined or unqualified; `handoff_unqualified`. 5 s/3 s/1 s limits are specified policy, not proof of residual f or uncertainty coverage. |
| Standalone audit, recovery/root, offline/output/re-exposure and startup budgets | Owning operation must specify original finite start/D and authorization; undefined refuses. Neither approval lifetime nor an expired online deadline supplies one. |
| Native codecs and four WC1TimeUse/1 homes | Contract/consumer owners review bytes, the protected witness-transition-map:1 mapping to enrolled WC1TimeUse:1, frozen-content/completion binding, genesis/migration, capacity, exact outcomes and per-window recovery before any G16 codec. XReleaseCommitted must contain all required authority/recovery durability before send, independent of later accounting; new connection/response transactions do not exist today. Separate use ledger needs explicit owner approval. |
| Original-reader/provider/witness and entropy | Select qualified installed source graph, independent confirmed history, live custody/invalidation and post-restore challenge/incarnation provenance. Broker interfaces and TLS Consume alone supply none. No circular dependency on WC1 to qualify WC1 time. |
| Darwin receipt and native parity | Joint provider/platform/consumer review of continuous-domain receipt version, boot/deadline mapping, native lifecycle/exclusion and file/device/namespace/act qualification for every row. No Linux receipt relabel or presumed macOS provider. |
| G17/G18 and use rollback custody | Owner selects independent exact custody/fresh-read provider, retention and whole-call SLA plus whole-lifetime old/delegated-executor enforcement. Consumer completion/use and audit authority require explicit scopes; existing closed record tuples do not settle them. |
| G14/G15/G19 | Accept archive/audit acknowledgment protocol, transaction/audit reservation order, retention, exact crash/restore runbooks and authorized recovery phases. Unknown burns remain held; no automatic redispatch, reset, mode downgrade or re-signing. |
| G20 and registry Q18–Q20 | Accept whole-attempt bridge accounting, protected read-completion measurement, independent exact content/use/visibility authentication and separate consumer exclusion. A WC1 profile or archive receipt does not close these consumer gates. |

No native pause, power-loss, restore or macOS qualification was run for this
specification. Documentation/link/hygiene/vector checks preserve publication and
existing corpus integrity only. Existing reviewer tests remain unchanged; there
is no new executable surface or supplied implementation surface table in this
proposal. Future implementation review must map all four windows and the named
negative controls to actual tests and narrowing evidence before activation.
