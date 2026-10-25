# Local transaction and archive contract v1

These libraries implement the G13–G15 transaction direction for the conditional
[witness contract](https://github.com/relux-works/swarma-keymaker/blob/b232f6aec52e9327daffd8e889b52ed0ebd2fd3f/spec/witness-service.md).
This is a local format, not a WS extension or a deployment qualification.
`service.New` installs closed dependencies and no store or signer. There is no
accepting production constructor, listener, dialer or recovery initializer.
Synthetic providers and explicit genesis exist only in tests. G07 and G10 retain
their S2 gates. No G16 codec, clock fallback or qualified-time success is added.

## Immutable format and publication

All integers below are big-endian. An envelope is four magic bytes, uint32 payload
length, uint32 manifest length, the exact canonical CCJ manifest, each original
object prefixed by uint32 length, and 32 raw SHA-256 bytes over everything before
the checksum. Payload length includes its manifest-length field, manifest and
objects; it excludes the first eight bytes and checksum. Unknown fields, versions,
phases, noncanonical manifests, truncated/extra bytes, digest/length mismatches and
oversized complete envelopes refuse. Wire limits remain unchanged.

| Object | Magic / phase | Complete cap |
| --- | --- | --- |
| Segment | WSG1 / segment | 1 MiB |
| Journal | WJN1 / prepare or outcome | 64 KiB |
| Root | WCM1 / root | 4096 bytes |
| Retained index | canonical local state | 1 MiB |
| Audit original | canonical line plus LF | 4096 bytes |

The closed manifest has `v:1`, `service`, `transaction`, `phase`, `prior_root`,
`index_hash`, `policy_hash`, `chain`, `stream`, `seq`, `prev_hash`, `head_hash`,
`audit_seq`, `audit_hash`, `segment_hash`, `prepare_hash`, `resolution_hash`, and
`objects`. Each object descriptor has `kind`, `length`, `hash`. At most 64 objects
fit an envelope. Hashes are lowercase raw SHA-256 hex; stream is null except for
records. Local chain values are records, controls and audits. **Audits is never a
custodian tuple chain.** A transaction ID is fixed before audit allocation;
segment, prepare, outcome and root are hashed in that order. Unused links are
zero hashes. No object hashes the root which will reference it.

Content-addressed `.obj`, `.seg` and `.jnl` files are immutable. `root` is the only
replaced name. The private index retains original record/receipt digests,
predecessors, original binding and witness-key context, exact action-ID results and restricted public consent/enrollment proof digests,
policy, bootstrap grants, audit tail and conservative byte charges. Reopening
checks the complete linked inventory, including historical roots. Orphan stages,
unpublished evidence, missing objects and damage close admission for separately
authorized recovery; there is no silent tail truncation or cleanup.

The index layout in `service/state.go` is private implementation state, version1:
canonical JSON with exact typed re-encoding, bounded revisions/bytes and original
per-stream order. Byte slices are base64 JSON values. Administrative proof objects are canonical
`{v:1,evidence:<typed AdministrativeEvidence JSON>}` and retain original byte
fields plus protected expected contexts; they never enter the audit line. These local layouts need
separate review before durable interoperability or migration is promised.

Publication orders every newly installed file as full write (looping short writes),
file sync, checked close, rename, directory sync. Immutable renames do not replace;
only root replacement is atomic. The prior root, originals, segment and prepare
journal precede exact independent custody confirmation and audit archive ack.
A new publication qualification precedes outcome and root installation. Only then
may a separately qualified release occur. No final lock is held over external
calls. Unknown append/control work returns outcome_unknown and holds admission;
audit-only uncertainty returns storage_unavailable and also holds admission.
No retry signs another receipt: it validates and returns the original after a new
audit-only transaction and all its barriers.

Linux amd64 uses openat2 descriptor-relative no-follow/beneath/no-mount-crossing
resolution and renameat2 no-replace. Missing kernel support refuses.
Other native backends refuse. Direct path opening rejects noncanonical paths,
symlinks, writable ancestors and wrong owner/mode; opened files must be regular,
service-owned0600, single-link and on the descriptor's device, directories0700.
An already-open protected descriptor is a separate installation authority boundary,
never request input. Descriptor checks do not establish ancestor custody, deployment mount
layout or account separation; the installation owner must qualify them.

Each transaction is charged 8 MiB history and 64 KiB audit, including temporary
copies, before writing. Preflight leaves a 16 MiB free-space reserve; logical
history and audit limits are 100 GiB and 1 GiB. The bounded local lineage stops at
1024 transactions and 16384 namespace entries. Capacity refuses without deleting
history. Free-space checks are not exclusive physical reservations on a shared
device, nor proof of flush/power-loss behavior. No acknowledged retention is
truncated. Qualified disk/namespace durability and hard reserve remain PENDING.

The owner decision (2026-10-25), G17 and registry Q10, selects one synchronous
independent custodian shared by both specs: exact predecessor confirmation and
fresh reads within the budget, with no periodic or local fallback. The provider
is not yet chosen; its protocol, SLA and qualification remain open dependencies.
The stricter exact tuple and independent confirmation rules below still apply.

Checksums establish local integrity only. Before work, independently verified
record/current-control tuples, audit anchor, exclusion and recovery assessment
must agree. A coherent older snapshot cannot authorize itself. No qualified
custodian yields storage_unavailable before append work. G17 tuples retain exactly
service, chain, stream, seq, record_hash, receipt_hash and control_hash. Independent
audit confirmation uses a separate contract and namespace.

## Global audit and reader scope

The owner decision (2026-10-25), G14/G15, keeps archive and audit custody separate
from the record custodian. It selects no archive/audit provider or protocol and
does not open disclosure, installation, retention or qualification gates. The
restricted reader rules below and the separate [consumer archive
constraints](#consumer-archive-interfaces) remain in force.

Audit entries contain exactly `v,seq,at,instance,principal,stream,operation,
request_id,record_hash,control_hash,result,code,prev_hash` plus LF. Unverified fields
are null; only protected identifiers (no whitespace, controls, path separators or scheme
delimiters), closed operations/results/codes and exact
hashes fit. Evidence bodies are retained separately. Qualified UTC is required
for success/refused entries; null time permits only diagnostic unknown, never
normal release. The 16-byte base64url instance is protected incarnation input;
syntax validation and OS randomness do not prove freshness after restore.
Missing root never authorizes genesis. Independently authorized genesis and
post-restore entropy are still PENDING. Safe-integer exhaustion closes admission.

One reservation retains the global audit revision through unlocked external calls.
Lock order is admission/configuration, affected stream gates in lexical order,
audit, local store. Reacquisition checks the pending reservation/revision; this
single-active coordinator prevents changes to heads/policy/audit in the interval.
Reentrant append receives busy; emergency stop takes no final gate. Every normal
append/admin/exact retry includes its durable audit. Latest/proof currently audit
a profile_unavailable refusal: successful head/page construction belongs to later
slices. No read-completion time fact is emitted.

`audit.Grant` is a protected typed reader schema: one opaque principal and 1–16
strictly sorted unique pins, at most64 distinct principals. `NewReaders` copies
it; authorization requires exact principal and pin. It does not inherit stream
readers or introduce a WS/config member. Default reader denies. Installing or
exposing this global channel needs separate disclosure/custody approval.

Failure telemetry contains 64 fixed numeric counters, saturating at the safe
integer maximum, with one diagnostic allowance per caller-supplied elapsed second,
burst1. It stores no request labels, queues or error strings and calls no append
logger. The coordinator does not install a diagnostic sink or clock. Failed
failure-audit closes admission and increments bounded health only.

## Consumer archive interfaces

`archive.Consumer` declares Retain, Retrieve, VerifyOffline and AdvanceAnchor.
Contexts carry the original job deadline; no method renews it. These are consumer
interfaces, not WS methods, URL selectors or admin operations. Retain receives
exact manifest objects and expected archive tail. Retrieve takes digest, expected
length and bounded opaque cursor. Offline verification takes old/candidate
record+control anchors, exact manifest and independent one-use approval;
advancement separately requires expected old anchor, verified continuity and a
fresh complete head. Audit/archive and registry anchors remain separate state.
A retained object proves neither latestness nor permission to advance an anchor.

Production defaults refuse storage_unavailable for retention/retrieval/audit and
profile_unavailable for unaccepted offline verification/advancement. No provider
wire codec, approval signature/profile, ACL or retention/SLA is selected here.
The in-memory test model demonstrates typed obligations only, not independent
custody, durable one-use approval or a production archive implementation.

## Explicit boundaries

The owner decision (2026-10-25), G18, requires that after pause, partition or
revoke an old instance or clone cannot write, sign or emit anything. Heartbeat,
flock and CAS are not fences. Lifetime exclusion remains unimplemented and
unqualified.

The owner decision (2026-10-25), G19, permits only evidence-bound recovery with
old instances fenced. When ambiguous, hold; never recreate. This records the
recovery policy without supplying a runbook or opening a recovery path. The
stricter no-auto-repair/genesis/regeneration/downgrade rules below still apply.

G16 time window codecs, durable use/burn state and enforced read-to-act bounds are
excluded. Time Prepare/Publish/Release are closed interfaces; their shapes are
not a reviewed provider adapter or authority evidence. G17 custodian, G18 lifetime
exclusion and G19 exact recovery likewise have closed defaults only. Interrupted
transactions remain held, with their original evidence retained. No auto-repair,
new genesis, receipt regeneration, downgrade or migration is implemented.

Unresolved WS integration includes successful latest/proof construction, complete
historical paging/ACLs, non-Keymaker record dispatch, durable consent/grant use,
qualified genesis and incarnation, provider protocols and exact recovery/use
transitions. The proposals leave exact local manifest/index layout and global
reader configuration/installation unspecified; this document makes the local
choices reviewable without extending any closed WS schema.

[Storage tests and qualification gaps](storage-tests.md) distinguish executable
control-flow checks from owner qualification.
