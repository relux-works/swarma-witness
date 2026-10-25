# Pure policy and transport validation

The conditional [service contract](https://github.com/relux-works/swarma-keymaker/blob/15b96da7ec1230e117ed7150a521ec33d13ef0cc/spec/witness-service.md)
and [consumer contract](https://github.com/relux-works/swarma-keymaker/blob/15b96da7ec1230e117ed7150a521ec33d13ef0cc/spec/keymaker-witness.md)
remain authoritative. These libraries implement pure S2 validation. They provide
no listener, serving process, activation, network lookup or production authority.

`config.Parse` accepts exactly `{service,bindings,principals}`. Bindings retain
G04; principals are exactly `{id,role,transport_pins}`, with one of writer,
reader, admin, publisher, bridge or observer. Config carries public values only;
there is no key/path/URL lookup or gate override. IDs and pins cannot cross
principal roles. Writers may be explicitly listed as readers. Registry publishers
never acquire bridge, append or administrative authority. The independent bridge
writes only its bound checkpoint stream; observers read only checkpoint streams that explicitly list their principal ID
and exact transport pin as a reader. Observer role alone grants no stream access.
An unbound peer receives `not_authorized` for foreign and nonexistent streams
before inner evidence or page lookup. No lookup is performed by these functions.

S2 validates witness-local principal IDs, transport pins and stream roles only.
It does not establish which OS account or process controls a credential, inventory
credentials held elsewhere, or qualify witness or custodian isolation. Before
registry activation, independently verify that the registry writer cannot reach
any witness append credential, that the bridge has no content authority, and
that the custodian has no registry or witness account access. Local role checks
and synthetic tests do not establish these custody or isolation properties.

G07 disclosure approval and G10 custody are unconditional closed gates,
`stream_unavailable` and `profile_unavailable` respectively. Valid config cannot
open either. `Handler` is deliberately unserved and does not implement
`http.Handler`. Its production readiness refuses. Pure fixture roots and returned
plans neither change these gates nor qualify an approval/transport/time provider.

G08 consent is an LF-terminated `{body,signature}`. Body is exactly
`{v,type,consent_id,service,stream,consumer,identity,lineage,binding_hash,
bootstrap_hash,action_id,disclosure_hash,key_epoch,key_id}`; v=1,
type/domain=`state-witness-bootstrap-consent/1`, then NUL and CCJ-1(body).
An independent bootstrap-approval key verifies the signature. IDs are 32hex,
binding/disclosure are D and bootstrap H is LF-inclusive. Every scope field and
the frozen first line must match the existing signed provision action. No admin
member is added. Input grants model reservation and exact retry equality only;
S3/S4 must provide durable single consumption and original-receipt retention.

`ValidateAdmin` checks protected administrative transport, existing S1 signed
schema, complete current/prospective local signing-role separation, action
bytes/replay and snapshot CAS. Newly provisioned record keys and rotated witness
keys are checked against administrator, consumer, registry-root and supplied
approval/enrollment authorities before a plan is returned. A retained
exact completed action returns a copy of its original result even across current
CAS changes; changed bytes under its ID refuse `position_conflict`. A pending
result, unresolved intent or uncertain barrier refuses `outcome_unknown`.
Current predecessor/head mismatch refuses `head_conflict`; binding/policy/epoch
mismatch refuses `evidence_invalid`; exhaustion refuses `sequence_exhausted`.
Provision requires an unused stream and writer_epoch=1. Writer rotation at an
empty provisioned stream refuses `bootstrap_required`. Witness rotation hashes
exactly `{service,key_epoch,key_id,public_key}`, excluding LF/proof, and requires
the existing new-key proof, distinct key and epoch+1. S3/S4 still own the old-key
receipt, service-wide barrier and historical retention; no plan activates them.

`PrepareAdmin` composes administrative validation with signed consent or writer
possession evidence; missing profiles refuse `profile_unavailable`. Its protected
principal snapshot represents separately enrolled, currently authorized pins,
including all readers in the complete replacement binding. No received signature
can enroll a principal or replace that snapshot. Reader/transport reauthorization
and policy/custody qualification remain prerequisite inputs, not claimed effects.
The G09 packet is exactly `{v,service,stream,action_hash,old_transport,
new_transport,old_record,new_record}`. Transport D references select retained
signed evidence; absent referenced profiles refuse. The closure is bounded to
8 objects, each <=65536, aggregate <=262144 bytes; signed lines remain <=8192.
The principal-possession body is exactly
`{v,type,service,stream,action_hash,principal_id,transport_pin,challenge,
channel_digest,key_epoch,key_id}`, signed by the distinct enrollment verifier
under `state-witness-principal-possession/1` + NUL + CCJ-1(body).
Action H, fresh 32hex challenge and exact independently supplied live-channel
context must match. The verifier is responsible for the completed G11 handshake,
exporter label `EXPORTER-state-witness-possession/1`, context
CCJ-1({action_hash,challenge}), and D of 32 exporter bytes. The library verifies
public evidence only; no exporter secret or attestor implementation is supplied.

G09 option B keeps record-key rotation unavailable: `profile_unavailable` even
with valid old/new intent signatures. Unchanged record keys retain their epoch;
writer policy epoch advances by exactly one. An old/new signature pair has no
action/challenge binding and is not a standalone possession proof. Future option
A belongs jointly to KC and the internal writer and requires an accepted durable
transaction binding both signing acts to the exact action and fresh challenge,
with replay limited to the same action. No new purpose-3 signer/domain or G04/G05
field is added. Current writers can validate exact historical record/receipt
retries without regenerating signatures; old peers cannot append anew.

G12 is exactly one HTTP/1.1 POST `/witness/v1` with the fixed media type
`application/vnd.swarma.state-witness.v1+json`, Host, a shortest positive decimal
Content-Length and Connection: close. Optional Accept equals the media type;
optional ASCII User-Agent <=256. Header names are case insensitive and values
strip only edge OWS. Other/duplicate/folded/control-bearing headers, TE, trailers,
compression, queries, redirects, upgrades and pipelined/trailing bodies close
without an application frame. Limits: start line256, field line1024, eight fields,
header section4096, body65536. Authorized frames then use unchanged S1 codecs;
responses validate the closed S1 success/refusal carrier and use HTTP200.
Pure fully-buffered checks do not claim preallocation refusal or streaming I/O.

Accept-relative budget is <=5s, TLS<=3s, headers/body<=1s each; the decoded caller
budget narrows the same deadline. Pure counters cap connections128, handshakes16,
operations16, source handshakes2, source entries1024 and handshake bytes65536.
Exact token models charge attempts/refusals: preauth global20/s burst40,
source2/s burst4; application peer20/s burst40, writes2/s burst4 and global200/s
burst256. The future server owns bounded tables, monotonic timing, atomic updates,
cancellation and fairness. There is no queue, live rate limiter or egress here.

Run the exact narrow command and see [tests and pending dependencies](policy-tests.md).
All WS refusal codes retain the existing enum/retryability. TLS/framing closes
carry no new application error member. Mixed-failure precedence outside these
pure stages remains G21; unknown irreversible work stays an S3/S4 fence.
