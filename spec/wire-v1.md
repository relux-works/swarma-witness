# Canonical wire and signature slice

This document records the codec decisions for version 1. The owning service and
consumer contracts are [WS](https://github.com/relux-works/swarma-keymaker/blob/7a2262ce2b8b84b9e9bc627972d4e07d62d34270/spec/witness-service.md)
and [KC](https://github.com/relux-works/swarma-keymaker/blob/7a2262ce2b8b84b9e9bc627972d4e07d62d34270/spec/keymaker-witness.md).
These pure libraries provide no listener, append/latest service, durable custody,
authorization, replay ledger or consumer activation. Mode A remains in force.

## Dependencies and canonical bytes

The strict key/base64/signature helpers are `swarma-envelope` at
`v0.0.0-20261026200550-5636986d0de5`, preserving the consumed historical S5
helpers. Its exact registrar CCJ dependency,
`v0.0.0-20261023164451-5f44ebf3f788`, is also used directly for parsing and
canonicalization. The dependency policy permits these exact versions only;
there are no replacements or copied verifiers. Newer currency APIs in the
dependency do not activate a Witness verifier or change any local /1 profile.

`wire.Parse` uses the duplicate-aware public registrar reader, then compares the
received bytes with their canonical encoding. Envelope `record.Parse` alone is
insufficient: it accepts noncanonical whitespace and caps all strings at 8192.
Container depth/count checks precede parsing; frames and binary encoded sizes
are bounded before decoding. Canonical JSON parsing is bounded by the complete
frame even when a string fails its subsequent field-specific limit.

Shared integers are int64 in the safe range, maximum 9007199254740991. H means
64 lowercase hex characters; D means `sha256:` followed by H. They are distinct.
Zero H is reserved for authorized genesis predecessors/anchors, never an implicit
first-use grant. Strings are exact UTF-8 bytes without normalization. UTC times
are real Gregorian `YYYY-MM-DDTHH:MM:SSZ`, years 1970–9999, no leap seconds,
fractions or offsets. Base64url is unpadded, exact-length when specified, with
zero unused bits and decode/re-encode equality.

## Closed bindings

The binding is exactly `{service,stream,consumer,identity,lineage,profile,
writer_epoch,writer_id,record_key,transport_pins,readers}`.

| Consumer | Profile | Identity | record_key |
| --- | --- | --- | --- |
| keymaker | keymaker-state-witness/1 | Exactly `{product,project,agent}` | Exactly `{public_key,key_id,key_epoch,purpose}`; purpose 3 |
| registrar | registrar-state-witness-sha1/1 or registrar-state-witness-sha256/1 | Provisioned opaque string | Required null |
| owner-registry | owner-registry-checkpoint/1 | Exactly `{registry_id,owner}` | Required null |

Service/stream are `[a-z0-9][a-z0-9._-]{0,127}`. Station components are
`[a-z][a-z0-9-]{0,62}`. Other identities, lineage and principal IDs are 1–255
UTF-8 bytes. Epochs are positive safe integers. Registry IDs use strict envelope
Ed25519 or compressed P-256 key strings. Signing public keys for Keymaker,
witness, admin and transition are Ed25519 raw32 encoded with `ed25519:` plus
base64url; their key IDs are D over raw32, with independent role/epoch pins.

Transport pins are D over canonical DER SubjectPublicKeyInfo. The `TransportPin`
helper derives them from DER; a pin-shaped string alone cannot prove certificate
possession or role. Writer pins contain 1–8 distinct values. Readers contain 0–32
exact `{id,transport_pins}` principals, each with 1–8 distinct pins. IDs are unique;
a pin cannot identify different principals. Explicit writer membership in readers
is allowed but does not automatically grant it. Parsing these bindings supplies
no provisioning, consent or transport authority.

## Records and evidence

All received objects are closed at every depth. Records/admin actions contain
exactly one final LF, which participates in their H. Signature envelopes are
exactly `{body,signature}`. Signatures cover domain, NUL and canonical body,
without LF. Domains come from protected context, never received claims:

| Artifact | Domain |
| --- | --- |
| Keymaker record | keymaker-witness-record/1 |
| Keymaker receipt / head | keymaker-witness-ack/1 / keymaker-witness-head/1 |
| Neutral receipt / head | state-witness-ack/1 / state-witness-head/1 |
| Admin / control receipt | state-witness-admin/1 / state-witness-control-ack/1 |
| New-key possession proof | state-witness-key-transition/1 |

The envelope helper validates canonical nonidentity prime-subgroup public points and R,
S<L, then ordinary Ed25519. Domain, purpose 3, role, computed key ID, station,
stream and independent epochs are additional checks. Intent at the final safe
sequence refuses `sequence_exhausted`; resolution at that sequence remains
representable. Null initial base requires explicit bootstrap-pair context and
first intent/resolution positions. Ordinary consumer pairing and local state
truth are consumer responsibilities.

Keymaker commit classes are exactly `binding-result`, `enrollment`,
`reconciliation`, `audit`, `retention`, `policy-custody`; kinds are exactly
`intent` and `committed`. Intent has null intent_hash; committed has H.
Receipt fields are copied from the admitted original record. Witness epochs
never replace writer epochs. A head includes the unchanged original receipt,
record, exact challenge and closed manifests, even for an equal anchor.
Historical receipt keys/control hashes and the current reply key/control hash
are supplied independently. Callers must compare requested trusted anchors,
fetch/verify every page, and validate historical signatures and consumer pairing;
a signed head or hash-checked page alone is not authoritative latestness.

Proof manifests cover contiguous anchor+1 through head with exact counts and
ordered page indices. Equal anchors alone permit zero pages. Committed heads
reference their immediate intent, including when before the requested anchor.
Pages contain 1–2 exact `{record,receipt}` entries and one of `records`, `controls`,
`intent`. Their D covers the complete canonical page without LF. Page checking
validates framing and content hash, not application truth or admission.

The administrative operations are exactly `provision`, `rotate_writer`,
`rotate_witness`, with WS's operation-specific nulls. Provision includes full
binding, zero expected head, bootstrap H and null expected binding. Writer
rotation includes a full binding, expected binding D/head and null bootstrap.
Witness rotation has null stream/head/bootstrap, expected policy D and a new
key object `{service,key_epoch,key_id,public_key,proof}`; proof excludes itself
from its body. Signature/schema checks do not grant S2 authorization, continuity,
consent, replay or CAS success. External signer callbacks see only a copy of a
bounded preimage; the reserved body is snapshotted before the call, and returned
signatures are verified independently.

Checkpoint wrapper decoding preserves the carried checkpoint/proof bytes
exactly. Its eight-field projection and timestamp are closed, but `Verify`
always returns `profile_unavailable`. Registry checkpoint verification, fork
admission, ancestry/currentness and wrapper mechanical pairing remain S6. No
checkpoint/2 or root-age exception is assumed.

## Registrar syntax adapter

The grammar is owned by [registrar §4.3](https://github.com/relux-works/swarma-registrar/blob/3fc31e457043d2479fd300698dee92ab0dd4bef2/spec/registrar.md),
landed revision `3fc31e457043d2479fd300698dee92ab0dd4bef2`. The prerequisite
mandatory `registry.Loader.ObjectFormat` code landed at
`264660e5dabbb3572c586e289268a190db172a7c`. These close the former G06 syntax
activation gate. This library imports only CCJ, no registry package or Loader;
its older CCJ dependency is not a claim to use the old Loader's format behavior.
A future Loader integration must pin the format-enforcing code and pass the
protected parameter explicitly.

`DecodeRegistrar` checks the exact flat record, LF/hash and syntax/format only.
The protected profile literal chooses the accepted format before examining the
revision: `-sha1/1` selects 40 lowercase hex, `-sha256/1` selects 64. Supplied length
never chooses an admitted algorithm, and there is no 40|64 default. Neither
transport authentication nor Git/candidate-state truth is established. The
WS-side classifications are:

| Isolated registrar case | WS code |
| --- | --- |
| Syntax/abbreviation/uppercase/branch/prefix or ±1 violation | request_malformed |
| Well-formed full ID conflicting with the protected format | evidence_invalid |
| Authenticated registrar registry_unavailable refusal | evidence_invalid |
| Accepted adapter/mandatory format unavailable | profile_unavailable |
| Missing/corrupt protected stream binding | stream_unavailable |

All are nonretryable. Classification of a refused other-format ID never selects
an accepted algorithm. The shared D grammar and exact digest comparison are
available independently, without claiming registrar candidate-state truth.

## Transport-independent carriers and bounds

Requests and params are exactly WS §4. Success for all four methods, including
admin, is `{v:1,request_id,result}` with one non-null canonical base64url string
of original result bytes, without an appended LF. Failure is exactly
`{v:1,request_id,error:{code,retryable}}` with WS's 18 codes and fixed retryability;
there is no detail/message/foreign error member. Correlation IDs are 32 lowercase
hex, timeouts 1–5000ms. Invalid/untrustworthy correlation yields no application
frame. The transport must authenticate and authorize before looking up streams;
these codecs perform no lookup and do not implement disclosure precedence.

| Quantity | Maximum bytes |
| --- | --- |
| Complete frame | 65536 |
| Consumer/admin line including LF | 8192 |
| Receipt/control receipt | 4096 |
| Signed head | 32768 |
| Proof page | 45056 |
| Named binary field's encoded ASCII | 16384 |
| Sole outer result's encoded ASCII | 60075 |
| Remaining outer metadata | 4096 |

Depth 16, arrays 64 and ordinary strings 8192 also apply. Only the named binary
carriers and sole outer result get larger string bounds. Raw, encoded, metadata
and total sizes are checked independently: 45056 raw encodes to 60075; plus 4096
is 64171, below 65536. Tests of isolated ceilings do not claim every maximum is
reachable together in the closed schema. Malformed encodings use
`request_malformed`; exceeded caps use `limit_exceeded`; mathematical/domain/
protected-evidence mismatches use `evidence_invalid`. Mixed-failure precedence
remains separately gated. HTTP media/framing/headers/read budgets, mTLS, per-peer
ACLs, admission/rate limits, storage, custodian and recovery remain unimplemented.
