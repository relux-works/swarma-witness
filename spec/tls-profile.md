# Proposed G11 digest codecs

These preimages require confirmation before their codec lands. They do not open
G07/G10, qualify a time/CA provider or authorize serving. The profile narrows the
conditional service contract, using the broker's [native operation recipe](https://github.com/relux-works/swarma-credential-broker/blob/a1c69eb9ed6576d3b060dfb3e697de2fd2180f0d/docs/time-contract.md).

**G11 v3 addition; preimages proposed for confirmation before landing the codec:** the native profile identifier is `state-witness-tls:1` (superseding the slash-bearing identifier above). A transport pin is `sha256:` + lowercase hex(SHA-256(DER SubjectPublicKeyInfo)), never a raw signing-key hash.

`chain_digest` is D over ASCII `state-witness-tls-chain/1`, NUL, uint32-big-endian certificate count, then for each certificate uint32-big-endian DER byte length and exact DER bytes. Use the exact presented order, leaf first, 1–4 certificates, each 1–8192 bytes and total DER<=32768. Include the root **if presented**; never synthesize, omit, reorder or normalize a presented certificate. This commits the actual presentation, including the presence/absence of a sent root; path validation independently requires the protected anchor and caps the verified path including its root.

`tls_policy_digest` is D over ASCII `state-witness-tls-policy/1`, NUL, and CCJ-1 of exactly the following object (array order is literal):

`{v:1,tls_version:"1.3",alpn:["http/1.1"],cipher_suites:["TLS_AES_128_GCM_SHA256","TLS_AES_256_GCM_SHA384","TLS_CHACHA20_POLY1305_SHA256"],groups:["X25519","P-256"],leaf_key:"Ed25519",ca_signatures:["Ed25519","ECDSA-P256-SHA256"],resumption:false,early_data:false,post_handshake_auth:false,proxy_termination:false,public_web_pki:false,leaf_usage:"digitalSignature",server_eku:"serverAuth",client_eku:"clientAuth",server_san:"urn:state-witness:service:<service>",client_san:"urn:state-witness:principal:<H(UTF8(principal_id))>",revocation:"local-full-crl",one_request:true,certificate_count:4,certificate_bytes:8192,chain_bytes:32768,crl_count:3,crl_bytes:65536,crl_entries:1024,time_profile:"state-witness-tls:1",trust_set_digest:D}`.

The SAN strings above are literal templates in the policy preimage; their substitutions are exact UTF-8 service/principal bytes, with H lowercase SHA-256. `trust_set_digest` is D over ASCII `state-witness-tls-trust-set/1`, NUL, and CCJ-1 of exactly `{service,config_generation,role,principal_id,pin_set,ca_set,crl_set}`: role is the peer's `server|client` certificate role, pin_set is its complete protected set of leaf SPKI pins, ca_set is D of each exact protected anchor DER, crl_set is D of each exact protected full-CRL DER. Each set is lexicographically sorted, duplicate-free and nonempty; service/principal/generation retain the operation schema. This binds the selected protected principal, all admitted pins, anchors and revocation snapshot, rather than trusting a caller-supplied digest. No WS request member changes. Policy generation and CRL high-water rechecks, complete native-time adapter acceptance, qualified handoff and production custody remain gates; these proposed preimages alone open none.

`transport.operation` builds exactly `{v:1,service,role,principal_id,peer_spki,
chain_digest,tls_policy_digest,connection_id,config_generation}`. Connection ID
and provider challenge are distinct fresh 32hex values. The native digest uses
`qualified-time/consumer-operation/1`, NUL, uint32-big-endian profile length,
profile bytes, uint32-big-endian operation length and operation CCJ-1 bytes.
No field or domain is selected from a received WS request.

`QualifiedTime.Consume` is an interface obligation, not a supplied provider or
verifier. It must verify the complete authenticated receipt/closure, native
scope, one-use challenge, current boot, protected identity/policy and dedicated
chrony-nts-authdata facts; durably retain U, in-flight observations and holds;
and refuse unknown confidence, holds, steps or unconfirmed continuity. Tests
substitute explicitly synthetic consumed facts only. There is no Sample API or
wall-clock fallback. The predicate retains nanosecond intervals, requires
L>=NotBefore and U<NotAfter for every path certificate including root,
U<AuthorityUntil, L>max(prior provider high-water, imported floor), and exact new
high-water=U. The provider's inclusive 1.5s uncertainty ceiling is retained;
protected policy may require a smaller bound. Production still needs the complete
native adapter and reviewed bounded fresh handoff outside final locks.

Path verification uses only protected anchors plus the exact leaf pin, one URI
SAN and exactly the role EKU. CRLs are local signed full lists with current
qualified interval, positive number and retained per-issuer high-water; revoked
leaves/intermediates, rollback and missing lists refuse. Protected DER is reparsed
and copied so mutable parsed views cannot diverge from the committed bytes.
No network fetching, proxy trust, TLS resumption or early-data path is supplied.
`TLSConfig` is unserved and uses custom qualified interval verification instead
of the standard library's default clock/trust path. It requires TLS1.3/http1.1,
X25519/P-256, full mTLS and no session cache/tickets. The HTTP/handler layer
remains closed; these settings cannot approve production readiness.

Frozen codec-only vectors in `TestTLSProposedPreimageVectors`:

| Preimage | D |
| --- | --- |
| Presented DER octets `[3000,300100]`, each hex | sha256:bee6019b95a12ab4f4cbb2ebccb0aa2fd9ee59b7769882c39fce741c829c550a |
| Exact policy with trust_set_digest=`sha256:` plus 64 zeroes | sha256:43c105018863712e3aa168cf2bb6ffcfcfc4707906a22456948f2d2618281493 |
| Native recipe with profile state-witness-tls:1 and operation `{"v":1}` | sha256:ca877341175ba392e0bc6fb1e48e91089ae424b5a8944cc4e653f13856ce3aaf |

The DER fragments above test bytes/lengths only and are not certificate examples.
Real handshake fixtures generate ephemeral keys in memory under private test
scratch, with no checked-in or logged private material. See [pending tests](policy-tests.md)
for durable reload, provider, application handoff and runtime qualification gaps.
