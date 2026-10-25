package transport

import (
	"bytes"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/relux-works/swarma-witness/records"
	"github.com/relux-works/swarma-witness/wire"
)

// Complete deterministic CCJ-1 input for the policy vectors. The second policy
// vector substitutes only trust_set_digest with the explicit trust vector below.
const zeroTrustPolicyCCJ = `{"alpn":["http/1.1"],"ca_signatures":["Ed25519","ECDSA-P256-SHA256"],"certificate_bytes":8192,"certificate_count":4,"chain_bytes":32768,"cipher_suites":["TLS_AES_128_GCM_SHA256","TLS_AES_256_GCM_SHA384","TLS_CHACHA20_POLY1305_SHA256"],"client_eku":"clientAuth","client_san":"urn:state-witness:principal:<H(UTF8(principal_id))>","crl_bytes":65536,"crl_count":3,"crl_entries":1024,"early_data":false,"groups":["X25519","P-256"],"leaf_key":"Ed25519","leaf_usage":"digitalSignature","one_request":true,"post_handshake_auth":false,"proxy_termination":false,"public_web_pki":false,"resumption":false,"revocation":"local-full-crl","server_eku":"serverAuth","server_san":"urn:state-witness:service:<service>","time_profile":"state-witness-tls:1","tls_version":"1.3","trust_set_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","v":1}`

// Claim: three initial frozen independent preimages pin domain labels, NUL and length
// prefixes, ordering and every canonical policy member. DER fragments below
// are codec-only octets, not claimed valid certificates or handshake fixtures.
func TestTLSProposedPreimageVectors(t *testing.T) {
	got, e := ChainDigest([][]byte{{0x30, 0}, {0x30, 1, 0}})
	if e != nil || got != "sha256:bee6019b95a12ab4f4cbb2ebccb0aa2fd9ee59b7769882c39fce741c829c550a" {
		t.Fatalf("chain vector: %s %v", got, e)
	}
	reordered, _ := ChainDigest([][]byte{{0x30, 1, 0}, {0x30, 0}})
	if reordered == got {
		t.Fatal("chain order unbound")
	}
	omitted, _ := ChainDigest([][]byte{{0x30, 0}})
	if omitted == got {
		t.Fatal("presented root omission unbound")
	}
	if _, e = ChainDigest([][]byte{make([]byte, 8193)}); wire.Code(e) != "limit_exceeded" {
		t.Fatal("certificate cap")
	}
	raw, e := TLSPolicyBytes("sha256:" + strings.Repeat("0", 64))
	if e != nil || !bytes.Equal(raw, []byte(zeroTrustPolicyCCJ)) {
		t.Fatal("policy preimage differs")
	}
	if hashDomain("state-witness-tls-policy/1", raw) != "sha256:43c105018863712e3aa168cf2bb6ffcfcfc4707906a22456948f2d2618281493" {
		t.Fatal("policy digest differs")
	}
	changed, _ := TLSPolicyBytes("sha256:" + strings.Repeat("1", 64))
	if bytes.Equal(changed, raw) {
		t.Fatal("trust set unbound")
	}
	got, e = ConsumerOperationDigest([]byte(`{"v":1}`))
	if e != nil || got != "sha256:ca877341175ba392e0bc6fb1e48e91089ae424b5a8944cc4e653f13856ce3aaf" {
		t.Fatalf("native vector: %s %v", got, e)
	}
}

// Review: an independent Python CCJ-1/domain oracle fixes the complete trust
// set; this uses codec-only DER octets, not a certificate validity claim.
func TestReviewTrustSetOracle(t *testing.T) {
	c := TLSContext{Service: "svc", Generation: 7, Role: "client", PrincipalID: "peer", Pins: []string{records.Digest([]byte("pin-a")), records.Digest([]byte("pin-b"))}, Roots: []*x509.Certificate{{Raw: []byte("synthetic-root-a")}, {Raw: []byte("synthetic-root-b")}}, CRLs: []*x509.RevocationList{{Raw: []byte("synthetic-full-crl-a")}}}
	want := "sha256:158ed795e5f0395893fd1167b0588a823ce458a23976cefc738e91a5827cbab0"
	// Full canonical input after hashing the literal UTF-8 octets above. All
	// fields, sets and their order are fixed; no generated keys enter a vector.
	const trustInputCCJ = `{"ca_set":["sha256:da4256a0abf8cfaa7126e918053aa6a42f13c861584c4e4c831f8f0be180b9d8","sha256:f4bd1544804bdd04fabbe67316a4244b32a9bfebfc27903321a8e6d6438a2c82"],"config_generation":7,"crl_set":["sha256:9887adb57c0edf6ba5d00be17beca74f02ab69c0a10918a96d03f186c3cb57ee"],"pin_set":["sha256:6893047cca0c26bee4f9df72113972c12adb86eda8d0876cbcb76632e1cd90be","sha256:9232c0990c60090e1ba8fb1fe06f68c0d841aac9ace0a1b6b9cc440ce922ae41"],"principal_id":"peer","role":"client","service":"svc"}`
	if hashDomain("state-witness-tls-trust-set/1", []byte(trustInputCCJ)) != want {
		t.Fatal("trust preimage vector differs")
	}
	got, e := TrustSetDigest(c)
	if e != nil || got != want {
		t.Fatalf("trust-set: %s %v", got, e)
	}
	// The same complete policy object as the zero-trust vector, now bound to
	// the explicit sorted svc/generation7/client/peer trust set above.
	policyInput := bytes.ReplaceAll([]byte(zeroTrustPolicyCCJ), []byte("sha256:"+strings.Repeat("0", 64)), []byte(want))
	if actual, err := TLSPolicyBytes(want); err != nil || !bytes.Equal(actual, policyInput) {
		t.Fatal("trust-bound policy input differs")
	}
	if policy, err := TLSPolicyDigest(c); err != nil || policy != "sha256:59229db02f375f344dc0a4a7c3a6ea7de5542dcbdecdeea22dd48031b766c498" {
		t.Fatalf("trust-bound policy vector: %s %v", policy, err)
	}
	c.Pins[0], c.Pins[1] = c.Pins[1], c.Pins[0]
	c.Roots[0], c.Roots[1] = c.Roots[1], c.Roots[0]
	if got, e = TrustSetDigest(c); wire.Code(e) != "evidence_invalid" || got != "" {
		t.Fatal("unsorted trust set accepted", got, e)
	}
	c.Pins[0], c.Pins[1] = c.Pins[1], c.Pins[0]
	c.Roots[0], c.Roots[1] = c.Roots[1], c.Roots[0]
	c.Pins[1] = records.Digest([]byte("changed"))
	if got, e = TrustSetDigest(c); e != nil || got == want {
		t.Fatal("changed trust did not bind", got, e)
	}
}
