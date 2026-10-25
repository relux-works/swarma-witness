package transport

import (
	"bytes"
	"github.com/relux-works/swarma-witness/wire"
	"strings"
	"testing"
)

// Claim: three frozen independent preimages pin domain labels, NUL and length
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
	const expected = `{"alpn":["http/1.1"],"ca_signatures":["Ed25519","ECDSA-P256-SHA256"],"certificate_bytes":8192,"certificate_count":4,"chain_bytes":32768,"cipher_suites":["TLS_AES_128_GCM_SHA256","TLS_AES_256_GCM_SHA384","TLS_CHACHA20_POLY1305_SHA256"],"client_eku":"clientAuth","client_san":"urn:state-witness:principal:<H(UTF8(principal_id))>","crl_bytes":65536,"crl_count":3,"crl_entries":1024,"early_data":false,"groups":["X25519","P-256"],"leaf_key":"Ed25519","leaf_usage":"digitalSignature","one_request":true,"post_handshake_auth":false,"proxy_termination":false,"public_web_pki":false,"resumption":false,"revocation":"local-full-crl","server_eku":"serverAuth","server_san":"urn:state-witness:service:<service>","time_profile":"state-witness-tls:1","tls_version":"1.3","trust_set_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","v":1}`
	if e != nil || !bytes.Equal(raw, []byte(expected)) {
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
