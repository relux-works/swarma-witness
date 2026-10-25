package transport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/relux-works/swarma-witness/records"
	"github.com/relux-works/swarma-witness/wire"
)

// Claim: all three input sets must already be strictly ascending and unique.
// Roots/CRLs are ordered by D(DER), which these codec-only octets deliberately
// place in the opposite order from raw DER. This proves no certificate validity.
func TestTLSStrictInputSets(t *testing.T) {
	ordered := TLSContext{Service: "svc", Generation: 7, Role: "client", PrincipalID: "peer",
		Pins:  []string{records.Digest([]byte("b")), records.Digest([]byte("a"))},
		Roots: []*x509.Certificate{{Raw: []byte("b")}, {Raw: []byte("a")}},
		CRLs:  []*x509.RevocationList{{Raw: []byte("d")}, {Raw: []byte("c")}},
	}
	if got, e := TrustSetDigest(ordered); e != nil || got == "" {
		t.Fatalf("sorted D(DER) control: %s %v", got, e)
	}
	for _, set := range []string{"pins", "anchors", "crls"} {
		for _, form := range []string{"unsorted", "duplicate"} {
			t.Run(set+"/"+form, func(t *testing.T) {
				c := ordered
				c.Pins = append([]string(nil), ordered.Pins...)
				c.Roots = append([]*x509.Certificate(nil), ordered.Roots...)
				c.CRLs = append([]*x509.RevocationList(nil), ordered.CRLs...)
				switch set {
				case "pins":
					c.Pins[0], c.Pins[1] = c.Pins[1], c.Pins[0]
					if form == "duplicate" {
						c.Pins[1] = c.Pins[0]
					}
				case "anchors":
					c.Roots[0], c.Roots[1] = c.Roots[1], c.Roots[0]
					if form == "duplicate" {
						c.Roots[1] = c.Roots[0]
					}
				case "crls":
					c.CRLs[0], c.CRLs[1] = c.CRLs[1], c.CRLs[0]
					if form == "duplicate" {
						c.CRLs[1] = c.CRLs[0]
					}
				}
				if got, e := TrustSetDigest(c); wire.Code(e) != "evidence_invalid" || got != "" {
					t.Fatalf("unordered or duplicate set accepted: %s %s %v", set, got, e)
				}
			})
		}
	}
}

// Claim: the unserved VerifyConnection callback checks the negotiated cipher
// and curve explicitly before time consumption. Each permitted combination has
// a valid synthetic certificate/time control; no Go-default bypass is claimed.
func TestTLSHandshakeChoiceBeforeTime(t *testing.T) {
	f := newTLSFixture(t, "server")
	leaf, e := x509.ParseCertificate(f.der)
	if e != nil {
		t.Fatal(e)
	}
	valid := tls.ConnectionState{Version: tls.VersionTLS13, NegotiatedProtocol: "http/1.1", CipherSuite: tls.TLS_AES_128_GCM_SHA256, CurveID: tls.X25519, PeerCertificates: []*x509.Certificate{leaf}}
	for _, suite := range []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256} {
		for _, curve := range []tls.CurveID{tls.X25519, tls.CurveP256} {
			t.Run(fmt.Sprintf("permitted/%x/%d", suite, curve), func(t *testing.T) {
				state := valid
				state.CipherSuite = suite
				state.CurveID = curve
				source := &syntheticTime{observed: f.observed}
				if e := TLSConfig(f.context, source).VerifyConnection(state); e != nil {
					t.Fatal("permitted handshake refused", e)
				}
				if source.calls != 1 {
					t.Fatal("permitted handshake did not consume time")
				}
			})
		}
	}
	for _, tc := range []struct {
		name  string
		suite uint16
		curve tls.CurveID
	}{
		{"zero-suite", 0, tls.X25519}, {"unknown-suite", 0xffff, tls.X25519}, {"tls12-suite", tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.X25519},
		{"zero-curve", tls.TLS_AES_128_GCM_SHA256, 0}, {"unknown-curve", tls.TLS_AES_128_GCM_SHA256, 0xffff}, {"p384", tls.TLS_AES_128_GCM_SHA256, tls.CurveP384}, {"hybrid", tls.TLS_AES_128_GCM_SHA256, tls.X25519MLKEM768},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := valid
			state.CipherSuite = tc.suite
			state.CurveID = tc.curve
			source := &syntheticTime{observed: f.observed}
			if e := TLSConfig(f.context, source).VerifyConnection(state); wire.Code(e) != "not_authorized" {
				t.Fatalf("forbidden handshake accepted: %v", e)
			}
			if source.calls != 0 {
				t.Fatal("forbidden handshake consumed time")
			}
		})
	}
}
