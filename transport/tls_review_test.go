package transport

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/relux-works/swarma-witness/wire"
)

// Review: full-CRL-only admission must not treat a delta list as a complete
// revocation snapshot merely because its indicator is marked noncritical.
func TestReviewTLSFullCRLOnly(t *testing.T) {
	f := newTLSFixture(t, "server")
	if e := validateFixture(f, &syntheticTime{observed: f.observed}); e != nil {
		t.Fatal("full CRL control", e)
	}
	for _, critical := range []bool{true, false} {
		t.Run(fmt.Sprint(critical), func(t *testing.T) {
			value, e := asn1.Marshal(big.NewInt(1))
			if e != nil {
				t.Fatal(e)
			}
			tmpl := &x509.RevocationList{Number: big.NewInt(2), ThisUpdate: f.observed.Add(-time.Minute), NextUpdate: f.observed.Add(time.Minute), ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 27}, Critical: critical, Value: value}}}
			raw, e := x509.CreateRevocationList(rand.Reader, tmpl, f.root, f.rootKey)
			if e != nil {
				t.Fatal(e)
			}
			crl, e := x509.ParseRevocationList(raw)
			if e != nil {
				t.Fatal(e)
			}
			bad := f
			bad.context.CRLs = []*x509.RevocationList{crl}
			if e = validateFixture(bad, &syntheticTime{observed: f.observed}); wire.Code(e) != "not_authorized" {
				t.Fatalf("unsupported delta CRL accepted (critical=%v): %v", critical, e)
			}
		})
	}
}

// Review: inclusive not-before and exclusive not-after/authority are tested
// exactly at, and immediately beside, each nanosecond edge through ValidateTLS.
func TestReviewTLSExactEdges(t *testing.T) {
	f := newTLSFixture(t, "server")
	leaf, e := x509.ParseCertificate(f.der)
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		name string
		at   time.Time
		ok   bool
	}{{"L-equals-not-before", leaf.NotBefore, true}, {"L-before-not-before", leaf.NotBefore.Add(-time.Nanosecond), false}, {"U-before-not-after", leaf.NotAfter.Add(-time.Nanosecond), true}, {"U-equals-not-after", leaf.NotAfter, false}} {
		t.Run(tc.name, func(t *testing.T) {
			source := &syntheticTime{observed: tc.at, alter: func(f *TimeFacts) { f.Uncertainty = 0; f.HighWater = f.Observed }}
			e := validateFixture(f, source)
			if tc.ok && e != nil {
				t.Fatal("valid edge", e)
			}
			if !tc.ok && wire.Code(e) != "not_authorized" {
				t.Fatalf("invalid edge: %v", e)
			}
		})
	}
}

// Claim: independently signed noncritical scope/indirection extensions and
// delta-only entry reasons cannot substitute for a full direct CRL. A full
// list with an ordinary reason on a different serial remains admissible.
func TestTLSFullDirectCRLProfile(t *testing.T) {
	f := newTLSFixture(t, "server")
	ordinary := x509.RevocationListEntry{SerialNumber: big.NewInt(3), RevocationTime: f.observed.Add(-time.Minute), ReasonCode: 1}
	control := f
	control.context.CRLs = []*x509.RevocationList{makeCRL(t, f.root, f.rootKey, f.observed, []x509.RevocationListEntry{ordinary}, big.NewInt(2))}
	if e := validateFixture(control, &syntheticTime{observed: f.observed}); e != nil {
		t.Fatal("full direct control", e)
	}
	for _, tc := range []struct {
		name  string
		oid   asn1.ObjectIdentifier
		value []byte
	}{
		{"issuing-distribution-point", asn1.ObjectIdentifier{2, 5, 29, 28}, []byte{0x30, 0x03, 0x84, 0x01, 0xff}},
		{"freshest-crl", asn1.ObjectIdentifier{2, 5, 29, 46}, []byte{0x30, 0x00}},
		{"unknown-crl-extension", asn1.ObjectIdentifier{1, 2, 3, 4}, []byte{0x05, 0x00}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, e := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(2), ThisUpdate: f.observed.Add(-time.Minute), NextUpdate: f.observed.Add(time.Minute), ExtraExtensions: []pkix.Extension{{Id: tc.oid, Value: tc.value}}}, f.root, f.rootKey)
			if e != nil {
				t.Fatal(e)
			}
			crl, e := x509.ParseRevocationList(raw)
			if e != nil {
				t.Fatal(e)
			}
			bad := f
			bad.context.CRLs = []*x509.RevocationList{crl}
			if e = validateFixture(bad, &syntheticTime{observed: f.observed}); wire.Code(e) != "not_authorized" {
				t.Fatalf("unsupported scoped CRL accepted: %v", e)
			}
		})
	}
	for _, name := range []string{"certificate-issuer", "remove-from-crl"} {
		t.Run(name, func(t *testing.T) {
			entry := ordinary
			if name == "certificate-issuer" {
				entry.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 29}, Value: []byte{0x30, 0x00}}}
			} else {
				entry.ReasonCode = 8
			}
			bad := f
			bad.context.CRLs = []*x509.RevocationList{makeCRL(t, f.root, f.rootKey, f.observed, []x509.RevocationListEntry{entry}, big.NewInt(2))}
			if e := validateFixture(bad, &syntheticTime{observed: f.observed}); wire.Code(e) != "not_authorized" {
				t.Fatalf("unsupported indirect/delta entry accepted: %v", e)
			}
		})
	}
}
