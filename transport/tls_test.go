package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"net"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-witness/records"
	"github.com/relux-works/swarma-witness/wire"
)

type syntheticTime struct {
	observed time.Time
	alter    func(*TimeFacts)
	calls    int
}

func (s *syntheticTime) Consume(_ context.Context, r TimeRequest) (TimeFacts, error) {
	s.calls++
	f := TimeFacts{Profile: r.Profile, OperationDigest: r.OperationDigest, Challenge: r.Challenge, Boot: r.Boot, Authority: r.Authority, Adapter: r.Adapter, Policy: r.Policy, Observed: s.observed, Uncertainty: time.Millisecond, AuthorityUntil: s.observed.Add(time.Hour), PriorHighWater: s.observed.Add(-time.Hour), JournalFloor: r.JournalFloor, HighWater: s.observed.Add(time.Millisecond), Receipt: []byte("synthetic full receipt"), Continuity: []byte("synthetic acknowledged continuity"), Generation: 1}
	if s.alter != nil {
		s.alter(&f)
	}
	return f, nil
}

type tlsFixture struct {
	context  TLSContext
	der      []byte
	root     *x509.Certificate
	rootKey  ed25519.PrivateKey
	leafKey  ed25519.PrivateKey
	observed time.Time
}

func newTLSFixture(t *testing.T, role string) tlsFixture {
	t.Helper()
	// All generated private keys stay ephemeral in memory; the test's private
	// scratch is 0700 and no key bytes are serialized, logged or checked in.
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	observed := time.Unix(2000000000, 123456789).UTC()
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: observed.Add(-time.Hour), NotAfter: observed.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{1, 2, 3}}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if e != nil {
		t.Fatal(e)
	}
	root, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	lp, lk, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	eku := x509.ExtKeyUsageClientAuth
	uri := "urn:state-witness:principal:" + records.Hash([]byte("peer"))
	if role == "server" {
		eku = x509.ExtKeyUsageServerAuth
		uri = "urn:state-witness:service:svc"
	}
	u, e := url.Parse(uri)
	if e != nil {
		t.Fatal(e)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: observed.Add(-time.Minute), NotAfter: observed.Add(time.Minute), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku}, URIs: []*url.URL{u}}
	der, e = x509.CreateCertificate(rand.Reader, leaf, root, lp, priv)
	if e != nil {
		t.Fatal(e)
	}
	parsed, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	pin, e := wire.TransportPin(parsed.RawSubjectPublicKeyInfo)
	if e != nil {
		t.Fatal(e)
	}
	crl := makeCRL(t, root, priv, observed, nil, big.NewInt(1))
	c := TLSContext{Service: "svc", Role: role, PrincipalID: "peer", Pins: []string{pin}, Roots: []*x509.Certificate{root}, CRLs: []*x509.RevocationList{crl}, CRLFloors: map[string]*big.Int{records.Digest(root.RawSubjectPublicKeyInfo): big.NewInt(1)}, Generation: 1, Authority: "authority", Adapter: "native-adapter", TimePolicy: "qualified-policy", Boot: "boot", JournalFloor: observed.Add(-2 * time.Hour)}
	return tlsFixture{c, der, root, priv, lk, observed}
}
func makeCRL(t *testing.T, root *x509.Certificate, k ed25519.PrivateKey, observed time.Time, revoked []x509.RevocationListEntry, num *big.Int) *x509.RevocationList {
	t.Helper()
	raw, e := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: num, ThisUpdate: observed.Add(-time.Minute), NextUpdate: observed.Add(time.Minute), RevokedCertificateEntries: revoked}, root, k)
	if e != nil {
		t.Fatal(e)
	}
	r, e := x509.ParseRevocationList(raw)
	if e != nil {
		t.Fatal(e)
	}
	return r
}
func validateFixture(f tlsFixture, source QualifiedTime) error {
	return ValidateTLS(context.Background(), f.context, [][]byte{f.der}, strings.Repeat("a", 32), strings.Repeat("b", 32), source)
}

// Claim: protected path+SPKI+role and contained consumed qualified-time interval
// are jointly required. Fixtures do not qualify a real time provider or CA.
func TestTLSRejectsUnpinnedAndWrongRoleKeys(t *testing.T) {
	f := newTLSFixture(t, "server")
	if e := validateFixture(f, &syntheticTime{observed: f.observed}); e != nil {
		t.Fatal("valid pinned peer:", e)
	}
	t.Run("unpinned", func(t *testing.T) {
		bad := f
		bad.context.Pins = []string{records.Digest([]byte("other"))}
		if e := validateFixture(bad, &syntheticTime{observed: f.observed}); wire.Code(e) != "not_authorized" {
			t.Fatalf("unpinned accepted: %v", e)
		}
	})
	t.Run("wrong-role", func(t *testing.T) {
		bad := f
		bad.context.Role = "client"
		if e := validateFixture(bad, &syntheticTime{observed: f.observed}); wire.Code(e) != "not_authorized" {
			t.Fatalf("wrong role accepted: %v", e)
		}
	})
	t.Run("untrusted-path", func(t *testing.T) {
		bad := f
		other := newTLSFixture(t, "server")
		bad.context.Roots = other.context.Roots
		if e := validateFixture(bad, &syntheticTime{observed: f.observed}); wire.Code(e) != "not_authorized" {
			t.Fatalf("CA path bypass: %v", e)
		}
	})
	for name, when := range map[string]time.Time{"expired": f.observed.Add(2 * time.Minute), "not-yet-valid": f.observed.Add(-2 * time.Minute), "upper-crosses-expiry": f.observed.Truncate(time.Second).Add(time.Minute)} {
		t.Run(name, func(t *testing.T) {
			if e := validateFixture(f, &syntheticTime{observed: when}); wire.Code(e) != "not_authorized" {
				t.Fatalf("validity interval widened: %v", e)
			}
		})
	}
	t.Run("revoked", func(t *testing.T) {
		bad := f
		bad.context.CRLs = []*x509.RevocationList{makeCRL(t, f.root, f.rootKey, f.observed, []x509.RevocationListEntry{{SerialNumber: big.NewInt(2), RevocationTime: f.observed.Add(-time.Minute)}}, big.NewInt(1))}
		if e := validateFixture(bad, &syntheticTime{observed: f.observed}); wire.Code(e) != "not_authorized" {
			t.Fatalf("revoked admitted: %v", e)
		}
	})
	t.Run("rollback", func(t *testing.T) {
		bad := f
		bad.context.CRLFloors = map[string]*big.Int{records.Digest(f.root.RawSubjectPublicKeyInfo): big.NewInt(2)}
		if e := validateFixture(bad, &syntheticTime{observed: f.observed}); wire.Code(e) != "not_authorized" {
			t.Fatalf("CRL rollback admitted: %v", e)
		}
	})
	for name, alter := range map[string]func(*TimeFacts){"old-boot": func(f *TimeFacts) { f.Boot = "old" }, "reused-challenge": func(f *TimeFacts) { f.Challenge = strings.Repeat("c", 32) }, "wrong-operation": func(f *TimeFacts) { f.OperationDigest = records.Digest([]byte("other")) }, "no-continuity": func(f *TimeFacts) { f.Continuity = nil }, "at-authority-until": func(f *TimeFacts) { f.AuthorityUntil = f.HighWater }, "floor": func(f *TimeFacts) { f.PriorHighWater = f.Observed }, "negative-delta": func(f *TimeFacts) { f.Uncertainty = -1 }} {
		t.Run(name, func(t *testing.T) {
			s := &syntheticTime{observed: f.observed, alter: alter}
			if e := validateFixture(f, s); wire.Code(e) != "profile_unavailable" {
				t.Fatalf("unqualified facts admitted: %v", e)
			}
			if s.calls != 1 {
				t.Fatal("provider call lost")
			}
		})
	}
	t.Run("signing-role-reuse", func(t *testing.T) {
		cert, _ := x509.ParseCertificate(f.der)
		pub := cert.PublicKey.(ed25519.PublicKey)
		bad := f
		bad.context.SigningKeys = []records.Key{{Public: "ed25519:" + base64.RawURLEncoding.EncodeToString(pub)}}
		if e := validateFixture(bad, &syntheticTime{observed: f.observed}); wire.Code(e) != "not_authorized" {
			t.Fatalf("signing role reused: %v", e)
		}
	})
	t.Run("extra-san", func(t *testing.T) {
		cert, _ := x509.ParseCertificate(f.der)
		u, _ := url.Parse("urn:extra")
		cert.URIs = append(cert.URIs, u)
		der, e := x509.CreateCertificate(rand.Reader, cert, f.root, f.leafKey.Public(), f.rootKey)
		if e != nil {
			t.Fatal(e)
		}
		bad := f
		bad.der = der
		if e = validateFixture(bad, &syntheticTime{observed: f.observed}); wire.Code(e) != "not_authorized" {
			t.Fatalf("extra SAN admitted: %v", e)
		}
	})
}

// Claim: no source cannot fall back to the host wall clock; a synthetic consumed
// receipt on the same fixture is the nearby positive control.
func TestTLSRefusesWithoutQualifiedTime(t *testing.T) {
	f := newTLSFixture(t, "server")
	if e := validateFixture(f, nil); wire.Code(e) != "profile_unavailable" {
		t.Fatalf("no-source fallback: %v", e)
	}
	if e := validateFixture(f, &syntheticTime{observed: f.observed}); e != nil {
		t.Fatal(e)
	}
}

// Claim: in-memory mutual handshakes negotiate TLS1.3/http1.1 and do not resume;
// invalid pins fail before application use. No socket/listener or egress is used.
func TestTLSMutualHandshake(t *testing.T) {
	client := newTLSFixture(t, "client")
	server := newTLSFixture(t, "server")
	for i := 0; i < 2; i++ {
		handshake(t, client, server, false)
	}
	handshake(t, client, server, true)
}
func handshake(t *testing.T, client, server tlsFixture, badPin bool) {
	t.Helper()
	sc := TLSConfig(client.context, &syntheticTime{observed: client.observed})
	cc := TLSConfig(server.context, &syntheticTime{observed: server.observed})
	sc.Certificates = []tls.Certificate{{Certificate: [][]byte{server.der}, PrivateKey: server.leafKey}}
	cc.Certificates = []tls.Certificate{{Certificate: [][]byte{client.der}, PrivateKey: client.leafKey}}
	if badPin {
		c := client.context
		c.Pins = []string{records.Digest([]byte("bad"))}
		sc = TLSConfig(c, &syntheticTime{observed: client.observed})
		sc.Certificates = []tls.Certificate{{Certificate: [][]byte{server.der}, PrivateKey: server.leafKey}}
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	_ = a.SetDeadline(time.Now().Add(3 * time.Second))
	_ = b.SetDeadline(time.Now().Add(3 * time.Second))
	s, c := tls.Server(a, sc), tls.Client(b, cc)
	ch := make(chan error, 1)
	go func() {
		e := s.Handshake()
		if e != nil {
			a.Close()
		}
		ch <- e
	}()
	ce := c.Handshake()
	if badPin && ce == nil {
		var alert [1]byte
		_, ce = c.Read(alert[:])
	}
	if ce != nil {
		b.Close()
	}
	se := <-ch
	if badPin {
		if wire.Code(se) != "not_authorized" {
			t.Fatalf("unpinned handshake wrong refusal: %v", se)
		}
		return
	}
	if ce != nil || se != nil {
		t.Fatalf("mutual handshake: client=%v server=%v", ce, se)
	}
	for _, state := range []tls.ConnectionState{s.ConnectionState(), c.ConnectionState()} {
		if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != "http/1.1" || state.DidResume || (state.CurveID != tls.X25519 && state.CurveID != tls.CurveP256) || (state.CipherSuite != tls.TLS_AES_128_GCM_SHA256 && state.CipherSuite != tls.TLS_AES_256_GCM_SHA384 && state.CipherSuite != tls.TLS_CHACHA20_POLY1305_SHA256) {
			t.Fatal("TLS negotiation weakened")
		}
	}
	if !sc.SessionTicketsDisabled || sc.ClientSessionCache != nil || !cc.SessionTicketsDisabled || cc.ClientSessionCache != nil {
		t.Fatal("resumption enabled")
	}
}

// Claim: unknown critical SAN types and duplicate URI identities do not become
// an alternate principal. This operates on a parsed certificate fixture only.
func TestTLSRejectsUnknownSAN(t *testing.T) {
	f := newTLSFixture(t, "server")
	cert, _ := x509.ParseCertificate(f.der)
	if !exactSAN(cert, "urn:state-witness:service:svc") {
		t.Fatal("valid SAN")
	}
	for i := range cert.Extensions {
		if cert.Extensions[i].Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			cert.Extensions[i].Value = []byte{0x30, 0x03, 0x82, 0x01, 'x'}
		}
	}
	if exactSAN(cert, "urn:state-witness:service:svc") {
		t.Fatal("unknown SAN type accepted")
	}
}

// Claim: the admitted alternate CA path is exactly P-256/SHA256; a neighboring
// P-384/SHA384 CA remains outside the profile while leaf keys stay Ed25519.
func TestTLSCAAlgorithmProfile(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			f := newTLSFixture(t, "server")
			k, e := ecdsa.GenerateKey(curve, rand.Reader)
			if e != nil {
				t.Fatal(e)
			}
			tmpl := &x509.Certificate{SerialNumber: big.NewInt(3), NotBefore: f.observed.Add(-time.Hour), NotAfter: f.observed.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, SubjectKeyId: []byte{4, 5, 6}}
			der, e := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
			if e != nil {
				t.Fatal(e)
			}
			root, e := x509.ParseCertificate(der)
			if e != nil {
				t.Fatal(e)
			}
			leaf, e := x509.ParseCertificate(f.der)
			if e != nil {
				t.Fatal(e)
			}
			leaf.SignatureAlgorithm = x509.UnknownSignatureAlgorithm
			f.der, e = x509.CreateCertificate(rand.Reader, leaf, root, f.leafKey.Public(), k)
			if e != nil {
				t.Fatal(e)
			}
			raw, e := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: f.observed.Add(-time.Minute), NextUpdate: f.observed.Add(time.Minute)}, root, k)
			if e != nil {
				t.Fatal(e)
			}
			crl, e := x509.ParseRevocationList(raw)
			if e != nil {
				t.Fatal(e)
			}
			f.context.Roots = []*x509.Certificate{root}
			f.context.CRLs = []*x509.RevocationList{crl}
			f.context.CRLFloors = map[string]*big.Int{records.Digest(root.RawSubjectPublicKeyInfo): big.NewInt(1)}
			e = validateFixture(f, &syntheticTime{observed: f.observed})
			if curve == elliptic.P256() {
				if e != nil {
					t.Fatal("P256 control", e)
				}
			} else if wire.Code(e) != "not_authorized" {
				t.Fatalf("unsupported CA admitted: %v", e)
			}
		})
	}
}
