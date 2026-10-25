package transport

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"time"

	"github.com/relux-works/swarma-witness/records"
	"github.com/relux-works/swarma-witness/wire"
)

const TLSProfile = "state-witness-tls:1"

// TLSContext is independently protected input. Role describes the peer's leaf
// role. No peer-selected key, root, current boot, policy or file is loaded here.
type TLSContext struct {
	Service, Role, PrincipalID           string
	Pins                                 []string
	Roots                                []*x509.Certificate
	CRLs                                 []*x509.RevocationList
	CRLFloors                            map[string]*big.Int // issuer SPKI D -> protected retained CRL number
	SigningKeys                          []records.Key
	Generation                           int64
	Authority, Adapter, TimePolicy, Boot string
	JournalFloor                         time.Time
}

func hashDomain(label string, raw []byte) string {
	return records.Digest(append([]byte(label+"\x00"), raw...))
}
func ChainDigest(chain [][]byte) (string, error) {
	if len(chain) < 1 || len(chain) > 4 {
		return "", wire.Refuse("limit_exceeded")
	}
	raw := binary.BigEndian.AppendUint32(nil, uint32(len(chain)))
	total := 0
	for _, der := range chain {
		if len(der) == 0 || len(der) > 8192 {
			return "", wire.Refuse("limit_exceeded")
		}
		total += len(der)
		if total > 32768 {
			return "", wire.Refuse("limit_exceeded")
		}
		raw = binary.BigEndian.AppendUint32(raw, uint32(len(der)))
		raw = append(raw, der...)
	}
	return hashDomain("state-witness-tls-chain/1", raw), nil
}
func strictSet(a []string) ([]any, error) {
	if len(a) == 0 || len(a) > 8 {
		return nil, wire.Refuse("evidence_invalid")
	}
	out := make([]any, len(a))
	for i, s := range a {
		if !wire.Digest(s) || i > 0 && a[i-1] >= s {
			return nil, wire.Refuse("evidence_invalid")
		}
		out[i] = s
	}
	return out, nil
}
func TrustSetDigest(c TLSContext) (string, error) {
	if !wire.Name(c.Service) || !wire.Opaque(c.PrincipalID) || c.Generation < 1 || c.Generation > wire.MaxInt || c.Role != "server" && c.Role != "client" {
		return "", wire.Refuse("evidence_invalid")
	}
	pins, e := strictSet(c.Pins)
	if e != nil {
		return "", e
	}
	if len(c.Roots) > 4 || len(c.CRLs) > 3 {
		return "", wire.Refuse("limit_exceeded")
	}
	roots := []string{}
	for _, r := range c.Roots {
		if r == nil || len(r.Raw) == 0 || len(r.Raw) > 8192 {
			return "", wire.Refuse("evidence_invalid")
		}
		roots = append(roots, records.Digest(r.Raw))
	}
	crls := []string{}
	for _, r := range c.CRLs {
		if r == nil || len(r.Raw) == 0 || len(r.Raw) > 65536 {
			return "", wire.Refuse("evidence_invalid")
		}
		crls = append(crls, records.Digest(r.Raw))
	}
	ca, e := strictSet(roots)
	if e != nil {
		return "", e
	}
	rev, e := strictSet(crls)
	if e != nil {
		return "", e
	}
	raw, e := wire.Canonical(map[string]any{"service": c.Service, "config_generation": c.Generation, "role": c.Role, "principal_id": c.PrincipalID, "pin_set": pins, "ca_set": ca, "crl_set": rev})
	if e != nil {
		return "", e
	}
	return hashDomain("state-witness-tls-trust-set/1", raw), nil
}
func TLSPolicyBytes(trustDigest string) ([]byte, error) {
	if !wire.Digest(trustDigest) {
		return nil, wire.Refuse("evidence_invalid")
	}
	return wire.Canonical(map[string]any{
		"v": int64(1), "tls_version": "1.3", "alpn": []any{"http/1.1"}, "cipher_suites": []any{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"}, "groups": []any{"X25519", "P-256"}, "leaf_key": "Ed25519", "ca_signatures": []any{"Ed25519", "ECDSA-P256-SHA256"}, "resumption": false, "early_data": false, "post_handshake_auth": false, "proxy_termination": false, "public_web_pki": false, "leaf_usage": "digitalSignature", "server_eku": "serverAuth", "client_eku": "clientAuth", "server_san": "urn:state-witness:service:<service>", "client_san": "urn:state-witness:principal:<H(UTF8(principal_id))>", "revocation": "local-full-crl", "one_request": true, "certificate_count": int64(4), "certificate_bytes": int64(8192), "chain_bytes": int64(32768), "crl_count": int64(3), "crl_bytes": int64(65536), "crl_entries": int64(1024), "time_profile": TLSProfile, "trust_set_digest": trustDigest})
}
func TLSPolicyDigest(c TLSContext) (string, error) {
	trust, e := TrustSetDigest(c)
	if e != nil {
		return "", e
	}
	raw, e := TLSPolicyBytes(trust)
	if e != nil {
		return "", e
	}
	return hashDomain("state-witness-tls-policy/1", raw), nil
}

type TimeRequest struct {
	Profile, OperationDigest, Challenge, Boot, Authority, Adapter, Policy string
	JournalFloor                                                          time.Time
}

// TimeFacts are returned only after provider-side full receipt/closure validation
// and durable consumption. There is intentionally no Sample/trusted-bool API.
type TimeFacts struct {
	Profile, OperationDigest, Challenge, Boot, Authority, Adapter, Policy string
	Observed                                                              time.Time
	Uncertainty                                                           time.Duration
	AuthorityUntil, PriorHighWater, JournalFloor, HighWater               time.Time
	Receipt, Continuity                                                   []byte
	Generation                                                            uint64
}

// QualifiedTime must implement broker a1c69eb native-operation semantics: verify
// complete authenticated receipt/closure, current boot, one-use challenge and
// protected policy (dedicated chrony-nts-authdata identity, nts_config=true,
// nts_association=verified, not configuration-only evidence); durably consume every U/hold/in-flight observation before
// returning. Unknown confidence, hold, step or unconfirmed continuity refuses.
// Failed TLS admission never rolls back consumption. No production
// implementation or qualified bounded handoff is supplied by this package.
type QualifiedTime interface {
	Consume(context.Context, TimeRequest) (TimeFacts, error)
}

func operation(c TLSContext, chain [][]byte, id string) ([]byte, error) {
	if !wire.RequestID(id) {
		return nil, wire.Refuse("request_malformed")
	}
	chainHash, e := ChainDigest(chain)
	if e != nil {
		return nil, e
	}
	leaf, e := x509.ParseCertificate(chain[0])
	if e != nil {
		return nil, wire.Refuse("evidence_invalid")
	}
	pin, e := wire.TransportPin(leaf.RawSubjectPublicKeyInfo)
	if e != nil {
		return nil, e
	}
	policy, e := TLSPolicyDigest(c)
	if e != nil {
		return nil, e
	}
	return wire.Canonical(map[string]any{"v": int64(1), "service": c.Service, "role": c.Role, "principal_id": c.PrincipalID, "peer_spki": pin, "chain_digest": chainHash, "tls_policy_digest": policy, "connection_id": id, "config_generation": c.Generation})
}

// ConsumerOperationDigest implements the broker's exact length-prefixed recipe.
func ConsumerOperationDigest(body []byte) (string, error) {
	if len(body) > 65536 {
		return "", wire.Refuse("limit_exceeded")
	}
	raw := binary.BigEndian.AppendUint32(nil, uint32(len(TLSProfile)))
	raw = append(raw, TLSProfile...)
	raw = binary.BigEndian.AppendUint32(raw, uint32(len(body)))
	raw = append(raw, body...)
	return hashDomain("qualified-time/consumer-operation/1", raw), nil
}
func interval(f TimeFacts, r TimeRequest) (time.Time, time.Time, error) {
	if f.Profile != r.Profile || f.OperationDigest != r.OperationDigest || f.Challenge != r.Challenge || f.Boot != r.Boot || f.Authority != r.Authority || f.Adapter != r.Adapter || f.Policy != r.Policy || f.Generation == 0 || len(f.Receipt) == 0 || len(f.Continuity) == 0 || len(f.Receipt) > 65536 || len(f.Continuity) > 65536 || f.Uncertainty < 0 || f.Uncertainty > 1500*time.Millisecond || f.Observed.IsZero() || !f.JournalFloor.Equal(r.JournalFloor) {
		return time.Time{}, time.Time{}, wire.Refuse("profile_unavailable")
	}
	l, u := f.Observed.Add(-f.Uncertainty), f.Observed.Add(f.Uncertainty)
	if !u.Before(f.AuthorityUntil) || !l.After(f.PriorHighWater) || !l.After(f.JournalFloor) || !u.Equal(f.HighWater) {
		return time.Time{}, time.Time{}, wire.Refuse("profile_unavailable")
	}
	return l, u, nil
}
func certificateAlgorithm(c *x509.Certificate, leaf bool) bool {
	if c.SignatureAlgorithm != x509.PureEd25519 && c.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		return false
	}
	switch k := c.PublicKey.(type) {
	case ed25519.PublicKey:
		return len(k) == 32
	case *ecdsa.PublicKey:
		return !leaf && k.Curve == elliptic.P256()
	}
	return false
}
func exactSAN(c *x509.Certificate, want string) bool {
	if len(c.URIs) != 1 || c.URIs[0].String() != want || len(c.DNSNames) > 0 || len(c.EmailAddresses) > 0 || len(c.IPAddresses) > 0 {
		return false
	}
	for _, ext := range c.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			var seq asn1.RawValue
			rest, e := asn1.Unmarshal(ext.Value, &seq)
			if e != nil || len(rest) > 0 || seq.Tag != 16 || !seq.IsCompound {
				return false
			}
			var entry asn1.RawValue
			rest, e = asn1.Unmarshal(seq.Bytes, &entry)
			return e == nil && len(rest) == 0 && entry.Class == 2 && entry.Tag == 6 && !entry.IsCompound && string(entry.Bytes) == want
		}
	}
	return false
}

// ValidateTLS checks an independently configured peer using consumed native time.
// This is a predicate for a future qualified handoff, not production readiness.
func ValidateTLS(ctx context.Context, c TLSContext, presented [][]byte, id, challenge string, source QualifiedTime) error {
	var freezeErr error
	c, freezeErr = freezeTLS(c)
	if freezeErr != nil {
		return freezeErr
	}
	if source == nil {
		return wire.Refuse("profile_unavailable")
	}
	if !wire.RequestID(challenge) || c.Boot == "" || c.Authority == "" || c.Adapter == "" || c.TimePolicy == "" {
		return wire.Refuse("profile_unavailable")
	}
	body, e := operation(c, presented, id)
	if e != nil {
		return e
	}
	digest, e := ConsumerOperationDigest(body)
	if e != nil {
		return e
	}
	r := TimeRequest{TLSProfile, digest, challenge, c.Boot, c.Authority, c.Adapter, c.TimePolicy, c.JournalFloor}
	facts, e := source.Consume(ctx, r)
	if e != nil {
		return wire.Refuse("profile_unavailable")
	}
	if ctx.Err() != nil {
		return wire.Refuse("deadline_exceeded")
	}
	l, u, e := interval(facts, r)
	if e != nil {
		return e
	}
	certs := make([]*x509.Certificate, len(presented))
	for i, der := range presented {
		certs[i], e = x509.ParseCertificate(der)
		if e != nil {
			return wire.Refuse("evidence_invalid")
		}
	}
	leaf := certs[0]
	pin, e := wire.TransportPin(leaf.RawSubjectPublicKeyInfo)
	if e != nil {
		return e
	}
	pinned := false
	for _, p := range c.Pins {
		if p == pin {
			pinned = true
		}
	}
	if !pinned {
		return wire.Refuse("not_authorized")
	}
	if !certificateAlgorithm(leaf, true) || leaf.IsCA || !leaf.BasicConstraintsValid || leaf.KeyUsage != x509.KeyUsageDigitalSignature || len(leaf.ExtKeyUsage) != 1 || len(leaf.UnknownExtKeyUsage) != 0 {
		return wire.Refuse("not_authorized")
	}
	pub := leaf.PublicKey.(ed25519.PublicKey)
	pk := records.Key{Public: "ed25519:" + base64.RawURLEncoding.EncodeToString(pub), ID: records.Digest(pub), Epoch: 1, Role: records.Writer}
	if e = records.ValidateKey(pk); e != nil {
		return e
	}
	for _, k := range c.SigningKeys {
		if pk.Public == k.Public {
			return wire.Refuse("not_authorized")
		}
	}
	eku := x509.ExtKeyUsageClientAuth
	uri := "urn:state-witness:principal:" + records.Hash([]byte(c.PrincipalID))
	if c.Role == "server" {
		eku = x509.ExtKeyUsageServerAuth
		uri = "urn:state-witness:service:" + c.Service
	}
	if leaf.ExtKeyUsage[0] != eku || !exactSAN(leaf, uri) {
		return wire.Refuse("not_authorized")
	}
	roots := x509.NewCertPool()
	for _, r := range c.Roots {
		roots.AddCert(r)
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	paths, e := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: l, KeyUsages: []x509.ExtKeyUsage{eku}, MaxConstraintComparisions: 10000})
	if e != nil {
		return wire.Refuse("not_authorized")
	}
	for _, path := range paths {
		if len(path) > 4 || len(path) < len(certs) {
			continue
		}
		total := 0
		good := true
		for i, cert := range path {
			total += len(cert.Raw)
			if len(cert.Raw) > 8192 || !certificateAlgorithm(cert, i == 0) || l.Before(cert.NotBefore) || !u.Before(cert.NotAfter) || i < len(certs) && !bytes.Equal(cert.Raw, certs[i].Raw) {
				good = false
				break
			}
			if i > 0 && (!cert.IsCA || !cert.BasicConstraintsValid) {
				good = false
				break
			}
			if i < len(path)-1 && !validCRL(c, path[i+1], cert, l, u) {
				good = false
				break
			}
		}
		if good && total <= 32768 {
			return nil
		}
	}
	return wire.Refuse("not_authorized")
}
func validCRL(c TLSContext, issuer, cert *x509.Certificate, l, u time.Time) bool {
	floor, ok := c.CRLFloors[records.Digest(issuer.RawSubjectPublicKeyInfo)]
	if !ok || floor == nil || floor.Sign() <= 0 {
		return false
	}
	matched := false
	for _, crl := range c.CRLs {
		if !bytes.Equal(crl.RawIssuer, issuer.RawSubject) {
			continue
		}
		if matched {
			return false
		}
		matched = true
		if crl.SignatureAlgorithm != x509.PureEd25519 && crl.SignatureAlgorithm != x509.ECDSAWithSHA256 {
			return false
		}
		if len(crl.Raw) > 65536 || len(crl.RevokedCertificateEntries) > 1024 || crl.Number == nil || crl.Number.Sign() <= 0 || crl.Number.Cmp(floor) < 0 || crl.CheckSignatureFrom(issuer) != nil || crl.ThisUpdate.After(l) || !u.Before(crl.NextUpdate) || crl.NextUpdate.IsZero() {
			return false
		}
		for _, ext := range crl.Extensions {
			if ext.Critical || !fullCRLExtension(ext.Id) {
				return false
			}
		}
		for _, entry := range crl.RevokedCertificateEntries {
			if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return false
			}
			for _, ext := range entry.Extensions {
				if ext.Critical || !fullCRLEntryExtension(ext.Id) {
					return false
				}
			}
			// removeFromCRL is delta-only; unassigned/out-of-range reason codes
			// cannot broaden this full/direct profile either.
			if entry.ReasonCode < 0 || entry.ReasonCode == 7 || entry.ReasonCode == 8 || entry.ReasonCode > 10 {
				return false
			}
		}
	}
	return matched
}

// Only authorityKeyIdentifier and cRLNumber are supported on a full direct
// CRL. Delta indicators, issuingDistributionPoint (including indirect/scoped
// lists), freshestCRL and unknown extensions refuse even when noncritical.
func fullCRLExtension(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(asn1.ObjectIdentifier{2, 5, 29, 35}) || oid.Equal(asn1.ObjectIdentifier{2, 5, 29, 20})
}

// Full/direct entries can describe a reason or invalidity date, but cannot
// change issuer through certificateIssuer, regardless of the critical flag.
func fullCRLEntryExtension(oid asn1.ObjectIdentifier) bool {
	return oid.Equal(asn1.ObjectIdentifier{2, 5, 29, 21}) || oid.Equal(asn1.ObjectIdentifier{2, 5, 29, 24})
}

// TLSConfig supplies no default x509 clock/trust fallback. VerifyConnection
// runs the custom full predicate on every nonresumed handshake. G07/G10 and
// bounded admission/reload remain closed outside this unserved configuration.
func TLSConfig(c TLSContext, source QualifiedTime) *tls.Config {
	frozen, freezeErr := freezeTLS(c)
	c = frozen
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}, SessionTicketsDisabled: true, ClientSessionCache: nil, CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}, Renegotiation: tls.RenegotiateNever, ClientAuth: tls.RequireAnyClientCert, InsecureSkipVerify: true, // Verified below using qualified interval, protected roots and pins.
		VerifyConnection: func(state tls.ConnectionState) error {
			if freezeErr != nil {
				return freezeErr
			}
			if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != "http/1.1" || state.DidResume {
				return wire.Refuse("not_authorized")
			}
			allowedSuite := state.CipherSuite == tls.TLS_AES_128_GCM_SHA256 || state.CipherSuite == tls.TLS_AES_256_GCM_SHA384 || state.CipherSuite == tls.TLS_CHACHA20_POLY1305_SHA256
			allowedCurve := state.CurveID == tls.X25519 || state.CurveID == tls.CurveP256
			if !allowedSuite || !allowedCurve {
				return wire.Refuse("not_authorized")
			}
			id, challenge := make([]byte, 16), make([]byte, 16)
			if _, e := rand.Read(id); e != nil {
				return wire.Refuse("profile_unavailable")
			}
			if _, e := rand.Read(challenge); e != nil {
				return wire.Refuse("profile_unavailable")
			}
			chain := make([][]byte, len(state.PeerCertificates))
			for i, cert := range state.PeerCertificates {
				chain[i] = cert.Raw
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			return ValidateTLS(ctx, c, chain, hex.EncodeToString(id), hex.EncodeToString(challenge), source)
		}}
}

// Reparse protected DER and copy containers so the hashed snapshot and the
// objects used for verification cannot diverge through a mutable x509 view.
func freezeTLS(c TLSContext) (TLSContext, error) {
	c.Pins = append([]string(nil), c.Pins...)
	c.SigningKeys = append([]records.Key(nil), c.SigningKeys...)
	roots := make([]*x509.Certificate, len(c.Roots))
	for i, r := range c.Roots {
		if r == nil || len(r.Raw) > 8192 {
			return TLSContext{}, wire.Refuse("evidence_invalid")
		}
		p, e := x509.ParseCertificate(append([]byte(nil), r.Raw...))
		if e != nil {
			return TLSContext{}, wire.Refuse("evidence_invalid")
		}
		roots[i] = p
	}
	c.Roots = roots
	crls := make([]*x509.RevocationList, len(c.CRLs))
	for i, r := range c.CRLs {
		if r == nil || len(r.Raw) > 65536 {
			return TLSContext{}, wire.Refuse("evidence_invalid")
		}
		p, e := x509.ParseRevocationList(append([]byte(nil), r.Raw...))
		if e != nil {
			return TLSContext{}, wire.Refuse("evidence_invalid")
		}
		crls[i] = p
	}
	c.CRLs = crls
	floors := map[string]*big.Int{}
	for k, n := range c.CRLFloors {
		if n == nil {
			return TLSContext{}, wire.Refuse("evidence_invalid")
		}
		floors[k] = new(big.Int).Set(n)
	}
	c.CRLFloors = floors
	return c, nil
}
