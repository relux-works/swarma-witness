package records_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/relux-works/swarma-witness/records"
	"github.com/relux-works/swarma-witness/wire"
)

func canon(t *testing.T, v any) []byte {
	t.Helper()
	b, e := wire.Canonical(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func expect(t *testing.T, e error, code string) {
	t.Helper()
	if wire.Code(e) != code {
		t.Fatalf("want %s got %v", code, e)
	}
}
func key(n byte, role records.Role) (records.Key, ed25519.PrivateKey) {
	s := bytes.Repeat([]byte{n}, 32)
	p := ed25519.NewKeyFromSeed(s)
	pub := p.Public().(ed25519.PublicKey)
	h := sha256.Sum256(pub)
	return records.Key{Public: "ed25519:" + base64.RawURLEncoding.EncodeToString(pub), ID: "sha256:" + hex.EncodeToString(h[:]), Epoch: 2, Role: role}, p
}
func bindingMap() map[string]any {
	k, _ := key(17, records.Writer)
	return map[string]any{"service": "witness", "stream": "station", "consumer": "keymaker", "identity": map[string]any{"product": "alpha", "project": "beta", "agent": "gamma"}, "lineage": "lineage", "profile": "keymaker-state-witness/1", "writer_epoch": int64(7), "writer_id": "writer", "record_key": map[string]any{"public_key": k.Public, "key_id": k.ID, "key_epoch": k.Epoch, "purpose": int64(3)}, "transport_pins": []any{"sha256:" + strings.Repeat("a", 64)}, "readers": []any{map[string]any{"id": "reader", "transport_pins": []any{"sha256:" + strings.Repeat("b", 64)}}}}
}
func binding(t *testing.T) wire.Binding {
	t.Helper()
	b, e := wire.DecodeBinding(canon(t, bindingMap()))
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func body() map[string]any {
	k, _ := key(17, records.Writer)
	return map[string]any{"v": int64(1), "type": "keymaker-state-witness/1", "consumer": "keymaker", "stream": "station", "station": map[string]any{"product": "alpha", "project": "beta", "agent": "gamma"}, "seq": int64(1), "state_epoch": int64(1), "kind": "intent", "commit_class": "audit", "base_state_digest": nil, "state_digest": "sha256:" + strings.Repeat("c", 64), "prev_hash": wire.ZeroHash, "intent_hash": nil, "key_epoch": k.Epoch, "key_id": k.ID}
}
func signed(t *testing.T, b map[string]any, domain records.Domain) []byte {
	t.Helper()
	_, p := key(17, records.Writer)
	pre := append([]byte(string(domain)+"\x00"), canon(t, b)...)
	return append(canon(t, map[string]any{"body": b, "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(p, pre))}), '\n')
}

// Binding fields close at every depth; profile/key nullability is consumer-
// specific. These are shape checks, not provisioning or consent authority.
func TestRecordsS1BindingShape(t *testing.T) {
	binding(t)
	for _, change := range []func(map[string]any){func(m map[string]any) { m["extra"] = nil }, func(m map[string]any) { m["identity"].(map[string]any)["extra"] = nil }, func(m map[string]any) { m["record_key"] = nil }, func(m map[string]any) { m["readers"].([]any)[0].(map[string]any)["extra"] = true }, func(m map[string]any) { m["profile"] = "other" }} {
		m := bindingMap()
		change(m)
		_, e := wire.DecodeBinding(canon(t, m))
		expect(t, e, "request_malformed")
	}
	for _, consumer := range []string{"registrar", "owner-registry"} {
		m := bindingMap()
		m["consumer"] = consumer
		m["record_key"] = nil
		if consumer == "registrar" {
			m["profile"] = "registrar-state-witness-sha1/1"
			m["identity"] = "registry"
		} else {
			k, _ := key(25, records.Writer)
			m["profile"] = "owner-registry-checkpoint/1"
			m["identity"] = map[string]any{"registry_id": k.Public, "owner": "owner"}
		}
		if _, e := wire.DecodeBinding(canon(t, m)); e != nil {
			t.Fatal(e)
		}
		m["record_key"] = bindingMap()["record_key"]
		_, e := wire.DecodeBinding(canon(t, m))
		expect(t, e, "request_malformed")
	}
}

// Each declared identity/ACL boundary has a positive control. Pin reuse by
// different IDs is forbidden; explicit writer membership grants read shape only.
func TestRecordsS1BindingBounds(t *testing.T) {
	for _, field := range []string{"service", "stream"} {
		for _, n := range []int{128, 129} {
			m := bindingMap()
			m[field] = strings.Repeat("a", n)
			_, e := wire.DecodeBinding(canon(t, m))
			if n == 128 {
				if e != nil {
					t.Fatal(e)
				}
			} else {
				expect(t, e, "limit_exceeded")
			}
		}
	}

	for _, n := range []int{8, 9} {
		m := bindingMap()
		pins := []any{}
		for i := 0; i < n; i++ {
			pins = append(pins, fmt.Sprintf("sha256:%064x", 100+i))
		}
		m["readers"].([]any)[0].(map[string]any)["transport_pins"] = pins
		_, e := wire.DecodeBinding(canon(t, m))
		if n == 8 {
			if e != nil {
				t.Fatal(e)
			}
		} else {
			expect(t, e, "limit_exceeded")
		}
	}
	for _, value := range []string{strings.Repeat("λ", 127) + "x", strings.Repeat("λ", 128)} {
		m := bindingMap()
		m["lineage"] = value
		_, e := wire.DecodeBinding(canon(t, m))
		if len(value) == 255 {
			if e != nil {
				t.Fatal(e)
			}
		} else {
			expect(t, e, "limit_exceeded")
		}
	}

	for _, n := range []int{63, 64} {
		m := bindingMap()
		m["identity"].(map[string]any)["agent"] = strings.Repeat("a", n)
		_, e := wire.DecodeBinding(canon(t, m))
		if n == 63 {
			if e != nil {
				t.Fatal(e)
			}
		} else {
			expect(t, e, "limit_exceeded")
		}
	}
	for _, n := range []int{255, 256} {
		m := bindingMap()
		m["lineage"] = strings.Repeat("x", n)
		_, e := wire.DecodeBinding(canon(t, m))
		if n == 255 {
			if e != nil {
				t.Fatal(e)
			}
		} else {
			expect(t, e, "limit_exceeded")
		}
	}
	for _, n := range []int{8, 9, 32, 33} {
		m := bindingMap()
		pins := []any{}
		for i := 0; i < n; i++ {
			pins = append(pins, "sha256:"+strings.Repeat("0", 62)+hex.EncodeToString([]byte{byte(i)}))
		}
		if n < 10 {
			m["transport_pins"] = pins
		} else {
			r := []any{}
			for i, p := range pins {
				r = append(r, map[string]any{"id": string(rune('A' + i)), "transport_pins": []any{p}})
			}
			m["readers"] = r
		}
		_, e := wire.DecodeBinding(canon(t, m))
		if n == 8 || n == 32 {
			if e != nil {
				t.Fatal(e)
			}
		} else {
			expect(t, e, "limit_exceeded")
		}
	}
	m := bindingMap()
	m["readers"] = []any{map[string]any{"id": "writer", "transport_pins": m["transport_pins"]}}
	if _, e := wire.DecodeBinding(canon(t, m)); e != nil {
		t.Fatal(e)
	}
	m["readers"].([]any)[0].(map[string]any)["id"] = "other"
	_, e := wire.DecodeBinding(canon(t, m))
	expect(t, e, "evidence_invalid")
}

// Raw32-derived signing IDs and SPKI pins have distinct sources; a matching
// format alone never authorizes a substituted key ID or wrong key purpose.
func TestRecordsS1KeyAndPinRepresentations(t *testing.T) {
	k, p := key(17, records.Writer)
	der, e := x509.MarshalPKIXPublicKey(p.Public())
	if e != nil {
		t.Fatal(e)
	}
	pin, e := wire.TransportPin(der)
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(der)
	if pin != fmt.Sprintf("sha256:%x", h) || pin == k.ID {
		t.Fatal("SPKI confused with raw32")
	}
	_, e = wire.TransportPin(p.Public().(ed25519.PublicKey))
	expect(t, e, "request_malformed")

	binding(t)
	for _, change := range []func(map[string]any){func(m map[string]any) {
		m["record_key"].(map[string]any)["key_id"] = "sha256:" + strings.Repeat("0", 64)
	}, func(m map[string]any) { m["record_key"].(map[string]any)["purpose"] = int64(5) }} {
		m := bindingMap()
		change(m)
		_, e := wire.DecodeBinding(canon(t, m))
		expect(t, e, "evidence_invalid")
	}
	m := bindingMap()
	m["transport_pins"] = []any{strings.Repeat("a", 64)}
	_, e = wire.DecodeBinding(canon(t, m))
	expect(t, e, "request_malformed")
}

// Role classification cannot promote a publisher to bridge/admin/witness.
// Actual transport authentication and per-stream ACLs remain S2.
func TestRecordsS1RoleSeparation(t *testing.T) {
	for _, role := range []records.Role{records.Publisher, records.Writer, records.Witness, records.Admin, records.Bridge} {
		k, p := key(17, role)
		raw := signed(t, body(), records.RecordDomain)
		_, e := records.VerifyEnvelope(bytes.TrimSuffix(raw, []byte{'\n'}), 8192, records.RecordDomain, k)
		if role == records.Writer {
			if e != nil {
				t.Fatal(e)
			}
		} else {
			expect(t, e, "evidence_invalid")
		}
		_ = p
	}
}

// The line hash includes exactly one LF. Protected binding selects domain/key
// and record projection; no body field can authorize another signature domain.
func TestRecordBindsLFDomainAndProtectedType(t *testing.T) {
	// The signature helper must not let a received domain claim choose another
	// witness domain, even with an independently valid signature for that claim.
	wk, wp := key(19, records.Witness)
	claimed := map[string]any{"domain": string(records.NeutralAck)}
	pre := append([]byte(string(records.NeutralAck)+"\x00"), canon(t, claimed)...)
	env := canon(t, map[string]any{"body": claimed, "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(wp, pre))})
	_, err := records.VerifyEnvelope(env, 4096, records.KeymakerAck, wk)
	expect(t, err, "evidence_invalid")

	b := binding(t)
	line := signed(t, body(), records.RecordDomain)
	r, e := records.DecodeKeymaker(line, b, true)
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(line)
	if r.Hash() != hex.EncodeToString(h[:]) {
		t.Fatal("LF-inclusive hash")
	}
	h = sha256.Sum256(line[:len(line)-1])
	if r.Hash() == hex.EncodeToString(h[:]) {
		t.Fatal("excluded LF")
	}
	for _, bad := range [][]byte{line[:len(line)-1], append(append([]byte{}, line...), '\n')} {
		_, e := records.DecodeKeymaker(bad, b, true)
		expect(t, e, "request_malformed")
	}
	for _, d := range []records.Domain{records.KeymakerAck, records.KeymakerHead, records.NeutralAck} {
		_, e := records.DecodeKeymaker(signed(t, body(), d), b, true)
		expect(t, e, "evidence_invalid")
	}
	m := body()
	m["key_epoch"] = int64(7)
	_, e = records.DecodeKeymaker(signed(t, m, records.RecordDomain), b, true)
	expect(t, e, "evidence_invalid")
}

// Intent reserves its resolution slot, including the final safe integer;
// zero, wrap and overflow refuse rather than renumbering the stream.
func TestRecordsReserveIntentResolutionRoom(t *testing.T) {
	for _, seq := range []int64{wire.MaxInt - 1, wire.MaxInt, 0} {
		m := body()
		m["seq"] = seq
		if seq > 1 {
			m["prev_hash"] = strings.Repeat("a", 64)
			m["base_state_digest"] = "sha256:" + strings.Repeat("b", 64)
		}
		_, e := records.DecodeKeymaker(signed(t, m, records.RecordDomain), binding(t), true)
		if seq == wire.MaxInt-1 {
			if e != nil {
				t.Fatal(e)
			}
		} else if seq == wire.MaxInt {
			expect(t, e, "sequence_exhausted")
		} else {
			expect(t, e, "request_malformed")
		}
	}
	m := body()
	m["seq"] = wire.MaxInt
	m["prev_hash"] = strings.Repeat("a", 64)
	m["base_state_digest"] = "sha256:" + strings.Repeat("b", 64)
	m["kind"] = "committed"
	m["intent_hash"] = strings.Repeat("a", 64)
	if _, e := records.DecodeKeymaker(signed(t, m, records.RecordDomain), binding(t), true); e != nil {
		t.Fatal(e)
	}
}

// Forbidden commit enums/null combinations refuse even when independently
// signed; the explicit bootstrap pair is the only null base digest control.
func TestRecordsS1EnumsAndNulls(t *testing.T) {
	for _, c := range []string{"binding-result", "enrollment", "reconciliation", "audit", "retention", "policy-custody"} {
		m := body()
		m["commit_class"] = c
		if _, e := records.DecodeKeymaker(signed(t, m, records.RecordDomain), binding(t), true); e != nil {
			t.Fatal(e)
		}
	}
	for _, change := range []func(map[string]any){func(m map[string]any) { m["commit_class"] = "other" }, func(m map[string]any) { m["kind"] = "resolved" }, func(m map[string]any) { m["intent_hash"] = strings.Repeat("a", 64) }, func(m map[string]any) { m["kind"] = "committed" }} {
		m := body()
		change(m)
		_, e := records.DecodeKeymaker(signed(t, m, records.RecordDomain), binding(t), true)
		expect(t, e, "request_malformed")
	}
	_, e := records.DecodeKeymaker(signed(t, body(), records.RecordDomain), binding(t), false)
	expect(t, e, "evidence_invalid")
}

// Locally derived torsion shifts supply small/mixed/identity/noncanonical
// point negatives without copying upstream fixture bytes. Both public and R
// are checked; a newly generated ordinary Ed25519 signature passes.
func TestRecordsS1Ed25519Points(t *testing.T) {
	k, p := key(17, records.Writer)
	pre := []byte("point control")
	sig := ed25519.Sign(p, pre)
	if e := records.Verify(k, sig, pre); e != nil {
		t.Fatal(e)
	}
	_, pub, _ := strings.Cut(k.Public, ":")
	raw, _ := base64.RawURLEncoding.DecodeString(pub)
	q := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	enc := append([]byte{}, raw...)
	sign := enc[31] >> 7
	enc[31] &= 127
	for i, j := 0, len(enc)-1; i < j; i, j = i+1, j-1 {
		enc[i], enc[j] = enc[j], enc[i]
	}
	y := new(big.Int).SetBytes(enc)
	y.Sub(q, y)
	mixed := y.FillBytes(make([]byte, 32))
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		mixed[i], mixed[j] = mixed[j], mixed[i]
	}
	mixed[31] |= (sign ^ 1) << 7
	identity := make([]byte, 32)
	identity[0] = 1
	noncanonical := q.FillBytes(make([]byte, 32))
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		noncanonical[i], noncanonical[j] = noncanonical[j], noncanonical[i]
	}
	for _, bad := range [][]byte{identity, make([]byte, 32), mixed, noncanonical} {
		bk := k
		bk.Public = "ed25519:" + base64.RawURLEncoding.EncodeToString(bad)
		h := sha256.Sum256(bad)
		bk.ID = "sha256:" + hex.EncodeToString(h[:])
		expect(t, records.Verify(bk, sig, pre), "evidence_invalid")
		bs := append([]byte{}, sig...)
		copy(bs, bad)
		expect(t, records.Verify(k, bs, pre), "evidence_invalid")
	}
	// Distinguish strict point rejection from the stdlib equation alone. These
	// deliberately weak signatures pass ordinary Ed25519 and must still refuse.
	little := func(b []byte) *big.Int {
		r := append([]byte(nil), b...)
		for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
			r[i], r[j] = r[j], r[i]
		}
		return new(big.Int).SetBytes(r)
	}
	encode := func(n *big.Int) []byte {
		b := n.FillBytes(make([]byte, 32))
		for i, j := 0, 31; i < j; i, j = i+1, j-1 {
			b[i], b[j] = b[j], b[i]
		}
		return b
	}
	order := new(big.Int).Lsh(big.NewInt(1), 252)
	tail, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	order.Add(order, tail)
	seedHash := sha512.Sum512(p.Seed())
	a := append([]byte(nil), seedHash[:32]...)
	a[0] &= 248
	a[31] &= 63
	a[31] |= 64
	secret := little(a)
	// Derive the standard generator encoding from y=4/5, not fixture bytes.
	generatorY := new(big.Int).Mul(big.NewInt(4), new(big.Int).ModInverse(big.NewInt(5), q))
	generatorY.Mod(generatorY, q)
	generator := encode(generatorY)
	weak := append(append([]byte{}, generator...), make([]byte, 32)...)
	weak[32] = 1
	if !ed25519.Verify(identity, pre, weak) {
		t.Fatal("identity equation control")
	}
	ik := k
	ik.Public = "ed25519:" + base64.RawURLEncoding.EncodeToString(identity)
	ik.ID = records.Digest(identity)
	expect(t, records.Verify(ik, weak, pre), "evidence_invalid")
	// R=identity has a valid equation for the ordinary public key when S=h*a.
	challenge := sha512.Sum512(append(append(append([]byte{}, identity...), raw...), pre...))
	h := little(challenge[:])
	h.Mod(h, order)
	scalar := new(big.Int).Mul(h, secret)
	scalar.Mod(scalar, order)
	weak = append(append([]byte{}, identity...), encode(scalar)...)
	if !ed25519.Verify(raw, pre, weak) {
		t.Fatal("R identity equation control")
	}
	expect(t, records.Verify(k, weak, pre), "evidence_invalid")
	// A+T with R=B satisfies the ordinary equation for an even challenge.
	mk := k
	mk.Public = "ed25519:" + base64.RawURLEncoding.EncodeToString(mixed)
	mk.ID = records.Digest(mixed)
	found := false
	for counter := 0; counter < 256; counter++ {
		msg := []byte(fmt.Sprintf("mixed equation %d", counter))
		sum := sha512.Sum512(append(append(append([]byte{}, generator...), mixed...), msg...))
		h := little(sum[:])
		h.Mod(h, order)
		if h.Bit(0) != 0 {
			continue
		}
		s := new(big.Int).Mul(h, secret)
		s.Add(s, big.NewInt(1))
		s.Mod(s, order)
		candidate := append(append([]byte{}, generator...), encode(s)...)
		if !ed25519.Verify(mixed, msg, candidate) {
			t.Fatal("mixed equation control")
		}
		expect(t, records.Verify(mk, candidate, msg), "evidence_invalid")
		found = true
		break
	}
	if !found {
		t.Fatal("bounded even challenge search")
	}

}

// S=L is out of range; canonical exact-length base64 is a separate gate from
// the signature equation and point checks.
func TestRecordsS1ScalarAndEncoding(t *testing.T) {
	k, p := key(17, records.Writer)
	pre := []byte("scalar control")
	sig := ed25519.Sign(p, pre)
	if e := records.Verify(k, sig, pre); e != nil {
		t.Fatal(e)
	}
	l := new(big.Int).Lsh(big.NewInt(1), 252)
	c, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	l.Add(l, c)
	s := l.FillBytes(make([]byte, 32))
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	copy(sig[32:], s)
	expect(t, records.Verify(k, sig, pre), "evidence_invalid")
	for _, s := range []string{"AA=", "AB", strings.Repeat("A", 85), strings.Repeat("A", 85) + "B"} {
		_, e := wire.DecodeBinary(s, 64, 64)
		expect(t, e, "request_malformed")
	}
}

// Domain and protected role/purpose are independent of mathematical validity.
func TestRecordsS1DomainAndRole(t *testing.T) {
	TestRecordBindsLFDomainAndProtectedType(t)
	TestRecordsS1RoleSeparation(t)
	m := bindingMap()
	m["record_key"].(map[string]any)["purpose"] = int64(4)
	_, e := wire.DecodeBinding(canon(t, m))
	expect(t, e, "evidence_invalid")
}

// The landed registrar profile selects exactly one object format. Full IDs
// of the other format are refused as evidence, never accepted by length; syntax
// errors and missing protected format remain distinct isolated refusals.
func TestRecordsS1RegistrarRevision(t *testing.T) {
	for _, profile := range []string{"registrar-state-witness-sha1/1", "registrar-state-witness-sha256/1"} {
		m := bindingMap()
		m["consumer"] = "registrar"
		m["profile"] = profile
		m["record_key"] = nil
		m["identity"] = "registry"
		b, e := wire.DecodeBinding(canon(t, m))
		if e != nil {
			t.Fatal(e)
		}
		width, other := 40, 64
		if strings.Contains(profile, "sha256") {
			width, other = 64, 40
		}
		samples := []struct{ revision, code string }{
			{strings.Repeat("a", width), ""}, {strings.Repeat("b", other), "evidence_invalid"},
			{"abc", "request_malformed"}, {strings.Repeat("A", width), "request_malformed"},
			{strings.Repeat("a", width-1), "request_malformed"}, {strings.Repeat("a", width+1), "request_malformed"},
			{"main", "request_malformed"}, {"sha1:" + strings.Repeat("a", width), "request_malformed"},
		}
		for _, sample := range samples {
			line := append(canon(t, map[string]any{"v": int64(1), "stream": b.Stream(), "seq": int64(1), "kind": "intent", "revision": sample.revision, "digest": "sha256:" + strings.Repeat("a", 64), "prev_hash": wire.ZeroHash, "intent_hash": nil}), '\n')
			r, e := records.DecodeRegistrar(line, b, true)
			expect(t, e, sample.code)
			if sample.code == "" && r.Hash() != records.Hash(line) {
				t.Fatal("registrar LF hash")
			}
		}
	}
	expect(t, records.CheckRegistrarRevision("", strings.Repeat("a", 40)), "profile_unavailable")
	if records.RegistrarRefusal(records.RegistrarRejected) != "evidence_invalid" || records.RegistrarRefusal(records.RegistrarMissing) != "profile_unavailable" {
		t.Fatal("classification table")
	}
}

// Registrar digest syntax is shared D grammar; an evidence comparison cannot
// equate a substituted but well-formed digest with the admitted original.
func TestRecordsS1RegistrarDigest(t *testing.T) {
	good := "sha256:" + strings.Repeat("a", 64)
	if e := records.CheckRegistrarDigest(good, good); e != nil {
		t.Fatal(e)
	}
	expect(t, records.CheckRegistrarDigest(strings.Repeat("a", 64), good), "request_malformed")
	expect(t, records.CheckRegistrarDigest("sha256:"+strings.Repeat("b", 64), good), "evidence_invalid")
}

// Wrapper decoding retains checkpoint originals byte-for-byte but never
// verifies them or confers checkpoint admission before S6.
func TestRecordsS1CheckpointOriginals(t *testing.T) {
	m := bindingMap()
	k, _ := key(25, records.Writer)
	m["consumer"] = "owner-registry"
	m["profile"] = "owner-registry-checkpoint/1"
	m["record_key"] = nil
	m["identity"] = map[string]any{"registry_id": k.Public, "owner": "owner"}
	b, e := wire.DecodeBinding(canon(t, m))
	if e != nil {
		t.Fatal(e)
	}
	cp := []byte(" {\"original\":true} ")
	w := map[string]any{"v": int64(1), "stream": "station", "seq": int64(1), "prev_hash": wire.ZeroHash, "writer_epoch": int64(7), "kind": "intent", "intent_hash": nil, "checkpoint": base64.RawURLEncoding.EncodeToString(cp), "registry_proof": "e30", "projection": map[string]any{"registry_id": k.Public, "owner": "owner", "registry_seq": int64(1), "registry_head": "sha256:" + strings.Repeat("a", 64), "checkpoint_id": "sha256:" + strings.Repeat("b", 64), "checkpoint_time": "2026-01-02T03:04:05Z", "candidate_digest": "sha256:" + strings.Repeat("c", 64), "previous_checkpoint_id": nil}}
	raw := append(canon(t, w), '\n')
	decoded, e := records.DecodeCheckpointWrapper(raw, b, true)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(decoded.Checkpoint(), cp) {
		t.Fatal("rewrote original")
	}
	expect(t, decoded.Verify(), "profile_unavailable")
	w["projection"].(map[string]any)["checkpoint_time"] = "2026-02-30T00:00:00Z"
	_, e = records.DecodeCheckpointWrapper(append(canon(t, w), '\n'), b, true)
	expect(t, e, "request_malformed")
}

// Zero H and null base cannot create a later implicit bootstrap, even with a
// valid writer signature. The authorized first intent and resolution pass.
func TestRecordsBootstrapNulls(t *testing.T) {
	first := body()
	if _, e := records.DecodeKeymaker(signed(t, first, records.RecordDomain), binding(t), true); e != nil {
		t.Fatal(e)
	}
	resolution := body()
	resolution["seq"] = int64(2)
	resolution["kind"] = "committed"
	resolution["prev_hash"] = strings.Repeat("a", 64)
	resolution["intent_hash"] = strings.Repeat("a", 64)
	if _, e := records.DecodeKeymaker(signed(t, resolution, records.RecordDomain), binding(t), true); e != nil {
		t.Fatal(e)
	}
	for _, seq := range []int64{3, 4} {
		m := body()
		m["seq"] = seq
		_, e := records.DecodeKeymaker(signed(t, m, records.RecordDomain), binding(t), true)
		expect(t, e, "evidence_invalid")
		m["prev_hash"] = strings.Repeat("a", 64)
		_, e = records.DecodeKeymaker(signed(t, m, records.RecordDomain), binding(t), true)
		expect(t, e, "evidence_invalid")
	}
}

// Registrar flat schemas retain exactly eight fields with no signature member;
// explicit bootstrap context and final-pair space are independent safeguards.
func TestRecordsRegistrarFields(t *testing.T) {
	m := bindingMap()
	m["consumer"] = "registrar"
	m["profile"] = "registrar-state-witness-sha256/1"
	m["record_key"] = nil
	m["identity"] = "registry"
	b, e := wire.DecodeBinding(canon(t, m))
	if e != nil {
		t.Fatal(e)
	}
	base := map[string]any{"v": int64(1), "stream": b.Stream(), "seq": int64(1), "kind": "intent", "revision": strings.Repeat("a", 64), "digest": "sha256:" + strings.Repeat("b", 64), "prev_hash": wire.ZeroHash, "intent_hash": nil}
	line := append(canon(t, base), '\n')
	if _, e = records.DecodeRegistrar(line, b, true); e != nil {
		t.Fatal(e)
	}
	_, e = records.DecodeRegistrar(line, b, false)
	expect(t, e, "evidence_invalid")
	for _, change := range []func(map[string]any){func(m map[string]any) { m["signature"] = "extra" }, func(m map[string]any) { m["digest"] = nil }, func(m map[string]any) { m["kind"] = "other" }, func(m map[string]any) { m["intent_hash"] = strings.Repeat("a", 64) }, func(m map[string]any) { delete(m, "revision") }} {
		v, _ := wire.Parse(canon(t, base), 8192)
		m := v.(map[string]any)
		change(m)
		_, e = records.DecodeRegistrar(append(canon(t, m), '\n'), b, true)
		expect(t, e, "request_malformed")
	}
	base["seq"] = wire.MaxInt
	base["prev_hash"] = strings.Repeat("a", 64)
	_, e = records.DecodeRegistrar(append(canon(t, base), '\n'), b, false)
	expect(t, e, "sequence_exhausted")
	base["kind"] = "committed"
	base["intent_hash"] = strings.Repeat("a", 64)
	if _, e = records.DecodeRegistrar(append(canon(t, base), '\n'), b, false); e != nil {
		t.Fatal(e)
	}
}
