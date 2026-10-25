package policy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/relux-works/swarma-witness/evidence"
	"github.com/relux-works/swarma-witness/records"
	"github.com/relux-works/swarma-witness/wire"
)

func key(t *testing.T, role records.Role) (records.Key, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return records.Key{Public: "ed25519:" + base64.RawURLEncoding.EncodeToString(pub), ID: records.Digest(pub), Epoch: 1, Role: role}, priv
}
func canon(t *testing.T, v any) []byte {
	t.Helper()
	b, e := wire.Canonical(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func signed(t *testing.T, m map[string]any, domain string, k records.Key, priv ed25519.PrivateKey) []byte {
	t.Helper()
	m["key_epoch"] = k.Epoch
	m["key_id"] = k.ID
	pre := append([]byte(domain+"\x00"), canon(t, m)...)
	return append(canon(t, map[string]any{"body": m, "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, pre))}), '\n')
}
func bindingMap(k records.Key, stream, id, pin string) map[string]any {
	return map[string]any{"service": "svc", "stream": stream, "consumer": "keymaker", "identity": map[string]any{"product": "p", "project": "p", "agent": "p"}, "lineage": "one", "profile": "keymaker-state-witness/1", "writer_epoch": int64(1), "writer_id": id, "record_key": map[string]any{"public_key": k.Public, "key_id": k.ID, "key_epoch": k.Epoch, "purpose": int64(3)}, "transport_pins": []any{pin}, "readers": []any{map[string]any{"id": "reader", "transport_pins": []any{records.Digest([]byte("reader"))}}}}
}
func binding(t *testing.T, m map[string]any) wire.Binding {
	t.Helper()
	b, e := wire.DecodeBinding(canon(t, m))
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func fixture(t *testing.T) (Snapshot, records.Key, ed25519.PrivateKey, map[string]any) {
	t.Helper()
	k, priv := key(t, records.Writer)
	pin := records.Digest([]byte("writer"))
	m := bindingMap(k, "one", "writer", pin)
	s := Snapshot{"svc", []wire.Binding{binding(t, m)}, []Principal{{"writer", Writer, []string{pin}}, {"reader", Reader, []string{records.Digest([]byte("reader"))}}, {"admin", Administrator, []string{records.Digest([]byte("admin"))}}, {"publisher", Publisher, []string{records.Digest([]byte("publisher"))}}, {"bridge", Bridge, []string{records.Digest([]byte("bridge"))}}, {"observer", Observer, []string{records.Digest([]byte("observer"))}}}}
	if e := s.Validate(); e != nil {
		t.Fatal(e)
	}
	return s, k, priv, m
}
func wantCode(t *testing.T, e error, want string) {
	t.Helper()
	if wire.Code(e) != want {
		t.Fatalf("code=%q want=%q", wire.Code(e), want)
	}
}
func peer(id string) Peer { return Peer{id, records.Digest([]byte(id))} }

// Claim: exact protected writer/reader memberships permit only their stream;
// publishers cannot inherit bridge/admin rights or expose guessed foreign pages.
func TestACLRejectsCrossStreamAndRegistryWriter(t *testing.T) {
	s, _, _, _ := fixture(t)
	for _, x := range []struct{ id, method, stream string }{{"writer", "append", "one"}, {"reader", "latest", "one"}, {"reader", "proof_page", "one"}, {"admin", "admin", ""}} {
		wantCode(t, s.Authorize(peer(x.id), x.method, x.stream), "")
	}
	for _, id := range []string{"writer", "reader", "publisher", "bridge", "observer"} {
		for _, method := range []string{"append", "latest", "proof_page"} {
			for _, stream := range []string{"foreign", "missing"} {
				wantCode(t, s.Authorize(peer(id), method, stream), "not_authorized")
			}
		}
	}
	wantCode(t, s.Authorize(peer("publisher"), "admin", ""), "not_authorized")
	// A genuine bridge and observer have only an independently bound checkpoint stream.
	pub, _ := key(t, records.Writer)
	reg := map[string]any{"service": "svc", "stream": "registry", "consumer": "owner-registry", "identity": map[string]any{"registry_id": pub.Public, "owner": "owner"}, "lineage": "r", "profile": "owner-registry-checkpoint/1", "writer_epoch": int64(1), "writer_id": "bridge", "record_key": nil, "transport_pins": []any{peer("bridge").Pin}, "readers": []any{map[string]any{"id": "observer", "transport_pins": []any{peer("observer").Pin}}}}
	s.Bindings = append(s.Bindings, binding(t, reg))
	wantCode(t, s.Authorize(peer("bridge"), "append", "registry"), "")
	wantCode(t, s.Authorize(peer("observer"), "latest", "registry"), "")
	wantCode(t, s.Authorize(peer("publisher"), "append", "registry"), "not_authorized")
	reg["writer_id"] = "publisher"
	reg["transport_pins"] = []any{peer("publisher").Pin}
	s.Bindings[1] = binding(t, reg)
	wantCode(t, s.Validate(), "evidence_invalid")
}

func action(b wire.Binding, op string) map[string]any {
	v, _ := wire.Parse(b.Bytes(), wire.LineLimit)
	m := map[string]any{"v": int64(1), "service": "svc", "seq": int64(1), "prev_hash": wire.ZeroHash, "action_id": strings.Repeat("a", 32), "operation": op, "stream": b.Stream(), "expected_binding_hash": nil, "new_binding": v, "expected_head": map[string]any{"seq": int64(0), "hash": wire.ZeroHash}, "bootstrap_hash": records.Hash([]byte("first"))}
	return m
}
func consentBody(b wire.Binding, first []byte, id, disclosure string) map[string]any {
	m, _ := bindingObject(b)
	return map[string]any{"v": int64(1), "type": consentDomain, "consent_id": strings.Repeat("b", 32), "service": b.Service(), "stream": b.Stream(), "consumer": b.Consumer(), "identity": m["identity"], "lineage": m["lineage"], "binding_hash": records.Digest(b.Bytes()), "bootstrap_hash": records.Hash(first), "action_id": id, "disclosure_hash": disclosure}
}

// Claim: pure provisioning needs independent signed consent and an exact frozen
// line; empty state never allocates a grant. Retry equality is modeled, not durable.
func TestProvisionRequiresConsentAndExactBootstrap(t *testing.T) {
	s, k, priv, _ := fixture(t)
	b := s.Bindings[0]
	first := signed(t, map[string]any{"v": int64(1), "type": "keymaker-state-witness/1", "consumer": "keymaker", "stream": "one", "station": b.Identity(), "seq": int64(1), "state_epoch": int64(1), "kind": "intent", "commit_class": "policy-custody", "base_state_digest": nil, "state_digest": records.Digest([]byte("candidate")), "prev_hash": wire.ZeroHash, "intent_hash": nil}, string(records.RecordDomain), k, priv)
	if _, e := records.DecodeKeymaker(first, b, true); e != nil {
		t.Fatal(e)
	}
	admin, ap := key(t, records.Admin)
	approve, cp := key(t, ApprovalRole)
	m := action(b, "provision")
	m["bootstrap_hash"] = records.Hash(first)
	line := signed(t, m, string(records.AdminDomain), admin, ap)
	s.Bindings = nil
	plan, e := ValidateAdmin(s, peer("admin"), line, admin, ControlSnapshot{Hash: wire.ZeroHash})
	wantCode(t, e, "")
	disclosure := records.Digest([]byte("approved disclosure"))
	cb := consentBody(b, first, wire.String(m["action_id"]), disclosure)
	consent := signed(t, cb, consentDomain, approve, cp)
	wantCode(t, ValidateProvisionEvidence(plan, consent, first, approve, disclosure), "")
	if _, e = PrepareAdmin(s, peer("admin"), line, admin, ControlSnapshot{Hash: wire.ZeroHash}, AdministrativeEvidence{}); wire.Code(e) != "profile_unavailable" {
		t.Fatalf("missing accepted approval: %v", e)
	}
	if _, e = PrepareAdmin(s, peer("admin"), line, admin, ControlSnapshot{Hash: wire.ZeroHash}, AdministrativeEvidence{Consent: consent, FirstLine: first, DisclosureDigest: disclosure, Approval: approve}); e != nil {
		t.Fatal("composed provision", e)
	}

	wantCode(t, ValidateProvisionEvidence(plan, nil, first, approve, disclosure), "bootstrap_required")
	wantCode(t, ValidateProvisionEvidence(plan, consent, append(first, 'x'), approve, disclosure), "bootstrap_required")
	for _, field := range []string{"binding_hash", "disclosure_hash", "bootstrap_hash", "action_id", "lineage"} {
		original := cb[field]
		switch field {
		case "action_id":
			cb[field] = strings.Repeat("c", 32)
		case "lineage":
			cb[field] = "other"
		case "bootstrap_hash":
			cb[field] = records.Hash([]byte("other"))
		default:
			cb[field] = records.Digest([]byte("other"))
		}
		wantCode(t, ValidateProvisionEvidence(plan, signed(t, cb, consentDomain, approve, cp), first, approve, disclosure), "evidence_invalid")
		cb[field] = original
	}
	cb["extra"] = nil
	wantCode(t, ValidateProvisionEvidence(plan, signed(t, cb, consentDomain, approve, cp), first, approve, disclosure), "request_malformed")
	delete(cb, "extra")
	wantCode(t, ValidateBootstrap(GrantSnapshot{}, wire.String(m["action_id"]), first), "bootstrap_required")
	g := GrantSnapshot{wire.String(m["action_id"]), append([]byte(nil), first...), true}
	wantCode(t, ValidateBootstrap(g, g.ReservedAction, first), "")
	wantCode(t, ValidateBootstrap(g, g.ReservedAction, first), "")
	wantCode(t, ValidateBootstrap(g, strings.Repeat("f", 32), first), "bootstrap_required")
	if !g.Consumed || !bytes.Equal(g.FirstLine, first) {
		t.Fatal("refusal changed bootstrap snapshot")
	}
	wantCode(t, ValidateEmptyLatest(false, 0), "stream_unavailable")
	wantCode(t, ValidateEmptyLatest(true, 0), "stream_empty")
	wantCode(t, ValidateEmptyLatest(true, 1), "")
}

// Claim: current admin transport and exact signed bytes govern pure action
// validation/replay; mismatched CAS and changed ID reuse retain the input state.
func TestAdminRejectsReplayAndRoleOverlap(t *testing.T) {
	s, _, _, _ := fixture(t)
	admin, priv := key(t, records.Admin)
	b := s.Bindings[0]
	s.Bindings = nil
	m := action(b, "provision")
	line := signed(t, m, string(records.AdminDomain), admin, priv)
	c := ControlSnapshot{Hash: wire.ZeroHash, Actions: map[string]RetainedAction{}}
	_, e := ValidateAdmin(s, peer("admin"), line, admin, c)
	wantCode(t, e, "")
	_, e = ValidateAdmin(s, peer("writer"), line, admin, c)
	wantCode(t, e, "not_authorized")
	c.Actions[wire.String(m["action_id"])] = RetainedAction{append([]byte(nil), line...), []byte("retained original receipt")}
	r, e := ValidateAdmin(s, peer("admin"), line, admin, c)
	wantCode(t, e, "")
	if !r.Replay || !bytes.Equal(r.Receipt, c.Actions[wire.String(m["action_id"])].Receipt) {
		t.Fatal("exact replay lost original result")
	}
	m["bootstrap_hash"] = records.Hash([]byte("changed"))
	changed := signed(t, m, string(records.AdminDomain), admin, priv)
	_, e = ValidateAdmin(s, peer("admin"), changed, admin, c)
	wantCode(t, e, "position_conflict")
	if !bytes.Equal(c.Actions[wire.String(m["action_id"])].Action, line) {
		t.Fatal("replay refusal mutated state")
	}
	delete(c.Actions, wire.String(m["action_id"]))
	m["prev_hash"] = records.Hash([]byte("wrong"))
	_, e = ValidateAdmin(s, peer("admin"), signed(t, m, string(records.AdminDomain), admin, priv), admin, c)
	wantCode(t, e, "head_conflict")
	m["prev_hash"] = wire.ZeroHash
	wrong := admin
	wrong.Role = records.Writer
	_, e = ValidateAdmin(s, peer("admin"), line, wrong, c)
	wantCode(t, e, "evidence_invalid")
	_, e = ValidateAdmin(s, peer("admin"), signed(t, m, string(records.RecordDomain), admin, priv), admin, c)
	wantCode(t, e, "evidence_invalid")
	c.Pending = true
	_, e = ValidateAdmin(s, peer("admin"), line, admin, c)
	wantCode(t, e, "outcome_unknown")
	s.Principals = append(s.Principals, Principal{"overlap", Bridge, []string{peer("publisher").Pin}})
	wantCode(t, s.Validate(), "evidence_invalid")
}

// Claim: epoch+1 policy rotation retains record-key authority/history, replaces
// old peer admission and refuses record-key changes even with valid signatures.
func TestRotationPreservesHistoricalAuthority(t *testing.T) {
	s, k, priv, m := fixture(t)
	old := s.Bindings[0]
	m["writer_epoch"] = int64(2)
	m["writer_id"] = "new-writer"
	newPin := records.Digest([]byte("new-writer"))
	m["transport_pins"] = []any{newPin}
	next := binding(t, m)
	wantCode(t, ValidateRotation(old, next), "")
	s.Principals = append(s.Principals, Principal{"new-writer", Writer, []string{newPin}})
	s.Bindings[0] = next
	wantCode(t, s.Authorize(peer("new-writer"), "append", "one"), "")
	wantCode(t, s.Authorize(peer("writer"), "append", "one"), "not_authorized")
	if !bytes.Equal(old.Bytes(), binding(t, bindingMap(k, "one", "writer", peer("writer").Pin)).Bytes()) {
		t.Fatal("historical binding altered")
	}
	admin, ap := key(t, records.Admin)
	a := action(next, "rotate_writer")
	a["expected_binding_hash"] = records.Digest(old.Bytes())
	a["expected_head"] = map[string]any{"seq": int64(2), "hash": records.Hash([]byte("head"))}
	a["bootstrap_hash"] = nil
	s.Bindings[0] = old
	c := ControlSnapshot{Hash: wire.ZeroHash, HeadSeq: 2, HeadHash: records.Hash([]byte("head"))}
	line := signed(t, a, string(records.AdminDomain), admin, ap)
	plan, e := ValidateAdmin(s, peer("admin"), line, admin, c)
	wantCode(t, e, "")
	if plan.Binding.WriterID() != "new-writer" {
		t.Fatal("rotation plan wrong")
	}
	c.HeadSeq = 0
	c.HeadHash = wire.ZeroHash
	a["expected_head"] = map[string]any{"seq": int64(0), "hash": wire.ZeroHash}
	_, e = ValidateAdmin(s, peer("admin"), signed(t, a, string(records.AdminDomain), admin, ap), admin, c)
	wantCode(t, e, "bootstrap_required")
	m["lineage"] = "foreign"
	wantCode(t, ValidateRotation(old, binding(t, m)), "evidence_invalid")
	m["lineage"] = "one"
	m["writer_epoch"] = int64(3)
	wantCode(t, ValidateRotation(old, binding(t, m)), "evidence_invalid")
	m["writer_epoch"] = int64(2)
	rk := m["record_key"].(map[string]any)
	rk["key_epoch"] = int64(2)
	wantCode(t, ValidateRotation(old, binding(t, m)), "evidence_invalid")
	newer, np := key(t, records.Writer)
	newer.Epoch = 2
	rk["key_id"] = newer.ID
	rk["public_key"] = newer.Public
	newerBinding := binding(t, m)
	intent := map[string]any{"v": int64(1), "type": "keymaker-state-witness/1", "consumer": "keymaker", "stream": "one", "station": old.Identity(), "seq": int64(3), "state_epoch": int64(2), "kind": "intent", "commit_class": "policy-custody", "base_state_digest": records.Digest([]byte("base")), "state_digest": records.Digest([]byte("candidate")), "prev_hash": records.Hash([]byte("head")), "intent_hash": nil}
	oldLine := signed(t, intent, string(records.RecordDomain), k, priv)
	newLine := signed(t, intent, string(records.RecordDomain), newer, np)
	if _, e = records.DecodeKeymaker(oldLine, old, false); e != nil {
		t.Fatal(e)
	}
	if _, e = records.DecodeKeymaker(newLine, newerBinding, false); e != nil {
		t.Fatal(e)
	}
	historicalRecord, e := records.DecodeKeymaker(oldLine, old, false)
	if e != nil {
		t.Fatal(e)
	}
	witness, wp := key(t, records.Witness)
	control := records.Hash([]byte("original control"))
	receipt, e := evidence.NewReceipt(historicalRecord, old, witness, control, func(pre []byte) ([]byte, error) { return ed25519.Sign(wp, pre), nil })
	if e != nil {
		t.Fatal(e)
	}
	s.Bindings[0] = next
	history := HistoricalReceipt{historicalRecord, receipt, witness, control}
	original, e := ValidateHistoricalRetry(s, peer("new-writer"), oldLine, history)
	wantCode(t, e, "")
	if !bytes.Equal(original, receipt) {
		t.Fatal("historical receipt replaced")
	}
	_, e = ValidateHistoricalRetry(s, peer("writer"), oldLine, history)
	wantCode(t, e, "not_authorized")
	_, e = ValidateHistoricalRetry(s, peer("new-writer"), newLine, history)
	wantCode(t, e, "position_conflict")
	wantCode(t, ValidateRotation(old, newerBinding), "profile_unavailable")
	packet := map[string]any{"v": int64(1), "service": "svc", "stream": "one", "action_hash": records.Hash(line), "old_transport": records.Digest([]byte("old")), "new_transport": records.Digest([]byte("new")), "old_record": base64.RawURLEncoding.EncodeToString(oldLine), "new_record": base64.RawURLEncoding.EncodeToString(newLine)}
	_, e = DecodePossessionPacket(canon(t, packet), "svc", "one", records.Hash(line))
	wantCode(t, e, "profile_unavailable")
	packet["old_record"] = nil
	packet["new_record"] = nil
	_, e = DecodePossessionPacket(canon(t, packet), "svc", "one", records.Hash(line))
	wantCode(t, e, "")
	full := bindingMap(k, "one", "writer", peer("writer").Pin)
	full["writer_epoch"] = wire.MaxInt
	wantCode(t, ValidateRotation(binding(t, full), next), "sequence_exhausted")
}

// Claim: signed transport possession requires the exact action, fresh challenge,
// principal, pin and channel context; digest-only or missing evidence is no proof.
func TestRotationPossessionEvidenceBound(t *testing.T) {
	k, priv := key(t, EnrollmentRole)
	c := PossessionContext{"svc", "one", records.Hash([]byte("action")), "writer", peer("writer").Pin, strings.Repeat("d", 32), records.Digest([]byte("exporter"))}
	m := map[string]any{"v": int64(1), "type": possessionDomain, "service": c.Service, "stream": c.Stream, "action_hash": c.ActionHash, "principal_id": c.PrincipalID, "transport_pin": c.Pin, "challenge": c.Challenge, "channel_digest": c.ChannelDigest}
	line := signed(t, m, possessionDomain, k, priv)
	wantCode(t, DecodePrincipalPossession(line, k, c), "")
	for _, field := range []string{"action_hash", "challenge", "channel_digest", "transport_pin", "principal_id"} {
		old := m[field]
		switch field {
		case "action_hash":
			m[field] = records.Hash([]byte("B"))
		case "challenge":
			m[field] = strings.Repeat("e", 32)
		case "principal_id":
			m[field] = "foreign"
		default:
			m[field] = records.Digest([]byte("B"))
		}
		wantCode(t, DecodePrincipalPossession(signed(t, m, possessionDomain, k, priv), k, c), "evidence_invalid")
		m[field] = old
	}
	m["extra"] = nil
	wantCode(t, DecodePrincipalPossession(signed(t, m, possessionDomain, k, priv), k, c), "request_malformed")
	delete(m, "extra")
	digest := records.Digest(line)
	packet := canon(t, map[string]any{"v": int64(1), "service": c.Service, "stream": c.Stream, "action_hash": c.ActionHash, "old_transport": digest, "new_transport": digest, "old_record": nil, "new_record": nil})
	objects := map[string][]byte{digest: line}
	wantCode(t, ValidateRotationEvidence(packet, objects, k, c, c), "")
	wantCode(t, ValidateRotationEvidence(nil, nil, k, c, c), "profile_unavailable")
	objects[digest] = append(append([]byte(nil), line...), 'x')
	wantCode(t, ValidateRotationEvidence(packet, objects, k, c, c), "evidence_invalid")
}
