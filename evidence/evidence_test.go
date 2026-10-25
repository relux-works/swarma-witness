package evidence_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/relux-works/swarma-witness/evidence"
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
func signing(n byte, epoch int64, role records.Role) (records.Key, ed25519.PrivateKey) {
	p := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{n}, 32))
	pub := p.Public().(ed25519.PublicKey)
	h := sha256.Sum256(pub)
	return records.Key{Public: "ed25519:" + base64.RawURLEncoding.EncodeToString(pub), ID: fmt.Sprintf("sha256:%x", h), Epoch: epoch, Role: role}, p
}
func sign(t *testing.T, body map[string]any, domain records.Domain, p ed25519.PrivateKey) []byte {
	return canon(t, map[string]any{"body": body, "signature": base64.RawURLEncoding.EncodeToString(ed25519.Sign(p, append([]byte(string(domain)+"\x00"), canon(t, body)...)))})
}
func fixture(t *testing.T) (wire.Binding, records.Record, records.Key, ed25519.PrivateKey) {
	t.Helper()
	k, p := signing(42, 2, records.Writer)
	m := map[string]any{"service": "witness", "stream": "station", "consumer": "keymaker", "identity": map[string]any{"product": "alpha", "project": "beta", "agent": "gamma"}, "lineage": "lineage", "profile": "keymaker-state-witness/1", "writer_epoch": int64(7), "writer_id": "writer", "record_key": map[string]any{"public_key": k.Public, "key_id": k.ID, "key_epoch": k.Epoch, "purpose": int64(3)}, "transport_pins": []any{"sha256:" + strings.Repeat("a", 64)}, "readers": []any{}}
	b, e := wire.DecodeBinding(canon(t, m))
	if e != nil {
		t.Fatal(e)
	}
	body := map[string]any{"v": int64(1), "type": "keymaker-state-witness/1", "consumer": "keymaker", "stream": "station", "station": m["identity"], "seq": int64(1), "state_epoch": int64(1), "kind": "intent", "commit_class": "audit", "base_state_digest": nil, "state_digest": "sha256:" + strings.Repeat("c", 64), "prev_hash": wire.ZeroHash, "intent_hash": nil, "key_epoch": k.Epoch, "key_id": k.ID}
	line := append(sign(t, body, records.RecordDomain, p), '\n')
	r, e := records.DecodeKeymaker(line, b, true)
	if e != nil {
		t.Fatal(e)
	}
	wk, wp := signing(43, 9, records.Witness)
	return b, r, wk, wp
}
func expect(t *testing.T, e error, code string) {
	t.Helper()
	if wire.Code(e) != code {
		t.Fatalf("want %s got %v", code, e)
	}
}

// Receipts copy exact writer projection and preserve original signature bytes;
// independently pinned witness and writer epochs cannot overwrite each other.
func TestEvidenceCopiesOriginalWriterFields(t *testing.T) {
	b, r, k, p := fixture(t)
	signer := func(pre []byte) ([]byte, error) { return ed25519.Sign(p, pre), nil }
	receipt, e := evidence.NewReceipt(r, b, k, strings.Repeat("d", 64), signer)
	if e != nil {
		t.Fatal(e)
	}
	if e = evidence.VerifyReceipt(receipt, r, b, k, strings.Repeat("d", 64)); e != nil {
		t.Fatal(e)
	}
	obj, e := wire.Parse(receipt, 4096)
	if e != nil {
		t.Fatal(e)
	}
	body := obj.(map[string]any)["body"].(map[string]any)
	if body["key_epoch"] != int64(2) || body["witness"].(map[string]any)["key_epoch"] != int64(9) {
		t.Fatal("writer overwritten")
	}
	for _, field := range []string{"key_epoch", "record_hash", "state_digest"} {
		v, _ := wire.Parse(receipt, 4096)
		m := v.(map[string]any)["body"].(map[string]any)
		if field == "key_epoch" {
			m[field] = int64(9)
		} else if field == "record_hash" {
			m[field] = strings.Repeat("a", 64)
		} else {
			m[field] = "sha256:" + strings.Repeat("b", 64)
		}
		bad := sign(t, m, records.KeymakerAck, p)
		expect(t, evidence.VerifyReceipt(bad, r, b, k, strings.Repeat("d", 64)), "evidence_invalid")
	}
	bad := append([]byte{}, receipt...)
	bad[len(bad)-4] ^= 1
	expect(t, evidence.VerifyReceipt(bad, r, b, k, strings.Repeat("d", 64)), "evidence_invalid")
}

// A fresh head carries the original receipt (even at equal anchor), exact
// challenged bytes and closed contiguous manifests; pages remain historical.
func TestEvidenceHeadAndPage(t *testing.T) {
	b, r, k, p := fixture(t)
	signer := func(pre []byte) ([]byte, error) { return ed25519.Sign(p, pre), nil }
	c := strings.Repeat("d", 64)
	receipt, e := evidence.NewReceipt(r, b, k, c, signer)
	if e != nil {
		t.Fatal(e)
	}
	manifest := map[string]any{"anchor_seq": int64(1), "anchor_hash": r.Hash(), "head_seq": int64(1), "head_hash": r.Hash(), "count": int64(0), "pages": []any{}}
	controls := map[string]any{"anchor_seq": int64(1), "anchor_hash": c, "head_seq": int64(1), "head_hash": c, "count": int64(0), "pages": []any{}}
	proof := map[string]any{"records": manifest, "controls": controls, "intent": nil}
	challenge := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	head, e := evidence.NewHead(r, b, k, c, receipt, k, c, challenge, proof, signer)
	if e != nil {
		t.Fatal(e)
	}
	if e = evidence.VerifyHead(head, r, b, k, c, receipt, k, c, challenge); e != nil {
		t.Fatal(e)
	}
	expect(t, evidence.VerifyHead(head, r, b, k, c, receipt, k, c, base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))), "evidence_invalid")
	manifest["count"] = int64(1)
	_, e = evidence.NewHead(r, b, k, c, receipt, k, c, challenge, proof, signer)
	expect(t, e, "evidence_invalid")
	page := map[string]any{"v": int64(1), "consumer": "keymaker", "stream": "station", "chain": "records", "anchor_seq": int64(0), "anchor_hash": wire.ZeroHash, "head_seq": int64(1), "head_hash": r.Hash(), "index": int64(0), "entries": []any{map[string]any{"record": base64.RawURLEncoding.EncodeToString(r.Line()), "receipt": base64.RawURLEncoding.EncodeToString(receipt)}}}
	raw := canon(t, page)
	hash := records.Digest(raw)
	if e := evidence.VerifyPage(raw, hash, b); e != nil {
		t.Fatal(e)
	}
	expect(t, evidence.VerifyPage(raw, "sha256:"+strings.Repeat("b", 64), b), "evidence_invalid")
	page["chain"] = "other"
	bad := canon(t, page)
	expect(t, evidence.VerifyPage(bad, records.Digest(bad), b), "request_malformed")
}

// Admin/control operation enums and nulls are closed before signing. A valid
// signature is not S2 authorization, replay, bootstrap or rotation approval.
func TestEvidenceControlSchemas(t *testing.T) {
	k, p := signing(44, 3, records.Admin)
	b, _, wk, wp := fixture(t)
	binding, e := wire.Parse(b.Bytes(), 8192)
	if e != nil {
		t.Fatal(e)
	}
	body := map[string]any{"v": int64(1), "service": "witness", "seq": int64(1), "prev_hash": wire.ZeroHash, "action_id": strings.Repeat("a", 32), "operation": "provision", "stream": "station", "expected_binding_hash": nil, "new_binding": binding, "expected_head": map[string]any{"seq": int64(0), "hash": wire.ZeroHash}, "bootstrap_hash": strings.Repeat("b", 64), "key_epoch": k.Epoch, "key_id": k.ID}
	line := append(sign(t, body, records.AdminDomain, p), '\n')
	if _, e := evidence.DecodeAction(line, k); e != nil {
		t.Fatal(e)
	}
	signer := func(pre []byte) ([]byte, error) { return ed25519.Sign(wp, pre), nil }
	control, e := evidence.NewControlReceipt(line, k, wk, signer)
	if e != nil {
		t.Fatal(e)
	}
	if e := evidence.VerifyControlReceipt(control, line, k, wk); e != nil {
		t.Fatal(e)
	}
	body["bootstrap_hash"] = nil
	_, e = evidence.DecodeAction(append(sign(t, body, records.AdminDomain, p), '\n'), k)
	expect(t, e, "request_malformed")
	body["operation"] = "delete"
	_, e = evidence.DecodeAction(append(sign(t, body, records.AdminDomain, p), '\n'), k)
	expect(t, e, "request_malformed")
}

// External signer callbacks cannot change the already reserved artifact's body
// or induce signing of over-limit evidence; rejection makes zero signer calls.
func TestEvidenceSignerBoundary(t *testing.T) {
	b, r, k, p := fixture(t)
	calls := 0
	signer := func(pre []byte) ([]byte, error) { calls++; return ed25519.Sign(p, pre), nil }
	_, e := evidence.NewReceipt(r, b, k, "bad", signer)
	expect(t, e, "request_malformed")
	if calls != 0 {
		t.Fatal("signed rejected evidence")
	}
	body := map[string]any{"value": "before"}
	mutator := func(pre []byte) ([]byte, error) { body["value"] = "after"; return ed25519.Sign(p, pre), nil }
	raw, e := records.SignEnvelope(body, 4096, records.KeymakerAck, k, mutator)
	if e != nil {
		t.Fatal(e)
	}
	verified, e := records.VerifyEnvelope(raw, 4096, records.KeymakerAck, k)
	if e != nil || verified["value"] != "before" {
		t.Fatal("signer changed reserved body", e)
	}
	calls = 0
	_, e = records.SignEnvelope(map[string]any{"value": strings.Repeat("x", 8193)}, 8192, records.KeymakerAck, k, signer)
	expect(t, e, "limit_exceeded")
	if calls != 0 {
		t.Fatal("over-cap signer call")
	}
}

// Registrar receipts bind the original writer policy epoch/id, even if a
// later protected binding has rotated. Neutral domains cannot verify as KM.
func TestEvidenceRegistrarProjection(t *testing.T) {
	original := map[string]any{"service": "witness", "stream": "registrar", "consumer": "registrar", "identity": "registry", "lineage": "lineage", "profile": "registrar-state-witness-sha1/1", "writer_epoch": int64(7), "writer_id": "writer", "record_key": nil, "transport_pins": []any{"sha256:" + strings.Repeat("a", 64)}, "readers": []any{}}
	b, e := wire.DecodeBinding(canon(t, original))
	if e != nil {
		t.Fatal(e)
	}
	body := map[string]any{"v": int64(1), "stream": "registrar", "seq": int64(1), "kind": "intent", "revision": strings.Repeat("a", 40), "digest": "sha256:" + strings.Repeat("b", 64), "prev_hash": wire.ZeroHash, "intent_hash": nil}
	r, e := records.DecodeRegistrar(append(canon(t, body), '\n'), b, true)
	if e != nil {
		t.Fatal(e)
	}
	k, p := signing(47, 9, records.Witness)
	signer := func(pre []byte) ([]byte, error) { return ed25519.Sign(p, pre), nil }
	original["writer_epoch"] = int64(8)
	original["writer_id"] = "new-writer"
	current, e := wire.DecodeBinding(canon(t, original))
	if e != nil {
		t.Fatal(e)
	}
	receipt, e := evidence.NewReceipt(r, current, k, strings.Repeat("c", 64), signer)
	if e != nil {
		t.Fatal(e)
	}
	if e = evidence.VerifyReceipt(receipt, r, current, k, strings.Repeat("c", 64)); e != nil {
		t.Fatal(e)
	}
	decoded, e := records.VerifyEnvelope(receipt, 4096, records.NeutralAck, k)
	if e != nil {
		t.Fatal(e)
	}
	writer := decoded["writer"].(map[string]any)
	if writer["epoch"] != int64(7) || writer["id"] != "writer" {
		t.Fatal("original neutral writer replaced")
	}
	_, e = records.VerifyEnvelope(receipt, 4096, records.KeymakerAck, k)
	expect(t, e, "evidence_invalid")
	decoded["projection"].(map[string]any)["digest"] = "sha256:" + strings.Repeat("d", 64)
	expect(t, evidence.VerifyReceipt(sign(t, decoded, records.NeutralAck, p), r, current, k, strings.Repeat("c", 64)), "evidence_invalid")
	original["identity"] = "other-registry"
	foreign, e := wire.DecodeBinding(canon(t, original))
	if e != nil {
		t.Fatal(e)
	}
	_, e = evidence.NewReceipt(r, foreign, k, strings.Repeat("c", 64), signer)
	expect(t, e, "evidence_invalid")

}

// Rotation schemas distinguish writer and witness operations and require the
// new witness's separate possession proof under the transition domain. Actual
// epoch advancement, old-key continuity and transition activation remain S2+.
func TestEvidenceRotationSchemas(t *testing.T) {
	admin, ap := signing(44, 3, records.Admin)
	b, _, _, _ := fixture(t)
	binding, e := wire.Parse(b.Bytes(), 8192)
	if e != nil {
		t.Fatal(e)
	}
	body := map[string]any{"v": int64(1), "service": "witness", "seq": int64(2), "prev_hash": strings.Repeat("a", 64), "action_id": strings.Repeat("b", 32), "operation": "rotate_writer", "stream": "station", "expected_binding_hash": "sha256:" + strings.Repeat("c", 64), "new_binding": binding, "expected_head": map[string]any{"seq": int64(1), "hash": strings.Repeat("d", 64)}, "bootstrap_hash": nil, "key_epoch": admin.Epoch, "key_id": admin.ID}
	decode := func() error {
		_, e := evidence.DecodeAction(append(sign(t, body, records.AdminDomain, ap), '\n'), admin)
		return e
	}
	if e = decode(); e != nil {
		t.Fatal(e)
	}
	body["expected_head"] = nil
	expect(t, decode(), "request_malformed")
	next, np := signing(45, 10, records.Transition)
	nextBody := map[string]any{"service": "witness", "key_epoch": next.Epoch, "key_id": next.ID, "public_key": next.Public}
	pre := append([]byte("state-witness-key-transition/1\x00"), canon(t, nextBody)...)
	nextBody["proof"] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(np, pre))
	body["operation"] = "rotate_witness"
	body["stream"] = nil
	body["expected_head"] = nil
	body["new_binding"] = nextBody
	if e = decode(); e != nil {
		t.Fatal(e)
	}
	nextBody["proof"] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(np, append([]byte("keymaker-witness-ack/1\x00"), pre[len("state-witness-key-transition/1\x00"):]...)))
	expect(t, decode(), "evidence_invalid")
}
