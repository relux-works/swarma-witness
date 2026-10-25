package policy

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-witness/records"
	"github.com/relux-works/swarma-witness/wire"
)

// Review: an observer may not gain membership in every registry checkpoint
// stream merely by having the observer role; unrelated bindings stay private.
func TestReviewObserverScope(t *testing.T) {
	s, _, _, _ := fixture(t)
	root, _ := key(t, records.Writer)
	for _, stream := range []string{"registry-one", "registry-two"} {
		m := map[string]any{"service": "svc", "stream": stream, "consumer": "owner-registry", "identity": map[string]any{"registry_id": root.Public, "owner": stream}, "lineage": stream, "profile": "owner-registry-checkpoint/1", "writer_epoch": int64(1), "writer_id": "bridge", "record_key": nil, "transport_pins": []any{peer("bridge").Pin}, "readers": []any{}}
		if stream == "registry-one" {
			m["readers"] = []any{map[string]any{"id": "observer", "transport_pins": []any{peer("observer").Pin}}}
		}
		s.Bindings = append(s.Bindings, binding(t, m))
	}
	secondPin := records.Digest([]byte("observer-second-pin"))
	for i := range s.Principals {
		if s.Principals[i].Role == Observer {
			s.Principals[i].Pins = append(s.Principals[i].Pins, secondPin)
		}
	}
	wantCode(t, s.Validate(), "")
	wantCode(t, s.Authorize(peer("bridge"), "append", "registry-one"), "")
	for _, method := range []string{"latest", "proof_page"} {
		t.Run(method, func(t *testing.T) {
			wantCode(t, s.Authorize(peer("observer"), method, "registry-one"), "")
			before := append([]byte(nil), s.Bindings[2].Bytes()...)
			if e := s.Authorize(peer("observer"), method, "registry-two"); wire.Code(e) != "not_authorized" {
				t.Fatalf("observer lacks explicit membership in registry-two: got %q", wire.Code(e))
			}
			if !bytes.Equal(before, s.Bindings[2].Bytes()) {
				t.Fatal("observer refusal changed binding")
			}
			wantCode(t, s.Authorize(Peer{"observer", secondPin}, method, "registry-one"), "not_authorized")
			wantCode(t, s.Authorize(peer("observer"), method, "one"), "not_authorized")
		})
	}
}

// Review: a signed next policy must preserve signing-role separation, not just
// the old snapshot. Positive controls use distinct ephemeral synthetic keys.
func TestReviewProspectiveSigningRoles(t *testing.T) {
	t.Run("provision-record-is-admin", func(t *testing.T) {
		for _, overlap := range []bool{false, true} {
			s, k, kp, _ := fixture(t)
			admin, ap := key(t, records.Admin)
			approval, cp := key(t, ApprovalRole)
			if overlap {
				k = admin
				kp = ap
			}
			b := binding(t, bindingMap(k, "one", "writer", peer("writer").Pin))
			s.Bindings = nil
			first := signed(t, map[string]any{"v": int64(1), "type": "keymaker-state-witness/1", "consumer": "keymaker", "stream": "one", "station": b.Identity(), "seq": int64(1), "state_epoch": int64(1), "kind": "intent", "commit_class": "policy-custody", "base_state_digest": nil, "state_digest": records.Digest([]byte("candidate")), "prev_hash": wire.ZeroHash, "intent_hash": nil}, string(records.RecordDomain), k, kp)
			if _, e := records.DecodeKeymaker(first, b, true); e != nil {
				t.Fatal(e)
			}
			m := action(b, "provision")
			m["bootstrap_hash"] = records.Hash(first)
			line := signed(t, m, string(records.AdminDomain), admin, ap)
			disclosure := records.Digest([]byte("approved disclosure"))
			consent := signed(t, consentBody(b, first, wire.String(m["action_id"]), disclosure), consentDomain, approval, cp)
			before := append([]byte(nil), line...)
			plan, e := PrepareAdmin(s, peer("admin"), line, admin, ControlSnapshot{Hash: wire.ZeroHash}, AdministrativeEvidence{Consent: consent, FirstLine: first, DisclosureDigest: disclosure, Approval: approval})
			if overlap && !reflect.DeepEqual(plan, Plan{}) {
				t.Fatal("role refusal returned partial plan")
			}
			if !bytes.Equal(before, line) {
				t.Fatal("role refusal changed action")
			}
			if !overlap && e != nil {
				t.Fatalf("distinct control: %v", e)
			}
			if overlap && (wire.Code(e) != "evidence_invalid" && wire.Code(e) != "not_authorized") {
				t.Fatalf("prospective admin/record overlap accepted: operation=%s code=%q", plan.Operation, wire.Code(e))
			}
		}
	})
	t.Run("new-witness-is-admin", func(t *testing.T) {
		for _, source := range []string{"distinct", "admin", "consumer", "registry", "approval", "enrollment"} {
			overlap := source != "distinct"
			s, consumer, consumerPrivate, _ := fixture(t)
			admin, ap := key(t, records.Admin)
			old, _ := key(t, records.Witness)
			next, np := key(t, records.Transition)
			next.Epoch = 2
			if source == "admin" {
				next = admin
				next.Epoch = 2
				next.Role = records.Transition
				np = ap
			}
			if source == "consumer" {
				next, np = consumer, consumerPrivate
				next.Epoch = 2
				next.Role = records.Transition
			}
			if source == "registry" {
				registry := map[string]any{"service": "svc", "stream": "registry", "consumer": "owner-registry", "identity": map[string]any{"registry_id": next.Public, "owner": "owner"}, "lineage": "r", "profile": "owner-registry-checkpoint/1", "writer_epoch": int64(1), "writer_id": "bridge", "record_key": nil, "transport_pins": []any{peer("bridge").Pin}, "readers": []any{}}
				s.Bindings = append(s.Bindings, binding(t, registry))
			}
			var supplied AdministrativeEvidence
			if source == "approval" {
				supplied.Approval = next
				supplied.Approval.Role = ApprovalRole
			}
			if source == "enrollment" {
				supplied.Enrollment = next
				supplied.Enrollment.Role = EnrollmentRole
			}
			n := map[string]any{"service": "svc", "key_epoch": int64(2), "key_id": next.ID, "public_key": next.Public}
			pre, e := records.Preimage(n, records.TransitionDomain)
			if e != nil {
				t.Fatal(e)
			}
			n["proof"] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(np, pre))
			oldBytes := canon(t, map[string]any{"service": "svc", "key_epoch": old.Epoch, "key_id": old.ID, "public_key": old.Public})
			m := map[string]any{"v": int64(1), "service": "svc", "seq": int64(1), "prev_hash": wire.ZeroHash, "action_id": strings.Repeat("a", 32), "operation": "rotate_witness", "stream": nil, "expected_binding_hash": records.Digest(oldBytes), "new_binding": n, "expected_head": nil, "bootstrap_hash": nil}
			line := signed(t, m, string(records.AdminDomain), admin, ap)
			before := append([]byte(nil), line...)
			plan, e := PrepareAdmin(s, peer("admin"), line, admin, ControlSnapshot{Hash: wire.ZeroHash, CurrentWitness: old}, supplied)
			if overlap && !reflect.DeepEqual(plan, Plan{}) {
				t.Fatalf("role refusal returned partial plan: %s", source)
			}
			if !bytes.Equal(before, line) {
				t.Fatal("role refusal changed action")
			}
			if !overlap && e != nil {
				t.Fatalf("distinct control: %v", e)
			}
			if overlap && (wire.Code(e) != "evidence_invalid" && wire.Code(e) != "not_authorized") {
				t.Fatalf("prospective admin/witness overlap accepted: operation=%s code=%q", plan.Operation, wire.Code(e))
			}
		}
	})
}
