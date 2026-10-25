package policy

import (
	"bytes"
	"github.com/relux-works/swarma-witness/evidence"
	"github.com/relux-works/swarma-witness/records"
	"github.com/relux-works/swarma-witness/wire"
)

type RetainedAction struct{ Action, Receipt []byte }
type ControlSnapshot struct {
	Seq                       int64
	Hash                      string
	HeadSeq                   int64
	HeadHash                  string
	Pending, UnresolvedIntent bool
	Actions                   map[string]RetainedAction
	CurrentWitness            records.Key
}
type Plan struct {
	Operation string
	Binding   wire.Binding
	Replay    bool
	Receipt   []byte
	Action    []byte
}

// ValidateAdmin returns a pure plan, never activation or a new control receipt.
// Historical exact replay uses trusted retained bytes before current-key CAS.
func ValidateAdmin(s Snapshot, peer Peer, line []byte, admin records.Key, c ControlSnapshot) (Plan, error) {
	if e := s.Authorize(peer, "admin", ""); e != nil {
		return Plan{}, e
	}
	if e := s.Validate(); e != nil {
		return Plan{}, e
	}
	v, e := wire.Line(line)
	if e != nil {
		return Plan{}, e
	}
	env, e := wire.Object(v, "body", "signature")
	if e != nil {
		return Plan{}, e
	}
	body, ok := env["body"].(map[string]any)
	if !ok {
		return Plan{}, wire.Refuse("request_malformed")
	}
	id := wire.String(body["action_id"])
	if old, ok := c.Actions[id]; ok {
		if !bytes.Equal(old.Action, line) {
			return Plan{}, wire.Refuse("position_conflict")
		}
		if len(old.Receipt) == 0 {
			return Plan{}, wire.Refuse("outcome_unknown")
		}
		return Plan{Replay: true, Action: append([]byte(nil), line...), Receipt: append([]byte(nil), old.Receipt...)}, nil
	}
	m, e := evidence.DecodeAction(line, admin)
	if e != nil {
		return Plan{}, e
	}
	if m["service"] != s.Service {
		return Plan{}, wire.Refuse("evidence_invalid")
	}
	if c.Pending || c.UnresolvedIntent {
		return Plan{}, wire.Refuse("outcome_unknown")
	}
	if c.Seq < 0 || c.Seq >= wire.MaxInt {
		return Plan{}, wire.Refuse("sequence_exhausted")
	}
	if !wire.Hash(c.Hash) || (c.Seq == 0) != (c.Hash == wire.ZeroHash) {
		return Plan{}, wire.Refuse("stream_unavailable")
	}
	if m["seq"] != c.Seq+1 || m["prev_hash"] != c.Hash {
		return Plan{}, wire.Refuse("head_conflict")
	}
	op := wire.String(m["operation"])
	plan := Plan{Operation: op, Action: append([]byte(nil), line...)}
	switch op {
	case "provision":
		for _, b := range s.Bindings {
			if b.Stream() == m["stream"] {
				return Plan{}, wire.Refuse("position_conflict")
			}
		}
		raw, _ := wire.Canonical(m["new_binding"])
		b, e := wire.DecodeBinding(raw)
		if e != nil {
			return Plan{}, e
		}
		if b.WriterEpoch() != 1 {
			return Plan{}, wire.Refuse("evidence_invalid")
		}
		// Binding/principal checks are reused for the prospective immutable snapshot.
		next := Snapshot{s.Service, append(append([]wire.Binding(nil), s.Bindings...), b), s.Principals}
		if e = next.Validate(); e != nil {
			return Plan{}, e
		}
		plan.Binding = b
	case "rotate_writer":
		old, e := s.Binding(wire.String(m["stream"]))
		if e != nil {
			return Plan{}, e
		}
		raw, _ := wire.Canonical(m["new_binding"])
		next, e := wire.DecodeBinding(raw)
		if e != nil {
			return Plan{}, e
		}
		if m["expected_binding_hash"] != records.Digest(old.Bytes()) {
			return Plan{}, wire.Refuse("evidence_invalid")
		}
		h := m["expected_head"].(map[string]any)
		if h["seq"] != c.HeadSeq || h["hash"] != c.HeadHash {
			return Plan{}, wire.Refuse("head_conflict")
		}
		if c.HeadSeq == 0 {
			return Plan{}, wire.Refuse("bootstrap_required")
		}
		if e = ValidateRotation(old, next); e != nil {
			return Plan{}, e
		}
		bindings := append([]wire.Binding(nil), s.Bindings...)
		for i, b := range bindings {
			if b.Stream() == old.Stream() {
				bindings[i] = next
			}
		}
		if e = (Snapshot{s.Service, bindings, s.Principals}).Validate(); e != nil {
			return Plan{}, e
		}
		plan.Binding = next
	case "rotate_witness":
		old := c.CurrentWitness
		if e := records.ValidateKey(old); e != nil {
			return Plan{}, wire.Refuse("profile_unavailable")
		}
		if old.Role != records.Witness {
			return Plan{}, wire.Refuse("evidence_invalid")
		}
		if old.Epoch >= wire.MaxInt {
			return Plan{}, wire.Refuse("sequence_exhausted")
		}
		raw, _ := wire.Canonical(map[string]any{"service": s.Service, "key_epoch": old.Epoch, "key_id": old.ID, "public_key": old.Public})
		n := m["new_binding"].(map[string]any)
		if m["expected_binding_hash"] != records.Digest(raw) || n["key_epoch"] != old.Epoch+1 || n["public_key"] == old.Public {
			return Plan{}, wire.Refuse("evidence_invalid")
		}
	}
	if e := validateSigningInventory(s, admin, c, plan, records.Key{}, records.Key{}); e != nil {
		return Plan{}, e
	}
	return plan, nil
}

// validateSigningInventory checks all locally supplied current and prospective
// signing keys. Retained old witness/consumer keys keep their original roles;
// no credential outside the protected inputs is discovered or qualified here.
func validateSigningInventory(s Snapshot, admin records.Key, c ControlSnapshot, plan Plan, approval, enrollment records.Key) error {
	roles := map[string]string{}
	add := func(public, role string) error {
		if public == "" {
			return nil
		}
		if prior, exists := roles[public]; exists && prior != role {
			return wire.Refuse("evidence_invalid")
		}
		roles[public] = role
		return nil
	}
	if e := add(admin.Public, "admin"); e != nil {
		return e
	}
	if e := add(c.CurrentWitness.Public, "witness"); e != nil {
		return e
	}
	if plan.Operation == "rotate_witness" {
		v, e := wire.Line(plan.Action)
		if e != nil {
			return e
		}
		n := v.(map[string]any)["body"].(map[string]any)["new_binding"].(map[string]any)
		if e = add(wire.String(n["public_key"]), "witness"); e != nil {
			return e
		}
	}
	bindings := append([]wire.Binding(nil), s.Bindings...)
	if plan.Binding.Valid() {
		bindings = append(bindings, plan.Binding)
	}
	for _, b := range bindings {
		public, _, _ := b.RecordKey()
		if e := add(public, "record"); e != nil {
			return e
		}
		if b.Consumer() == "owner-registry" {
			m, e := bindingObject(b)
			if e != nil {
				return e
			}
			if e = add(wire.String(m["identity"].(map[string]any)["registry_id"]), "registry-root"); e != nil {
				return e
			}
		}
	}
	for _, key := range []struct{ public, role string }{{approval.Public, "approval"}, {enrollment.Public, "enrollment"}} {
		if e := add(key.public, key.role); e != nil {
			return e
		}
	}
	return nil
}

// ValidateProvisionEvidence checks the exact frozen line and consent against an
// already decoded provision plan. It does not approve disclosure or custody.
func ValidateProvisionEvidence(plan Plan, consent, first []byte, approval records.Key, disclosure string) error {
	if plan.Operation != "provision" || !plan.Binding.Valid() {
		return wire.Refuse("evidence_invalid")
	}
	if len(first) == 0 || len(consent) == 0 {
		return wire.Refuse("bootstrap_required")
	}
	v, e := wire.Line(plan.Action)
	if e != nil {
		return e
	}
	m := v.(map[string]any)["body"].(map[string]any)
	if m["bootstrap_hash"] != records.Hash(first) {
		return wire.Refuse("bootstrap_required")
	}
	pub, _, _ := plan.Binding.RecordKey()
	if pub != "" && pub == approval.Public {
		return wire.Refuse("not_authorized")
	}
	_, e = DecodeConsent(consent, approval, ConsentContext{plan.Binding, wire.String(m["action_id"]), disclosure, first})
	return e
}

// AdministrativeEvidence contains retained public bytes and independently
// supplied live-channel expectations, never an approval boolean/caller URL.
type AdministrativeEvidence struct {
	Consent, FirstLine   []byte
	DisclosureDigest     string
	Approval, Enrollment records.Key
	Packet               []byte
	Objects              map[string][]byte
	Old, New             PossessionContext
}

// PrepareAdmin composes pure validation stages before returning an evidence-
// checked plan. It still cannot cross the G07/G10 or S3/S4 activation gates.
func PrepareAdmin(s Snapshot, peer Peer, line []byte, admin records.Key, c ControlSnapshot, p AdministrativeEvidence) (Plan, error) {
	plan, e := ValidateAdmin(s, peer, line, admin, c)
	if e != nil {
		return Plan{}, e
	}
	if plan.Replay {
		return plan, nil
	}
	if e := validateSigningInventory(s, admin, c, plan, p.Approval, p.Enrollment); e != nil {
		return Plan{}, e
	}

	switch plan.Operation {
	case "provision":
		if p.Approval.Public == "" {
			return Plan{}, wire.Refuse("profile_unavailable")
		}
		if p.Approval.Public == admin.Public {
			return Plan{}, wire.Refuse("not_authorized")
		}
		e = ValidateProvisionEvidence(plan, p.Consent, p.FirstLine, p.Approval, p.DisclosureDigest)
	case "rotate_writer":
		if p.Enrollment.Public == "" {
			return Plan{}, wire.Refuse("profile_unavailable")
		}
		if p.Enrollment.Public == admin.Public {
			return Plan{}, wire.Refuse("not_authorized")
		}
		if p.Old.ActionHash != records.Hash(line) || p.Old.Service != s.Service || p.Old.Stream != plan.Binding.Stream() {
			return Plan{}, wire.Refuse("evidence_invalid")
		}
		old, err := s.Binding(plan.Binding.Stream())
		if err != nil {
			return Plan{}, err
		}
		if p.Old.PrincipalID != old.WriterID() || p.New.PrincipalID != plan.Binding.WriterID() {
			return Plan{}, wire.Refuse("evidence_invalid")
		}
		for _, pair := range []struct {
			b       wire.Binding
			context PossessionContext
		}{{old, p.Old}, {plan.Binding, p.New}} {
			m, _ := bindingObject(pair.b)
			found := false
			for _, pin := range m["transport_pins"].([]any) {
				if pin == pair.context.Pin {
					found = true
				}
			}
			if !found {
				return Plan{}, wire.Refuse("evidence_invalid")
			}
		}
		e = ValidateRotationEvidence(p.Packet, p.Objects, p.Enrollment, p.Old, p.New)
	}
	if e != nil {
		return Plan{}, e
	}
	return plan, nil
}
