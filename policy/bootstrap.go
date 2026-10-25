package policy

import (
	"bytes"
	"github.com/relux-works/swarma-witness/records"
	"github.com/relux-works/swarma-witness/wire"
)

const ApprovalRole records.Role = "bootstrap-approval"
const EnrollmentRole records.Role = "enrollment-verifier"
const consentDomain = "state-witness-bootstrap-consent/1"
const possessionDomain = "state-witness-principal-possession/1"

// verifyExternal admits only these two separately keyed, fixed profiles. It
// exposes no signer and does not extend the purpose-3 record-signing API.
func verifyExternal(line []byte, k records.Key, domain string, role records.Role) (map[string]any, error) {
	v, e := wire.Line(line)
	if e != nil {
		return nil, e
	}
	env, e := wire.Object(v, "body", "signature")
	if e != nil {
		return nil, e
	}
	body, ok := env["body"].(map[string]any)
	if !ok {
		return nil, wire.Refuse("request_malformed")
	}
	if k.Role != role {
		return nil, wire.Refuse("not_authorized")
	}
	sig, e := wire.DecodeBinary(wire.String(env["signature"]), 64, 64)
	if e != nil {
		return nil, e
	}
	raw, e := wire.Canonical(body)
	if e != nil {
		return nil, e
	}
	if e = records.Verify(k, sig, append([]byte(domain+"\x00"), raw...)); e != nil {
		return nil, e
	}
	if body["key_epoch"] != k.Epoch || body["key_id"] != k.ID {
		return nil, wire.Refuse("evidence_invalid")
	}
	return body, nil
}

type ConsentContext struct {
	Binding                    wire.Binding
	ActionID, DisclosureDigest string
	FirstLine                  []byte
}
type Consent struct {
	ID  string
	raw []byte
}

func (c Consent) Bytes() []byte { return append([]byte(nil), c.raw...) }
func DecodeConsent(line []byte, k records.Key, c ConsentContext) (Consent, error) {
	pub, _, _ := c.Binding.RecordKey()
	if pub != "" && pub == k.Public {
		return Consent{}, wire.Refuse("not_authorized")
	}
	m, e := verifyExternal(line, k, consentDomain, ApprovalRole)
	if e != nil {
		return Consent{}, e
	}
	m, e = wire.Object(m, "v", "type", "consent_id", "service", "stream", "consumer", "identity", "lineage", "binding_hash", "bootstrap_hash", "action_id", "disclosure_hash", "key_epoch", "key_id")
	if e != nil {
		return Consent{}, e
	}
	if !wire.One(m["v"]) || m["type"] != consentDomain || !wire.RequestID(m["consent_id"]) || !wire.RequestID(m["action_id"]) || !wire.Name(m["service"]) || !wire.Name(m["stream"]) || !wire.Digest(m["binding_hash"]) || !wire.Hash(m["bootstrap_hash"]) || !wire.Digest(m["disclosure_hash"]) {
		return Consent{}, wire.Refuse("request_malformed")
	}
	if !c.Binding.Valid() || len(c.FirstLine) == 0 {
		return Consent{}, wire.Refuse("bootstrap_required")
	}
	if _, e = wire.Line(c.FirstLine); e != nil {
		return Consent{}, e
	}
	b, _ := bindingObject(c.Binding)
	for _, key := range []string{"service", "stream", "consumer", "identity", "lineage"} {
		x, _ := wire.Canonical(m[key])
		y, _ := wire.Canonical(b[key])
		if !bytes.Equal(x, y) {
			return Consent{}, wire.Refuse("evidence_invalid")
		}
	}
	if m["action_id"] != c.ActionID || m["binding_hash"] != records.Digest(c.Binding.Bytes()) || m["bootstrap_hash"] != records.Hash(c.FirstLine) || m["disclosure_hash"] != c.DisclosureDigest {
		return Consent{}, wire.Refuse("evidence_invalid")
	}
	return Consent{wire.String(m["consent_id"]), append([]byte(nil), line...)}, nil
}

// GrantSnapshot is historical input to a plan, never a durable grant ledger.
type GrantSnapshot struct {
	ReservedAction string
	FirstLine      []byte
	Consumed       bool
}

func ValidateBootstrap(g GrantSnapshot, action string, line []byte) error {
	if !wire.RequestID(action) || g.ReservedAction == "" || len(g.FirstLine) == 0 {
		return wire.Refuse("bootstrap_required")
	}
	if action != g.ReservedAction || !bytes.Equal(g.FirstLine, line) {
		return wire.Refuse("bootstrap_required")
	}
	return nil // exact retry never allocates or consumes a second grant
}
func ValidateEmptyLatest(bound bool, head int64) error {
	if !bound {
		return wire.Refuse("stream_unavailable")
	}
	if head == 0 {
		return wire.Refuse("stream_empty")
	}
	return nil
}

// DurableTransitions is intentionally unimplemented. S3/S4 must atomically
// retain IDs, original results, reservations, consumption and activation.
type DurableTransitions interface {
	LookupAction(id string) (RetainedAction, error)
	ReserveAction(action []byte) error
	ReserveConsent(action, consent []byte) error
	ConsumeBootstrap(action, line []byte) error
	Activate(plan Plan) error
}
