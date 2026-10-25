package evidence

import (
	"github.com/relux-works/swarma-witness/records"
	"github.com/relux-works/swarma-witness/wire"
)

// DecodeAction checks signatures and closed operation-specific schema only;
// admin role authorization, consent, history, CAS and replay handling are S2+.
func DecodeAction(line []byte, k records.Key) (map[string]any, error) {
	if _, e := wire.Line(line); e != nil {
		return nil, e
	}
	m, e := records.VerifyEnvelope(line[:len(line)-1], wire.LineLimit-1, records.AdminDomain, k)
	if e != nil {
		return nil, e
	}
	m, e = wire.Object(m, "v", "service", "seq", "prev_hash", "action_id", "operation", "stream", "expected_binding_hash", "new_binding", "expected_head", "bootstrap_hash", "key_epoch", "key_id")
	if e != nil {
		return nil, e
	}
	if !wire.One(m["v"]) || !wire.Name(m["service"]) || !wire.Integer(m["seq"], 1, wire.MaxInt) || !wire.Hash(m["prev_hash"]) || !wire.RequestID(m["action_id"]) || !wire.Integer(m["key_epoch"], 1, wire.MaxInt) || !wire.Digest(m["key_id"]) {
		return nil, wire.Refuse("request_malformed")
	}
	if m["key_epoch"] != k.Epoch || m["key_id"] != k.ID {
		return nil, wire.Refuse("evidence_invalid")
	}
	switch m["operation"] {
	case "provision", "rotate_writer":
		if !wire.Name(m["stream"]) || !wire.Anchor(m["expected_head"]) {
			return nil, wire.Refuse("request_malformed")
		}
		raw, e := wire.Canonical(m["new_binding"])
		if e != nil {
			return nil, e
		}
		b, e := wire.DecodeBinding(raw)
		if e != nil {
			return nil, e
		}
		if b.Service() != m["service"] || b.Stream() != m["stream"] {
			return nil, wire.Refuse("evidence_invalid")
		}
		a := m["expected_head"].(map[string]any)
		if m["operation"] == "provision" {
			if m["expected_binding_hash"] != nil || !wire.Hash(m["bootstrap_hash"]) || a["seq"] != int64(0) {
				return nil, wire.Refuse("request_malformed")
			}
		} else if !wire.Digest(m["expected_binding_hash"]) || m["bootstrap_hash"] != nil {
			return nil, wire.Refuse("request_malformed")
		}
	case "rotate_witness":
		if m["stream"] != nil || m["expected_head"] != nil || m["bootstrap_hash"] != nil || !wire.Digest(m["expected_binding_hash"]) {
			return nil, wire.Refuse("request_malformed")
		}
		n, e := wire.Object(m["new_binding"], "service", "key_epoch", "key_id", "public_key", "proof")
		if e != nil || !wire.Name(n["service"]) || !wire.Integer(n["key_epoch"], 1, wire.MaxInt) || !wire.Digest(n["key_id"]) {
			return nil, wire.Refuse("request_malformed")
		}
		if n["service"] != m["service"] {
			return nil, wire.Refuse("evidence_invalid")
		}
		newKey := records.Key{Public: wire.String(n["public_key"]), ID: wire.String(n["key_id"]), Epoch: n["key_epoch"].(int64), Role: records.Transition}
		if e = records.ValidateKey(newKey); e != nil {
			return nil, e
		}
		sig, e := wire.DecodeBinary(wire.String(n["proof"]), 64, 64)
		if e != nil {
			return nil, e
		}
		body := map[string]any{}
		for key, value := range n {
			if key != "proof" {
				body[key] = value
			}
		}
		pre, e := records.Preimage(body, records.TransitionDomain)
		if e != nil {
			return nil, e
		}
		if e = records.Verify(newKey, sig, pre); e != nil {
			return nil, e
		}
	default:
		return nil, wire.Refuse("request_malformed")
	}
	return m, nil
}
func controlBody(line []byte, admin, witness records.Key) (map[string]any, error) {
	a, e := DecodeAction(line, admin)
	if e != nil {
		return nil, e
	}
	return map[string]any{"v": int64(1), "service": a["service"], "seq": a["seq"], "control_hash": records.Hash(line), "action_id": a["action_id"], "operation": a["operation"], "stream": a["stream"], "witness": map[string]any{"service": a["service"], "key_epoch": witness.Epoch, "key_id": witness.ID}}, nil
}
func NewControlReceipt(line []byte, admin, witness records.Key, sign records.Signer) ([]byte, error) {
	body, e := controlBody(line, admin, witness)
	if e != nil {
		return nil, e
	}
	return records.SignEnvelope(body, wire.ReceiptLimit, records.ControlAck, witness, sign)
}
func VerifyControlReceipt(raw, line []byte, admin, witness records.Key) error {
	body, e := records.VerifyEnvelope(raw, wire.ReceiptLimit, records.ControlAck, witness)
	if e != nil {
		return e
	}
	if _, e = wire.Object(body, "v", "service", "seq", "control_hash", "action_id", "operation", "stream", "witness"); e != nil {
		return e
	}
	expected, e := controlBody(line, admin, witness)
	if e != nil {
		return e
	}
	return equal(body, expected)
}
