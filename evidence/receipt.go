// Package evidence constructs and checks bounded signed artifacts. Signature
// validity does not establish append, latestness, durability or authorization.
package evidence

import (
	"bytes"

	"github.com/relux-works/swarma-witness/records"
	"github.com/relux-works/swarma-witness/wire"
)

func witness(b wire.Binding, k records.Key) map[string]any {
	return map[string]any{"service": b.Service(), "key_epoch": k.Epoch, "key_id": k.ID}
}
func ackDomain(b wire.Binding) records.Domain {
	if b.Consumer() == "keymaker" {
		return records.KeymakerAck
	}
	return records.NeutralAck
}
func headDomain(b wire.Binding) records.Domain {
	if b.Consumer() == "keymaker" {
		return records.KeymakerHead
	}
	return records.NeutralHead
}
func receiptBody(r records.Record, b wire.Binding, k records.Key, control string) (map[string]any, error) {
	if !r.Valid() || !b.Valid() {
		return nil, wire.Refuse("stream_unavailable")
	}

	if !r.Binding().SameScope(b) {
		return nil, wire.Refuse("evidence_invalid")
	}
	if b.Consumer() == "registrar" {
		body := r.Body()
		if e := records.CheckRegistrarRevision(b.Profile(), wire.String(body["revision"])); e != nil {
			return nil, e
		}
		return map[string]any{"v": int64(1), "consumer": b.Consumer(), "stream": b.Stream(), "seq": body["seq"], "record_hash": r.Hash(), "writer": map[string]any{"epoch": r.Binding().WriterEpoch(), "id": r.Binding().WriterID()}, "projection": map[string]any{"kind": body["kind"], "revision": body["revision"], "digest": body["digest"]}, "witness": witness(b, k), "control_hash": control}, nil
	}
	if b.Consumer() != "keymaker" {
		return nil, wire.Refuse("profile_unavailable")
	}

	if !wire.Hash(control) {
		return nil, wire.Refuse("request_malformed")
	}
	_, id, epoch := b.RecordKey()
	body := r.Body()
	station, _ := wire.Canonical(body["station"])
	identity, _ := wire.Canonical(b.Identity())
	if body["stream"] != b.Stream() || body["key_id"] != id || body["key_epoch"] != epoch || !bytes.Equal(station, identity) {
		return nil, wire.Refuse("evidence_invalid")
	}
	out := map[string]any{}
	for _, field := range []string{"v", "consumer", "stream", "station", "seq", "state_epoch", "kind", "base_state_digest", "state_digest", "key_epoch", "key_id"} {
		out[field] = body[field]
	}
	out["record_hash"] = r.Hash()
	out["witness"] = witness(b, k)
	out["control_hash"] = control
	return out, nil
}
func NewReceipt(r records.Record, b wire.Binding, k records.Key, control string, sign records.Signer) ([]byte, error) {
	body, e := receiptBody(r, b, k, control)
	if e != nil {
		return nil, e
	}
	if e = CheckReceiptBody(body, b); e != nil {
		return nil, e
	}
	return records.SignEnvelope(body, wire.ReceiptLimit, ackDomain(b), k, sign)
}
func VerifyReceipt(raw []byte, r records.Record, b wire.Binding, k records.Key, control string) error {
	body, e := records.VerifyEnvelope(raw, wire.ReceiptLimit, ackDomain(b), k)
	if e != nil {
		return e
	}
	if e = CheckReceiptBody(body, b); e != nil {
		return e
	}
	expected, e := receiptBody(r, b, k, control)
	if e != nil {
		return e
	}
	return equal(body, expected)
}
func equal(a, b any) error {
	x, e := wire.Canonical(a)
	if e != nil {
		return e
	}
	y, e := wire.Canonical(b)
	if e != nil {
		return e
	}
	if !bytes.Equal(x, y) {
		return wire.Refuse("evidence_invalid")
	}
	return nil
}
func checkWitness(v any, b wire.Binding) error {
	w, e := wire.Object(v, "service", "key_epoch", "key_id")
	if e != nil {
		return e
	}
	if !wire.Name(w["service"]) || !wire.Integer(w["key_epoch"], 1, wire.MaxInt) || !wire.Digest(w["key_id"]) {
		return wire.Refuse("request_malformed")
	}
	if w["service"] != b.Service() {
		return wire.Refuse("evidence_invalid")
	}
	return nil
}

// CheckReceiptBody closes both neutral and Keymaker projections. Neutral
// schema decoding grants no registrar/checkpoint verification capability.
func CheckReceiptBody(body map[string]any, b wire.Binding) error {
	if !b.Valid() {
		return wire.Refuse("stream_unavailable")
	}
	var m map[string]any
	var e error
	if b.Consumer() == "keymaker" {
		m, e = wire.Object(body, "v", "consumer", "stream", "station", "seq", "state_epoch", "kind", "base_state_digest", "state_digest", "record_hash", "key_epoch", "key_id", "witness", "control_hash")
		if e != nil {
			return e
		}
		if e = wire.Station(m["station"]); e != nil {
			return e
		}
		if !wire.Integer(m["state_epoch"], 1, wire.MaxInt) || !wire.Integer(m["key_epoch"], 1, wire.MaxInt) || !wire.Digest(m["key_id"]) || !wire.Digest(m["state_digest"]) || m["base_state_digest"] != nil && !wire.Digest(m["base_state_digest"]) {
			return wire.Refuse("request_malformed")
		}
	} else {
		m, e = wire.Object(body, "v", "consumer", "stream", "seq", "record_hash", "writer", "projection", "witness", "control_hash")
		if e != nil {
			return e
		}
		w, e := wire.Object(m["writer"], "epoch", "id")
		if e != nil || !wire.Integer(w["epoch"], 1, wire.MaxInt) || !wire.Opaque(w["id"]) {
			return wire.Refuse("request_malformed")
		}
		if b.Consumer() == "registrar" {
			p, e := wire.Object(m["projection"], "kind", "revision", "digest")
			if e != nil || !wire.Opaque(p["revision"]) || !wire.Digest(p["digest"]) {
				return wire.Refuse("request_malformed")
			}
			if e = records.CheckRegistrarRevision(b.Profile(), wire.String(p["revision"])); e != nil {
				return e
			}
			if p["kind"] != "intent" && p["kind"] != "committed" {
				return wire.Refuse("request_malformed")
			}
		} else if b.Consumer() == "owner-registry" {
			if e = records.CheckpointProjection(m["projection"], true); e != nil {
				return e
			}
		} else {
			return wire.Refuse("profile_unavailable")
		}
	}
	if !wire.One(m["v"]) || !wire.Name(m["stream"]) || !wire.Integer(m["seq"], 1, wire.MaxInt) || !wire.Hash(m["record_hash"]) || !wire.Hash(m["control_hash"]) {
		return wire.Refuse("request_malformed")
	}
	if b.Consumer() == "keymaker" && m["kind"] != "intent" && m["kind"] != "committed" {
		return wire.Refuse("request_malformed")
	}
	if m["consumer"] != b.Consumer() || m["stream"] != b.Stream() {
		return wire.Refuse("evidence_invalid")
	}
	return checkWitness(m["witness"], b)
}
