package records

import (
	"bytes"

	"github.com/relux-works/swarma-witness/wire"
)

// Record holds schema-validated original bytes and their protected context. Methods return copies;
// the zero value is invalid. It does not prove local state or semantic pairing.
type Record struct {
	line    []byte
	binding wire.Binding
}

func (r Record) Valid() bool  { return len(r.line) > 0 }
func (r Record) Line() []byte { return append([]byte(nil), r.line...) }
func (r Record) Hash() string { return Hash(r.line) }

// Binding returns the immutable original decoding context, including writer
// policy epoch/principal. A later receipt must not replace that projection.
func (r Record) Binding() wire.Binding { return r.binding }
func (r Record) Body() map[string]any {
	if !r.Valid() {
		return nil
	}
	v, _ := wire.Line(r.line)
	m := v.(map[string]any)
	if r.binding.Consumer() == "keymaker" {
		return m["body"].(map[string]any)
	}
	return m
}
func DecodeKeymaker(line []byte, b wire.Binding, bootstrapPair bool) (Record, error) {
	if !b.Valid() {
		return Record{}, wire.Refuse("stream_unavailable")
	}
	if b.Consumer() != "keymaker" || b.Profile() != "keymaker-state-witness/1" {
		return Record{}, wire.Refuse("profile_unavailable")
	}
	if _, e := wire.Line(line); e != nil {
		return Record{}, e
	}
	public, id, epoch := b.RecordKey()
	m, e := VerifyEnvelope(line[:len(line)-1], wire.LineLimit-1, RecordDomain, Key{Public: public, ID: id, Epoch: epoch, Role: Writer})
	if e != nil {
		return Record{}, e
	}
	m, e = wire.Object(m, "v", "type", "consumer", "stream", "station", "seq", "state_epoch", "kind", "commit_class", "base_state_digest", "state_digest", "prev_hash", "intent_hash", "key_epoch", "key_id")
	if e != nil {
		return Record{}, e
	}
	if !wire.One(m["v"]) || m["type"] != "keymaker-state-witness/1" || m["consumer"] != "keymaker" || !wire.Name(m["stream"]) || !wire.Integer(m["seq"], 1, wire.MaxInt) || !wire.Integer(m["state_epoch"], 1, wire.MaxInt) || !wire.Integer(m["key_epoch"], 1, wire.MaxInt) || !wire.Digest(m["key_id"]) || !wire.Digest(m["state_digest"]) || !wire.Hash(m["prev_hash"]) {
		return Record{}, wire.Refuse("request_malformed")
	}
	if e = wire.Station(m["station"]); e != nil {
		return Record{}, e
	}
	switch m["commit_class"] {
	case "binding-result", "enrollment", "reconciliation", "audit", "retention", "policy-custody":
	default:
		return Record{}, wire.Refuse("request_malformed")
	}
	if e = kind(m); e != nil {
		return Record{}, e
	}
	if m["base_state_digest"] != nil && !wire.Digest(m["base_state_digest"]) {
		return Record{}, wire.Refuse("request_malformed")
	}

	if m["prev_hash"] == wire.ZeroHash && !(bootstrapPair && m["seq"] == int64(1) && m["kind"] == "intent") {
		return Record{}, wire.Refuse("evidence_invalid")
	}
	if m["kind"] == "committed" && m["intent_hash"] == wire.ZeroHash {
		return Record{}, wire.Refuse("evidence_invalid")
	}
	if m["base_state_digest"] == nil && !(bootstrapPair && (m["seq"] == int64(1) && m["kind"] == "intent" || m["seq"] == int64(2) && m["kind"] == "committed")) {
		return Record{}, wire.Refuse("evidence_invalid")
	}
	station, _ := wire.Canonical(m["station"])
	identity, _ := wire.Canonical(b.Identity())
	if m["stream"] != b.Stream() || !bytes.Equal(station, identity) || m["key_epoch"] != epoch || m["key_id"] != id || m["base_state_digest"] == nil && !bootstrapPair {
		return Record{}, wire.Refuse("evidence_invalid")
	}
	return Record{line: append([]byte(nil), line...), binding: b}, nil
}
func kind(m map[string]any) error {
	switch m["kind"] {
	case "intent":
		if m["intent_hash"] != nil {
			return wire.Refuse("request_malformed")
		}
		if m["seq"] == wire.MaxInt {
			return wire.Refuse("sequence_exhausted")
		}
	case "committed":
		if !wire.Hash(m["intent_hash"]) {
			return wire.Refuse("request_malformed")
		}
	default:
		return wire.Refuse("request_malformed")
	}
	return nil
}
