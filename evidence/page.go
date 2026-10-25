package evidence

import (
	"github.com/relux-works/swarma-witness/records"
	"github.com/relux-works/swarma-witness/wire"
)

// VerifyPage checks exact canonical page/hash and entry framing, not record
// signatures, pairing or membership in a trusted fresh head. Those are separate
// required consumer checks; a cached immutable page alone is not latestness.
func VerifyPage(raw []byte, expected string, b wire.Binding) error {
	if !b.Valid() {
		return wire.Refuse("stream_unavailable")
	}
	v, e := wire.Parse(raw, wire.PageLimit)
	if e != nil {
		return e
	}
	m, e := wire.Object(v, "v", "consumer", "stream", "chain", "anchor_seq", "anchor_hash", "head_seq", "head_hash", "index", "entries")
	if e != nil {
		return e
	}
	if !wire.One(m["v"]) || !wire.Name(m["stream"]) || !wire.Integer(m["anchor_seq"], 0, wire.MaxInt) || !wire.Integer(m["head_seq"], 1, wire.MaxInt) || !wire.Integer(m["index"], 0, 63) || !wire.Hash(m["anchor_hash"]) || !wire.Hash(m["head_hash"]) {
		return wire.Refuse("request_malformed")
	}
	chain := wire.String(m["chain"])
	if chain != "records" && chain != "controls" && chain != "intent" {
		return wire.Refuse("request_malformed")
	}
	entries, ok := m["entries"].([]any)
	if !ok || len(entries) == 0 {
		return wire.Refuse("request_malformed")
	}
	if len(entries) > 2 {
		return wire.Refuse("limit_exceeded")
	}
	if chain == "intent" && (len(entries) != 1 || m["index"] != int64(0) || m["anchor_seq"] != m["head_seq"] || m["anchor_hash"] != m["head_hash"]) {
		return wire.Refuse("evidence_invalid")
	}
	if chain != "intent" && (m["anchor_seq"].(int64) >= m["head_seq"].(int64) || (m["anchor_seq"] == int64(0)) != (m["anchor_hash"] == wire.ZeroHash)) {
		return wire.Refuse("evidence_invalid")
	}
	for _, entry := range entries {
		entry, e := wire.Object(entry, "record", "receipt")
		if e != nil {
			return e
		}
		line, e := wire.DecodeBinary(wire.String(entry["record"]), -1, wire.LineLimit)
		if e != nil {
			return e
		}
		if _, e = wire.Line(line); e != nil {
			return e
		}
		receipt, e := wire.DecodeBinary(wire.String(entry["receipt"]), -1, wire.ReceiptLimit)
		if e != nil {
			return e
		}
		v, e := wire.Parse(receipt, wire.ReceiptLimit)
		if e != nil {
			return e
		}
		env, e := wire.Object(v, "body", "signature")
		if e != nil {
			return e
		}
		if _, ok := env["body"].(map[string]any); !ok {
			return wire.Refuse("request_malformed")
		}
		if _, e = wire.DecodeBinary(wire.String(env["signature"]), 64, 64); e != nil {
			return e
		}
	}
	if !wire.Digest(expected) {
		return wire.Refuse("request_malformed")
	}
	if m["consumer"] != b.Consumer() || m["stream"] != b.Stream() || records.Digest(raw) != expected {
		return wire.Refuse("evidence_invalid")
	}
	return nil
}
