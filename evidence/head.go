package evidence

import (
	"encoding/base64"

	"github.com/relux-works/swarma-witness/records"
	"github.com/relux-works/swarma-witness/wire"
)

// NewHead preserves a separately verified historical receipt. Current witness
// rotation affects only the new head envelope. Anchors come from caller-held
// trusted evidence; this constructor does not decide their authorization.
func NewHead(r records.Record, b wire.Binding, current records.Key, control string, receipt []byte, historical records.Key, historicalControl, challenge string, proof map[string]any, sign records.Signer) ([]byte, error) {
	if e := VerifyReceipt(receipt, r, b, historical, historicalControl); e != nil {
		return nil, e
	}
	body, e := receiptBody(r, b, current, control)
	if e != nil {
		return nil, e
	}
	body["record"] = base64.RawURLEncoding.EncodeToString(r.Line())
	body["receipt"] = base64.RawURLEncoding.EncodeToString(receipt)
	body["challenge"] = challenge
	body["proof"] = proof
	if e = checkHeadBody(body, r, b); e != nil {
		return nil, e
	}
	return records.SignEnvelope(body, wire.HeadLimit, headDomain(b), current, sign)
}

// VerifyHead checks signature, original record/receipt, challenge and structural
// continuity. The caller must also compare manifests with its requested trusted
// anchors and fetch/verify every referenced page before claiming latestness.
func VerifyHead(raw []byte, r records.Record, b wire.Binding, current records.Key, control string, receipt []byte, historical records.Key, historicalControl, challenge string) error {
	body, e := records.VerifyEnvelope(raw, wire.HeadLimit, headDomain(b), current)
	if e != nil {
		return e
	}
	if e = checkHeadBody(body, r, b); e != nil {
		return e
	}
	if e = VerifyReceipt(receipt, r, b, historical, historicalControl); e != nil {
		return e
	}
	if body["record"] != base64.RawURLEncoding.EncodeToString(r.Line()) || body["receipt"] != base64.RawURLEncoding.EncodeToString(receipt) || body["challenge"] != challenge {
		return wire.Refuse("evidence_invalid")
	}
	expected, e := receiptBody(r, b, current, control)
	if e != nil {
		return e
	}
	for _, field := range []string{"record", "receipt", "challenge", "proof"} {
		delete(body, field)
	}
	return equal(body, expected)
}
func checkHeadBody(body map[string]any, r records.Record, b wire.Binding) error {
	base := map[string]any{}
	for k, v := range body {
		switch k {
		case "record", "receipt", "challenge", "proof":
		default:
			base[k] = v
		}
	}
	if len(body) != len(base)+4 {
		return wire.Refuse("request_malformed")
	}
	if e := CheckReceiptBody(base, b); e != nil {
		return e
	}
	for field, max := range map[string]int{"record": wire.LineLimit, "receipt": wire.ReceiptLimit, "challenge": 32} {
		n := -1
		if field == "challenge" {
			n = 32
		}
		s, ok := body[field].(string)
		if !ok {
			return wire.Refuse("request_malformed")
		}
		if _, e := wire.DecodeBinary(s, n, max); e != nil {
			return e
		}
	}
	return CheckProof(body["proof"], r, wire.String(body["control_hash"]))
}

// CheckProof bounds complete manifest descriptors; it does not replace page
// hash, historical signature, anchor authority or application pairing checks.
func CheckProof(v any, r records.Record, control string) error {
	if !r.Valid() {
		return wire.Refuse("stream_unavailable")
	}
	p, e := wire.Object(v, "records", "controls", "intent")
	if e != nil {
		return e
	}
	raw, e := wire.Canonical(v)
	if e != nil {
		return e
	}
	if len(raw) > 16384 {
		return wire.Refuse("proof_limit")
	}
	pages, entries := int64(0), int64(0)
	for _, chain := range []string{"records", "controls"} {
		m, e := wire.Object(p[chain], "anchor_seq", "anchor_hash", "head_seq", "head_hash", "count", "pages")
		if e != nil {
			return e
		}
		if !wire.Integer(m["anchor_seq"], 0, wire.MaxInt) || !wire.Integer(m["head_seq"], 1, wire.MaxInt) || !wire.Integer(m["count"], 0, 128) || !wire.Hash(m["anchor_hash"]) || !wire.Hash(m["head_hash"]) {
			return wire.Refuse("request_malformed")
		}
		a, h, c := m["anchor_seq"].(int64), m["head_seq"].(int64), m["count"].(int64)
		if a > h || h-a != c || (a == 0) != (m["anchor_hash"] == wire.ZeroHash) {
			return wire.Refuse("evidence_invalid")
		}
		if chain == "records" && (h != r.Body()["seq"] || m["head_hash"] != r.Hash()) || chain == "controls" && m["head_hash"] != control {
			return wire.Refuse("evidence_invalid")
		}
		ds, ok := m["pages"].([]any)
		if !ok {
			return wire.Refuse("request_malformed")
		}
		if c == 0 && (len(ds) != 0 || m["anchor_hash"] != m["head_hash"]) {
			return wire.Refuse("evidence_invalid")
		}
		next := a
		for index, d := range ds {
			d, e := wire.Object(d, "index", "first_seq", "last_seq", "page_hash")
			if e != nil {
				return e
			}
			if !wire.Integer(d["index"], 0, 63) || !wire.Integer(d["first_seq"], 1, wire.MaxInt) || !wire.Integer(d["last_seq"], 1, wire.MaxInt) || !wire.Digest(d["page_hash"]) {
				return wire.Refuse("request_malformed")
			}
			first, last := d["first_seq"].(int64), d["last_seq"].(int64)
			if d["index"] != int64(index) || next == wire.MaxInt || first != next+1 || last < first || last-first > 1 || last > h {
				return wire.Refuse("evidence_invalid")
			}
			next = last
		}
		if next != h {
			return wire.Refuse("evidence_invalid")
		}
		pages += int64(len(ds))
		entries += c
	}
	body := r.Body()
	if body["kind"] == "committed" {
		i, e := wire.Object(p["intent"], "seq", "record_hash", "page_hash")
		if e != nil {
			return e
		}
		if !wire.Integer(i["seq"], 1, wire.MaxInt) || !wire.Hash(i["record_hash"]) || !wire.Digest(i["page_hash"]) {
			return wire.Refuse("request_malformed")
		}
		if i["seq"] != body["seq"].(int64)-1 || i["record_hash"] != body["prev_hash"] || i["record_hash"] != body["intent_hash"] {
			return wire.Refuse("evidence_invalid")
		}
		pages++
		entries++
	} else if p["intent"] != nil {
		return wire.Refuse("request_malformed")
	}
	if pages > 64 || entries > 128 {
		return wire.Refuse("proof_limit")
	}
	return nil
}
