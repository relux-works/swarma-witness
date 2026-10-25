// Package audit owns the single service-wide audit chain. It never calls a
// witness append API or an external logger; transaction owners serialize its tail.
package audit

import (
	"encoding/base64"
	"unicode"

	"github.com/relux-works/swarma-witness/records"
	"github.com/relux-works/swarma-witness/wire"
)

type Tail struct {
	Seq  int64
	Hash string
}
type Fields struct{ At, Instance, Principal, Stream, Operation, RequestID, RecordHash, ControlHash, Result, Code string }

func optional(s string) any {
	if s == "" {
		return nil
	}
	return s
}
func New(t Tail, f Fields) ([]byte, Tail, error) {
	if t.Seq >= wire.MaxInt {
		return nil, t, wire.Refuse("sequence_exhausted")
	}
	if t.Seq < 0 || !wire.Hash(t.Hash) || (t.Seq == 0) != (t.Hash == wire.ZeroHash) {
		return nil, t, wire.Refuse("storage_unavailable")
	}
	m := map[string]any{"v": int64(1), "seq": t.Seq + 1, "at": optional(f.At), "instance": f.Instance, "principal": optional(f.Principal), "stream": optional(f.Stream), "operation": optional(f.Operation), "request_id": optional(f.RequestID), "record_hash": optional(f.RecordHash), "control_hash": optional(f.ControlHash), "result": f.Result, "code": optional(f.Code), "prev_hash": t.Hash}
	b, e := wire.Canonical(m)
	if e != nil {
		return nil, t, e
	}
	b = append(b, '\n')
	if e = Validate(b, t); e != nil {
		return nil, t, e
	}
	return b, Tail{t.Seq + 1, records.Hash(b)}, nil
}
func Validate(line []byte, prior Tail) error {
	if len(line) > 4096 {
		return wire.Refuse("limit_exceeded")
	}
	v, e := wire.Line(line)
	if e != nil {
		return e
	}
	m, e := wire.Object(v, "v", "seq", "at", "instance", "principal", "stream", "operation", "request_id", "record_hash", "control_hash", "result", "code", "prev_hash")
	if e != nil {
		return e
	}
	if prior.Seq < 0 || !wire.Hash(prior.Hash) || (prior.Seq == 0) != (prior.Hash == wire.ZeroHash) || !wire.One(m["v"]) || !wire.Integer(m["seq"], 1, wire.MaxInt) || prior.Seq >= wire.MaxInt || m["seq"] != prior.Seq+1 || m["prev_hash"] != prior.Hash {
		return wire.Refuse("evidence_invalid")
	}
	id, ok := m["instance"].(string)
	if !ok {
		return wire.Refuse("request_malformed")
	}
	instance, e := base64.RawURLEncoding.Strict().DecodeString(id)
	if e != nil || len(instance) != 16 || base64.RawURLEncoding.EncodeToString(instance) != id {
		return wire.Refuse("request_malformed")
	}
	for _, k := range []string{"principal"} {
		if m[k] != nil && !validPrincipal(m[k]) {
			return wire.Refuse("request_malformed")
		}
	}
	if m["stream"] != nil && !wire.Name(m["stream"]) || m["request_id"] != nil && !wire.RequestID(m["request_id"]) {
		return wire.Refuse("request_malformed")
	}
	for _, k := range []string{"record_hash", "control_hash"} {
		if m[k] != nil && !wire.Hash(m[k]) {
			return wire.Refuse("request_malformed")
		}
	}
	if m["operation"] != nil {
		switch m["operation"] {
		case "append", "admin", "latest", "proof_page", "retry":
		default:
			return wire.Refuse("request_malformed")
		}
	}
	result := m["result"]
	if result != "success" && result != "refused" && result != "unknown" {
		return wire.Refuse("request_malformed")
	}
	if m["at"] == nil {
		if result != "unknown" {
			return wire.Refuse("profile_unavailable")
		}
	} else if !wire.Timestamp(m["at"]) {
		return wire.Refuse("request_malformed")
	}
	if result == "success" {
		if m["code"] != nil {
			return wire.Refuse("request_malformed")
		}
	} else if m["code"] != nil {
		if _, ok := wire.Retryable(wire.String(m["code"])); !ok {
			return wire.Refuse("request_malformed")
		}
	}
	return nil
}

// Audit identities are protected identifiers, never free text, URLs or paths.
// The local audit profile refuses separators, scheme delimiters and controls.
func validPrincipal(v any) bool {
	if !wire.Opaque(v) {
		return false
	}
	for _, r := range v.(string) {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r == ':' || r == '/' || r == '\\' {
			return false
		}
	}
	return true
}
