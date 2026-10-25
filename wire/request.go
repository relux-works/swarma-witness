package wire

import (
	"encoding/base64"

	"github.com/relux-works/waggle/record"
)

// Request has passed shape/encoding checks, never peer or stream authorization.
type Request struct {
	ID, Method string
	TimeoutMS  int64
	Params     map[string]any
}

func DecodeRequest(raw []byte) (Request, error) {
	v, e := Parse(raw, FrameLimit)
	if e != nil {
		return Request{}, e
	}
	m, e := Object(v, "v", "request_id", "timeout_ms", "method", "params")
	if e != nil || !One(m["v"]) || !RequestID(m["request_id"]) || !Integer(m["timeout_ms"], 1, 5000) {
		return Request{}, Refuse("request_malformed")
	}
	method := String(m["method"])
	var p map[string]any
	switch method {
	case "append":
		p, e = Object(m["params"], "stream", "expected_seq", "expected_hash", "record")
		if e == nil {
			if !Name(p["stream"]) || !Integer(p["expected_seq"], 0, MaxInt) || !Hash(p["expected_hash"]) || (p["expected_seq"] == int64(0)) != (p["expected_hash"] == ZeroHash) {
				e = Refuse("request_malformed")
			} else {
				e = checkLineCarrier(p["record"])
			}
		}
	case "latest":
		p, e = Object(m["params"], "stream", "challenge", "anchor", "control_anchor")
		if e == nil {
			if !Name(p["stream"]) || !Anchor(p["anchor"]) || !Anchor(p["control_anchor"]) {
				e = Refuse("request_malformed")
			} else {
				_, e = DecodeBinary(String(p["challenge"]), 32, 32)
			}
		}
	case "proof_page":
		p, e = Object(m["params"], "stream", "page_hash")
		if e == nil && (!Name(p["stream"]) || !Digest(p["page_hash"])) {
			e = Refuse("request_malformed")
		}
	case "admin":
		p, e = Object(m["params"], "action")
		if e == nil {
			e = checkLineCarrier(p["action"])
		}
	default:
		e = Refuse("request_malformed")
	}
	if e != nil {
		return Request{}, e
	}
	return Request{ID: String(m["request_id"]), Method: method, TimeoutMS: m["timeout_ms"].(int64), Params: p}, nil
}
func checkLineCarrier(v any) error {
	s, ok := v.(string)
	if !ok {
		return Refuse("request_malformed")
	}
	b, e := DecodeBinary(s, -1, LineLimit)
	if e != nil {
		return e
	}
	_, e = Line(b)
	return e
}

// Correlation only trusts an unambiguous canonical bounded envelope and valid ID.
// A return of "" instructs transport not to construct an application response.
func Correlation(raw []byte) string {
	v, e := Parse(raw, FrameLimit)
	if e != nil {
		return ""
	}
	m, ok := v.(map[string]any)
	if !ok || !RequestID(m["request_id"]) {
		return ""
	}
	return String(m["request_id"])
}

type Response struct {
	Result []byte
	Error  *Error
}

func rawLimit(method string) int {
	switch method {
	case "append", "admin":
		return ReceiptLimit
	case "latest":
		return HeadLimit
	case "proof_page":
		return PageLimit
	}
	return 0
}

// CheckResultBounds is shared by encoding and decoding. Counts include all
// actual metadata bytes except the encoded carrier's contents, including quotes.
func CheckResultBounds(method string, raw, encoded, meta, total int) error {
	limit := rawLimit(method)
	if limit == 0 {
		return Refuse("request_malformed")
	}
	if raw < 0 || encoded < 0 || meta < 0 || total < 0 || raw > limit || encoded > ResultLimit || meta > MetadataLimit || total > FrameLimit {
		return Refuse("limit_exceeded")
	}
	return nil
}
func EncodeSuccess(id, method string, raw []byte) ([]byte, error) {
	if !RequestID(id) || len(raw) == 0 {
		return nil, Refuse("request_malformed")
	}
	if e := CheckResultBounds(method, len(raw), base64.RawURLEncoding.EncodedLen(len(raw)), 0, 0); e != nil {
		return nil, e
	}
	s := base64.RawURLEncoding.EncodeToString(raw)
	b, e := Canonical(map[string]any{"v": int64(1), "request_id": id, "result": s})
	if e != nil {
		return nil, e
	}
	if e = CheckResultBounds(method, len(raw), len(s), len(b)-len(s), len(b)); e != nil {
		return nil, e
	}
	return b, nil
}
func EncodeFailure(id, code string) ([]byte, error) {
	r, ok := Retryable(code)
	if !ok || !RequestID(id) {
		return nil, Refuse("request_malformed")
	}
	return Canonical(map[string]any{"v": int64(1), "request_id": id, "error": map[string]any{"code": code, "retryable": r}})
}
func DecodeResponse(raw []byte, id, method string) (Response, error) {
	v, e := parse(raw, FrameLimit, true)
	if e != nil {
		return Response{}, e
	}
	m, ok := v.(map[string]any)
	if !ok || !One(m["v"]) || !RequestID(m["request_id"]) {
		return Response{}, Refuse("request_malformed")
	}
	if !RequestID(id) || String(m["request_id"]) != id {
		return Response{}, Refuse("evidence_invalid")
	}
	if _, ok = m["result"]; ok {
		m, e = Object(v, "v", "request_id", "result")
		if e != nil {
			return Response{}, e
		}
		s, ok := m["result"].(string)
		if !ok || s == "" {
			return Response{}, Refuse("request_malformed")
		}
		limit := rawLimit(method)
		if e = CheckResultBounds(method, 0, len(s), len(raw)-len(s), len(raw)); e != nil {
			return Response{}, e
		}
		if len(s) > base64.RawURLEncoding.EncodedLen(limit) {
			return Response{}, Refuse("limit_exceeded")
		}
		b, e := record.DecodeBase64(s, -1)
		if e != nil {
			return Response{}, Refuse("request_malformed")
		}
		if e = CheckResultBounds(method, len(b), len(s), len(raw)-len(s), len(raw)); e != nil {
			return Response{}, e
		}
		return Response{Result: b}, nil
	}
	m, e = Object(v, "v", "request_id", "error")
	if e != nil {
		return Response{}, e
	}
	errObj, e := Object(m["error"], "code", "retryable")
	if e != nil {
		return Response{}, e
	}
	code := String(errObj["code"])
	r, ok := Retryable(code)
	b, isBool := errObj["retryable"].(bool)
	if !ok || !isBool || r != b {
		return Response{}, Refuse("request_malformed")
	}
	return Response{Error: &Error{Code: code, Retryable: r}}, nil
}
