package wire

import (
	"bytes"
	"encoding/base64"
	"regexp"
	"strings"
	"time"

	"github.com/relux-works/swarma-registrar/ccj"
	"github.com/relux-works/waggle/record"
)

const (
	MaxInt        int64 = 9007199254740991
	FrameLimit          = 65536
	LineLimit           = 8192
	ReceiptLimit        = 4096
	HeadLimit           = 32768
	PageLimit           = 45056
	CarrierLimit        = 16384
	ResultLimit         = 60075
	MetadataLimit       = 4096
	ZeroHash            = "0000000000000000000000000000000000000000000000000000000000000000"
)

// Parse bounds containers before allocation, uses the pinned public registrar
// CCJ reader, then enforces WS's stricter exact received/canonical equality.
func Parse(raw []byte, max int) (any, error) { return parse(raw, max, false) }
func parse(raw []byte, max int, result bool) (any, error) {
	if max < 0 || max > FrameLimit || len(raw) > max {
		return nil, Refuse("limit_exceeded")
	}
	if e := containers(raw); e != nil {
		return nil, e
	}
	v, e := ccj.Parse(raw, ccj.RegistrationMalformed)
	if e != nil {
		return nil, Refuse("request_malformed")
	}
	if e = stringBounds(v, "", 0, result); e != nil {
		return nil, e
	}
	b, e := Canonical(v)
	if e != nil || !bytes.Equal(raw, b) {
		return nil, Refuse("request_malformed")
	}
	return v, nil
}
func Canonical(v any) ([]byte, error) {
	b, e := ccj.Marshal(v, ccj.RegistrationMalformed)
	if e != nil {
		return nil, Refuse("request_malformed")
	}
	return b, nil
}

// containers performs only allocation bounds; registrar remains the lexical and
// duplicate-name authority. Nested values count once per enclosing array.
func containers(raw []byte) error {
	type frame struct {
		array, expect bool
		count         int
	}
	stack := make([]frame, 0, 16)
	quoted, escaped := false, false
	for _, c := range raw {
		if quoted {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				quoted = false
			}
			continue
		}
		if c == ' ' || c == '\n' || c == '\r' || c == '\t' {
			continue
		}
		if len(stack) > 0 {
			f := &stack[len(stack)-1]
			if f.array && f.expect && c != ']' {
				f.count++
				f.expect = false
				if f.count > 64 {
					return Refuse("limit_exceeded")
				}
			}
		}
		switch c {
		case '"':
			quoted = true
		case '{', '[':
			if len(stack) == 16 {
				return Refuse("limit_exceeded")
			}
			stack = append(stack, frame{array: c == '[', expect: true})
		case '}', ']':
			if len(stack) == 0 {
				return Refuse("request_malformed")
			}
			stack = stack[:len(stack)-1]
		case ',':
			if len(stack) > 0 {
				stack[len(stack)-1].expect = true
			}
		}
	}
	return nil
}
func stringBounds(v any, field string, depth int, result bool) error {
	switch x := v.(type) {
	case map[string]any:
		for k, v := range x {
			if len(k) > 8192 {
				return Refuse("limit_exceeded")
			}
			if e := stringBounds(v, k, depth+1, result); e != nil {
				return e
			}
		}
	case []any:
		for _, v := range x {
			if e := stringBounds(v, "", depth+1, result); e != nil {
				return e
			}
		}
	case string:
		n := 8192
		switch field {
		case "service", "stream":
			n = 128
		case "record", "receipt", "checkpoint", "registry_proof", "action":
			n = CarrierLimit
		case "result":
			if result && depth == 1 {
				n = ResultLimit
			}
		}
		if len(x) > n {
			return Refuse("limit_exceeded")
		}
		if n != 8192 {
			for _, c := range []byte(x) {
				if c > 127 {
					return Refuse("request_malformed")
				}
			}
		}
	}
	return nil
}
func DecodeBinary(s string, length, max int) ([]byte, error) {
	if max < 0 || max > FrameLimit || len(s) > CarrierLimit {
		return nil, Refuse("limit_exceeded")
	}
	if length >= 0 && len(s) != base64.RawURLEncoding.EncodedLen(length) {
		return nil, Refuse("request_malformed")
	}
	if len(s) > base64.RawURLEncoding.EncodedLen(max) {
		return nil, Refuse("limit_exceeded")
	}
	b, e := record.DecodeBase64(s, length)
	if e != nil {
		return nil, Refuse("request_malformed")
	}
	if len(b) > max {
		return nil, Refuse("limit_exceeded")
	}
	return b, nil
}
func Line(raw []byte) (any, error) {
	if len(raw) > LineLimit {
		return nil, Refuse("limit_exceeded")
	}
	if len(raw) < 2 || raw[len(raw)-1] != '\n' || bytes.Contains(raw[:len(raw)-1], []byte{'\n'}) {
		return nil, Refuse("request_malformed")
	}
	return Parse(raw[:len(raw)-1], LineLimit-1)
}
func Object(v any, fields ...string) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok || len(m) != len(fields) {
		return nil, Refuse("request_malformed")
	}
	for _, k := range fields {
		if _, ok := m[k]; !ok {
			return nil, Refuse("request_malformed")
		}
	}
	return m, nil
}
func String(v any) string                { s, _ := v.(string); return s }
func Integer(v any, min, max int64) bool { n, ok := v.(int64); return ok && n >= min && n <= max }
func One(v any) bool                     { return Integer(v, 1, 1) }

var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var idPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
var namePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

func Hash(v any) bool { s, ok := v.(string); return ok && hashPattern.MatchString(s) }
func Digest(v any) bool {
	s, ok := v.(string)
	return ok && len(s) == 71 && strings.HasPrefix(s, "sha256:") && hashPattern.MatchString(s[7:])
}
func RequestID(v any) bool { s, ok := v.(string); return ok && idPattern.MatchString(s) }
func Name(v any) bool      { s, ok := v.(string); return ok && namePattern.MatchString(s) }
func Opaque(v any) bool    { s, ok := v.(string); return ok && len(s) > 0 && len(s) <= 255 }
func Timestamp(v any) bool {
	s, ok := v.(string)
	if !ok || len(s) != 20 || s < "1970-01-01T00:00:00Z" {
		return false
	}
	t, e := time.Parse("2006-01-02T15:04:05Z", s)
	return e == nil && t.Year() <= 9999 && t.Format("2006-01-02T15:04:05Z") == s
}

// Anchor validates shape only. A zero predecessor still needs external explicit
// genesis authorization; this codec never infers it from an empty store.
func Anchor(v any) bool {
	m, e := Object(v, "seq", "hash")
	if e != nil || !Integer(m["seq"], 0, MaxInt) || !Hash(m["hash"]) {
		return false
	}
	return (m["seq"] == int64(0)) == (m["hash"] == ZeroHash)
}
