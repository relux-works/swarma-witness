package wire_test

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/relux-works/swarma-witness/wire"
)

func expect(t *testing.T, err error, code string) {
	t.Helper()
	if wire.Code(err) != code {
		t.Fatalf("want %s, got %v", code, err)
	}
}
func canon(t *testing.T, v any) []byte {
	t.Helper()
	b, e := wire.Canonical(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func request() map[string]any {
	return map[string]any{"v": int64(1), "request_id": strings.Repeat("a", 32), "timeout_ms": int64(5000), "method": "latest", "params": map[string]any{"stream": "station", "challenge": base64.RawURLEncoding.EncodeToString(make([]byte, 32)), "anchor": map[string]any{"seq": int64(0), "hash": strings.Repeat("0", 64)}, "control_anchor": map[string]any{"seq": int64(0), "hash": strings.Repeat("0", 64)}}}
}

// Exact CCJ bytes survive round-trip; duplicate aliases, lexical repairs and
// schema drift refuse. Unicode scalar order is independent of UTF-16 order.
func TestWireRejectsNoncanonical(t *testing.T) {
	good := canon(t, request())
	if _, e := wire.DecodeRequest(good); e != nil {
		t.Fatal(e)
	}
	for _, bad := range [][]byte{
		append([]byte(" "), good...), append(append([]byte{}, good...), '\n'),
		[]byte(`{"a":1,"\u0061":2}`), []byte(`{"a":1,"a":2}`),
		[]byte(`{"x":1.0}`), []byte(`{"x":1e0}`), []byte(`{"x":-0}`), []byte(`{"x":9007199254740992}`),
		[]byte(`{"x":"\ud800"}`), []byte("{\"x\":\"\xff\"}"), append([]byte{239, 187, 191}, good...),
		[]byte(`{"z":1,"a":2}`), []byte(`{"a":"\u0061"}`), []byte(`{"a":"\/"}`), append(good, byte('x')),
	} {
		_, e := wire.Parse(bad, wire.FrameLimit)
		expect(t, e, "request_malformed")
	}
	for _, change := range []func(map[string]any){func(m map[string]any) { m["extra"] = nil }, func(m map[string]any) { delete(m, "v") }, func(m map[string]any) { m["V"] = m["v"]; delete(m, "v") }, func(m map[string]any) { m["params"].(map[string]any)["challenge"] = strings.Repeat("A", 42) + "B" }, func(m map[string]any) { m["params"].(map[string]any)["challenge"] = strings.Repeat("A", 43) + "=" }} {
		m := request()
		change(m)
		_, e := wire.DecodeRequest(canon(t, m))
		expect(t, e, "request_malformed")
	}
	scalar := []byte("{\"\ue000\":1,\"\U00010000\":2}")
	v, e := wire.Parse(scalar, 100)
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(canon(t, v), scalar) {
		t.Fatal("scalar order")
	}
}

// Raw and encoded caps are charged independently before base64 decoding;
// named carriers do not extend ordinary strings, depth, array or frame caps.
func TestWireChargesDecodedAndEncodedBounds(t *testing.T) {
	for _, n := range []int{8192, 8193} {
		s := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{'x'}, n))
		_, e := wire.DecodeBinary(s, -1, 8192)
		if n == 8192 {
			if e != nil {
				t.Fatal(e)
			}
		} else {
			expect(t, e, "limit_exceeded")
		}
	}
	_, e := wire.Parse(bytes.Repeat([]byte{'x'}, 65537), 65536)
	expect(t, e, "limit_exceeded")
	for _, n := range []int{8192, 8193} {
		raw := canon(t, map[string]any{"x": strings.Repeat("x", n)})
		_, e := wire.Parse(raw, 65536)
		if n == 8192 {
			if e != nil {
				t.Fatal(e)
			}
		} else {
			expect(t, e, "limit_exceeded")
		}
	}
	for _, n := range []int{16, 17} {
		raw := []byte(strings.Repeat("[", n) + "0" + strings.Repeat("]", n))
		_, e := wire.Parse(raw, 65536)
		if n == 16 {
			if e != nil {
				t.Fatal(e)
			}
		} else {
			expect(t, e, "limit_exceeded")
		}
	}
	for _, n := range []int{64, 65} {
		a := make([]any, n)
		_, e := wire.Parse(canon(t, a), 65536)
		if n == 64 {
			if e != nil {
				t.Fatal(e)
			}
		} else {
			expect(t, e, "limit_exceeded")
		}
	}
	_, e = wire.Parse(canon(t, map[string]any{"record": strings.Repeat("A", 10923)}), 65536)
	if e != nil {
		t.Fatal(e)
	}
	_, e = wire.DecodeBinary(strings.Repeat("A", 16386), -1, 20000)
	expect(t, e, "limit_exceeded")
}

// G12 uses one canonical non-null binary result for every method, with matching
// request correlation; untrusted IDs never permit an application error frame.
func TestWireS1ResultCarrier(t *testing.T) {
	for _, method := range []string{"append", "latest", "proof_page", "admin"} {
		b, e := wire.EncodeSuccess(strings.Repeat("a", 32), method, []byte(`{}`))
		if e != nil {
			t.Fatal(e)
		}
		v, e := wire.DecodeResponse(b, strings.Repeat("a", 32), method)
		if e != nil || !bytes.Equal(v.Result, []byte(`{}`)) {
			t.Fatal(e)
		}
	}
	for _, result := range []any{nil, map[string]any{}, "", "AB", "e30="} {
		m := map[string]any{"v": int64(1), "request_id": strings.Repeat("a", 32), "result": result}
		_, e := wire.DecodeResponse(canon(t, m), strings.Repeat("a", 32), "append")
		expect(t, e, "request_malformed")
	}
}

// Aggregate accounting controls test reachable size guards independently;
// they do not claim a closed-schema frame can reach every aggregate ceiling.
func TestWireS1FrameBounds(t *testing.T) {
	for _, c := range []struct{ raw, encoded, meta, total int }{{45056, 60075, 4096, 64171}, {45057, 60076, 1, 60077}, {1, 60076, 1, 60077}, {1, 2, 4097, 4099}, {1, 2, 1, 65537}} {
		e := wire.CheckResultBounds("proof_page", c.raw, c.encoded, c.meta, c.total)
		if c.raw == 45056 {
			if e != nil {
				t.Fatal(e)
			}
		} else {
			expect(t, e, "limit_exceeded")
		}
	}
	b, e := wire.EncodeSuccess(strings.Repeat("a", 32), "proof_page", bytes.Repeat([]byte{'x'}, 45056))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = wire.DecodeResponse(b, strings.Repeat("a", 32), "proof_page"); e != nil {
		t.Fatal(e)
	}
}

// A valid ID survives bad params for refusal correlation, but malformed IDs and
// ambiguous duplicate aliases produce no correlatable response.
func TestWireS1Correlation(t *testing.T) {
	m := request()
	m["method"] = "other"
	raw := canon(t, m)
	_, e := wire.DecodeRequest(raw)
	expect(t, e, "request_malformed")
	if wire.Correlation(raw) != strings.Repeat("a", 32) {
		t.Fatal("lost ID")
	}
	m["request_id"] = "bad"
	raw = canon(t, m)
	if wire.Correlation(raw) != "" {
		t.Fatal("untrusted ID")
	}
	if _, e = wire.EncodeFailure("bad", "busy"); wire.Code(e) != "request_malformed" {
		t.Fatal(e)
	}
	good, e := wire.EncodeFailure(strings.Repeat("a", 32), "busy")
	if e != nil {
		t.Fatal(e)
	}
	r, e := wire.DecodeResponse(good, strings.Repeat("a", 32), "latest")
	if e != nil || r.Error.Code != "busy" || !r.Error.Retryable {
		t.Fatal(e)
	}
	_, e = wire.DecodeResponse(good, strings.Repeat("b", 32), "latest")
	expect(t, e, "evidence_invalid")
	m = map[string]any{"v": int64(1), "request_id": strings.Repeat("a", 32), "error": map[string]any{"code": "busy", "retryable": false}}
	_, e = wire.DecodeResponse(canon(t, m), strings.Repeat("a", 32), "latest")
	expect(t, e, "request_malformed")
}

// A complete canonical line fits exactly8192 including LF; cap+1 refuses
// before profile parsing. Valid append/admin carrier frames retain those bytes.
func TestWireLineBoundaryAndMethods(t *testing.T) {
	for _, n := range []int{8183, 8184} {
		line := append(canon(t, map[string]any{"x": strings.Repeat("x", n)}), '\n')
		_, e := wire.Line(line)
		if n == 8183 {
			if len(line) != 8192 || e != nil {
				t.Fatal("line boundary", e)
			}
		} else {
			expect(t, e, "limit_exceeded")
		}
		for _, method := range []string{"append", "admin"} {
			m := request()
			m["method"] = method
			if method == "append" {
				m["params"] = map[string]any{"stream": "station", "expected_seq": int64(0), "expected_hash": wire.ZeroHash, "record": base64.RawURLEncoding.EncodeToString(line)}
			} else {
				m["params"] = map[string]any{"action": base64.RawURLEncoding.EncodeToString(line)}
			}
			_, e := wire.DecodeRequest(canon(t, m))
			if n == 8183 {
				if e != nil {
					t.Fatal(e)
				}
			} else {
				expect(t, e, "limit_exceeded")
			}
		}
	}
}

// The closed WS enum has18 members, with only busy/rate_limited retryable;
// foreign codes and added error members never become wire diagnostics.
func TestWireErrorsClosed(t *testing.T) {
	codes := []string{"request_malformed", "limit_exceeded", "not_authorized", "stream_unavailable", "bootstrap_required", "stream_empty", "head_conflict", "position_conflict", "checkpoint_fork", "sequence_exhausted", "profile_unavailable", "proof_limit", "evidence_invalid", "storage_unavailable", "outcome_unknown", "deadline_exceeded", "rate_limited", "busy"}
	for _, c := range codes {
		raw, e := wire.EncodeFailure(strings.Repeat("a", 32), c)
		if e != nil {
			t.Fatal(e)
		}
		r, e := wire.DecodeResponse(raw, strings.Repeat("a", 32), "latest")
		if e != nil || r.Error == nil || r.Error.Code != c || r.Error.Retryable != (c == "busy" || c == "rate_limited") {
			t.Fatal(c, e)
		}
	}
	_, e := wire.EncodeFailure(strings.Repeat("a", 32), "registry_unavailable")
	expect(t, e, "request_malformed")
	m := map[string]any{"v": int64(1), "request_id": strings.Repeat("a", 32), "error": map[string]any{"code": "busy", "retryable": true, "detail": "extra"}}
	_, e = wire.DecodeResponse(canon(t, m), strings.Repeat("a", 32), "latest")
	expect(t, e, "request_malformed")
}
