package audit

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/relux-works/swarma-witness/wire"
)

// Closed audit fields preserve one cross-stream sequence; absent qualified time
// permits diagnostic unknown only. No fixture establishes a qualified clock.
func TestAuditClosedSchemaAndGlobalOrder(t *testing.T) {
	f := Fields{At: "2026-01-01T00:00:00Z", Instance: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 16)), Principal: "peer", Stream: "one", Operation: "append", Result: "success"}
	prior := Tail{Hash: wire.ZeroHash}
	a, next, e := New(prior, f)
	if e != nil {
		t.Fatal(e)
	}
	f.Stream = "two"
	b, last, e := New(next, f)
	if e != nil || last.Seq != 2 || Validate(b, next) != nil {
		t.Fatal("global ordering", e)
	}
	if Validate(b, prior) == nil {
		t.Fatal("cross-stream sequence reset accepted")
	}
	for _, principal := range []string{"https://example.invalid", "local/file", "free text", "line\nfeed"} {
		bad := f
		bad.Principal = principal
		if _, _, e = New(last, bad); wire.Code(e) != "request_malformed" {
			t.Fatal("audit identifier rejects text/path/URL", e)
		}
	}
	f.At = ""
	if _, _, e = New(last, f); wire.Code(e) != "profile_unavailable" {
		t.Fatal("null-time success", e)
	}
	f.Result = "unknown"
	f.Code = "profile_unavailable"
	if _, _, e = New(last, f); e != nil {
		t.Fatal("unknown diagnostic", e)
	}
	v, _ := wire.Line(a)
	m := v.(map[string]any)
	m["extra"] = "text"
	raw, _ := wire.Canonical(m)
	if Validate(append(raw, '\n'), prior) == nil {
		t.Fatal("unknown audit member")
	}
	m = v.(map[string]any)
	delete(m, "extra")
	m["code"] = "invented"
	m["result"] = "refused"
	raw, _ = wire.Canonical(m)
	if Validate(append(raw, '\n'), prior) == nil {
		t.Fatal("unknown error code")
	}
}

// Explicit global grants never inherit a stream reader, and telemetry has fixed
// cardinality, saturating counters and a burst-one diagnostic allowance.
func TestAuditReadersAndBoundedHealth(t *testing.T) {
	pin := "sha256:" + wire.ZeroHash
	rules := []Grant{{Principal: "auditor", Pins: []string{pin}}}
	r, e := NewReaders(rules)
	if e != nil {
		t.Fatal(e)
	}
	rules[0].Pins[0] = "changed"
	if r.AuthorizeAudit("auditor", pin) != nil || wire.Code(r.AuthorizeAudit("reader", pin)) != "not_authorized" || wire.Code((Readers{}).AuthorizeAudit("auditor", pin)) != "not_authorized" {
		t.Fatal("explicit reader boundary")
	}
	if _, e = NewReaders([]Grant{{Principal: "auditor", Pins: []string{pin, pin}}}); wire.Code(e) != "request_malformed" {
		t.Fatal("duplicate pins", e)
	}
	var h Health
	h.counts[0] = wire.MaxInt
	if !h.Failure(0, 0) || h.Failure(0, 0) || h.Failure(63, 999999999) || !h.Failure(63, 1000000000) || h.Failure(64, 2000000000) || h.Counts()[0] != wire.MaxInt || h.Counts()[63] != 2 {
		t.Fatal("bounded health")
	}
}
