package transport

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-witness/policy"
	"github.com/relux-works/swarma-witness/records"
	"github.com/relux-works/swarma-witness/wire"
)

func canonical(t *testing.T, v any) []byte {
	t.Helper()
	b, e := wire.Canonical(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func request(t *testing.T, stream string) []byte {
	return canonical(t, map[string]any{"v": int64(1), "request_id": strings.Repeat("a", 32), "timeout_ms": int64(5000), "method": "proof_page", "params": map[string]any{"stream": stream, "page_hash": records.Digest([]byte("guessed page"))}})
}
func httpRequest(body []byte) []byte {
	return []byte(fmt.Sprintf("POST /witness/v1 HTTP/1.1\r\nHost: witness.invalid\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", MediaType, len(body), body))
}

// Claim: one bounded HTTP request admits its exact canonical frame; duplicates,
// extra transport features, bad correlation and pipelined messages close silently.
func TestACLTransportFramingAndBudgets(t *testing.T) {
	body := request(t, "one")
	valid := httpRequest(body)
	f, e := DecodeHTTP(valid, "witness.invalid")
	if e != nil || !bytes.Equal(f.Body(), body) {
		t.Fatal("valid frame", e)
	}
	for name, raw := range map[string][]byte{
		"duplicate": bytes.Replace(valid, []byte("Host: witness.invalid"), []byte("Host: witness.invalid\r\nhost: witness.invalid"), 1),
		"transfer":  bytes.Replace(valid, []byte("Connection: close"), []byte("Connection: close\r\nTransfer-Encoding: chunked"), 1),
		"extra":     bytes.Replace(valid, []byte("Connection: close"), []byte("Connection: close\r\nAuthorization: anything"), 1),
		"media":     bytes.Replace(valid, []byte(MediaType), []byte(MediaType+";charset=utf-8"), 1),
		"path":      bytes.Replace(valid, []byte("/witness/v1"), []byte("/witness/v1?x"), 1),
		"version":   bytes.Replace(valid, []byte("HTTP/1.1"), []byte("HTTP/2.0"), 1),
		"short":     valid[:len(valid)-1], "pipeline": append(append([]byte(nil), valid...), valid...),
		"untrusted-id": httpRequest([]byte(`{"request_id":"x"}`)),
		"oversize":     []byte("POST /witness/v1 HTTP/1.1\r\nHost: witness.invalid\r\nContent-Type: " + MediaType + "\r\nConnection: close\r\nContent-Length: 65537\r\n\r\n"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, e := DecodeHTTP(raw, "witness.invalid"); e != ErrClose {
				t.Fatalf("want close got %v", e)
			}
		})
	}
	response, e := wire.EncodeFailure(strings.Repeat("a", 32), "not_authorized")
	if e != nil {
		t.Fatal(e)
	}
	if _, e := HTTPResponse(response, strings.Repeat("a", 32), "proof_page"); e != nil {
		t.Fatal(e)
	}
	if _, e := HTTPResponse(body, strings.Repeat("a", 32), "proof_page"); e != ErrClose {
		t.Fatal("request used as response")
	}
	if e := ValidateBudget(time.Second, time.Second, 0, 0, 5000); e != nil {
		t.Fatal(e)
	}
	for _, elapsed := range []time.Duration{-1, 5 * time.Second, 6 * time.Second} {
		if wire.Code(ValidateBudget(elapsed, 0, 0, 0, 5000)) != "deadline_exceeded" {
			t.Fatal("elapsed boundary")
		}
	}
	if wire.Code(ValidateBudget(time.Second, 0, 0, 0, 1000)) != "deadline_exceeded" {
		t.Fatal("caller cap widened")
	}
	if e := ValidateAdmission(AdmissionCounts{}); e != nil {
		t.Fatal(e)
	}
	for _, c := range []AdmissionCounts{{Connections: 128}, {Handshakes: 16}, {Operations: 16}, {SourceHandshakes: 2}, {SourceEntries: 1024, NewSource: true}, {HandshakeBytes: 65537}} {
		if ValidateAdmission(c) != ErrClose {
			t.Fatal("admission ceiling")
		}
	}
}

// Claim: authorization precedes inner evidence decoding and distinguishes no
// guessed foreign/missing page; these pure checks perform no storage lookup.
func TestACLTransportAuthorizesBeforeInnerEvidence(t *testing.T) {
	pin := records.Digest([]byte("reader"))
	braw := canonical(t, map[string]any{"service": "svc", "stream": "one", "consumer": "registrar", "identity": "repo", "lineage": "l", "profile": "registrar-state-witness-sha1/1", "writer_epoch": int64(1), "writer_id": "writer", "record_key": nil, "transport_pins": []any{records.Digest([]byte("writer"))}, "readers": []any{map[string]any{"id": "reader", "transport_pins": []any{pin}}}})
	b, e := wire.DecodeBinding(braw)
	if e != nil {
		t.Fatal(e)
	}
	s := policy.Snapshot{Service: "svc", Bindings: []wire.Binding{b}, Principals: []policy.Principal{{ID: "reader", Role: policy.Reader, Pins: []string{pin}}, {ID: "writer", Role: policy.Writer, Pins: []string{records.Digest([]byte("writer"))}}}}
	peer := policy.Peer{ID: "reader", Pin: pin}
	if _, e = ValidateAuthorizedFrame(s, peer, request(t, "one")); e != nil {
		t.Fatal(e)
	}
	for _, stream := range []string{"foreign", "missing"} {
		v, _ := wire.Parse(request(t, stream), wire.FrameLimit)
		v.(map[string]any)["params"].(map[string]any)["page_hash"] = "invalid inner evidence"
		if _, e = ValidateAuthorizedFrame(s, peer, canonical(t, v)); wire.Code(e) != "not_authorized" {
			t.Fatalf("foreign existence leaked: %v", e)
		}
	}
	if e := (Handler{}).ProductionReady(); e == nil {
		t.Fatal("zero handler activated")
	}
}

// Claim: exact token models enforce source/write bursts and refill without
// granting elapsed-time extensions. This does not qualify runtime fairness.
func TestACLRateBudgetControls(t *testing.T) {
	s := FreshRateSnapshot(0)
	for i := 0; i < 4; i++ {
		var e error
		s, e = ChargePreauth(s, 0)
		if e != nil {
			t.Fatal("valid burst", e)
		}
	}
	next, e := ChargePreauth(s, 0)
	if e != ErrClose {
		t.Fatal("source burst widened")
	}
	if next.PreauthGlobal.Tokens >= s.PreauthGlobal.Tokens {
		t.Fatal("refusal uncharged")
	}
	s, e = ChargePreauth(next, time.Second/2)
	if e != nil {
		t.Fatal("2/s refill", e)
	}
	s = FreshRateSnapshot(0)
	for i := 0; i < 4; i++ {
		s, e = ChargeApplication(s, 0, true)
		if e != nil {
			t.Fatal(e)
		}
	}
	if _, e = ChargeApplication(s, 0, true); wire.Code(e) != "rate_limited" {
		t.Fatal("write burst widened")
	}
	if _, e = ChargeApplication(s, time.Second/2, true); e != nil {
		t.Fatal("write refill", e)
	}
	if _, e = ChargePreauth(FreshRateSnapshot(time.Second), 0); e != ErrClose {
		t.Fatal("monotonic rollback admitted")
	}
}
