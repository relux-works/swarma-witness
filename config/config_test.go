package config

import (
	"github.com/relux-works/swarma-witness/records"
	"github.com/relux-works/swarma-witness/wire"
	"testing"
)

func configValue() map[string]any {
	return map[string]any{"service": "svc", "bindings": []any{}, "principals": []any{map[string]any{"id": "admin", "role": "admin", "transport_pins": []any{records.Digest([]byte("admin"))}}}}
}
func parseValue(t *testing.T, m map[string]any) (Protected, error) {
	t.Helper()
	raw, e := wire.Canonical(m)
	if e != nil {
		t.Fatal(e)
	}
	return Parse(raw)
}

// Claim: even valid protected configuration cannot open G07; unknown fields,
// including attempted gate/lookup overrides, reject rather than install authority.
func TestProvisionG07RemainsClosed(t *testing.T) {
	m := configValue()
	p, e := parseValue(t, m)
	if e != nil {
		t.Fatal(e)
	}
	if e = DisclosureGate(); wire.Code(e) != "stream_unavailable" {
		t.Fatalf("G07 opened: %v", e)
	}
	if e = p.ProductionReady(); wire.Code(e) != "stream_unavailable" {
		t.Fatalf("production gate=%v", e)
	}
	for _, field := range []string{"disclosure_approved", "custody_qualified", "lookup_url", "key", "path"} {
		m[field] = true
		_, e = parseValue(t, m)
		if wire.Code(e) != "request_malformed" {
			t.Fatalf("override %s accepted: %v", field, e)
		}
		delete(m, field)
	}
	copy := p.Snapshot()
	copy.Principals[0].Pins[0] = records.Digest([]byte("changed"))
	if p.Snapshot().Principals[0].Pins[0] == copy.Principals[0].Pins[0] {
		t.Fatal("configuration aliases caller")
	}
}

// Claim: G10 remains unavailable independently of G07; parsing public values
// cannot install signer custody or root authority.
func TestAdminG10RemainsClosed(t *testing.T) {
	if _, e := parseValue(t, configValue()); e != nil {
		t.Fatal(e)
	}
	if e := CustodyGate(); wire.Code(e) != "profile_unavailable" {
		t.Fatalf("G10 opened: %v", e)
	}
	m := configValue()
	ps := m["principals"].([]any)
	ps[0].(map[string]any)["extra"] = nil
	if _, e := parseValue(t, m); wire.Code(e) != "request_malformed" {
		t.Fatalf("nested extra accepted: %v", e)
	}
	raw, _ := wire.Canonical(configValue())
	if _, e := Parse(append(raw, ' ')); wire.Code(e) != "request_malformed" {
		t.Fatal("noncanonical accepted")
	}
}
