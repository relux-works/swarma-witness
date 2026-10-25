// Package config decodes protected configuration values without loading keys,
// paths, URLs or caller-selected evidence. It cannot open production gates.
package config

import (
	"github.com/relux-works/swarma-witness/policy"
	"github.com/relux-works/swarma-witness/wire"
)

type Protected struct{ snapshot policy.Snapshot }

func Parse(raw []byte) (Protected, error) {
	v, e := wire.Parse(raw, wire.FrameLimit)
	if e != nil {
		return Protected{}, e
	}
	m, e := wire.Object(v, "service", "bindings", "principals")
	if e != nil {
		return Protected{}, e
	}
	bs, ok := m["bindings"].([]any)
	if !ok {
		return Protected{}, wire.Refuse("request_malformed")
	}
	ps, ok := m["principals"].([]any)
	if !ok {
		return Protected{}, wire.Refuse("request_malformed")
	}
	s := policy.Snapshot{Service: wire.String(m["service"])}
	for _, v := range bs {
		raw, e := wire.Canonical(v)
		if e != nil {
			return Protected{}, e
		}
		b, e := wire.DecodeBinding(raw)
		if e != nil {
			return Protected{}, e
		}
		s.Bindings = append(s.Bindings, b)
	}
	for _, v := range ps {
		p, e := wire.Object(v, "id", "role", "transport_pins")
		if e != nil {
			return Protected{}, e
		}
		pins, ok := p["transport_pins"].([]any)
		if !ok {
			return Protected{}, wire.Refuse("request_malformed")
		}
		q := policy.Principal{ID: wire.String(p["id"]), Role: policy.Role(wire.String(p["role"]))}
		for _, pin := range pins {
			q.Pins = append(q.Pins, wire.String(pin))
		}
		s.Principals = append(s.Principals, q)
	}
	if e = s.Validate(); e != nil {
		return Protected{}, e
	}
	return Protected{s}, nil
}

// Snapshot copies all mutable containers; parsed bindings already own bytes.
func (p Protected) Snapshot() policy.Snapshot {
	s := p.snapshot
	s.Bindings = append([]wire.Binding(nil), s.Bindings...)
	s.Principals = append([]policy.Principal(nil), s.Principals...)
	for i := range s.Principals {
		s.Principals[i].Pins = append([]string(nil), s.Principals[i].Pins...)
	}
	return s
}
