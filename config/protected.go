package config

import "github.com/relux-works/swarma-witness/wire"

// DisclosureGate (G07) requires an owner decision and a reviewed approval
// contract. No configuration boolean, constructor or environment can open it.
func DisclosureGate() error { return wire.Refuse("stream_unavailable") }

// CustodyGate (G10) requires independently installed roots and qualified custody.
// Parsing public configuration is never such an installation or qualification.
func CustodyGate() error { return wire.Refuse("profile_unavailable") }
func (p Protected) ProductionReady() error {
	if e := p.snapshot.Validate(); e != nil {
		return e
	}
	if e := DisclosureGate(); e != nil {
		return e
	}
	return CustodyGate()
}
