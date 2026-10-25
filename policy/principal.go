// Package policy validates immutable policy facts and transition plans only.
// It supplies no production approval, durable activation or admission service.
package policy

import "github.com/relux-works/swarma-witness/wire"

type Role string

const (
	Writer        Role = "writer"
	Reader        Role = "reader"
	Administrator Role = "admin"
	Publisher     Role = "publisher"
	Bridge        Role = "bridge"
	Observer      Role = "observer"
)

type Principal struct {
	ID   string
	Role Role
	Pins []string
}

func ValidatePrincipals(ps []Principal) error {
	if len(ps) > 64 {
		return wire.Refuse("limit_exceeded")
	}
	ids, pins := map[string]bool{}, map[string]string{}
	for _, p := range ps {
		if !wire.Opaque(p.ID) || ids[p.ID] || len(p.Pins) == 0 || len(p.Pins) > 8 {
			return wire.Refuse("evidence_invalid")
		}
		switch p.Role {
		case Writer, Reader, Administrator, Publisher, Bridge, Observer:
		default:
			return wire.Refuse("evidence_invalid")
		}
		ids[p.ID] = true
		seen := map[string]bool{}
		for _, pin := range p.Pins {
			if !wire.Digest(pin) || seen[pin] {
				return wire.Refuse("evidence_invalid")
			}
			if prior, ok := pins[pin]; ok && prior != p.ID {
				return wire.Refuse("evidence_invalid")
			}
			pins[pin] = p.ID
			seen[pin] = true
		}
	}
	return nil
}

// Peer is an already authenticated transport identity, not request metadata.
type Peer struct{ ID, Pin string }

func PrincipalFor(ps []Principal, peer Peer) (Principal, error) {
	if e := ValidatePrincipals(ps); e != nil {
		return Principal{}, e
	}
	for _, p := range ps {
		if p.ID == peer.ID {
			for _, pin := range p.Pins {
				if pin == peer.Pin {
					return p, nil
				}
			}
		}
	}
	return Principal{}, wire.Refuse("not_authorized")
}
