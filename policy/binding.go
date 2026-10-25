package policy

import "github.com/relux-works/swarma-witness/wire"

type Snapshot struct {
	Service    string
	Bindings   []wire.Binding
	Principals []Principal
}

func (s Snapshot) Validate() error {
	if !wire.Name(s.Service) || len(s.Bindings) > 64 {
		return wire.Refuse("stream_unavailable")
	}
	if e := ValidatePrincipals(s.Principals); e != nil {
		return e
	}
	seen := map[string]bool{}
	for _, b := range s.Bindings {
		if !b.Valid() || b.Service() != s.Service || seen[b.Stream()] {
			return wire.Refuse("stream_unavailable")
		}
		seen[b.Stream()] = true
		m, _ := bindingObject(b)
		check := func(id string, pins []any, writer bool) error {
			for _, pin := range pins {
				p, e := PrincipalFor(s.Principals, Peer{id, wire.String(pin)})
				if e != nil {
					return wire.Refuse("evidence_invalid")
				}
				if writer {
					if b.Consumer() == "owner-registry" {
						if p.Role != Bridge {
							return wire.Refuse("evidence_invalid")
						}
					} else if p.Role != Writer {
						return wire.Refuse("evidence_invalid")
					}
				} else if p.Role != Reader && p.Role != Writer && p.Role != Bridge && !(p.Role == Observer && b.Consumer() == "owner-registry") {
					return wire.Refuse("evidence_invalid")
				}
			}
			return nil
		}
		if e := check(b.WriterID(), m["transport_pins"].([]any), true); e != nil {
			return e
		}
		for _, r := range m["readers"].([]any) {
			p := r.(map[string]any)
			if e := check(wire.String(p["id"]), p["transport_pins"].([]any), false); e != nil {
				return e
			}
		}
	}
	return nil
}
func bindingObject(b wire.Binding) (map[string]any, error) {
	v, e := wire.Parse(b.Bytes(), wire.LineLimit)
	if e != nil {
		return nil, e
	}
	return v.(map[string]any), nil
}
func (s Snapshot) Binding(stream string) (wire.Binding, error) {
	if e := s.Validate(); e != nil {
		return wire.Binding{}, e
	}
	for _, b := range s.Bindings {
		if b.Stream() == stream {
			return b, nil
		}
	}
	return wire.Binding{}, wire.Refuse("stream_unavailable")
}

// Authorize uses protected membership before any record/head/page lookup.
// A foreign or nonexistent stream produces the same denial for an unbound peer.
func (s Snapshot) Authorize(peer Peer, method, stream string) error {
	p, e := PrincipalFor(s.Principals, peer)
	if e != nil {
		return e
	}
	if method == "admin" {
		if p.Role == Administrator {
			return nil
		}
		return wire.Refuse("not_authorized")
	}
	if p.Role == Publisher {
		return wire.Refuse("not_authorized")
	}
	if e = s.Validate(); e != nil {
		return e
	}
	for _, b := range s.Bindings {
		if b.Stream() != stream {
			continue
		}
		m, _ := bindingObject(b)
		if method == "append" {
			if p.ID == b.WriterID() && (p.Role == Writer || b.Consumer() == "owner-registry" && p.Role == Bridge) {
				for _, pin := range m["transport_pins"].([]any) {
					if pin == peer.Pin {
						return nil
					}
				}
			}
		} else if method == "latest" || method == "proof_page" {
			for _, r := range m["readers"].([]any) {
				q := r.(map[string]any)
				if q["id"] == p.ID {
					for _, pin := range q["transport_pins"].([]any) {
						if pin == peer.Pin {
							return nil
						}
					}
				}
			}
		}
	}
	return wire.Refuse("not_authorized")
}
