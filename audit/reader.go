package audit

import "github.com/relux-works/swarma-witness/wire"

// Grant is a protected, service-wide audit-reader rule, separate from stream
// readers. This local typed schema is not a WS method or a configuration member.
type Grant struct {
	Principal string
	Pins      []string
}
type Readers struct{ grants map[string][]string }

func NewReaders(rules []Grant) (Readers, error) {
	r := Readers{grants: map[string][]string{}}
	if len(rules) > 64 {
		return Readers{}, wire.Refuse("limit_exceeded")
	}
	for _, rule := range rules {
		if !validPrincipal(rule.Principal) || len(rule.Pins) == 0 || len(rule.Pins) > 16 || r.grants[rule.Principal] != nil {
			return Readers{}, wire.Refuse("request_malformed")
		}
		for j, pin := range rule.Pins {
			if !wire.Digest(pin) || j > 0 && pin <= rule.Pins[j-1] {
				return Readers{}, wire.Refuse("request_malformed")
			}
		}
		r.grants[rule.Principal] = append([]string(nil), rule.Pins...)
	}
	return r, nil
}
func (r Readers) AuthorizeAudit(principal, pin string) error {
	for _, approved := range r.grants[principal] {
		if approved == pin {
			return nil
		}
	}
	return wire.Refuse("not_authorized")
}
