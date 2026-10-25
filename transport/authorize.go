package transport

import (
	"github.com/relux-works/swarma-witness/policy"
	"github.com/relux-works/swarma-witness/wire"
)

// ValidateAuthorizedFrame derives scope before inner decoding. This pure
// predicate has no lookup/dispatcher, so even guessed pages reveal no content.
func ValidateAuthorizedFrame(s policy.Snapshot, peer policy.Peer, raw []byte) (wire.Request, error) {
	v, e := wire.Parse(raw, wire.FrameLimit)
	if e != nil || wire.Correlation(raw) == "" {
		return wire.Request{}, ErrClose
	}
	m, e := wire.Object(v, "v", "request_id", "timeout_ms", "method", "params")
	if e != nil {
		return wire.Request{}, ErrClose
	}
	params, ok := m["params"].(map[string]any)
	if !ok {
		return wire.Request{}, wire.Refuse("request_malformed")
	}
	method := wire.String(m["method"])
	if e = s.Authorize(peer, method, wire.String(params["stream"])); e != nil {
		return wire.Request{}, e
	}
	return wire.DecodeRequest(raw)
}
