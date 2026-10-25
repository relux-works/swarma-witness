package service

import (
	"context"

	"github.com/relux-works/swarma-witness/policy"
	"github.com/relux-works/swarma-witness/store"
	"github.com/relux-works/swarma-witness/wire"
)

// Failure audit never reenters Append/Admin. If that audit cannot be retained,
// only fixed bounded health accounting remains and admission closes.
func (s *Service) finishRefusal(ctx context.Context, peer policy.Peer, stream, operation, id string, result *[]byte, refusal *error) {
	if *refusal == nil {
		return
	}
	*result = nil
	s.admission.Lock()
	held := s.held
	s.admission.Unlock()
	if held {
		return
	}
	code := wire.Code(*refusal)
	if code == "sequence_exhausted" || ctx.Err() != nil {
		s.fail(false)
		return
	}
	if !wire.RequestID(id) {
		id = ""
	}
	_, e := s.commit(ctx, s.state, store.Manifest{Chain: "audits"}, nil, s.auditFields(peer, stream, operation, id, "", "refused", code), nil)
	if e != nil {
		s.fail(false)
		if code != "profile_unavailable" {
			*refusal = wire.Refuse("storage_unavailable")
		}
	}
}
