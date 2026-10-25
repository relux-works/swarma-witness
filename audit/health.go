package audit

import (
	"sync"

	"github.com/relux-works/swarma-witness/wire"
)

// Health has exactly 64 fixed slots. It emits only a numeric fixed cause at
// most once per elapsed second (burst one); no clock, callback, queue or text.
type Health struct {
	mu      sync.Mutex
	counts  [64]int64
	last    int64
	emitted bool
}

func (h *Health) Failure(cause uint8, elapsedNS int64) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if cause >= 64 || elapsedNS < 0 {
		return false
	}
	if h.counts[cause] < wire.MaxInt {
		h.counts[cause]++
	}
	if h.emitted && (elapsedNS < h.last || elapsedNS-h.last < 1_000_000_000) {
		return false
	}
	h.last = elapsedNS
	h.emitted = true
	return true
}
func (h *Health) Counts() [64]int64 { h.mu.Lock(); defer h.mu.Unlock(); return h.counts }

// Reader is deliberately distinct from per-stream authorization. No accepting
// audit-reader policy or WS method is introduced by the local audit codec.
type Reader interface {
	AuthorizeAudit(principal, pin string) error
}
type ClosedReader struct{}

func (ClosedReader) AuthorizeAudit(string, string) error { return wire.Refuse("not_authorized") }
