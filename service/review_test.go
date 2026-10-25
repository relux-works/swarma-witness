package service

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/relux-works/swarma-witness/store"
	"github.com/relux-works/swarma-witness/wire"
)

// A failed read-audit reserve or unavailable storage must close readiness like
// the append path. The available control writes its audit and remains ready.
func TestReviewerReadAuditReserveClosesAdmission(t *testing.T) {
	for _, method := range []string{"latest", "proof_page"} {
		t.Run(method, func(t *testing.T) {
			for _, which := range []string{"available", "audit-full", "storage-unavailable", "independent-storage-unavailable"} {
				t.Run(which, func(t *testing.T) {
					f := newFixture(t, store.Calls{})
					before, _ := f.s.disk.Snapshot()
					if which == "audit-full" {
						f.s.state.AuditBytes = 1 << 30
					}
					if which == "storage-unavailable" {
						if e := f.s.disk.Close(); e != nil {
							t.Fatal(e)
						}
					}
					if which == "independent-storage-unavailable" {
						f.remote.index = store.Hash([]byte("different independently retained index"))
					}
					_, e := f.s.Read(context.Background(), peer("reader"), method, "one", strings.Repeat("7", 32))
					if which != "available" {
						if wire.Code(e) != "storage_unavailable" {
							t.Fatal("reserve refusal", e)
						}
						after, _ := f.s.disk.Snapshot()
						if !bytes.Equal(before, after) || len(f.s.state.Entries) != 0 || f.s.state.AuditSeq != 0 {
							t.Fatal("reserve failure changed state")
						}
						if e = f.s.Ready(); wire.Code(e) != "storage_unavailable" {
							t.Fatalf("audit reserve loss must close admission: Ready=%v", e)
						}
						// A subsequent append is denied before signing or changing the root.
						_, e = f.append(t)
						if wire.Code(e) != "storage_unavailable" || f.signs.Load() != 0 {
							t.Fatal("audit failure admitted later append", e)
						}
					} else if wire.Code(e) != "profile_unavailable" || f.s.state.AuditSeq != 1 || f.s.Ready() != nil {
						t.Fatal("valid audited read", e)
					}
				})
			}
		})
	}
}

// Public append reaches custody with all final local gates unlocked. Emergency
// stop during that external call prevents publication/release, retaining prepare.
func TestReviewerCustodyUnlockedAndStopCloses(t *testing.T) {
	for _, stop := range []bool{false, true} {
		t.Run(map[bool]string{false: "complete", true: "stop"}[stop], func(t *testing.T) {
			f := newFixture(t, store.Calls{})
			calls := 0
			f.remote.callback = func() {
				calls++
				if !f.s.admission.TryLock() {
					t.Fatal("custody held admission")
				}
				f.s.admission.Unlock()
				if !f.s.auditGate.TryLock() {
					t.Fatal("custody held audit")
				}
				f.s.auditGate.Unlock()
				for _, gate := range f.s.streams {
					if !gate.TryLock() {
						t.Fatal("custody held stream")
					}
					gate.Unlock()
				}
				if stop {
					f.s.Stop()
				}
			}
			got, e := f.append(t)
			if calls != 1 {
				t.Fatal("custody not reached")
			}
			if stop {
				if wire.Code(e) != "outcome_unknown" || len(got) != 0 || len(f.s.state.Entries) != 0 || wire.Code(f.s.Ready()) != "storage_unavailable" {
					t.Fatal("stop released or published", e)
				}
			} else {
				if e != nil || len(got) == 0 {
					t.Fatal("complete transaction", e)
				}
			}
		})
	}
}
