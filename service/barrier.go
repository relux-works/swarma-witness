package service

import (
	"context"
	"crypto/rand"
	"sync"
	"sync/atomic"

	"github.com/relux-works/swarma-witness/archive"
	"github.com/relux-works/swarma-witness/audit"
	"github.com/relux-works/swarma-witness/config"
	"github.com/relux-works/swarma-witness/custodian"
	"github.com/relux-works/swarma-witness/policy"
	"github.com/relux-works/swarma-witness/records"
	"github.com/relux-works/swarma-witness/store"
	"github.com/relux-works/swarma-witness/wire"
)

type dependencies struct {
	custody   custodian.Provider
	archive   archive.Audit
	exclusion custodian.Exclusion
	recovery  custodian.Recovery
	time      custodian.Time
}
type Service struct {
	admission     sync.Mutex
	auditGate     sync.Mutex
	streams       map[string]*sync.Mutex
	active        atomic.Bool
	stopped       atomic.Bool
	pending, held bool
	disk          *store.Disk
	state         state
	policy        policy.Snapshot
	deps          dependencies
	admin         records.Key
	signers       map[string]records.Signer
	instance      string
	health        audit.Health
}

// New cannot open storage or accept provider injection. G07/G10 and G16-G19
// need separately reviewed provisioning and native adapters before serving.
func New(p config.Protected) *Service {
	return &Service{policy: p.Snapshot(), deps: dependencies{custodian.Closed{}, archive.Closed{}, custodian.ClosedExclusion{}, custodian.ClosedRecovery{}, custodian.ClosedTime{}}}
}
func (s *Service) Stop() { s.stopped.Store(true) }
func (s *Service) Ready() error {
	if s.disk == nil || s.stopped.Load() {
		return wire.Refuse("storage_unavailable")
	}
	s.admission.Lock()
	defer s.admission.Unlock()
	if s.pending || s.held {
		return wire.Refuse("storage_unavailable")
	}
	return nil
}
func tuple(service string, e entry) custodian.Tuple {
	stream := e.Stream
	return custodian.Tuple{Service: service, Chain: "records", Stream: &stream, Seq: e.Seq, RecordHash: e.Record, ReceiptHash: e.Receipt, ControlHash: e.Control}
}
func (s *Service) checkIndependent(ctx context.Context) error {
	if s.deps.custody == nil || s.deps.archive == nil || s.deps.exclusion == nil || s.deps.recovery == nil || s.deps.time == nil {
		return wire.Refuse("storage_unavailable")
	}
	root, _ := s.disk.Snapshot()
	if e := s.deps.recovery.Assess(ctx, s.policy.Service, root); e != nil {
		return e
	}
	if e := s.deps.exclusion.Check(ctx, s.policy.Service); e != nil {
		return e
	}
	if e := s.deps.archive.CheckAudit(ctx, s.policy.Service, archive.Tail{Seq: s.state.AuditSeq, Hash: s.state.AuditHash}); e != nil {
		return e
	}
	seen := map[string]bool{}
	for i := len(s.state.Entries) - 1; i >= 0; i-- {
		v := s.state.Entries[i]
		if seen[v.Stream] {
			continue
		}
		seen[v.Stream] = true
		var challenge [32]byte
		if _, e := rand.Read(challenge[:]); e != nil {
			return wire.Refuse("storage_unavailable")
		}
		r := custodian.Request{Tuple: tuple(s.policy.Service, v), Challenge: challenge}
		evidence, e := s.deps.custody.ReadFresh(ctx, r)
		if e != nil {
			return e
		}
		if e = s.deps.custody.VerifyFresh(r, evidence); e != nil {
			return e
		}
	}
	if len(s.state.Actions) > 0 {
		a := s.state.Actions[len(s.state.Actions)-1]
		var challenge [32]byte
		if _, e := rand.Read(challenge[:]); e != nil {
			return wire.Refuse("storage_unavailable")
		}
		r := custodian.Request{Tuple: custodian.Tuple{Service: s.policy.Service, Chain: "controls", Seq: a.Seq, RecordHash: a.Line, ReceiptHash: a.Receipt, ControlHash: a.Line}, Challenge: challenge}
		v, e := s.deps.custody.ReadFresh(ctx, r)
		if e != nil {
			return e
		}
		if e = s.deps.custody.VerifyFresh(r, v); e != nil {
			return e
		}
	}
	if len(s.state.Actions) == 0 {
		var challenge [32]byte
		if _, e := rand.Read(challenge[:]); e != nil {
			return wire.Refuse("storage_unavailable")
		}
		r := custodian.Request{Tuple: custodian.Tuple{Service: s.policy.Service, Chain: "controls", RecordHash: wire.ZeroHash, ReceiptHash: wire.ZeroHash, ControlHash: wire.ZeroHash}, Challenge: challenge}
		v, e := s.deps.custody.ReadFresh(ctx, r)
		if e != nil {
			return e
		}
		if e = s.deps.custody.VerifyFresh(r, v); e != nil {
			return e
		}
	}
	return nil
}

// reserve owns the global pending revision through unlocked external calls.
// There is no waiting queue or recursive entry. Exact lock graph: admission ->
// affected streams (lexical for admin) -> audit -> disk's internal storage gate.
func (s *Service) reserve(ctx context.Context, peer policy.Peer, method, stream string) (func(), error) {
	if !s.active.CompareAndSwap(false, true) {
		return nil, wire.Refuse("busy")
	}
	s.admission.Lock()
	if e := s.policy.Authorize(peer, method, stream); e != nil {
		s.admission.Unlock()
		s.active.Store(false)
		return nil, e
	}
	if s.disk == nil || s.pending || s.held || s.stopped.Load() {
		s.admission.Unlock()
		s.active.Store(false)
		return nil, wire.Refuse("storage_unavailable")
	}
	if ctx.Err() != nil {
		s.admission.Unlock()
		s.active.Store(false)
		return nil, wire.Refuse("deadline_exceeded")
	}
	if s.state.AuditSeq >= wire.MaxInt || s.state.Revision >= 1024 {
		s.held = true
		s.admission.Unlock()
		s.active.Store(false)
		if s.state.AuditSeq >= wire.MaxInt {
			return nil, wire.Refuse("sequence_exhausted")
		}
		return nil, wire.Refuse("storage_unavailable")
	}
	s.pending = true
	s.admission.Unlock()
	end := func() { s.admission.Lock(); s.pending = false; s.admission.Unlock(); s.active.Store(false) }
	if e := s.checkIndependent(ctx); e != nil {
		end()
		return nil, e
	}
	return end, nil
}
func (s *Service) fail(work bool) error {
	s.admission.Lock()
	s.held = true
	s.admission.Unlock()
	s.health.Failure(0, 0)
	if work {
		return wire.Refuse("outcome_unknown")
	}
	return wire.Refuse("storage_unavailable")
}

func (s *Service) commit(ctx context.Context, next state, m store.Manifest, objects []store.Object, fields audit.Fields, transition *custodian.Transition) ([]byte, error) {
	// Transaction identity is fixed before audit allocation. There are no locks
	// over time, custody or archive calls; active/pending retains the reservation.
	var nonce [32]byte
	if _, e := rand.Read(nonce[:]); e != nil {
		return nil, s.fail(false)
	}
	tx := store.Hash(nonce[:])
	m.Transaction = tx
	at, e := s.deps.time.Prepare(ctx, tx)
	if e != nil {
		return nil, e
	}
	fields.At = at
	s.admission.Lock()
	keys := s.lockStreams(m.Stream)
	s.auditGate.Lock()
	line, tail, e := audit.New(audit.Tail{Seq: s.state.AuditSeq, Hash: s.state.AuditHash}, fields)
	if e != nil {
		s.auditGate.Unlock()
		s.unlockStreams(keys)
		s.admission.Unlock()
		return nil, e
	}
	next.Revision++
	next.AuditSeq = tail.Seq
	next.AuditHash = tail.Hash
	next.AuditBytes += 64 << 10
	next.HistoryBytes += 8 << 20
	raw, e := encodeState(next)
	if e == nil && (next.Revision > 1024 || next.HistoryBytes > 100<<30 || next.AuditBytes > 1<<30 || len(next.Entries)+len(next.Actions) > 1024) {
		e = wire.Refuse("storage_unavailable")
	}
	objects = append(objects, store.Object{Kind: "audit", Bytes: line}, store.Object{Kind: "index", Bytes: raw})
	root, _ := s.disk.Snapshot()
	m.Service = s.policy.Service
	m.Prior = store.Hash(root)
	m.Index = store.Hash(raw)
	m.Policy = store.Hash(next.Policy)
	m.AuditSeq = tail.Seq
	m.Audit = tail.Hash
	if e == nil {
		e = store.CheckPlan(m, objects)
	}
	if e == nil {
		e = s.disk.Preflight(int64(8 * store.SegmentLimit))
	}
	if e != nil {
		s.auditGate.Unlock()
		s.unlockStreams(keys)
		s.admission.Unlock()
		return nil, e
	}
	prepared, e := s.disk.Prepare(m, objects)
	s.auditGate.Unlock()
	s.unlockStreams(keys)
	s.admission.Unlock()
	if e != nil {
		return nil, s.fail(m.Chain != "audits")
	}
	var custody []byte
	if transition != nil {
		transition.Transaction = tx
		v, e := s.deps.custody.Confirm(ctx, *transition)
		if e != nil {
			return nil, s.fail(m.Chain != "audits")
		}
		if e = s.deps.custody.VerifyConfirmation(*transition, v); e != nil {
			return nil, s.fail(m.Chain != "audits")
		}
		custody = v.Original
	}
	manifest := archive.Manifest{Service: s.policy.Service, Transaction: tx, Previous: archive.Tail{Seq: s.state.AuditSeq, Hash: s.state.AuditHash}, Next: archive.Tail{Seq: tail.Seq, Hash: tail.Hash}}
	for _, o := range objects {
		manifest.Objects = append(manifest.Objects, archive.Object{Kind: o.Kind, Hash: store.Hash(o.Bytes), Bytes: append([]byte(nil), o.Bytes...)})
	}
	manifest.Objects = append(manifest.Objects, archive.Object{Kind: "prepare", Hash: store.Hash(prepared.Bytes()), Bytes: prepared.Bytes()})
	ack, e := s.deps.archive.ConfirmAudit(ctx, manifest)
	if e != nil {
		return nil, s.fail(m.Chain != "audits")
	}
	if e = s.deps.archive.VerifyAudit(manifest, ack); e != nil {
		return nil, s.fail(m.Chain != "audits")
	}
	if e = s.deps.time.Publish(ctx, tx); e != nil {
		return nil, s.fail(m.Chain != "audits")
	}
	if e = s.deps.exclusion.Check(ctx, s.policy.Service); e != nil {
		return nil, s.fail(m.Chain != "audits")
	}
	if ctx.Err() != nil || s.stopped.Load() {
		return nil, s.fail(m.Chain != "audits")
	}
	s.admission.Lock()
	keys = s.lockStreams(m.Stream)
	s.auditGate.Lock()
	if !s.pending || s.state.Revision+1 != next.Revision {
		s.auditGate.Unlock()
		s.unlockStreams(keys)
		s.admission.Unlock()
		return nil, s.fail(m.Chain != "audits")
	}
	e = s.disk.Publish(prepared, []store.Object{{Kind: "custody", Bytes: custody}, {Kind: "archive", Bytes: ack.Original}})
	if e == nil {
		s.state = next
		s.policy, e = snapshot(next.Policy)
	}
	s.auditGate.Unlock()
	s.unlockStreams(keys)
	s.admission.Unlock()
	if e != nil {
		return nil, s.fail(m.Chain != "audits")
	}
	if e = s.deps.time.Release(ctx, tx); e != nil {
		return nil, s.fail(m.Chain != "audits")
	}
	if ctx.Err() != nil || s.stopped.Load() {
		return nil, s.fail(m.Chain != "audits")
	}
	return line, nil
}
func (s *Service) lockStreams(stream string) []string {
	keys := []string{}
	if stream != "" {
		keys = append(keys, stream)
	} else {
		for _, b := range s.policy.Bindings {
			keys = append(keys, b.Stream())
		}
	}
	sortStrings(keys)
	for _, k := range keys {
		if s.streams[k] == nil {
			s.streams[k] = &sync.Mutex{}
		}
		s.streams[k].Lock()
	}
	return keys
}
func (s *Service) unlockStreams(keys []string) {
	for i := len(keys) - 1; i >= 0; i-- {
		s.streams[keys[i]].Unlock()
	}
}
func sortStrings(v []string) {
	for i := 1; i < len(v); i++ {
		for j := i; j > 0 && v[j] < v[j-1]; j-- {
			v[j], v[j-1] = v[j-1], v[j]
		}
	}
}
