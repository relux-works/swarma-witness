package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/relux-works/swarma-witness/archive"
	"github.com/relux-works/swarma-witness/audit"
	"github.com/relux-works/swarma-witness/custodian"
	"github.com/relux-works/swarma-witness/evidence"
	"github.com/relux-works/swarma-witness/policy"
	"github.com/relux-works/swarma-witness/records"
	"github.com/relux-works/swarma-witness/store"
	"github.com/relux-works/swarma-witness/wire"
)

// These providers are synthetic test facts only: no signatures, failure-domain
// separation, power-loss retention, post-restore entropy or timing qualification.
type independent struct {
	tuples                   map[string]custodian.Tuple
	tail                     archive.Tail
	index                    string
	failCustody, failArchive bool
	callback                 func()
	confirmCalls             int
}

func scope(t custodian.Tuple) string {
	if t.Stream != nil {
		return t.Chain + ":" + *t.Stream
	}
	return t.Chain
}
func (i *independent) ReadFresh(_ context.Context, r custodian.Request) (custodian.Evidence, error) {
	v, ok := i.tuples[scope(r.Tuple)]
	if !ok || !reflect.DeepEqual(v, r.Tuple) {
		return custodian.Evidence{}, wire.Refuse("storage_unavailable")
	}
	b, _ := json.Marshal(r)
	return custodian.Evidence{Original: b}, nil
}
func (i *independent) VerifyFresh(r custodian.Request, e custodian.Evidence) error {
	b, _ := json.Marshal(r)
	if !bytes.Equal(b, e.Original) {
		return wire.Refuse("evidence_invalid")
	}
	return nil
}
func (i *independent) Confirm(_ context.Context, t custodian.Transition) (custodian.Evidence, error) {
	i.confirmCalls++
	if i.callback != nil {
		i.callback()
	}
	if i.failCustody {
		return custodian.Evidence{}, wire.Refuse("storage_unavailable")
	}
	if !reflect.DeepEqual(i.tuples[scope(t.Previous)], t.Previous) {
		return custodian.Evidence{}, wire.Refuse("storage_unavailable")
	}
	i.tuples[scope(t.Next)] = t.Next
	b, _ := json.Marshal(t)
	return custodian.Evidence{Original: b}, nil
}
func (i *independent) VerifyConfirmation(t custodian.Transition, e custodian.Evidence) error {
	b, _ := json.Marshal(t)
	if !bytes.Equal(b, e.Original) {
		return wire.Refuse("evidence_invalid")
	}
	return nil
}
func (i *independent) ConfirmAudit(_ context.Context, m archive.Manifest) (archive.Ack, error) {
	if i.failArchive || m.Previous != i.tail {
		return archive.Ack{}, wire.Refuse("storage_unavailable")
	}
	i.tail = m.Next
	for _, o := range m.Objects {
		if o.Kind == "index" {
			i.index = o.Hash
		}
	}
	b, _ := json.Marshal(m)
	return archive.Ack{Original: storeHashBytes(b)}, nil
}
func storeHashBytes(b []byte) []byte { return []byte(store.Hash(b)) }
func (i *independent) VerifyAudit(m archive.Manifest, a archive.Ack) error {
	b, _ := json.Marshal(m)
	if !bytes.Equal(a.Original, storeHashBytes(b)) {
		return wire.Refuse("evidence_invalid")
	}
	return nil
}
func (i *independent) CheckAudit(_ context.Context, _ string, t archive.Tail) error {
	if t != i.tail {
		return wire.Refuse("storage_unavailable")
	}
	return nil
}
func (i *independent) Assess(_ context.Context, _ string, b []byte) error {
	m, _, e := store.Decode(b, store.RootMagic)
	if e != nil || m.Index != i.index || m.AuditSeq != i.tail.Seq || m.Audit != i.tail.Hash {
		return wire.Refuse("storage_unavailable")
	}
	return nil
}

type syntheticExclusion struct{}

func (syntheticExclusion) Check(context.Context, string) error { return nil }

type syntheticTime struct{ deny bool }

func (t syntheticTime) Prepare(context.Context, string) (string, error) {
	if t.deny {
		return "", wire.Refuse("profile_unavailable")
	}
	return "2026-01-01T00:00:00Z", nil
}
func (t syntheticTime) Publish(context.Context, string) error { return nil }
func (t syntheticTime) Release(context.Context, string) error { return nil }

type fixture struct {
	s                               *Service
	remote                          *independent
	dir                             string
	recordKey, witnessKey, adminKey records.Key
	recordPrivate, adminPrivate     ed25519.PrivateKey
	signs                           *atomic.Int64
	calls                           store.Calls
}

func key(seed byte, role records.Role) (records.Key, ed25519.PrivateKey) {
	p := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32))
	public := p.Public().(ed25519.PublicKey)
	h := sha256.Sum256(public)
	return records.Key{Public: "ed25519:" + base64.RawURLEncoding.EncodeToString(public), ID: "sha256:" + hex.EncodeToString(h[:]), Epoch: 1, Role: role}, p
}
func canonical(t *testing.T, v any) []byte {
	t.Helper()
	b, e := wire.Canonical(v)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func signed(t *testing.T, m map[string]any, k records.Key, p ed25519.PrivateKey, d records.Domain) []byte {
	t.Helper()
	m["key_id"] = k.ID
	m["key_epoch"] = k.Epoch
	b, e := records.SignEnvelope(m, wire.LineLimit-1, d, k, func(pre []byte) ([]byte, error) { return ed25519.Sign(p, pre), nil })
	if e != nil {
		t.Fatal(e)
	}
	return append(b, '\n')
}
func peer(id string) policy.Peer {
	return policy.Peer{ID: id, Pin: "sha256:" + strings.Repeat(map[string]string{"writer": "a", "reader": "b", "admin": "d"}[id], 64)}
}
func (f *fixture) line(t *testing.T, seq int64, prev string, salt string) []byte {
	return f.streamLine(t, "one", seq, prev, salt)
}
func (f *fixture) streamLine(t *testing.T, stream string, seq int64, prev string, salt string) []byte {
	return signed(t, map[string]any{"v": int64(1), "type": "keymaker-state-witness/1", "consumer": "keymaker", "stream": stream, "station": map[string]any{"product": "alpha", "project": "beta", "agent": "gamma"}, "seq": seq, "state_epoch": int64(1), "kind": "intent", "commit_class": "audit", "base_state_digest": nil, "state_digest": records.Digest([]byte("candidate" + salt)), "prev_hash": prev, "intent_hash": nil}, f.recordKey, f.recordPrivate, records.RecordDomain)
}
func newFixture(t *testing.T, calls store.Calls, extra ...string) *fixture {
	t.Helper()
	rk, rp := key(17, records.Writer)
	wk, wp := key(19, records.Witness)
	ak, ap := key(23, records.Admin)
	b, e := wire.DecodeBinding(canonical(t, map[string]any{"service": "witness", "stream": "one", "consumer": "keymaker", "identity": map[string]any{"product": "alpha", "project": "beta", "agent": "gamma"}, "lineage": "lineage", "profile": "keymaker-state-witness/1", "writer_epoch": int64(1), "writer_id": "writer", "record_key": map[string]any{"public_key": rk.Public, "key_id": rk.ID, "key_epoch": rk.Epoch, "purpose": int64(3)}, "transport_pins": []any{peer("writer").Pin}, "readers": []any{map[string]any{"id": "reader", "transport_pins": []any{peer("reader").Pin}}}}))
	if e != nil {
		t.Fatal(e)
	}
	p := policy.Snapshot{Service: "witness", Bindings: []wire.Binding{b}, Principals: []policy.Principal{{ID: "writer", Role: policy.Writer, Pins: []string{peer("writer").Pin}}, {ID: "reader", Role: policy.Reader, Pins: []string{peer("reader").Pin}}, {ID: "admin", Role: policy.Administrator, Pins: []string{peer("admin").Pin}}}}
	for _, stream := range extra {
		v, e := wire.Parse(b.Bytes(), wire.LineLimit)
		if e != nil {
			t.Fatal(e)
		}
		m := v.(map[string]any)
		m["stream"] = stream
		other, e := wire.DecodeBinding(canonical(t, m))
		if e != nil {
			t.Fatal(e)
		}
		p.Bindings = append(p.Bindings, other)
	}
	if e = p.Validate(); e != nil {
		t.Fatal(e)
	}
	f := &fixture{dir: t.TempDir(), recordKey: rk, recordPrivate: rp, witnessKey: wk, adminKey: ak, adminPrivate: ap, signs: &atomic.Int64{}, calls: calls}
	os.Chmod(f.dir, 0700)
	policyRaw, e := policyBytes(p)
	if e != nil {
		t.Fatal(e)
	}
	initial := state{Version: 1, Policy: policyRaw, Witness: wk, Grants: map[string]string{"one": records.Hash(f.line(t, 1, wire.ZeroHash, ""))}, AuditHash: wire.ZeroHash}
	for _, stream := range extra {
		initial.Grants[stream] = records.Hash(f.streamLine(t, stream, 1, wire.ZeroHash, ""))
	}
	raw, e := encodeState(initial)
	if e != nil {
		t.Fatal(e)
	}
	// Explicit synthetic genesis; the service never infers it from missing files.
	if e = os.WriteFile(filepath.Join(f.dir, store.Hash(raw)+".obj"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	root, e := store.Encode(store.RootMagic, store.Manifest{Service: "witness", Transaction: wire.ZeroHash, Phase: "root", Index: store.Hash(raw), Policy: store.Hash(policyRaw)}, nil)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(f.dir, "root"), root, 0600); e != nil {
		t.Fatal(e)
	}
	stream := "one"
	f.remote = &independent{tuples: map[string]custodian.Tuple{"records:one": {Service: "witness", Chain: "records", Stream: &stream, RecordHash: wire.ZeroHash, ReceiptHash: wire.ZeroHash, ControlHash: wire.ZeroHash}, "controls": {Service: "witness", Chain: "controls", RecordHash: wire.ZeroHash, ReceiptHash: wire.ZeroHash, ControlHash: wire.ZeroHash}}, tail: archive.Tail{Hash: wire.ZeroHash}, index: store.Hash(raw)}
	for _, name := range extra {
		stream := name
		f.remote.tuples["records:"+stream] = custodian.Tuple{Service: "witness", Chain: "records", Stream: &stream, RecordHash: wire.ZeroHash, ReceiptHash: wire.ZeroHash, ControlHash: wire.ZeroHash}
	}
	dir, e := os.Open(f.dir)
	if e != nil {
		t.Fatal(e)
	}
	disk, e := store.Inspect(dir, "witness", calls)
	if e != nil {
		t.Fatal(e)
	}
	f.s = &Service{disk: disk, state: initial, policy: p, deps: dependencies{f.remote, f.remote, syntheticExclusion{}, f.remote, syntheticTime{}}, admin: ak, signers: map[string]records.Signer{wk.Public: func(b []byte) ([]byte, error) { f.signs.Add(1); return ed25519.Sign(wp, b), nil }}, instance: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7}, 16)), streams: map[string]*sync.Mutex{}}
	t.Cleanup(func() { disk.Close() })
	return f
}
func (f *fixture) append(t *testing.T) ([]byte, error) {
	t.Helper()
	return f.s.Append(context.Background(), peer("writer"), "one", strings.Repeat("1", 32), Head{Hash: wire.ZeroHash}, f.line(t, 1, wire.ZeroHash, ""))
}
func (f *fixture) reopen(t *testing.T) *Service {
	t.Helper()
	dir, e := os.Open(f.dir)
	if e != nil {
		t.Fatal(e)
	}
	d, e := store.Inspect(dir, "witness", store.Calls{})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { d.Close() })
	_, m := d.Snapshot()
	raw, e := d.ReadObject(m.Index)
	if e != nil {
		t.Fatal(e)
	}
	st, e := decodeState(raw)
	if e != nil {
		t.Fatal(e)
	}
	p, e := snapshot(st.Policy)
	if e != nil {
		t.Fatal(e)
	}
	return &Service{disk: d, state: st, policy: p, deps: f.s.deps, admin: f.s.admin, signers: f.s.signers, instance: f.s.instance, streams: map[string]*sync.Mutex{}}
}
func want(t *testing.T, e error, code string, claim string) {
	t.Helper()
	if wire.Code(e) != code {
		t.Fatalf("%s: want %s got %v", claim, code, e)
	}
}

// Wrong expected head and gaps never append. Concurrent requests have one winner;
// clean busy losers retry and then see head_conflict. Reopen retains the winner.
func TestCASRejectsGapAndConcurrentLoser(t *testing.T) {
	f := newFixture(t, store.Calls{})
	_, e := f.s.Append(context.Background(), peer("writer"), "one", strings.Repeat("1", 32), Head{Seq: 1, Hash: wire.ZeroHash}, f.line(t, 1, wire.ZeroHash, ""))
	want(t, e, "head_conflict", "CAS expected predecessor")
	_, e = f.s.Append(context.Background(), peer("writer"), "one", strings.Repeat("1", 32), Head{Hash: wire.ZeroHash}, f.line(t, 2, wire.ZeroHash, ""))
	want(t, e, "head_conflict", "gap rejected")
	if _, e = f.append(t); e != nil {
		t.Fatal(e)
	}
	s := f.reopen(t)
	if len(s.state.Entries) != 1 {
		t.Fatal("one retained effect after reopen")
	}
	_, e = s.Append(context.Background(), peer("writer"), "one", strings.Repeat("1", 32), Head{Hash: wire.ZeroHash}, f.line(t, 2, wire.ZeroHash, ""))
	want(t, e, "head_conflict", "concurrent loser cannot add gap")
	g := newFixture(t, store.Calls{})
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Go(func() { _, e := g.append(t); results <- e })
	}
	wg.Wait()
	close(results)
	success := 0
	for e := range results {
		if e == nil {
			success++
		} else {
			want(t, e, "busy", "bounded concurrency")
		}
	}
	if success < 1 || len(g.s.state.Entries) != 1 {
		t.Fatal("concurrent one stored effect")
	}
	// Two distinct signed continuations race for the same next position.
	h := newFixture(t, store.Calls{})
	if _, e := h.append(t); e != nil {
		t.Fatal(e)
	}
	prev := h.s.state.Entries[0].Record
	lines := make([][]byte, 2)
	for j := range 2 {
		v, _ := wire.Line(h.line(t, 2, prev, fmt.Sprint(j)))
		body := v.(map[string]any)["body"].(map[string]any)
		body["base_state_digest"] = records.Digest([]byte("base"))
		lines[j] = signed(t, body, h.recordKey, h.recordPrivate, records.RecordDomain)
	}
	compete := make(chan error, 2)
	for j := range 2 {
		wg.Go(func() {
			_, e := h.s.Append(context.Background(), peer("writer"), "one", strings.Repeat("5", 32), Head{Seq: 1, Hash: prev}, lines[j])
			compete <- e
		})
	}
	wg.Wait()
	close(compete)
	winners := 0
	for e := range compete {
		if e == nil {
			winners++
		} else if wire.Code(e) != "busy" && wire.Code(e) != "position_conflict" {
			t.Fatal("distinct concurrent loser", e)
		}
	}
	if winners != 1 || len(h.s.state.Entries) != 2 {
		t.Fatal("distinct concurrent CAS must have exactly one winner")
	}

}

// Equality is exact LF-inclusive bytes AND original predecessor. Current writer
// policy rotation does not rewrite historical receipt or invoke its signer again.
func TestOccupiedPositionRequiresExactBytesAndPredecessor(t *testing.T) {
	// A modeled digest collision isolates exact-byte comparison; no real SHA collision is claimed.
	if exactOriginal([]byte("a\n"), []byte("b\n"), true) || !exactOriginal([]byte("a\n"), []byte("a\n"), true) {
		t.Fatal("digest equality cannot replace exact bytes")
	}

	f := newFixture(t, store.Calls{})
	original, e := f.append(t)
	if e != nil {
		t.Fatal(e)
	}
	signs := f.signs.Load()
	_, e = f.s.Append(context.Background(), peer("writer"), "one", strings.Repeat("2", 32), Head{Hash: wire.ZeroHash}, f.line(t, 1, wire.ZeroHash, "other"))
	want(t, e, "position_conflict", "different occupied bytes")
	_, e = f.s.Append(context.Background(), peer("writer"), "one", strings.Repeat("2", 32), Head{Seq: 1, Hash: wire.ZeroHash}, f.line(t, 1, wire.ZeroHash, ""))
	want(t, e, "head_conflict", "original predecessor retained")
	f.s = f.reopen(t)
	beforeRetryAudit := f.s.state.AuditSeq
	for range 2 {
		retry, e := f.append(t)
		if e != nil || !bytes.Equal(retry, original) {
			t.Fatal("original receipt retry", e)
		}
	}
	if f.signs.Load() != signs || len(f.s.state.Entries) != 1 || f.s.state.AuditSeq != beforeRetryAudit+2 {
		t.Fatal("retry creates no new receipt and audits lookup")
	}
	// Model a protected current writer-policy epoch change, leaving record key.
	b := f.s.policy.Bindings[0]
	v, _ := wire.Parse(b.Bytes(), wire.LineLimit)
	bm := v.(map[string]any)
	bm["writer_epoch"] = int64(2)
	rotated, e := wire.DecodeBinding(canonical(t, bm))
	if e != nil {
		t.Fatal(e)
	}
	f.s.policy.Bindings[0] = rotated
	f.s.state.Policy, e = policyBytes(f.s.policy)
	if e != nil {
		t.Fatal(e)
	}
	got, e := f.append(t)
	if e != nil || !bytes.Equal(got, original) || f.signs.Load() != signs {
		t.Fatal("post-writer-rotation original receipt", e)
	}
}

// Each injected real-call barrier blocks response until it completes. Failing
// it preserves evidence and fences uncertain work; this is not power-loss proof.
func TestPreparedReceiptCannotEscapeBarriers(t *testing.T) {
	type event struct{ op, name string }
	var trace []event
	n := store.NativeCalls()
	record := func(op, name string) { trace = append(trace, event{op, name}) }
	c := store.Calls{Write: func(f *os.File, b []byte) (int, error) { record("write", f.Name()); return n.Write(f, b) }, Sync: func(f *os.File) error { record("sync", f.Name()); return n.Sync(f) }, Close: func(f *os.File) error { record("close", f.Name()); return n.Close(f) }, Rename: func(f *os.File, a, b string, r bool) error { record("rename", b); return n.Rename(f, a, b, r) }, SyncDir: func(f *os.File) error { record("dirsync", "directory"); return n.SyncDir(f) }}
	f := newFixture(t, c)
	if _, e := f.append(t); e != nil {
		t.Fatal(e)
	}
	for i, event := range trace {
		expected := []string{"write", "sync", "close", "rename", "dirsync"}[i%5]
		if event.op != expected {
			t.Fatalf("full barrier order: call %d want %s got %s", i, expected, event.op)
		}
	}
	if len(trace)%5 != 0 {
		t.Fatal("full barrier order: missing final directory sync")
	}
	for j := 0; j < len(trace); j++ {
		t.Run(fmt.Sprintf("call-%02d-%s", j, trace[j].op), func(t *testing.T) {
			count := 0
			entered, release := make(chan struct{}), make(chan struct{})
			step := func() error {
				hit := count == j
				count++
				if hit {
					close(entered)
					<-release
					return errors.New("injected call failure")
				}
				return nil
			}
			calls := store.Calls{Write: func(f *os.File, b []byte) (int, error) {
				if e := step(); e != nil {
					return 0, e
				}
				return n.Write(f, b)
			}, Sync: func(f *os.File) error {
				if e := step(); e != nil {
					return e
				}
				return n.Sync(f)
			}, Close: func(f *os.File) error {
				if e := step(); e != nil {
					f.Close()
					return e
				}
				return n.Close(f)
			}, Rename: func(f *os.File, a, b string, r bool) error {
				if e := step(); e != nil {
					return e
				}
				return n.Rename(f, a, b, r)
			}, SyncDir: func(f *os.File) error {
				if e := step(); e != nil {
					return e
				}
				return n.SyncDir(f)
			}}
			g := newFixture(t, calls)
			result := make(chan error, 1)
			go func() { _, e := g.append(t); result <- e }()
			select {
			case <-entered:
			case e := <-result:
				t.Fatal("required barrier was not reached", e)
			case <-time.After(3 * time.Second):
				t.Fatal("barrier setup timeout")
			}
			select {
			case e := <-result:
				t.Fatal("prepared receipt escaped blocked barrier", e)
			default:
			}
			close(release)
			e := <-result
			want(t, e, "outcome_unknown", "barrier uncertainty dominates")
			want(t, g.s.Ready(), "storage_unavailable", "barrier failure fences")
		})
	}
	for _, which := range []string{"custody", "archive"} {
		t.Run(which, func(t *testing.T) {
			g := newFixture(t, store.Calls{})
			g.remote.failCustody = which == "custody"
			g.remote.failArchive = which == "archive"
			_, e := g.append(t)
			want(t, e, "outcome_unknown", "external barrier holds receipt")
			if len(g.s.state.Entries) != 0 {
				t.Fatal("no prepared publication")
			}
		})
	}
}

// Audit/archive failure prevents append or retry release; recursion is rejected
// before lock acquisition, and a retry consumes an audit slot but not a receipt.
func TestAuditFailureClosesAdmissionWithoutRecursion(t *testing.T) {
	f := newFixture(t, store.Calls{})
	f.remote.failArchive = true
	_, e := f.append(t)
	want(t, e, "outcome_unknown", "audit failure blocks release")
	g := newFixture(t, store.Calls{})
	if _, e = g.append(t); e != nil {
		t.Fatal(e)
	}
	count := g.signs.Load()
	g.remote.failArchive = true
	_, e = g.append(t)
	want(t, e, "storage_unavailable", "retry requires durable audit")
	if g.signs.Load() != count {
		t.Fatal("retry signer was invoked")
	}
	h := newFixture(t, store.Calls{})
	h.remote.callback = func() {
		h.remote.callback = nil
		_, e := h.append(t)
		want(t, e, "busy", "audit append recursion denied")
	}
	if _, e = h.append(t); e != nil {
		t.Fatal(e)
	}
	// The pure codec separately proves exhaustion independently of root readiness.
	_, _, e = audit.New(audit.Tail{Seq: wire.MaxInt, Hash: wire.ZeroHash}, audit.Fields{})
	want(t, e, "sequence_exhausted", "audit safe integer exhaustion")
	z := newFixture(t, store.Calls{})
	// Isolate the exhausted protected counter: admission must stop before any
	// independent callback, signer or filesystem work, without a reset.
	z.s.state.AuditSeq = wire.MaxInt
	_, e = z.append(t)
	want(t, e, "sequence_exhausted", "audit exhaustion closes admission")
	want(t, z.s.Ready(), "storage_unavailable", "audit exhausted readiness")
	if z.signs.Load() != 0 || z.s.state.AuditSeq != wire.MaxInt {
		t.Fatal("exhaustion performed work or reset")
	}
	want(t, (audit.ClosedReader{}).AuthorizeAudit("reader", peer("reader").Pin), "not_authorized", "stream reader cannot read global audit")
}

// Logical reserve/history exhaustion is pre-work backpressure with no deletion.
// Coherent local rollback is rejected by independent archive/custody facts.
func TestStorageReserveAndRetentionFailClosed(t *testing.T) {
	f := newFixture(t, store.Calls{})
	oldFiles := map[string][]byte{}
	names, _ := os.ReadDir(f.dir)
	for _, name := range names {
		oldFiles[name.Name()], _ = os.ReadFile(filepath.Join(f.dir, name.Name()))
	}
	if _, e := f.append(t); e != nil {
		t.Fatal(e)
	}
	// Restore the entire isolated fixture, so local checksums and inventory agree.
	f.s.disk.Close()
	names, _ = os.ReadDir(f.dir)
	for _, name := range names {
		if _, ok := oldFiles[name.Name()]; !ok {
			if e := os.Remove(filepath.Join(f.dir, name.Name())); e != nil {
				t.Fatal(e)
			}
		}
	}
	for name, b := range oldFiles {
		if e := os.WriteFile(filepath.Join(f.dir, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	f.s = f.reopen(t)
	_, e := f.append(t)
	want(t, e, "storage_unavailable", "local hash alone cannot accept rollback")
	if f.signs.Load() != 1 {
		t.Fatal("rollback must be rejected before work")
	}
	g := newFixture(t, store.Calls{})
	if _, e := g.append(t); e != nil {
		t.Fatal(e)
	}
	g.s.state.HistoryBytes = 100 << 30
	before, _ := g.s.disk.Snapshot()
	_, e = g.append(t)
	want(t, e, "storage_unavailable", "capacity preflight closes without mutation")
	after, _ := g.s.disk.Snapshot()
	if !bytes.Equal(before, after) || len(g.s.state.Entries) != 1 {
		t.Fatal("full history must not be deleted")
	}
	h := newFixture(t, store.Calls{})
	h.s.deps.custody = custodian.Closed{}
	before, _ = h.s.disk.Snapshot()
	_, e = h.append(t)
	want(t, e, "storage_unavailable", "no qualified custodian before work")
	after, _ = h.s.disk.Snapshot()
	if !bytes.Equal(before, after) || h.signs.Load() != 0 {
		t.Fatal("closed custodian caused work")
	}
	unauth := peer("reader")
	_, e = h.s.Append(context.Background(), unauth, "one", strings.Repeat("1", 32), Head{Hash: wire.ZeroHash}, []byte("bad"))
	want(t, e, "not_authorized", "authorization precedes inner evidence")
}

// A witness-key action keeps its old-key receipt and history until one root
// publishes policy and audit. A failed external barrier activates neither half.
func TestAdminActivationIsAtomicWithHistory(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			f := newFixture(t, store.Calls{})
			nk, np := key(29, records.Witness)
			nk.Epoch = 2
			n := map[string]any{"service": "witness", "key_epoch": nk.Epoch, "key_id": nk.ID, "public_key": nk.Public}
			pre, e := records.Preimage(n, records.TransitionDomain)
			if e != nil {
				t.Fatal(e)
			}
			n["proof"] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(np, pre))
			old := canonical(t, map[string]any{"service": "witness", "key_epoch": f.witnessKey.Epoch, "key_id": f.witnessKey.ID, "public_key": f.witnessKey.Public})
			line := signed(t, map[string]any{"v": int64(1), "service": "witness", "seq": int64(1), "prev_hash": wire.ZeroHash, "action_id": strings.Repeat("a", 32), "operation": "rotate_witness", "stream": nil, "expected_binding_hash": records.Digest(old), "new_binding": n, "expected_head": nil, "bootstrap_hash": nil}, f.adminKey, f.adminPrivate, records.AdminDomain)
			f.s.signers[nk.Public] = func(pre []byte) ([]byte, error) { return ed25519.Sign(np, pre), nil }
			f.remote.failCustody = fail
			receipt, e := f.s.Admin(context.Background(), peer("admin"), strings.Repeat("3", 32), line, policy.AdministrativeEvidence{})
			if fail {
				want(t, e, "outcome_unknown", "control acknowledgement required")
				if f.s.state.Witness.Public != f.witnessKey.Public || len(f.s.state.Actions) != 0 {
					t.Fatal("new key activated before control ack")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			if e = evidence.VerifyControlReceipt(receipt, line, f.adminKey, f.witnessKey); e != nil {
				t.Fatal("old-key original control receipt", e)
			}
			proofOriginal, e := f.s.disk.ReadObject(f.s.state.Actions[0].Proof)
			if e != nil {
				t.Fatal("administrative proof originals retained", e)
			}
			if f.s.state.Witness.Public != nk.Public {
				t.Fatal("new key not atomically activated")
			}
			f.s = f.reopen(t)
			proofReopened, e := f.s.disk.ReadObject(f.s.state.Actions[0].Proof)
			if e != nil || !bytes.Equal(proofOriginal, proofReopened) {
				t.Fatal("exact administrative proof reopen", e)
			}
			again, e := f.s.Admin(context.Background(), peer("admin"), strings.Repeat("4", 32), line, policy.AdministrativeEvidence{})
			if e != nil || !bytes.Equal(again, receipt) {
				t.Fatal("exact retained admin replay", e)
			}
		})
	}
}

// Distinct stream appends, an original retry and a refused read all publish
// one service-wide audit tail without adding a record for the lookup/read.
func TestAuditClosedServiceStreams(t *testing.T) {
	f := newFixture(t, store.Calls{}, "two")
	first, e := f.append(t)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.Append(context.Background(), peer("writer"), "two", strings.Repeat("6", 32), Head{Hash: wire.ZeroHash}, f.streamLine(t, "two", 1, wire.ZeroHash, "")); e != nil {
		t.Fatal(e)
	}
	again, e := f.append(t)
	if e != nil || !bytes.Equal(first, again) {
		t.Fatal("global audit retry", e)
	}
	_, e = f.s.Read(context.Background(), peer("reader"), "latest", "two", strings.Repeat("7", 32))
	want(t, e, "profile_unavailable", "read success remains unavailable")
	if len(f.s.state.Entries) != 2 || f.s.state.AuditSeq != 4 || f.remote.tail.Seq != 4 || f.remote.tail.Hash != f.s.state.AuditHash {
		t.Fatal("service-wide audit lost interleaved operation")
	}
	root, _ := f.s.disk.Snapshot()
	var lines [][]byte
	for {
		m, _, e := store.Decode(root, store.RootMagic)
		if e != nil {
			t.Fatal(e)
		}
		if m.Transaction == wire.ZeroHash {
			break
		}
		raw, e := os.ReadFile(filepath.Join(f.dir, m.Segment+".seg"))
		if e != nil {
			t.Fatal(e)
		}
		_, objects, e := store.Decode(raw, store.SegmentMagic)
		if e != nil {
			t.Fatal(e)
		}
		for _, o := range objects {
			if o.Kind == "audit" {
				lines = append(lines, o.Bytes)
			}
		}
		root, e = f.s.disk.ReadObject(m.Prior)
		if e != nil {
			t.Fatal(e)
		}
	}
	tail := audit.Tail{Hash: wire.ZeroHash}
	for j := len(lines) - 1; j >= 0; j-- {
		if e := audit.Validate(lines[j], tail); e != nil {
			t.Fatal("retained global audit predecessor", e)
		}
		tail = audit.Tail{Seq: tail.Seq + 1, Hash: records.Hash(lines[j])}
	}
	if tail.Seq != 4 || tail.Hash != f.remote.tail.Hash {
		t.Fatal("retained global audit tail")
	}
}
