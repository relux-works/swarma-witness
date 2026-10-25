package archive

import (
	"bytes"
	"context"
	"testing"

	"github.com/relux-works/swarma-witness/records"
	"github.com/relux-works/swarma-witness/wire"
)

// This bounded in-memory model is test-only. It has no production retention,
// authority signer, post-restore freshness, SLA or durable one-use guarantee.
type memoryArchive struct {
	objects map[string][]byte
	head    Tail
	anchor  Anchor
	used    bool
}

func (m *memoryArchive) Retain(ctx context.Context, manifest Manifest, expected Tail) (Ack, error) {
	if ctx.Err() != nil || expected != m.head || manifest.Previous != expected {
		return Ack{}, wire.Refuse("storage_unavailable")
	}
	if len(manifest.Objects) > 16 {
		return Ack{}, wire.Refuse("limit_exceeded")
	}
	for _, o := range manifest.Objects {
		if len(o.Bytes) > 4096 || records.Hash(o.Bytes) != o.Hash {
			return Ack{}, wire.Refuse("evidence_invalid")
		}
	}
	for _, o := range manifest.Objects {
		m.objects[o.Hash] = append([]byte(nil), o.Bytes...)
	}
	m.head = manifest.Next
	return Ack{Original: []byte("synthetic retained acknowledgement")}, nil
}
func (m *memoryArchive) Retrieve(ctx context.Context, q Query) ([]byte, error) {
	b, ok := m.objects[q.Hash]
	if ctx.Err() != nil || !ok || int64(len(b)) != q.Length || len(q.Cursor) > 64 || records.Hash(b) != q.Hash {
		return nil, wire.Refuse("storage_unavailable")
	}
	return append([]byte(nil), b...), nil
}
func (m *memoryArchive) VerifyOffline(_ context.Context, old, next Anchor, manifest Manifest, a Approval) (Continuity, error) {
	if old != m.anchor || next.Record.Seq != old.Record.Seq+1 || len(manifest.Objects) != 1 || !bytes.Equal(a.Original, []byte("independent one-use test approval")) || m.used {
		return Continuity{}, wire.Refuse("evidence_invalid")
	}
	if _, e := m.Retrieve(context.Background(), Query{Hash: manifest.Objects[0].Hash, Length: int64(len(manifest.Objects[0].Bytes))}); e != nil {
		return Continuity{}, e
	}
	return Continuity{Original: []byte(next.Record.Hash)}, nil
}
func (m *memoryArchive) AdvanceAnchor(_ context.Context, old Anchor, c Continuity, h CompleteHead, a Approval) (DurableAnchor, error) {
	if old != m.anchor || m.used || !bytes.Equal(a.Original, []byte("independent one-use test approval")) || !bytes.Equal(h.Original, c.Original) || len(h.Original) != 64 {
		return DurableAnchor{}, wire.Refuse("evidence_invalid")
	}
	m.used = true
	m.anchor.Record = Tail{Seq: old.Record.Seq + 1, Hash: string(c.Original)}
	return DurableAnchor{Original: append([]byte(nil), c.Original...)}, nil
}

// Exact retrieval preserves LF and checks length/hash. Archive bytes alone
// cannot advance a consumer anchor; modeled approval, continuity and fresh head
// are separate prerequisites, and a used approval cannot advance twice.
func TestArchiveExactRetrievalAndSeparateAnchor(t *testing.T) {
	ctx := context.Background()
	m := &memoryArchive{objects: map[string][]byte{}, head: Tail{Hash: wire.ZeroHash}}
	var consumer Consumer = m
	raw := []byte("exact original\n")
	hash := records.Hash(raw)
	manifest := Manifest{Previous: m.head, Next: Tail{Seq: 1, Hash: hash}, Objects: []Object{{Kind: "record", Hash: hash, Bytes: raw}}}
	if _, e := consumer.Retain(ctx, manifest, m.head); e != nil {
		t.Fatal(e)
	}
	got, e := consumer.Retrieve(ctx, Query{Hash: hash, Length: int64(len(raw))})
	if e != nil || !bytes.Equal(got, raw) {
		t.Fatal("exact archive retrieval", e)
	}
	got[0] = 'X'
	again, _ := consumer.Retrieve(ctx, Query{Hash: hash, Length: int64(len(raw))})
	if !bytes.Equal(again, raw) {
		t.Fatal("archive ownership")
	}
	if _, e = consumer.Retrieve(ctx, Query{Hash: hash, Length: int64(len(raw) - 1)}); wire.Code(e) != "storage_unavailable" {
		t.Fatal("retrieval expected length", e)
	}
	old := m.anchor
	next := old
	next.Record = manifest.Next
	if _, e = consumer.AdvanceAnchor(ctx, old, Continuity{}, CompleteHead{}, Approval{}); wire.Code(e) != "evidence_invalid" || m.anchor != old {
		t.Fatal("archive alone advanced anchor", e)
	}
	approval := Approval{Original: []byte("independent one-use test approval")}
	c, e := consumer.VerifyOffline(ctx, old, next, manifest, approval)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = consumer.AdvanceAnchor(ctx, old, c, CompleteHead{Original: []byte(wire.ZeroHash)}, approval); wire.Code(e) != "evidence_invalid" || m.anchor != old {
		t.Fatal("fresh head required", e)
	}
	if _, e = consumer.AdvanceAnchor(ctx, old, c, CompleteHead{Original: []byte(hash)}, approval); e != nil {
		t.Fatal(e)
	}
	if _, e = consumer.AdvanceAnchor(ctx, m.anchor, c, CompleteHead{Original: []byte(hash)}, approval); wire.Code(e) != "evidence_invalid" {
		t.Fatal("approval replay", e)
	}
	m.objects[hash][0] = 'X'
	if _, e = consumer.Retrieve(ctx, Query{Hash: hash, Length: int64(len(raw))}); wire.Code(e) != "storage_unavailable" {
		t.Fatal("corrupt archive", e)
	}
}

// Production archive interfaces have no accepting implementation or WS route.
func TestArchiveDefaultsClosed(t *testing.T) {
	c := Closed{}
	ctx := context.Background()
	_, a := c.Retain(ctx, Manifest{}, Tail{})
	_, b := c.Retrieve(ctx, Query{})
	_, d := c.VerifyOffline(ctx, Anchor{}, Anchor{}, Manifest{}, Approval{})
	_, e := c.AdvanceAnchor(ctx, Anchor{}, Continuity{}, CompleteHead{}, Approval{})
	for _, err := range []error{a, b, c.CheckAudit(ctx, "svc", Tail{}), c.VerifyAudit(Manifest{}, Ack{})} {
		if wire.Code(err) != "storage_unavailable" {
			t.Fatal(err)
		}
	}
	for _, err := range []error{d, e} {
		if wire.Code(err) != "profile_unavailable" {
			t.Fatal(err)
		}
	}
}
