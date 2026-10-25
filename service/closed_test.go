package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/relux-works/swarma-witness/policy"
	"os"
	"testing"

	"github.com/relux-works/swarma-witness/custodian"
	"github.com/relux-works/swarma-witness/store"
	"github.com/relux-works/swarma-witness/wire"
)

// Qualified time, exclusion and recovery stay absent in production. Synthetic
// dependencies isolate each pre-work refusal; none is a qualification fixture.
func TestServiceDependenciesStayClosed(t *testing.T) {
	for _, name := range []string{"time", "exclusion", "recovery"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, store.Calls{})
			before, _ := f.s.disk.Snapshot()
			switch name {
			case "time":
				f.s.deps.time = custodian.ClosedTime{}
			case "exclusion":
				f.s.deps.exclusion = custodian.ClosedExclusion{}
			case "recovery":
				f.s.deps.recovery = custodian.ClosedRecovery{}
			}
			_, e := f.append(t)
			if wire.Code(e) != "profile_unavailable" {
				t.Fatal("closed dependency", e)
			}
			after, _ := f.s.disk.Snapshot()
			if !bytes.Equal(before, after) || len(f.s.state.Entries) != 0 {
				t.Fatal("unqualified dependency published")
			}
		})
	}
	ctx := context.Background()
	c := custodian.ClosedTime{}
	if _, e := c.Prepare(ctx, "tx"); wire.Code(e) != "profile_unavailable" {
		t.Fatal(e)
	}
	if wire.Code(c.Publish(ctx, "tx")) != "profile_unavailable" || wire.Code(c.Release(ctx, "tx")) != "profile_unavailable" {
		t.Fatal("time authority")
	}
}

// A failed file-sync leaves explicit unpublished evidence. Reopening detects
// that inventory instead of silently serving the old root; no repair is tried.
func TestPreparedReopenRejectsUnpublishedEvidence(t *testing.T) {
	f := newFixture(t, store.Calls{Sync: func(*os.File) error { return errors.New("injected sync failure") }})
	_, e := f.append(t)
	if wire.Code(e) != "outcome_unknown" {
		t.Fatal(e)
	}
	f.s.disk.Close()
	dir, e := os.Open(f.dir)
	if e != nil {
		t.Fatal(e)
	}
	if d, e := store.Inspect(dir, "witness", store.Calls{}); wire.Code(e) != "storage_unavailable" {
		if d != nil {
			d.Close()
		}
		t.Fatal("unpublished evidence accepted", e)
	}
}

// The local evidence closure keeps original consent/packet/object bytes and
// rejects an over-cap closure before store preparation. It grants no approval.
func TestAdminActivationProofClosure(t *testing.T) {
	p := policy.AdministrativeEvidence{Consent: []byte("consent\n"), FirstLine: []byte("record\n"), Packet: []byte("packet"), Objects: map[string][]byte{"object": []byte("original")}}
	raw, e := retainAdminProof(p)
	if e != nil {
		t.Fatal(e)
	}
	var envelope struct {
		Version  int64                         `json:"v"`
		Evidence policy.AdministrativeEvidence `json:"evidence"`
	}
	if e = json.Unmarshal(raw, &envelope); e != nil || envelope.Version != 1 || !bytes.Equal(envelope.Evidence.Consent, p.Consent) || !bytes.Equal(envelope.Evidence.FirstLine, p.FirstLine) || !bytes.Equal(envelope.Evidence.Packet, p.Packet) || !bytes.Equal(envelope.Evidence.Objects["object"], p.Objects["object"]) {
		t.Fatal("exact admin proof closure", e)
	}
	p.Objects["oversized"] = make([]byte, store.SegmentLimit+1)
	if _, e = retainAdminProof(p); wire.Code(e) != "limit_exceeded" {
		t.Fatal("admin proof cap", e)
	}
}
