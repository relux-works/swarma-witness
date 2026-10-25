package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-witness/wire"
)

func timeKey() TimeUseKey {
	return TimeUseKey{Lineage: "test-lineage", Original: strings.Repeat("1", 32), Window: "P", Slot: 1}
}
func allocateUse(t *testing.T, d *Disk) {
	t.Helper()
	root, _ := d.Snapshot()
	if err := d.AllocateTimeUses(Hash(root), []TimeUseKey{timeKey()}); err != nil {
		t.Fatal(err)
	}
}
func admittedUse(t *testing.T, d *Disk) *TimeUseAdmission {
	t.Helper()
	root, _ := d.Snapshot()
	a, err := d.AdmitTimeUse(timeKey(), Hash(root))
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func useData() TimeUse {
	// Storage-codec data only; deliberately not authenticated broker evidence.
	return TimeUse{Key: timeKey(), State: "burned", Revision: 1, Run: "attempt", Epoch: "writer:epoch-42", Intent: []byte("retained native intent"), Handoff: []byte("structural data"), Originals: [][]byte{[]byte("1"), []byte("2"), []byte("3"), []byte("4"), []byte("5")}}
}

// Local metadata retains one stable original key and cannot allocate it twice,
// reset a burn, delete tombstones, or reinterpret a changed handoff as unused.
// This does not authenticate use custody or qualify storage durability.
func TestTimeUseMonotoneTransitions(t *testing.T) {
	d, _ := reviewerDisk(t, Calls{})
	allocateUse(t, d)
	before, _ := d.Snapshot()
	if err := d.AllocateTimeUses(Hash(before), []TimeUseKey{timeKey()}); wire.Code(err) != "storage_unavailable" {
		t.Fatal("duplicate original slot accepted", err)
	}
	a := admittedUse(t, d)
	if err := a.Burn(useData()); err != nil {
		t.Fatal("valid local burn", err)
	}
	if err := a.Burn(useData()); wire.Code(err) != "storage_unavailable" {
		t.Fatal("second burn accepted", err)
	}
	if err := a.Finish("committed", []byte("exact outcome")); err != nil {
		t.Fatal(err)
	}
	if err := a.Finish("held", nil); wire.Code(err) != "storage_unavailable" {
		t.Fatal("terminal disposition overwritten", err)
	}
	a.Release()
	root, _ := d.Snapshot()
	if _, err := d.AdmitTimeUse(timeKey(), Hash(root)); wire.Code(err) != "storage_unavailable" {
		t.Fatal("burned original became unused", err)
	}
	old := []TimeUse{useData()}
	for _, next := range [][]TimeUse{nil, {{Key: timeKey(), State: "unused"}}, {func() TimeUse { u := useData(); u.Revision++; return u }()}} {
		if validTimeUseStep(old, next) {
			t.Fatal("rollback/deletion/revision reset accepted")
		}
	}
}

// Reopen returns status only; an observed durable burn with no outcome remains
// held even if no native effect happened. Ordinary service-root commits inherit
// the use hash and preserve every retained original and burn across reopen.
func TestTimeUseRecoveryAndOwningRoot(t *testing.T) {
	for _, finish := range []bool{false, true} {
		d, dir := reviewerDisk(t, Calls{})
		allocateUse(t, d)
		a := admittedUse(t, d)
		if err := a.Burn(useData()); err != nil {
			t.Fatal(err)
		}
		if finish {
			if err := a.Finish("committed", []byte("original outcome")); err != nil {
				t.Fatal(err)
			}
		}
		a.Release()
		_, prior := d.Snapshot()
		m, objects := reviewerNext(d)
		p, err := d.Prepare(m, objects)
		if err != nil {
			t.Fatal(err)
		}
		if err = d.Publish(p, nil); err != nil {
			t.Fatal(err)
		}
		_, after := d.Snapshot()
		if after.TimeUses != prior.TimeUses || after.TimeUses == "" {
			t.Fatal("owning root erased use metadata")
		}
		fd, err := os.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		reopened, err := Inspect(fd, "test", Calls{})
		if err != nil {
			t.Fatal(err)
		}
		u, err := reopened.TimeUseStatus(timeKey())
		want := "held"
		if finish {
			want = "committed"
		}
		if err != nil || u.State != want || !bytes.Equal(u.Handoff, useData().Handoff) {
			t.Fatal("recovery must retain exact burned status", err, u.State)
		}
		root, _ := reopened.Snapshot()
		if _, err = reopened.AdmitTimeUse(timeKey(), Hash(root)); wire.Code(err) != "storage_unavailable" {
			t.Fatal("restart authorized redispatch", err)
		}
		reopened.Close()
	}
}

// Each injected local burn barrier fails at that specific call and fences the
// store before releasing L. A subsequent admission refuses; no unknown cut
// returns an unused dispatch capability. Native device/power-loss is PENDING.
func TestTimeUseBurnBarrierFailures(t *testing.T) {
	for _, cut := range []string{"write", "sync", "close", "rename", "directory", "readback"} {
		t.Run(cut, func(t *testing.T) {
			d, _ := reviewerDisk(t, Calls{})
			allocateUse(t, d)
			a := admittedUse(t, d)
			n := NativeCalls()
			injected := errors.New("injected burn barrier")
			hit := false
			switch cut {
			case "write":
				d.calls.Write = func(*os.File, []byte) (int, error) { hit = true; return 0, injected }
			case "sync":
				d.calls.Sync = func(*os.File) error { hit = true; return injected }
			case "close":
				d.calls.Close = func(f *os.File) error { hit = true; _ = n.Close(f); return injected }
			case "rename":
				d.calls.Rename = func(*os.File, string, string, bool) error { hit = true; return injected }
			case "directory":
				d.calls.SyncDir = func(*os.File) error { hit = true; return injected }
			case "readback":
				rootInstalled := false
				d.calls.Rename = func(dir *os.File, old, next string, replace bool) error {
					err := n.Rename(dir, old, next, replace)
					if err == nil && next == "root" {
						rootInstalled = true
					}
					return err
				}
				d.calls.SyncDir = func(dir *os.File) error {
					if err := n.SyncDir(dir); err != nil {
						return err
					}
					if rootInstalled {
						hit = true
						return os.WriteFile(filepath.Join(dir.Name(), "root"), []byte("injected root readback damage"), 0600)
					}
					return nil
				}
			}
			if err := a.Burn(useData()); wire.Code(err) != "storage_unavailable" || !hit || !d.held {
				t.Fatal("unknown burn must fence store at intended barrier", cut, err)
			}
			a.Release()
			root, _ := d.Snapshot()
			if _, err := d.AdmitTimeUse(timeKey(), Hash(root)); wire.Code(err) != "storage_unavailable" {
				t.Fatal("unknown burn admitted replacement", err)
			}
		})
	}
}

// A coherent local successor may not remove retained burns using either JSON
// null or an empty table. Private phase writers plant the inconsistent history;
// normal persistence rejects it earlier. Valid retained history reopens above.
func TestTimeUseReopenRejectsDeletedTable(t *testing.T) {
	for _, empty := range [][]TimeUse{nil, {}} {
		d, dir := reviewerDisk(t, Calls{})
		allocateUse(t, d)
		a := admittedUse(t, d)
		if err := a.Burn(useData()); err != nil {
			t.Fatal(err)
		}
		if err := a.Finish("committed", []byte("original outcome")); err != nil {
			t.Fatal(err)
		}
		a.Release()
		root, m := d.Snapshot()
		b, err := timeUseBytes(empty)
		if err != nil {
			t.Fatal(err)
		}
		m.Prior, m.TimeUses, m.Transaction = Hash(root), Hash(b), Hash([]byte("inconsistent local successor"))
		// Deliberately bypass the normal monotonicity preflight only in this
		// isolated fixture, keeping every checksum and phase link consistent.
		d.mu.Lock()
		p, err := d.prepareLocked(m, []Object{{Kind: "time-use", Bytes: b}})
		if err == nil {
			err = d.publishLocked(p, nil)
		}
		d.mu.Unlock()
		if err != nil {
			t.Fatal("plant must reach reopen", err)
		}
		fd, err := os.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		reopened, err := Inspect(fd, "test", Calls{})
		if reopened != nil {
			reopened.Close()
		}
		if wire.Code(err) != "storage_unavailable" {
			t.Fatal("deleted retained burns must refuse on reopen", err)
		}
	}
}
