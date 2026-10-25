package store

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-witness/wire"
)

// Private synthetic genesis enables only local filesystem checks, not service readiness.
func reviewerDisk(t *testing.T, calls Calls) (*Disk, string) {
	t.Helper()
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	raw := []byte("synthetic index")
	root, e := Encode(RootMagic, Manifest{Service: "test", Transaction: wire.ZeroHash, Phase: "root", Index: Hash(raw)}, nil)
	if e != nil {
		t.Fatal(e)
	}
	for name, b := range map[string][]byte{"root": root, Hash(raw) + ".obj": raw} {
		if e := os.WriteFile(filepath.Join(dir, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	fd, e := os.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	d, e := Inspect(fd, "test", calls)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { d.Close() })
	return d, dir
}
func reviewerNext(d *Disk) (Manifest, []Object) {
	root, _ := d.Snapshot()
	index := []byte("next index")
	return Manifest{Service: "test", Transaction: Hash([]byte("tx")), Prior: Hash(root), Index: Hash(index), AuditSeq: 1, Audit: Hash([]byte("audit"))}, []Object{{Kind: "index", Bytes: index}}
}

// Public Prepare must stop before rename when a close reports failure; the
// paired complete transaction must publish and reopen byte-identically.
func TestReviewerCheckedCloseBeforeRename(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid", true: "close-error"}[fail], func(t *testing.T) {
			n := NativeCalls()
			renames := 0
			c := Calls{Close: func(f *os.File) error {
				e := n.Close(f)
				if e != nil {
					return e
				}
				if fail {
					return errors.New("review close fault")
				}
				return nil
			}, Rename: func(f *os.File, a, b string, r bool) error { renames++; return n.Rename(f, a, b, r) }}
			d, dir := reviewerDisk(t, c)
			before, _ := d.Snapshot()
			m, objects := reviewerNext(d)
			p, e := d.Prepare(m, objects)
			if fail {
				after, _ := d.Snapshot()
				if wire.Code(e) != "storage_unavailable" || p != nil || renames != 0 || !bytes.Equal(before, after) {
					t.Fatalf("checked close must precede any rename: error=%v renames=%d prepared=%v", e, renames, p != nil)
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			if e = d.Publish(p, nil); e != nil {
				t.Fatal(e)
			}
			expected, _ := d.Snapshot()
			fd, e := os.Open(dir)
			if e != nil {
				t.Fatal(e)
			}
			reopened, e := Inspect(fd, "test", Calls{})
			if e != nil {
				t.Fatal(e)
			}
			defer reopened.Close()
			actual, _ := reopened.Snapshot()
			if !bytes.Equal(actual, expected) {
				t.Fatal("valid root lost")
			}
		})
	}
}

// Corrupt or unpublished local fixture bytes must refuse public Inspect;
// this is local integrity checking and does not establish independent recovery.
func TestReviewerReopenDamage(t *testing.T) {
	for _, kind := range []string{"truncated-root", "changed-object", "unexpected-file", "unpublished-stage", "linked-object"} {
		t.Run(kind, func(t *testing.T) {
			d, dir := reviewerDisk(t, Calls{})
			m, objects := reviewerNext(d)
			p, e := d.Prepare(m, objects)
			if e != nil {
				t.Fatal(e)
			}
			if e = d.Publish(p, nil); e != nil {
				t.Fatal(e)
			}
			_, head := d.Snapshot()
			switch kind {
			case "truncated-root":
				b, e := os.ReadFile(filepath.Join(dir, "root"))
				if e != nil {
					t.Fatal(e)
				}
				e = os.WriteFile(filepath.Join(dir, "root"), b[:len(b)-1], 0600)
				if e != nil {
					t.Fatal(e)
				}
			case "changed-object":
				if e = os.WriteFile(filepath.Join(dir, head.Index+".obj"), []byte("changed"), 0600); e != nil {
					t.Fatal(e)
				}
			case "unexpected-file", "unpublished-stage":
				if e = os.WriteFile(filepath.Join(dir, kind), []byte("pending"), 0600); e != nil {
					t.Fatal(e)
				}
			case "linked-object":
				if e = os.Link(filepath.Join(dir, head.Index+".obj"), filepath.Join(t.TempDir(), "copy")); e != nil {
					t.Fatal(e)
				}
			}
			fd, e := os.Open(dir)
			if e != nil {
				t.Fatal(e)
			}
			got, e := Inspect(fd, "test", Calls{})
			if got != nil {
				got.Close()
			}
			if wire.Code(e) != "storage_unavailable" || got != nil {
				t.Fatalf("damaged %s accepted: %v", kind, e)
			}
		})
	}
}

// Checksummed local fixtures with inconsistent phase links are still damaged.
// Recomputed local checksums model a writer-format defect, not rollback authority.
func TestReviewerPhaseLinksAgreeOnReopen(t *testing.T) {
	for _, which := range []string{"valid", "prepare-segment", "outcome-segment", "outcome-prepare"} {
		t.Run(which, func(t *testing.T) {
			d, dir := reviewerDisk(t, Calls{})
			m, objects := reviewerNext(d)
			p, e := d.Prepare(m, objects)
			if e != nil {
				t.Fatal(e)
			}
			if e = d.Publish(p, nil); e != nil {
				t.Fatal(e)
			}
			root, head := d.Snapshot()
			if which == "valid" {
				fd, e := os.Open(dir)
				if e != nil {
					t.Fatal(e)
				}
				got, e := Inspect(fd, "test", Calls{})
				if e != nil {
					t.Fatal("valid phase closure", e)
				}
				defer got.Close()
				actual, _ := got.Snapshot()
				if !bytes.Equal(actual, root) {
					t.Fatal("valid phase closure changed root")
				}
				return
			}
			selected := head.Resolution
			if which == "prepare-segment" {
				selected = head.Prepare
			}
			raw, e := os.ReadFile(filepath.Join(dir, selected+".jnl"))
			if e != nil {
				t.Fatal(e)
			}
			journal, objs, e := Decode(raw, JournalMagic)
			if e != nil {
				t.Fatal(e)
			}
			if which == "outcome-prepare" {
				journal.Prepare = Hash([]byte("different prepare"))
			} else {
				journal.Segment = Hash([]byte("different segment"))
			}
			changed, e := Encode(JournalMagic, journal, objs)
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(filepath.Join(dir, Hash(changed)+".jnl"), changed, 0600); e != nil {
				t.Fatal(e)
			}
			if e = os.Remove(filepath.Join(dir, selected+".jnl")); e != nil {
				t.Fatal(e)
			}
			if which == "prepare-segment" {
				head.Prepare = Hash(changed)
				// Keep outcome -> prepare consistent so only prepare -> segment
				// is invalid; another guard must not mask that missing check.
				outcomeRaw, e := os.ReadFile(filepath.Join(dir, head.Resolution+".jnl"))
				if e != nil {
					t.Fatal(e)
				}
				outcome, outObjects, e := Decode(outcomeRaw, JournalMagic)
				if e != nil {
					t.Fatal(e)
				}
				outcome.Prepare = head.Prepare
				outcomeRaw, e = Encode(JournalMagic, outcome, outObjects)
				if e != nil {
					t.Fatal(e)
				}
				if e = os.WriteFile(filepath.Join(dir, Hash(outcomeRaw)+".jnl"), outcomeRaw, 0600); e != nil {
					t.Fatal(e)
				}
				if e = os.Remove(filepath.Join(dir, head.Resolution+".jnl")); e != nil {
					t.Fatal(e)
				}
				head.Resolution = Hash(outcomeRaw)
			} else {
				head.Resolution = Hash(changed)
			}
			root, e = Encode(RootMagic, head, nil)
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(filepath.Join(dir, "root"), root, 0600); e != nil {
				t.Fatal(e)
			}
			fd, e := os.Open(dir)
			if e != nil {
				t.Fatal(e)
			}
			got, e := Inspect(fd, "test", Calls{})
			if got != nil {
				got.Close()
			}
			if wire.Code(e) != "storage_unavailable" || got != nil {
				t.Fatalf("inconsistent %s link accepted on reopen: %v", which, e)
			}
		})
	}
}
