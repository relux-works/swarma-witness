//go:build linux && amd64

package store

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-witness/wire"
)

// Isolated descriptor fixtures test local barriers and descriptor validation,
// not ancestor custody, independent rollback detection or device persistence.
func TestStorageProtectedFilesAndShortWrites(t *testing.T) {
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	fd, e := os.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer fd.Close()
	n := NativeCalls()
	d := &Disk{dir: fd, calls: n}
	d.calls.Write = func(f *os.File, b []byte) (int, error) {
		if len(b) > 3 {
			b = b[:3]
		}
		return n.Write(f, b)
	}
	original := []byte("complete exact bytes")
	if e = d.install("good", original, false); e != nil {
		t.Fatal(e)
	}
	got, e := d.read("good", 100)
	if e != nil || !bytes.Equal(got, original) {
		t.Fatal("short writes lost bytes", e)
	}
	if e = d.install("good", []byte("changed"), false); wire.Code(e) != "storage_unavailable" {
		t.Fatal("immutable conflict", e)
	}
	d.calls.Write = func(*os.File, []byte) (int, error) { return 0, nil }
	if e = d.install("zero", []byte("zero"), false); wire.Code(e) != "storage_unavailable" {
		t.Fatal("zero progress", e)
	}
	if e = os.Symlink("good", filepath.Join(dir, "symbolic")); e != nil {
		t.Fatal(e)
	}
	if _, e = openFile(fd, "symbolic", false); e == nil {
		t.Fatal("symlink accepted")
	}
	if e = os.Link(filepath.Join(dir, "good"), filepath.Join(dir, "hard")); e != nil {
		t.Fatal(e)
	}
	if _, e = openFile(fd, "hard", false); e == nil {
		t.Fatal("hard link accepted")
	}
	if _, e = openFile(fd, "../good", false); e == nil {
		t.Fatal("path traversal accepted")
	}
	wide := filepath.Join(dir, "wide")
	if e = os.WriteFile(wide, original, 0644); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(wide, 0644); e != nil {
		t.Fatal(e)
	}
	info, e := os.Stat(wide)
	if e != nil {
		t.Fatal(e)
	}
	if got := info.Mode().Perm(); got != 0644 {
		t.Fatalf("wide fixture mode = %04o, want 0644", got)
	}
	if _, e = openFile(fd, "wide", false); e == nil {
		t.Fatal("wrong file mode accepted")
	}
	if e = os.Chmod(wide, 0600); e != nil {
		t.Fatal(e)
	}
	protected, e := openFile(fd, "wide", false)
	if e != nil {
		t.Fatal("valid directory and file rejected", e)
	}
	if e = protected.Close(); e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(dir, 0770); e != nil {
		t.Fatal(e)
	}
	if _, e = openFile(fd, "wide", false); e == nil {
		t.Fatal("changed directory mode accepted")
	}
	if _, e = Open(filepath.Join(dir, ".."), "svc", Calls{}); wire.Code(e) != "storage_unavailable" {
		t.Fatal("unclean path", e)
	}
}

// Missing root never creates genesis; a valid checksum cannot excuse unknown
// local versions or object damage. These cases do not model a real power cut.
func TestStorageMissingGenesisAndDamage(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	fd, _ := os.Open(dir)
	if _, e := Inspect(fd, "svc", Calls{}); wire.Code(e) != "storage_unavailable" {
		t.Fatal("missing root inferred genesis", e)
	}
	m := Manifest{Service: "svc", Transaction: wire.ZeroHash, Phase: "root", Index: Hash([]byte("index")), Policy: wire.ZeroHash}
	root, e := Encode(RootMagic, m, nil)
	if e != nil {
		t.Fatal(e)
	}
	root[3] = '2'
	if _, _, e = Decode(root, RootMagic); wire.Code(e) != "storage_unavailable" {
		t.Fatal("version accepted", e)
	}
}
