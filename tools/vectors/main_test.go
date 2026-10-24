package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Empty bootstrap integrity succeeds while explicitly leaving conformance
// pending; malformed locks and undeclared data return status 1 without success.
func TestVectorCommandDoesNotClaimConformance(t *testing.T) {
	root := t.TempDir()
	corpus := filepath.Join(root, "testdata", "witness-v1")
	if err := os.MkdirAll(corpus, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(corpus, "manifest.json"), []byte(`{"schema":1,"files":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	if status := run([]string{"-check", "-root", root}, &out, &errs); status != 0 || errs.Len() != 0 || !strings.Contains(out.String(), "0 vectors") || !strings.Contains(out.String(), "PENDING:") {
		t.Fatalf("empty control: status=%d out=%q err=%q", status, &out, &errs)
	}
	lock := filepath.Join(t.TempDir(), "lock.json")
	if err := os.WriteFile(lock, []byte("not-json"), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errs.Reset()
	if status := run([]string{"-check", "-root", root, "-lock", lock}, &out, &errs); status != 1 || out.Len() != 0 || errs.String() != "vector_lock_invalid\n" {
		t.Fatalf("wrong lock refusal: status=%d out=%q err=%q", status, &out, &errs)
	}
	if err := os.WriteFile(filepath.Join(corpus, "unlisted.bin"), []byte("public"), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errs.Reset()
	if status := run([]string{"-check", "-root", root}, &out, &errs); status != 1 || out.Len() != 0 || !strings.Contains(errs.String(), "vector_undeclared") {
		t.Fatalf("wrong data refusal: status=%d out=%q err=%q", status, &out, &errs)
	}
}
