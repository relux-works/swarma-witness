package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The command refuses a private tracking tree with status 1 and a bounded
// category, passes the cleaned module, and requires an explicit check operation.
func TestHygieneCommandRequiresCleanModule(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module github.com/relux-works/swarma-witness\n\ngo 1.26.0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(root, ".task-board")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	var out, errs bytes.Buffer
	if status := run([]string{"-check", "-root", root}, &out, &errs); status != 1 || out.Len() != 0 || !strings.Contains(errs.String(), "hygiene_private_artifact") {
		t.Fatalf("wrong refusal: status=%d out=%q err=%q", status, &out, &errs)
	}
	if err := os.Remove(private); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errs.Reset()
	if status := run([]string{"-check", "-root", root}, &out, &errs); status != 0 || errs.Len() != 0 || !strings.HasPrefix(out.String(), "PASS:") {
		t.Fatalf("clean control: status=%d out=%q err=%q", status, &out, &errs)
	}
	if status := run(nil, &out, &errs); status != 2 {
		t.Fatalf("missing operation: %d", status)
	}
}
