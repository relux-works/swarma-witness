package hygiene

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The checker rejects each bounded private-artifact witness without printing its
// contents; the same root passes after removal. This is not universal secret detection.
func TestHygieneRejectsPrivateArtifacts(t *testing.T) {
	cases := map[string]struct{ body, code string }{
		".task-board/state.json": {"{}", "hygiene_private_artifact"},
		"config.txt":             {strings.Join([]string{"-----BEGIN", "PRIVATE KEY-----"}, " "), "hygiene_private_key"},
		"notes.md":               {strings.Join([]string{"", "home", "example", "private"}, "/"), "hygiene_local_path"},
		"identity.txt":           {strings.Join([]string{"worker", "1", "_sample_", "dev", "1"}, ""), "hygiene_identity"},
	}
	for name, example := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, name)
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(example.body), 0600); err != nil {
				t.Fatal(err)
			}
			findings, err := Check(root, nil)
			if err != nil || len(findings) != 1 || findings[0].Code != example.code {
				t.Fatalf("missing private-artifact refusal: %v %v", findings, err)
			}
			for _, f := range findings {
				if strings.Contains(f.String(), example.body) && len(example.body) > 2 {
					t.Fatal("finding echoed private content")
				}
			}
			if err := os.RemoveAll(filepath.Join(root, strings.Split(name, "/")[0])); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("Public bootstrap.\n"), 0600); err != nil {
				t.Fatal(err)
			}
			findings, err = Check(root, nil)
			if err != nil || len(findings) != 0 {
				t.Fatalf("clean positive refused: %v %v", findings, err)
			}
		})
	}
}

// Symlink entries refuse without following their contents; regular files remain
// valid. The caller supplies a trusted, quiescent repository checkout.
func TestHygieneRejectsLinks(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(t.TempDir(), "public.txt")
	if err := os.WriteFile(target, []byte("public"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	findings, err := Check(root, nil)
	if err != nil || len(findings) != 1 || findings[0].Code != "hygiene_link" {
		t.Fatalf("wrong link refusal: %v %v", findings, err)
	}
	if err := os.Remove(filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "linked"), []byte("public"), 0600); err != nil {
		t.Fatal(err)
	}
	findings, err = Check(root, nil)
	if err != nil || len(findings) != 0 {
		t.Fatalf("regular control refused: %v %v", findings, err)
	}
}

// Optional private deny entries flag matching content without echoing it; an
// unrelated public file passes. The deny list itself is never stored in this repo.
func TestHygienePrivateDenyList(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "README.md")
	marker := "synthetic-protected-value"
	if err := os.WriteFile(path, []byte(marker), 0600); err != nil {
		t.Fatal(err)
	}
	findings, err := Check(root, []string{marker})
	if err != nil || len(findings) != 1 || findings[0].Code != "hygiene_private_value" {
		t.Fatalf("missing deny refusal: %v %v", findings, err)
	}
	if strings.Contains(findings[0].String(), marker) {
		t.Fatal("private value leaked")
	}
	if err := os.WriteFile(path, []byte("public"), 0600); err != nil {
		t.Fatal(err)
	}
	findings, err = Check(root, []string{marker})
	if err != nil || len(findings) != 0 {
		t.Fatalf("unrelated positive refused: %v %v", findings, err)
	}
}

// A forbidden filename is redacted in every finding, including link and private
// tracking findings; replacing it with an ordinary public file passes.
func TestHygieneRedactsPrivateNames(t *testing.T) {
	marker := "synthetic-protected-name"
	for _, mode := range []string{"file", "link", "directory"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, marker)
			switch mode {
			case "file":
				if err := os.WriteFile(path, []byte(marker), 0600); err != nil {
					t.Fatal(err)
				}
			case "link":
				if err := os.Symlink("absent", path); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.MkdirAll(filepath.Join(path, ".task-board"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			findings, err := Check(root, []string{marker})
			if err != nil || len(findings) == 0 {
				t.Fatal("missing name refusal", err)
			}
			for _, finding := range findings {
				if strings.Contains(finding.String(), marker) {
					t.Fatal("private filename echoed")
				}
			}
			if err := os.RemoveAll(path); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "public.txt"), []byte("public"), 0600); err != nil {
				t.Fatal(err)
			}
			if findings, err = Check(root, []string{marker}); err != nil || len(findings) != 0 {
				t.Fatal("public control refused", err)
			}
		})
	}
}
