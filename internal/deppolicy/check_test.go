package deppolicy

import (
	"os"
	"testing"
)

const header = "module github.com/relux-works/swarma-witness\n\ngo 1.26.0\n"

// Only the approved exact version can be required; no dependency, an allowed
// dependency, and its indirect form are valid controls. No module is downloaded.
func TestDependencyPolicyRejectsUnapprovedModule(t *testing.T) {
	for _, example := range []struct{ tail, code string }{
		{"require example.invalid/unapproved v1.0.0\n", "dependency_not_approved"},
		{"require github.com/relux-works/waggle v0.0.0-20261024213811-aaaaaaaaaaaa\n", "dependency_not_approved"},
		{"replace github.com/relux-works/waggle => ../local\n", "directive_not_approved"},
		{"require github.com/relux-works/swarma-keymaker v1.0.0\n", "dependency_not_approved"},
		{"toolchain go1.27.0\n", "directive_not_approved"},
		{"require github.com/relux-works/swarma-credential-broker v1.0.0\n", "dependency_not_approved"},
		{"require golang.org/x/sys v0.39.0\n", "dependency_not_approved"},
		{"require github.com/pelletier/go-toml/v2 v2.2.4\n", "dependency_not_approved"},
	} {
		if err := Check([]byte(header + example.tail)); err == nil || err.Error() != example.code {
			t.Fatal("unapproved directive/module accepted", err)
		}
	}
	for _, tail := range []string{"", "require github.com/relux-works/swarma-envelope " + EnvelopeVersion + "\n", "require github.com/relux-works/swarma-credential-broker " + BrokerVersion + "\n", "require golang.org/x/sys v0.38.0 // indirect\n", "require (\n github.com/relux-works/swarma-envelope " + EnvelopeVersion + " // indirect\n)\n"} {
		if err := Check([]byte(header + tail)); err != nil {
			t.Fatal("approved positive", err)
		}
	}
}

// The repository itself must remain at the declared module/Go baseline; local
// replacements and unreviewed transitive requirements cannot silently enter S0.
func TestDependencyPolicyRepository(t *testing.T) {
	data, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	if err = Check(data); err != nil {
		t.Fatal(err)
	}
	for _, example := range []struct{ body, code string }{
		{"module example.invalid/other\ngo 1.26.0\n", "module_not_approved"},
		{"module github.com/relux-works/swarma-witness\ngo 1.27.0\n", "go_not_approved"},
		{header + "require (\n", "module_incomplete"},
	} {
		if err = Check([]byte(example.body)); err == nil || err.Error() != example.code {
			t.Fatal("module baseline violation accepted", err)
		}
	}
}
