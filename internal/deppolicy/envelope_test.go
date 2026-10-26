package deppolicy

import "testing"

// The published envelope pin is accepted in either require form. Its old
// module identity, version drift, duplicate/dual requirements and replacements
// remain forbidden. This checks metadata policy, not downloaded code or serving.
func TestDependencyPolicyEnvelopeIdentity(t *testing.T) {
	approved := "require github.com/relux-works/swarma-envelope " + EnvelopeVersion + "\n"
	for _, tail := range []string{
		approved,
		"require (\n github.com/relux-works/swarma-envelope " + EnvelopeVersion + " // indirect\n)\n",
	} {
		if err := Check([]byte(header + tail)); err != nil {
			t.Fatal("published envelope control", err)
		}
	}
	old := "require github.com/relux-works/waggle v0.0.0-20261025015329-5f4e7435d756\n"
	for _, row := range []struct{ name, tail, code string }{
		{"old identity", old, "dependency_not_approved"},
		{"dual identity", approved + old, "dependency_not_approved"},
		{"wrong version", "require github.com/relux-works/swarma-envelope v0.0.0-20261025015329-5f4e7435d756\n", "dependency_not_approved"},
		{"duplicate", approved + approved, "dependency_not_approved"},
		{"replacement", approved + "replace github.com/relux-works/swarma-envelope => ../local\n", "directive_not_approved"},
	} {
		t.Run(row.name, func(t *testing.T) {
			if err := Check([]byte(header + row.tail)); err == nil || err.Error() != row.code {
				t.Fatal("module boundary", err)
			}
		})
	}
}
