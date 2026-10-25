package wire_test

import (
	"os"
	"testing"

	"github.com/relux-works/swarma-witness/internal/deppolicy"
)

// The exact Waggle/CCJ graph is allowed; previous pins and an unreviewed CCJ
// upgrade remain forbidden. This checks policy without activating any Loader.
func TestWireDependencyPins(t *testing.T) {
	raw, e := os.ReadFile("../go.mod")
	if e != nil {
		t.Fatal(e)
	}
	if e = deppolicy.Check(raw); e != nil {
		t.Fatal(e)
	}
	header := "module github.com/relux-works/swarma-witness\n\ngo 1.26.0\n"
	for _, line := range []string{"require github.com/relux-works/waggle v0.0.0-20261024213811-9b42338b8a57\n", "require github.com/relux-works/swarma-registrar v0.0.0-20261023164451-000000000000\n"} {
		if e = deppolicy.Check([]byte(header + line)); e == nil || e.Error() != "dependency_not_approved" {
			t.Fatal("pin drift accepted", e)
		}
	}
}
