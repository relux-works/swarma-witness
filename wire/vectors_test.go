package wire_test

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/relux-works/swarma-witness/wire"
)

// Frozen first-party bytes exercise schema and canonicality without fixture
// regeneration during tests; integrity/provenance remains the vector tool's job.
func TestWireVectors(t *testing.T) {
	raw, e := os.ReadFile("../testdata/witness-v1/wire.json")
	if e != nil {
		t.Fatal(e)
	}
	var corpus struct {
		Schema int
		Cases  []struct{ Name, Raw, Code string }
	}
	if e = json.Unmarshal(raw, &corpus); e != nil {
		t.Fatal(e)
	}
	if corpus.Schema != 1 || len(corpus.Cases) != 5 {
		t.Fatal("corpus contract")
	}
	for _, c := range corpus.Cases {
		t.Run(c.Name, func(t *testing.T) {
			b, e := base64.RawURLEncoding.Strict().DecodeString(c.Raw)
			if e != nil {
				t.Fatal(e)
			}
			_, e = wire.DecodeRequest(b)
			expect(t, e, c.Code)
		})
	}
}
