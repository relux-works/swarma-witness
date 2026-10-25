package records_test

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/relux-works/swarma-witness/records"
	"github.com/relux-works/swarma-witness/wire"
)

// Fixed independently signed control and wrong-domain twin share one body.
// The expected LF-inclusive hash is frozen, not recomputed into the fixture.
func TestRecordsVectors(t *testing.T) {
	raw, e := os.ReadFile("../testdata/witness-v1/keymaker.json")
	if e != nil {
		t.Fatal(e)
	}
	var f map[string]json.RawMessage
	if e = json.Unmarshal(raw, &f); e != nil {
		t.Fatal(e)
	}
	text := func(name string) string {
		var s string
		if e := json.Unmarshal(f[name], &s); e != nil {
			t.Fatal(e)
		}
		return s
	}
	binary := func(name string) []byte {
		b, e := base64.RawURLEncoding.Strict().DecodeString(text(name))
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	b, e := wire.DecodeBinding(binary("binding"))
	if e != nil {
		t.Fatal(e)
	}
	line := binary("line")
	r, e := records.DecodeKeymaker(line, b, true)
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(line)
	if r.Hash() != text("line_hash") || hex.EncodeToString(h[:]) != text("line_hash") {
		t.Fatal("frozen LF hash")
	}
	_, e = records.DecodeKeymaker(binary("wrong_domain_line"), b, true)
	expect(t, e, "evidence_invalid")
	// Stdlib verification binds the literal domain and exact stored body bytes;
	// strict subgroup checks above remain supplied by the pinned helper.
	var env struct {
		Body      json.RawMessage
		Signature string
	}
	if e = json.Unmarshal(line, &env); e != nil {
		t.Fatal(e)
	}
	public, _, _ := b.RecordKey()
	pub, e := base64.RawURLEncoding.DecodeString(public[len("ed25519:"):])
	if e != nil {
		t.Fatal(e)
	}
	sig, e := base64.RawURLEncoding.DecodeString(env.Signature)
	if e != nil {
		t.Fatal(e)
	}
	pre := append([]byte("keymaker-witness-record/1\x00"), env.Body...)
	if !ed25519.Verify(pub, pre, sig) {
		t.Fatal("independent fixture signature")
	}
}

// Both protected registrar formats consume frozen valid lines and opposite-
// format negative twins. No registry/Loader or candidate truth is inferred.
func TestRecordsRegistrarVectors(t *testing.T) {
	raw, e := os.ReadFile("../testdata/witness-v1/registrar.json")
	if e != nil {
		t.Fatal(e)
	}
	var corpus struct {
		Schema int
		Spec   string `json:"spec_revision"`
		Cases  []map[string]string
	}
	if e = json.Unmarshal(raw, &corpus); e != nil {
		t.Fatal(e)
	}
	if corpus.Schema != 1 || corpus.Spec != records.RegistrarSpec || len(corpus.Cases) != 2 {
		t.Fatal("registrar corpus")
	}
	for _, c := range corpus.Cases {
		binary := func(name string) []byte {
			b, e := base64.RawURLEncoding.Strict().DecodeString(c[name])
			if e != nil {
				t.Fatal(e)
			}
			return b
		}
		b, e := wire.DecodeBinding(binary("binding"))
		if e != nil {
			t.Fatal(e)
		}
		r, e := records.DecodeRegistrar(binary("line"), b, true)
		if e != nil {
			t.Fatal(e)
		}
		if r.Hash() != c["line_hash"] {
			t.Fatal("registrar fixed hash")
		}
		_, e = records.DecodeRegistrar(binary("wrong_format_line"), b, true)
		expect(t, e, "evidence_invalid")
	}
}
