package evidence_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"

	"github.com/relux-works/swarma-witness/evidence"
	"github.com/relux-works/swarma-witness/records"
	"github.com/relux-works/swarma-witness/wire"
)

// Frozen first-party receipt has unequal writer/witness epochs. Verification
// uses its independent witness pin and rejects an otherwise valid wrong pin.
func TestEvidenceVectors(t *testing.T) {
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
	r, e := records.DecodeKeymaker(binary("line"), b, true)
	if e != nil {
		t.Fatal(e)
	}
	var epoch int64
	if e = json.Unmarshal(f["witness_epoch"], &epoch); e != nil {
		t.Fatal(e)
	}
	k := records.Key{Public: text("witness_public"), ID: text("witness_id"), Epoch: epoch, Role: records.Witness}
	receipt := binary("receipt")
	if e = evidence.VerifyReceipt(receipt, r, b, k, text("control_hash")); e != nil {
		t.Fatal(e)
	}
	wrong, _ := signing(82, epoch, records.Witness)
	expect(t, evidence.VerifyReceipt(receipt, r, b, wrong, text("control_hash")), "evidence_invalid")
	var env struct {
		Body      json.RawMessage
		Signature string
	}
	if e = json.Unmarshal(receipt, &env); e != nil {
		t.Fatal(e)
	}
	pub, e := base64.RawURLEncoding.DecodeString(k.Public[len("ed25519:"):])
	if e != nil {
		t.Fatal(e)
	}
	sig, e := base64.RawURLEncoding.DecodeString(env.Signature)
	if e != nil {
		t.Fatal(e)
	}
	if !ed25519.Verify(pub, append([]byte("keymaker-witness-ack/1\x00"), env.Body...), sig) {
		t.Fatal("independent receipt signature")
	}
}

// Frozen neutral receipts verify for both protected registrar profiles under a
// separately pinned witness; literal-domain stdlib checks are independent.
func TestEvidenceRegistrarVectors(t *testing.T) {
	raw, e := os.ReadFile("../testdata/witness-v1/registrar.json")
	if e != nil {
		t.Fatal(e)
	}
	var corpus struct {
		Public string `json:"witness_public"`
		ID     string `json:"witness_id"`
		Epoch  int64  `json:"witness_epoch"`
		Cases  []map[string]string
	}
	if e = json.Unmarshal(raw, &corpus); e != nil {
		t.Fatal(e)
	}
	k := records.Key{Public: corpus.Public, ID: corpus.ID, Epoch: corpus.Epoch, Role: records.Witness}
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
		receipt := binary("receipt")
		if e = evidence.VerifyReceipt(receipt, r, b, k, c["control_hash"]); e != nil {
			t.Fatal(e)
		}
		var env struct {
			Body      json.RawMessage
			Signature string
		}
		if e = json.Unmarshal(receipt, &env); e != nil {
			t.Fatal(e)
		}
		pub, e := base64.RawURLEncoding.DecodeString(k.Public[len("ed25519:"):])
		if e != nil {
			t.Fatal(e)
		}
		sig, e := base64.RawURLEncoding.DecodeString(env.Signature)
		if e != nil {
			t.Fatal(e)
		}
		if !ed25519.Verify(pub, append([]byte("state-witness-ack/1\x00"), env.Body...), sig) {
			t.Fatal("neutral fixture signature")
		}
		wrong, _ := signing(84, k.Epoch, records.Witness)
		expect(t, evidence.VerifyReceipt(receipt, r, b, wrong, c["control_hash"]), "evidence_invalid")
	}
}
