package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/relux-works/swarma-witness/wire"
)

// Exact payloads survive the local envelope; truncation, changed checksums,
// version/member changes and over-cap payloads refuse, never truncate a tail.
func TestPreparedLocalCodec(t *testing.T) {
	m := Manifest{Service: "witness", Transaction: wire.ZeroHash, Phase: "segment", Prior: wire.ZeroHash, Index: wire.ZeroHash, Policy: wire.ZeroHash, Audit: wire.ZeroHash}
	b, e := Encode(SegmentMagic, m, []Object{{Kind: "record", Bytes: []byte("exact\n")}})
	if e != nil {
		t.Fatal(e)
	}
	if e = CheckPlan(m, []Object{{Kind: "record", Bytes: []byte("exact\n")}}); e != nil {
		t.Fatal("valid prepare closure", e)
	}
	_, objects, e := Decode(b, SegmentMagic)
	if e != nil || !bytes.Equal(objects[0].Bytes, []byte("exact\n")) {
		t.Fatal("exact local object", e)
	}
	for _, bad := range [][]byte{b[:len(b)-1], append(append([]byte(nil), b...), 0), append([]byte("BAD1"), b[4:]...)} {
		if _, _, e := Decode(bad, SegmentMagic); wire.Code(e) != "storage_unavailable" {
			t.Fatal("damaged local envelope", e)
		}
	}
	bad := append([]byte(nil), b...)
	bad[20] ^= 1
	if _, _, e := Decode(bad, SegmentMagic); wire.Code(e) != "storage_unavailable" {
		t.Fatal("checksum rejection", e)
	}
	for _, mutation := range []func(map[string]any){func(m map[string]any) { m["v"] = int64(2) }, func(m map[string]any) { m["extra"] = true }} {
		v, err := wire.Parse(b[12:12+int(binary.BigEndian.Uint32(b[8:12]))], wire.LineLimit)
		if err != nil {
			t.Fatal(err)
		}
		m := v.(map[string]any)
		mutation(m)
		raw, _ := wire.Canonical(m)
		next := append([]byte(nil), b[:12]...)
		binary.BigEndian.PutUint32(next[8:12], uint32(len(raw)))
		next = append(next, raw...)
		next = append(next, b[12+int(binary.BigEndian.Uint32(b[8:12])):len(b)-32]...)
		binary.BigEndian.PutUint32(next[4:8], uint32(len(next)-8))
		sum := sha256.Sum256(next)
		next = append(next, sum[:]...)
		if _, _, e := Decode(next, SegmentMagic); wire.Code(e) != "storage_unavailable" {
			t.Fatal("closed local manifest", e)
		}
	}
	if e := CheckPlan(m, []Object{{Kind: "record", Bytes: make([]byte, SegmentLimit)}}); wire.Code(e) != "limit_exceeded" {
		t.Fatal("complete segment cap", e)
	}
}
