// Package store implements bounded local immutable objects and publication.
// Its hashes detect damage, never rollback or qualified durability by themselves.
package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"

	"github.com/relux-works/swarma-registrar/ccj"
	"github.com/relux-works/swarma-witness/wire"
)

const SegmentMagic = "WSG1"
const JournalMagic = "WJN1"
const RootMagic = "WCM1"
const SegmentLimit = 1 << 20
const JournalLimit = 64 << 10
const RootLimit = 4096

type Object struct {
	Kind  string
	Bytes []byte
}
type Manifest struct {
	Service, Transaction, Phase, Prior, Index, Policy string
	Chain, Stream                                     string
	Seq                                               int64
	Previous, Head                                    string
	AuditSeq                                          int64
	Audit, Segment, Prepare, Resolution               string
}

func Hash(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func capFor(magic string) int {
	switch magic {
	case SegmentMagic:
		return SegmentLimit
	case JournalMagic:
		return JournalLimit
	case RootMagic:
		return RootLimit
	}
	return 0
}
func normalize(m Manifest) Manifest {
	for _, p := range []*string{&m.Prior, &m.Index, &m.Policy, &m.Previous, &m.Head, &m.Audit, &m.Segment, &m.Prepare, &m.Resolution} {
		if *p == "" {
			*p = wire.ZeroHash
		}
	}
	if m.Chain == "" {
		m.Chain = "audits"
	}
	return m
}
func manifestMap(m Manifest, objects []Object) map[string]any {
	items := []any{}
	for _, o := range objects {
		items = append(items, map[string]any{"kind": o.Kind, "length": int64(len(o.Bytes)), "hash": Hash(o.Bytes)})
	}
	var stream any
	if m.Stream != "" {
		stream = m.Stream
	}
	return map[string]any{"v": int64(1), "service": m.Service, "transaction": m.Transaction, "phase": m.Phase, "prior_root": m.Prior, "index_hash": m.Index, "policy_hash": m.Policy, "chain": m.Chain, "stream": stream, "seq": m.Seq, "prev_hash": m.Previous, "head_hash": m.Head, "audit_seq": m.AuditSeq, "audit_hash": m.Audit, "segment_hash": m.Segment, "prepare_hash": m.Prepare, "resolution_hash": m.Resolution, "objects": items}
}

// Encode has an outer complete-payload length, an inner manifest length, exact
// object lengths, and a checksum covering every preceding byte including magic.
func Encode(magic string, m Manifest, objects []Object) ([]byte, error) {
	m = normalize(m)
	limit := capFor(magic)
	if limit == 0 || len(objects) > 64 {
		return nil, wire.Refuse("limit_exceeded")
	}
	raw, e := wire.Canonical(manifestMap(m, objects))
	if e != nil {
		return nil, e
	}
	n := 12 + len(raw) + 32
	for _, o := range objects {
		if !wire.Name(o.Kind) || len(o.Bytes) > SegmentLimit {
			return nil, wire.Refuse("limit_exceeded")
		}
		n += 4 + len(o.Bytes)
	}
	if n > limit {
		return nil, wire.Refuse("limit_exceeded")
	}
	b := make([]byte, 12, n)
	copy(b, magic)
	binary.BigEndian.PutUint32(b[4:8], uint32(n-8-32))
	binary.BigEndian.PutUint32(b[8:12], uint32(len(raw)))
	b = append(b, raw...)
	for _, o := range objects {
		b = binary.BigEndian.AppendUint32(b, uint32(len(o.Bytes)))
		b = append(b, o.Bytes...)
	}
	h := sha256.Sum256(b)
	b = append(b, h[:]...)
	if _, _, e = Decode(b, magic); e != nil {
		return nil, wire.Refuse("request_malformed")
	}
	return b, nil
}
func Decode(b []byte, magic string) (Manifest, []Object, error) {
	fail := func() (Manifest, []Object, error) { return Manifest{}, nil, wire.Refuse("storage_unavailable") }
	limit := capFor(magic)
	if limit == 0 || len(b) < 44 || len(b) > limit || string(b[:4]) != magic {
		return fail()
	}
	h := sha256.Sum256(b[:len(b)-32])
	if !bytes.Equal(h[:], b[len(b)-32:]) || int(binary.BigEndian.Uint32(b[4:8])) != len(b)-40 {
		return fail()
	}
	n := int(binary.BigEndian.Uint32(b[8:12]))
	if n > len(b)-44 {
		return fail()
	}
	raw := b[12 : 12+n]
	// Bound nesting before the canonical parser allocates recursive values.
	depth := 0
	quoted, escaped := false, false
	for _, c := range raw {
		if quoted {
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				quoted = false
			}
			continue
		}
		switch c {
		case '"':
			quoted = true
		case '{', '[':
			depth++
			if depth > 16 {
				return fail()
			}
		case '}', ']':
			depth--
			if depth < 0 {
				return fail()
			}
		}
	}
	v, e := ccj.Parse(raw, ccj.RegistrationMalformed)
	if e != nil {
		return fail()
	}
	canon, e := wire.Canonical(v)
	if e != nil || !bytes.Equal(raw, canon) {
		return fail()
	}
	x, e := wire.Object(v, "v", "service", "transaction", "phase", "prior_root", "index_hash", "policy_hash", "chain", "stream", "seq", "prev_hash", "head_hash", "audit_seq", "audit_hash", "segment_hash", "prepare_hash", "resolution_hash", "objects")
	if e != nil || !wire.One(x["v"]) || !wire.Name(x["service"]) || !wire.Hash(x["transaction"]) || !wire.Integer(x["seq"], 0, wire.MaxInt) || !wire.Integer(x["audit_seq"], 0, wire.MaxInt) {
		return fail()
	}
	for _, k := range []string{"prior_root", "index_hash", "policy_hash", "prev_hash", "head_hash", "audit_hash", "segment_hash", "prepare_hash", "resolution_hash"} {
		if !wire.Hash(x[k]) {
			return fail()
		}
	}
	phase := wire.String(x["phase"])
	if magic == SegmentMagic && phase != "segment" || magic == RootMagic && phase != "root" || magic == JournalMagic && phase != "prepare" && phase != "outcome" {
		return fail()
	}
	chain := wire.String(x["chain"])
	if chain != "records" && chain != "controls" && chain != "audits" {
		return fail()
	}
	if chain == "records" {
		if !wire.Name(x["stream"]) {
			return fail()
		}
	} else if x["stream"] != nil {
		return fail()
	}
	items, ok := x["objects"].([]any)
	if !ok || len(items) > 64 {
		return fail()
	}
	offset := 12 + n
	objects := []Object{}
	for _, v := range items {
		o, e := wire.Object(v, "kind", "length", "hash")
		if e != nil || !wire.Name(o["kind"]) || !wire.Integer(o["length"], 0, SegmentLimit) || !wire.Hash(o["hash"]) || offset+4 > len(b)-32 {
			return fail()
		}
		size := int(binary.BigEndian.Uint32(b[offset : offset+4]))
		offset += 4
		if int64(size) != o["length"] || size > len(b)-32-offset {
			return fail()
		}
		data := b[offset : offset+size]
		offset += size
		if Hash(data) != o["hash"] {
			return fail()
		}
		objects = append(objects, Object{wire.String(o["kind"]), append([]byte(nil), data...)})
	}
	if offset != len(b)-32 {
		return fail()
	}
	return Manifest{Service: wire.String(x["service"]), Transaction: wire.String(x["transaction"]), Phase: phase, Prior: wire.String(x["prior_root"]), Index: wire.String(x["index_hash"]), Policy: wire.String(x["policy_hash"]), Chain: chain, Stream: wire.String(x["stream"]), Seq: x["seq"].(int64), Previous: wire.String(x["prev_hash"]), Head: wire.String(x["head_hash"]), AuditSeq: x["audit_seq"].(int64), Audit: wire.String(x["audit_hash"]), Segment: wire.String(x["segment_hash"]), Prepare: wire.String(x["prepare_hash"]), Resolution: wire.String(x["resolution_hash"])}, objects, nil
}
