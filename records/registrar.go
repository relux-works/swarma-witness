package records

import (
	"github.com/relux-works/swarma-witness/wire"
)

// RegistrarSpec is the landed grammar source, independent of the older CCJ
// module pin. No registry package or Loader is imported by this syntax adapter.
const RegistrarSpec = "3fc31e457043d2479fd300698dee92ab0dd4bef2"

// RegistrarCase describes the WS mapping; producer codes are never forwarded.
type RegistrarCase int

const (
	RevisionMalformed RegistrarCase = iota
	RevisionOtherFormat
	RegistrarRejected
	RegistrarMissing
)

func RegistrarRefusal(c RegistrarCase) string {
	switch c {
	case RevisionMalformed:
		return "request_malformed"
	case RevisionOtherFormat, RegistrarRejected:
		return "evidence_invalid"
	}
	return "profile_unavailable"
}

// CheckRegistrarRevision applies registrar §4.3 at RegistrarSpec. Only the
// protected profile selects the accepted width, never the supplied ID length.
func CheckRegistrarRevision(profile, revision string) error {
	width := 0
	switch profile {
	case "registrar-state-witness-sha1/1":
		width = 40
	case "registrar-state-witness-sha256/1":
		width = 64
	default:
		return wire.Refuse(RegistrarRefusal(RegistrarMissing))
	}
	for _, c := range []byte(revision) {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return wire.Refuse(RegistrarRefusal(RevisionMalformed))
		}
	}
	if len(revision) == width {
		return nil
	}
	if len(revision) == 40 || len(revision) == 64 {
		return wire.Refuse(RegistrarRefusal(RevisionOtherFormat))
	}
	return wire.Refuse(RegistrarRefusal(RevisionMalformed))
}

// DecodeRegistrar validates exact flat bytes, profile syntax and format only.
// It does not authenticate transport or inspect Git/candidate-state contents.
// bootstrapFirst is external explicit first-intent context, not empty-store inference.
func DecodeRegistrar(line []byte, b wire.Binding, bootstrapFirst bool) (Record, error) {
	fail := func(e error) (Record, error) { return Record{}, e }
	if !b.Valid() {
		return fail(wire.Refuse("stream_unavailable"))
	}
	if b.Consumer() != "registrar" {
		return fail(wire.Refuse("profile_unavailable"))
	}
	v, e := wire.Line(line)
	if e != nil {
		return fail(e)
	}
	m, e := wire.Object(v, "v", "stream", "seq", "kind", "revision", "digest", "prev_hash", "intent_hash")
	if e != nil {
		return fail(e)
	}
	if !wire.One(m["v"]) || !wire.Name(m["stream"]) || !wire.Integer(m["seq"], 1, wire.MaxInt) || !wire.Digest(m["digest"]) || !wire.Hash(m["prev_hash"]) {
		return fail(wire.Refuse("request_malformed"))
	}
	revision, ok := m["revision"].(string)
	if !ok {
		return fail(wire.Refuse("request_malformed"))
	}
	if e = CheckRegistrarRevision(b.Profile(), revision); e != nil {
		return fail(e)
	}
	if e = kind(m); e != nil {
		return fail(e)
	}
	if m["stream"] != b.Stream() || m["prev_hash"] == wire.ZeroHash && !(bootstrapFirst && m["seq"] == int64(1) && m["kind"] == "intent") || m["kind"] == "committed" && m["intent_hash"] == wire.ZeroHash {
		return fail(wire.Refuse("evidence_invalid"))
	}
	return Record{line: append([]byte(nil), line...), binding: b}, nil
}
func CheckRegistrarDigest(actual, expected string) error {
	if !wire.Digest(actual) {
		return wire.Refuse("request_malformed")
	}
	if actual != expected {
		return wire.Refuse("evidence_invalid")
	}
	return nil
}
