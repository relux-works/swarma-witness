package wire

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"regexp"

	"github.com/relux-works/waggle/record"
)

// Binding is an immutable decoded schema, not provisioning/consent evidence.
// Accessors return independent values; its zero value is never valid.
type Binding struct {
	raw                                          []byte
	service, stream, consumer, profile, writerID string
	writerEpoch                                  int64
	lineage                                      string
	keyPublic, keyID                             string
	keyEpoch                                     int64
}

func (b Binding) Bytes() []byte                      { return append([]byte(nil), b.raw...) }
func (b Binding) Valid() bool                        { return len(b.raw) > 0 }
func (b Binding) Service() string                    { return b.service }
func (b Binding) Stream() string                     { return b.stream }
func (b Binding) Consumer() string                   { return b.consumer }
func (b Binding) Profile() string                    { return b.profile }
func (b Binding) WriterID() string                   { return b.writerID }
func (b Binding) WriterEpoch() int64                 { return b.writerEpoch }
func (b Binding) RecordKey() (string, string, int64) { return b.keyPublic, b.keyID, b.keyEpoch }
func (b Binding) Identity() any {
	if !b.Valid() {
		return nil
	}
	v, _ := Parse(b.raw, LineLimit)
	return v.(map[string]any)["identity"]
}

var stationName = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)

func Station(v any) error {
	m, e := Object(v, "product", "project", "agent")
	if e != nil {
		return e
	}
	for _, k := range []string{"product", "project", "agent"} {
		s, ok := m[k].(string)
		if !ok {
			return Refuse("request_malformed")
		}
		if len(s) > 63 {
			return Refuse("limit_exceeded")
		}
		if !stationName.MatchString(s) {
			return Refuse("request_malformed")
		}
	}
	return nil
}
func identityString(v any) error {
	s, ok := v.(string)
	if !ok || len(s) == 0 {
		return Refuse("request_malformed")
	}
	if len(s) > 255 {
		return Refuse("limit_exceeded")
	}
	return nil
}
func DecodeBinding(raw []byte) (Binding, error) {
	v, e := Parse(raw, LineLimit)
	if e != nil {
		return Binding{}, e
	}
	m, e := Object(v, "service", "stream", "consumer", "identity", "lineage", "profile", "writer_epoch", "writer_id", "record_key", "transport_pins", "readers")
	if e != nil {
		return Binding{}, e
	}
	fail := func(e error) (Binding, error) { return Binding{}, e }
	if !Name(m["service"]) || !Name(m["stream"]) || !Integer(m["writer_epoch"], 1, MaxInt) {
		return fail(Refuse("request_malformed"))
	}
	for _, k := range []string{"lineage", "writer_id"} {
		if e = identityString(m[k]); e != nil {
			return fail(e)
		}
	}
	b := Binding{raw: append([]byte(nil), raw...), service: String(m["service"]), stream: String(m["stream"]), consumer: String(m["consumer"]), profile: String(m["profile"]), writerID: String(m["writer_id"]), writerEpoch: m["writer_epoch"].(int64), lineage: String(m["lineage"])}
	switch b.consumer {
	case "keymaker":
		if b.profile != "keymaker-state-witness/1" {
			return fail(Refuse("request_malformed"))
		}
		if e = Station(m["identity"]); e != nil {
			return fail(e)
		}
		k, e := Object(m["record_key"], "public_key", "key_id", "key_epoch", "purpose")
		if e != nil {
			return fail(e)
		}
		if !Integer(k["key_epoch"], 1, MaxInt) || !Digest(k["key_id"]) || !Integer(k["purpose"], 1, MaxInt) {
			return fail(Refuse("request_malformed"))
		}
		pub := String(k["public_key"])
		alg, rawKey, e := record.KeyBytes(pub)
		if e != nil || alg != "ed25519" {
			return fail(Refuse("request_malformed"))
		}
		if record.ValidateKey(pub) != nil || k["key_id"] != fmt.Sprintf("sha256:%x", sha256.Sum256(rawKey)) || k["purpose"] != int64(3) {
			return fail(Refuse("evidence_invalid"))
		}
		b.keyPublic, b.keyID, b.keyEpoch = pub, String(k["key_id"]), k["key_epoch"].(int64)
	case "registrar":
		if b.profile != "registrar-state-witness-sha1/1" && b.profile != "registrar-state-witness-sha256/1" || m["record_key"] != nil {
			return fail(Refuse("request_malformed"))
		}
		if e = identityString(m["identity"]); e != nil {
			return fail(e)
		}
	case "owner-registry":
		if b.profile != "owner-registry-checkpoint/1" || m["record_key"] != nil {
			return fail(Refuse("request_malformed"))
		}
		i, e := Object(m["identity"], "registry_id", "owner")
		if e != nil {
			return fail(e)
		}
		if e = identityString(i["owner"]); e != nil {
			return fail(e)
		}
		if _, _, e = record.KeyBytes(String(i["registry_id"])); e != nil {
			return fail(Refuse("request_malformed"))
		}
		if record.ValidateKey(String(i["registry_id"])) != nil {
			return fail(Refuse("evidence_invalid"))
		}
	default:
		return fail(Refuse("request_malformed"))
	}
	owners := map[string]string{}
	pins := func(v any, id string) error {
		a, ok := v.([]any)
		if !ok || len(a) == 0 {
			return Refuse("request_malformed")
		}
		if len(a) > 8 {
			return Refuse("limit_exceeded")
		}
		seen := map[string]bool{}
		for _, p := range a {
			if !Digest(p) {
				return Refuse("request_malformed")
			}
			s := String(p)
			if seen[s] {
				return Refuse("request_malformed")
			}
			seen[s] = true
			if prior, ok := owners[s]; ok && prior != id {
				return Refuse("evidence_invalid")
			}
			owners[s] = id
		}
		return nil
	}
	if e = pins(m["transport_pins"], b.writerID); e != nil {
		return fail(e)
	}
	readers, ok := m["readers"].([]any)
	if !ok {
		return fail(Refuse("request_malformed"))
	}
	if len(readers) > 32 {
		return fail(Refuse("limit_exceeded"))
	}
	ids := map[string]bool{}
	for _, r := range readers {
		p, e := Object(r, "id", "transport_pins")
		if e != nil {
			return fail(e)
		}
		if e = identityString(p["id"]); e != nil {
			return fail(e)
		}
		id := String(p["id"])
		if ids[id] {
			return fail(Refuse("request_malformed"))
		}
		ids[id] = true
		if e = pins(p["transport_pins"], id); e != nil {
			return fail(e)
		}
	}
	return b, nil
}

// TransportPin hashes canonical DER SubjectPublicKeyInfo, independently of the
// raw32 signing-key ID. Certificate trust, role and validity are S2 concerns.
func TransportPin(der []byte) (string, error) {
	public, e := x509.ParsePKIXPublicKey(der)
	if e != nil {
		return "", Refuse("request_malformed")
	}
	canonical, e := x509.MarshalPKIXPublicKey(public)
	if e != nil || !bytes.Equal(canonical, der) {
		return "", Refuse("request_malformed")
	}
	return fmt.Sprintf("sha256:%x", sha256.Sum256(der)), nil
}

// SameScope permits changing writer policy/ACLs but never identity, lineage,
// service or record profile. Actual rotation authorization remains external.
func (b Binding) SameScope(other Binding) bool {
	if !b.Valid() || !other.Valid() || b.service != other.service || b.stream != other.stream || b.consumer != other.consumer || b.profile != other.profile || b.lineage != other.lineage {
		return false
	}
	a, e := Canonical(b.Identity())
	if e != nil {
		return false
	}
	c, e := Canonical(other.Identity())
	return e == nil && bytes.Equal(a, c)
}
