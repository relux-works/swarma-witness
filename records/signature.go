// Package records checks consumer line schemas and independently pinned
// signatures. It grants no transport, storage or consumer state authority.
package records

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-witness/wire"
)

type Role string

const (
	Writer     Role = "record-writer"
	Witness    Role = "witness"
	Admin      Role = "admin"
	Transition Role = "transition"
	Publisher  Role = "registry-publisher"
	Bridge     Role = "checkpoint-bridge"
)

type Domain string

const (
	RecordDomain     Domain = "keymaker-witness-record/1"
	KeymakerAck      Domain = "keymaker-witness-ack/1"
	KeymakerHead     Domain = "keymaker-witness-head/1"
	NeutralAck       Domain = "state-witness-ack/1"
	NeutralHead      Domain = "state-witness-head/1"
	ControlAck       Domain = "state-witness-control-ack/1"
	AdminDomain      Domain = "state-witness-admin/1"
	TransitionDomain Domain = "state-witness-key-transition/1"
)

type Key struct {
	Public, ID string
	Epoch      int64
	Role       Role
}

func domainRole(d Domain) Role {
	switch d {
	case RecordDomain:
		return Writer
	case KeymakerAck, KeymakerHead, NeutralAck, NeutralHead, ControlAck:
		return Witness
	case AdminDomain:
		return Admin
	case TransitionDomain:
		return Transition
	}
	return ""
}
func Digest(b []byte) string { return fmt.Sprintf("sha256:%x", sha256.Sum256(b)) }
func Hash(b []byte) string   { return fmt.Sprintf("%x", sha256.Sum256(b)) }
func ValidateKey(k Key) error {
	alg, pub, e := record.KeyBytes(k.Public)
	if e != nil || alg != "ed25519" {
		return wire.Refuse("request_malformed")
	}
	if k.Epoch < 1 || k.Epoch > wire.MaxInt || !wire.Digest(k.ID) {
		return wire.Refuse("request_malformed")
	}
	if record.ValidateKey(k.Public) != nil || Digest(pub) != k.ID {
		return wire.Refuse("evidence_invalid")
	}
	return nil
}
func Verify(k Key, sig, pre []byte) error {
	if e := ValidateKey(k); e != nil {
		return e
	}
	if record.VerifySignature(k.Public, sig, pre) != nil {
		return wire.Refuse("evidence_invalid")
	}
	return nil
}
func Preimage(body map[string]any, d Domain) ([]byte, error) {
	if domainRole(d) == "" {
		return nil, wire.Refuse("profile_unavailable")
	}
	raw, e := wire.Canonical(body)
	if e != nil {
		return nil, e
	}
	return append([]byte(string(d)+"\x00"), raw...), nil
}

// VerifyEnvelope selects a domain from protected context, not received data.
// The caller must additionally check the domain's exact closed body schema.
func VerifyEnvelope(raw []byte, max int, d Domain, k Key) (map[string]any, error) {
	v, e := wire.Parse(raw, max)
	if e != nil {
		return nil, e
	}
	m, e := wire.Object(v, "body", "signature")
	if e != nil {
		return nil, e
	}
	body, ok := m["body"].(map[string]any)
	if !ok {
		return nil, wire.Refuse("request_malformed")
	}
	s, ok := m["signature"].(string)
	if !ok {
		return nil, wire.Refuse("request_malformed")
	}
	sig, e := wire.DecodeBinary(s, 64, 64)
	if e != nil {
		return nil, e
	}
	if domainRole(d) == "" {
		return nil, wire.Refuse("profile_unavailable")
	}
	if k.Role != domainRole(d) {
		return nil, wire.Refuse("evidence_invalid")
	}
	pre, e := Preimage(body, d)
	if e != nil {
		return nil, e
	}
	if e = Verify(k, sig, pre); e != nil {
		return nil, e
	}
	return body, nil
}

// Signer receives bounded canonical preimages only. S1 supplies no private-key
// custody implementation. The returned signature is independently checked.
type Signer func([]byte) ([]byte, error)

func SignEnvelope(body map[string]any, max int, d Domain, k Key, sign Signer) ([]byte, error) {
	if k.Role != domainRole(d) || domainRole(d) == "" {
		return nil, wire.Refuse("evidence_invalid")
	}
	if e := ValidateKey(k); e != nil {
		return nil, e
	}
	pre, e := Preimage(body, d)
	if e != nil {
		return nil, e
	}
	reserve, e := wire.Canonical(map[string]any{"body": body, "signature": base64.RawURLEncoding.EncodeToString(make([]byte, 64))})
	if e != nil {
		return nil, e
	}
	reserved, e := wire.Parse(reserve, max)
	if e != nil {
		return nil, e
	}
	// Snapshot the validated body before entering external signer code.
	body = reserved.(map[string]any)["body"].(map[string]any)
	if sign == nil {
		return nil, wire.Refuse("profile_unavailable")
	}
	sig, e := sign(append([]byte(nil), pre...))
	if e != nil {
		return nil, wire.Refuse("profile_unavailable")
	}
	if len(sig) != 64 || Verify(k, sig, pre) != nil {
		return nil, wire.Refuse("evidence_invalid")
	}
	return wire.Canonical(map[string]any{"body": body, "signature": base64.RawURLEncoding.EncodeToString(sig)})
}
