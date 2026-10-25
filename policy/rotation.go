package policy

import (
	"bytes"
	"github.com/relux-works/swarma-witness/evidence"
	"github.com/relux-works/swarma-witness/records"
	"github.com/relux-works/swarma-witness/wire"
)

func ValidateRotation(old, next wire.Binding) error {
	if !old.SameScope(next) {
		return wire.Refuse("evidence_invalid")
	}
	if old.WriterEpoch() >= wire.MaxInt {
		return wire.Refuse("sequence_exhausted")
	}
	if next.WriterEpoch() != old.WriterEpoch()+1 {
		return wire.Refuse("evidence_invalid")
	}
	a, aid, ae := old.RecordKey()
	b, bid, be := next.RecordKey()
	if a != b || aid != bid {
		return wire.Refuse("profile_unavailable")
	}
	if ae != be {
		return wire.Refuse("evidence_invalid")
	}
	return nil
}

type PossessionContext struct{ Service, Stream, ActionHash, PrincipalID, Pin, Challenge, ChannelDigest string }

func DecodePrincipalPossession(line []byte, k records.Key, c PossessionContext) error {
	m, e := verifyExternal(line, k, possessionDomain, EnrollmentRole)
	if e != nil {
		return e
	}
	m, e = wire.Object(m, "v", "type", "service", "stream", "action_hash", "principal_id", "transport_pin", "challenge", "channel_digest", "key_epoch", "key_id")
	if e != nil {
		return e
	}
	if !wire.One(m["v"]) || m["type"] != possessionDomain || !wire.Name(m["service"]) || !wire.Name(m["stream"]) || !wire.Hash(m["action_hash"]) || !wire.Opaque(m["principal_id"]) || !wire.Digest(m["transport_pin"]) || !wire.RequestID(m["challenge"]) || !wire.Digest(m["channel_digest"]) {
		return wire.Refuse("request_malformed")
	}
	for key, want := range map[string]string{"service": c.Service, "stream": c.Stream, "action_hash": c.ActionHash, "principal_id": c.PrincipalID, "transport_pin": c.Pin, "challenge": c.Challenge, "channel_digest": c.ChannelDigest} {
		if m[key] != want {
			return wire.Refuse("evidence_invalid")
		}
	}
	return nil
}

type PossessionPacket struct{ OldTransport, NewTransport string }

// DecodePossessionPacket checks references only; the retained closure and live
// channel evidence must be independently verified, never fetched from a caller.
func DecodePossessionPacket(raw []byte, service, stream, actionHash string) (PossessionPacket, error) {
	v, e := wire.Parse(raw, wire.LineLimit)
	if e != nil {
		return PossessionPacket{}, e
	}
	m, e := wire.Object(v, "v", "service", "stream", "action_hash", "old_transport", "new_transport", "old_record", "new_record")
	if e != nil {
		return PossessionPacket{}, e
	}
	if !wire.One(m["v"]) || !wire.Name(m["service"]) || !wire.Name(m["stream"]) || !wire.Hash(m["action_hash"]) || !wire.Digest(m["old_transport"]) || !wire.Digest(m["new_transport"]) {
		return PossessionPacket{}, wire.Refuse("request_malformed")
	}
	if m["service"] != service || m["stream"] != stream || m["action_hash"] != actionHash {
		return PossessionPacket{}, wire.Refuse("evidence_invalid")
	}
	if m["old_record"] != nil || m["new_record"] != nil {
		return PossessionPacket{}, wire.Refuse("profile_unavailable")
	}
	return PossessionPacket{wire.String(m["old_transport"]), wire.String(m["new_transport"])}, nil
}

// ValidateRotationEvidence checks a bounded retained closure against independently
// supplied live-channel contexts. It does not produce live possession evidence.
func ValidateRotationEvidence(raw []byte, objects map[string][]byte, k records.Key, old, new PossessionContext) error {
	if len(raw) == 0 || len(objects) == 0 {
		return wire.Refuse("profile_unavailable")
	}
	if old.Service != new.Service || old.Stream != new.Stream || old.ActionHash != new.ActionHash {
		return wire.Refuse("evidence_invalid")
	}
	if len(objects) > 8 {
		return wire.Refuse("limit_exceeded")
	}
	total := 0
	for digest, obj := range objects {
		if len(obj) > 65536 {
			return wire.Refuse("limit_exceeded")
		}
		total += len(obj)
		if records.Digest(obj) != digest {
			return wire.Refuse("evidence_invalid")
		}
	}
	if total > 262144 {
		return wire.Refuse("limit_exceeded")
	}
	p, e := DecodePossessionPacket(raw, old.Service, old.Stream, old.ActionHash)
	if e != nil {
		return e
	}
	for _, pair := range []struct {
		ref     string
		context PossessionContext
	}{{p.OldTransport, old}, {p.NewTransport, new}} {
		line, ok := objects[pair.ref]
		if !ok {
			return wire.Refuse("profile_unavailable")
		}
		if e = DecodePrincipalPossession(line, k, pair.context); e != nil {
			return e
		}
	}
	return nil
}

// HistoricalReceipt is independently retained input, never a newly signed result.
type HistoricalReceipt struct {
	Record      records.Record
	Receipt     []byte
	Witness     records.Key
	ControlHash string
}

// ValidateHistoricalRetry admits only a current writer's exact retained line,
// checking the historical binding/key and original receipt without resigning.
func ValidateHistoricalRetry(s Snapshot, peer Peer, line []byte, h HistoricalReceipt) ([]byte, error) {
	if !h.Record.Valid() {
		return nil, wire.Refuse("evidence_invalid")
	}
	if e := s.Authorize(peer, "append", h.Record.Binding().Stream()); e != nil {
		return nil, e
	}
	current, e := s.Binding(h.Record.Binding().Stream())
	if e != nil {
		return nil, e
	}
	if !current.SameScope(h.Record.Binding()) {
		return nil, wire.Refuse("evidence_invalid")
	}
	if !bytes.Equal(line, h.Record.Line()) {
		return nil, wire.Refuse("position_conflict")
	}
	if e = evidence.VerifyReceipt(h.Receipt, h.Record, h.Record.Binding(), h.Witness, h.ControlHash); e != nil {
		return nil, e
	}
	return append([]byte(nil), h.Receipt...), nil
}
