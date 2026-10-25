package records

import "github.com/relux-works/swarma-witness/wire"

// CheckpointWrapper is decoded but deliberately not an admitted Record. Its
// carried originals are never canonicalized or interpreted by the WS codec.
type CheckpointWrapper struct{ checkpoint, proof, line []byte }

func (c CheckpointWrapper) Checkpoint() []byte    { return append([]byte(nil), c.checkpoint...) }
func (c CheckpointWrapper) RegistryProof() []byte { return append([]byte(nil), c.proof...) }
func (c CheckpointWrapper) Line() []byte          { return append([]byte(nil), c.line...) }
func (c CheckpointWrapper) Verify() error         { return wire.Refuse("profile_unavailable") }
func CheckpointProjection(v any, genesis bool) error {
	p, e := wire.Object(v, "registry_id", "owner", "registry_seq", "registry_head", "checkpoint_id", "checkpoint_time", "candidate_digest", "previous_checkpoint_id")
	if e != nil {
		return e
	}
	if !wire.Opaque(p["registry_id"]) || !wire.Opaque(p["owner"]) || !wire.Integer(p["registry_seq"], 1, wire.MaxInt) || !wire.Digest(p["registry_head"]) || !wire.Digest(p["checkpoint_id"]) || !wire.Timestamp(p["checkpoint_time"]) || !wire.Digest(p["candidate_digest"]) || p["previous_checkpoint_id"] != nil && !wire.Digest(p["previous_checkpoint_id"]) {
		return wire.Refuse("request_malformed")
	}
	if p["previous_checkpoint_id"] == nil && !genesis {
		return wire.Refuse("evidence_invalid")
	}
	return nil
}
func DecodeCheckpointWrapper(line []byte, b wire.Binding, genesis bool) (CheckpointWrapper, error) {
	fail := func(e error) (CheckpointWrapper, error) { return CheckpointWrapper{}, e }
	if !b.Valid() {
		return fail(wire.Refuse("stream_unavailable"))
	}
	if b.Consumer() != "owner-registry" {
		return fail(wire.Refuse("profile_unavailable"))
	}
	v, e := wire.Line(line)
	if e != nil {
		return fail(e)
	}
	m, e := wire.Object(v, "v", "stream", "seq", "prev_hash", "writer_epoch", "kind", "intent_hash", "checkpoint", "registry_proof", "projection")
	if e != nil {
		return fail(e)
	}
	if !wire.One(m["v"]) || !wire.Name(m["stream"]) || !wire.Integer(m["seq"], 1, wire.MaxInt) || !wire.Hash(m["prev_hash"]) || !wire.Integer(m["writer_epoch"], 1, wire.MaxInt) {
		return fail(wire.Refuse("request_malformed"))
	}
	if e = kind(m); e != nil {
		return fail(e)
	}
	if e = CheckpointProjection(m["projection"], genesis); e != nil {
		return fail(e)
	}
	p := m["projection"].(map[string]any)
	identity := b.Identity().(map[string]any)
	if m["stream"] != b.Stream() || m["writer_epoch"] != b.WriterEpoch() || p["registry_id"] != identity["registry_id"] || p["owner"] != identity["owner"] {
		return fail(wire.Refuse("evidence_invalid"))
	}
	cp, e := wire.DecodeBinary(wire.String(m["checkpoint"]), -1, wire.LineLimit)
	if e != nil {
		return fail(e)
	}
	proof, e := wire.DecodeBinary(wire.String(m["registry_proof"]), -1, wire.LineLimit)
	if e != nil {
		return fail(e)
	}
	if len(cp) == 0 || len(proof) == 0 {
		return fail(wire.Refuse("request_malformed"))
	}
	return CheckpointWrapper{checkpoint: cp, proof: proof, line: append([]byte(nil), line...)}, nil
}
