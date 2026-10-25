package service

import (
	"bytes"
	"context"

	"github.com/relux-works/swarma-witness/audit"
	"github.com/relux-works/swarma-witness/custodian"
	"github.com/relux-works/swarma-witness/evidence"
	"github.com/relux-works/swarma-witness/policy"
	"github.com/relux-works/swarma-witness/records"
	"github.com/relux-works/swarma-witness/store"
	"github.com/relux-works/swarma-witness/wire"
)

type Head struct {
	Seq  int64
	Hash string
}

func (s *Service) Append(ctx context.Context, peer policy.Peer, stream, id string, expected Head, line []byte) (result []byte, resultErr error) {
	end, e := s.reserve(ctx, peer, "append", stream)
	if e != nil {
		return nil, e
	}
	defer end()
	defer s.finishRefusal(ctx, peer, stream, "append", id, &result, &resultErr)
	if !wire.RequestID(id) || expected.Seq < 0 || expected.Seq > wire.MaxInt || !wire.Hash(expected.Hash) {
		return nil, wire.Refuse("request_malformed")
	}
	v, e := wire.Line(line)
	if e != nil {
		return nil, e
	}
	env, e := wire.Object(v, "body", "signature")
	if e != nil {
		return nil, e
	}
	body, ok := env["body"].(map[string]any)
	if !ok || !wire.Integer(body["seq"], 1, wire.MaxInt) {
		return nil, wire.Refuse("request_malformed")
	}
	seq := body["seq"].(int64)
	for _, old := range s.state.Entries {
		if old.Stream != stream || old.Seq != seq {
			continue
		}
		original, e := s.disk.ReadObject(old.Record)
		if e != nil {
			return nil, s.fail(false)
		}
		if !exactOriginal(original, line, records.Hash(original) == records.Hash(line)) {
			return nil, wire.Refuse("position_conflict")
		}
		if expected.Seq != old.Seq-1 || expected.Hash != old.Previous {
			return nil, wire.Refuse("head_conflict")
		}
		binding, e := wire.DecodeBinding(old.Binding)
		if e != nil {
			return nil, s.fail(false)
		}
		record, e := records.DecodeKeymaker(original, binding, old.Seq <= 2)
		if e != nil {
			return nil, s.fail(false)
		}
		receipt, e := s.disk.ReadObject(old.Receipt)
		if e != nil {
			return nil, s.fail(false)
		}
		if e = evidence.VerifyReceipt(receipt, record, binding, old.Witness, old.Control); e != nil {
			return nil, s.fail(false)
		}
		// Exact retry is an audit-only transaction. No receipt constructor, signer,
		// current-key record reauthorization or record append occurs on this path.
		_, e = s.commit(ctx, s.state, store.Manifest{Chain: "audits"}, nil, s.auditFields(peer, stream, "retry", id, old.Record, "success", ""), nil)
		if e != nil {
			return nil, e
		}
		return append([]byte(nil), receipt...), nil
	}
	head, exists := s.state.head(stream)
	headSeq, headHash := int64(0), wire.ZeroHash
	if exists {
		headSeq = head.Seq
		headHash = head.Record
	}
	if headSeq >= wire.MaxInt {
		return nil, wire.Refuse("sequence_exhausted")
	}
	if expected.Seq != headSeq || expected.Hash != headHash || seq != headSeq+1 || body["prev_hash"] != headHash {
		return nil, wire.Refuse("head_conflict")
	}
	if !exists && s.state.Grants[stream] != records.Hash(line) {
		return nil, wire.Refuse("bootstrap_required")
	}
	binding, e := s.policy.Binding(stream)
	if e != nil {
		return nil, e
	}
	record, e := records.DecodeKeymaker(line, binding, seq <= 2)
	if e != nil {
		return nil, e
	}
	_, control := s.state.control()
	receipt, e := evidence.NewReceipt(record, binding, s.state.Witness, control, s.signers[s.state.Witness.Public])
	if e != nil {
		return nil, e
	}
	next := s.state
	next.Entries = append(append([]entry(nil), next.Entries...), entry{Stream: stream, Seq: seq, Previous: headHash, Record: record.Hash(), Receipt: records.Hash(receipt), Binding: binding.Bytes(), Witness: s.state.Witness, Control: control})
	next.Grants = map[string]string{}
	for k, v := range s.state.Grants {
		if k != stream {
			next.Grants[k] = v
		}
	}
	prior := entry{Stream: stream, Seq: 0, Record: wire.ZeroHash, Receipt: wire.ZeroHash, Control: control}
	if exists {
		prior = head
	}
	t := custodian.Transition{Previous: tuple(s.policy.Service, prior), Next: tuple(s.policy.Service, next.Entries[len(next.Entries)-1])}
	_, e = s.commit(ctx, next, store.Manifest{Chain: "records", Stream: stream, Seq: seq, Previous: headHash, Head: record.Hash()}, []store.Object{{Kind: "record", Bytes: record.Line()}, {Kind: "receipt", Bytes: receipt}}, s.auditFields(peer, stream, "append", id, record.Hash(), "success", ""), &t)
	if e != nil {
		return nil, e
	}
	return append([]byte(nil), receipt...), nil
}
func (s *Service) auditFields(peer policy.Peer, stream, operation, id, hash, result, code string) audit.Fields {
	_, control := s.state.control()
	return audit.Fields{Instance: s.instance, Principal: peer.ID, Stream: stream, Operation: operation, RequestID: id, RecordHash: hash, ControlHash: control, Result: result, Code: code}
}

// Read validates authorization and independent evidence before a bounded,
// durably audited refusal. G21/G22 latest/proof construction remains unavailable;
// no synthetic signed head or partial page is exposed as a service success.
func (s *Service) Read(ctx context.Context, peer policy.Peer, method, stream, id string) ([]byte, error) {
	if method != "latest" && method != "proof_page" {
		return nil, wire.Refuse("request_malformed")
	}
	end, e := s.reserve(ctx, peer, method, stream)
	if e != nil {
		return nil, e
	}
	defer end()
	if !wire.RequestID(id) {
		return nil, wire.Refuse("request_malformed")
	}
	_, e = s.commit(ctx, s.state, store.Manifest{Chain: "audits"}, nil, s.auditFields(peer, stream, method, id, "", "refused", "profile_unavailable"), nil)
	if e != nil {
		return nil, e
	}
	return nil, wire.Refuse("profile_unavailable")
}

// Digest equality is only an acceleration hint; exact bytes remain mandatory.
func exactOriginal(original, line []byte, digestEqual bool) bool {
	return digestEqual && bytes.Equal(original, line)
}
