package service

import (
	"context"
	"encoding/json"
	"github.com/relux-works/swarma-registrar/ccj"

	"github.com/relux-works/swarma-witness/custodian"
	"github.com/relux-works/swarma-witness/evidence"
	"github.com/relux-works/swarma-witness/policy"
	"github.com/relux-works/swarma-witness/records"
	"github.com/relux-works/swarma-witness/store"
	"github.com/relux-works/swarma-witness/wire"
)

func (s *Service) Admin(ctx context.Context, peer policy.Peer, id string, line []byte, proof policy.AdministrativeEvidence) (result []byte, resultErr error) {
	end, e := s.reserve(ctx, peer, "admin", "")
	if e != nil {
		return nil, e
	}
	defer end()
	defer s.finishRefusal(ctx, peer, "", "admin", id, &result, &resultErr)
	if !wire.RequestID(id) {
		return nil, wire.Refuse("request_malformed")
	}
	seq, hash := s.state.control()
	c := policy.ControlSnapshot{Seq: seq, Hash: hash, Actions: map[string]policy.RetainedAction{}, CurrentWitness: s.state.Witness}
	v, e := wire.Line(line)
	if e != nil {
		return nil, e
	}
	env, ok := v.(map[string]any)
	if !ok {
		return nil, wire.Refuse("request_malformed")
	}
	body, ok := env["body"].(map[string]any)
	if !ok {
		return nil, wire.Refuse("request_malformed")
	}
	if stream := wire.String(body["stream"]); stream != "" {
		if h, ok := s.state.head(stream); ok {
			c.HeadSeq = h.Seq
			c.HeadHash = h.Record
		} else {
			c.HeadHash = wire.ZeroHash
		}
	}
	for _, a := range s.state.Actions {
		action, e := s.disk.ReadObject(a.Line)
		if e != nil {
			return nil, s.fail(false)
		}
		receipt, e := s.disk.ReadObject(a.Receipt)
		if e != nil {
			return nil, s.fail(false)
		}
		if _, e = s.disk.ReadObject(a.Proof); e != nil {
			return nil, s.fail(false)
		}
		c.Actions[a.ID] = policy.RetainedAction{Action: action, Receipt: receipt}
	}
	plan, e := policy.PrepareAdmin(s.policy, peer, line, s.admin, c, proof)
	if e != nil {
		return nil, e
	}
	if plan.Replay {
		_, e = s.commit(ctx, s.state, store.Manifest{Chain: "audits"}, nil, s.auditFields(peer, "", "retry", id, records.Hash(line), "success", ""), nil)
		if e != nil {
			return nil, e
		}
		return append([]byte(nil), plan.Receipt...), nil
	}
	proofBytes, e := retainAdminProof(proof)
	if e != nil {
		return nil, e
	}
	receipt, e := evidence.NewControlReceipt(line, s.admin, s.state.Witness, s.signers[s.state.Witness.Public])
	if e != nil {
		return nil, e
	}
	next := s.state
	next.Actions = append(append([]action(nil), next.Actions...), action{ID: wire.String(body["action_id"]), Proof: records.Hash(proofBytes), Seq: seq + 1, Line: records.Hash(line), Receipt: records.Hash(receipt), Witness: s.state.Witness})
	prospective := s.policy
	prospective.Bindings = append([]wire.Binding(nil), s.policy.Bindings...)
	if plan.Binding.Valid() {
		replaced := false
		for i, b := range prospective.Bindings {
			if b.Stream() == plan.Binding.Stream() {
				prospective.Bindings[i] = plan.Binding
				replaced = true
			}
		}
		if !replaced {
			prospective.Bindings = append(prospective.Bindings, plan.Binding)
		}
	}
	if plan.Operation == "provision" {
		next.Grants = map[string]string{}
		for k, v := range s.state.Grants {
			next.Grants[k] = v
		}
		next.Grants[plan.Binding.Stream()] = wire.String(body["bootstrap_hash"])
	}
	if plan.Operation == "rotate_witness" {
		n := body["new_binding"].(map[string]any)
		next.Witness = records.Key{Public: wire.String(n["public_key"]), ID: wire.String(n["key_id"]), Epoch: n["key_epoch"].(int64), Role: records.Witness}
		if s.signers[next.Witness.Public] == nil {
			return nil, wire.Refuse("profile_unavailable")
		}
	}
	next.Policy, e = policyBytes(prospective)
	if e != nil {
		return nil, e
	}
	prevReceipt := wire.ZeroHash
	if len(s.state.Actions) > 0 {
		prevReceipt = s.state.Actions[len(s.state.Actions)-1].Receipt
	}
	t := custodian.Transition{Previous: custodian.Tuple{Service: s.policy.Service, Chain: "controls", Seq: seq, RecordHash: hash, ReceiptHash: prevReceipt, ControlHash: hash}, Next: custodian.Tuple{Service: s.policy.Service, Chain: "controls", Seq: seq + 1, RecordHash: records.Hash(line), ReceiptHash: records.Hash(receipt), ControlHash: records.Hash(line)}}
	_, e = s.commit(ctx, next, store.Manifest{Chain: "controls", Seq: seq + 1, Previous: hash, Head: records.Hash(line)}, []store.Object{{Kind: "control", Bytes: append([]byte(nil), line...)}, {Kind: "receipt", Bytes: receipt}, {Kind: "admin-proof", Bytes: proofBytes}}, s.auditFields(peer, "", "admin", id, records.Hash(line), "success", ""), &t)
	if e != nil {
		return nil, e
	}
	return append([]byte(nil), receipt...), nil
}

// Preserve the exact public consent/enrollment originals and protected expected
// contexts as restricted evidence, never audit text. This is local version1.
func retainAdminProof(p policy.AdministrativeEvidence) ([]byte, error) {
	if len(p.Objects) > 64 {
		return nil, wire.Refuse("limit_exceeded")
	}
	n := len(p.Consent) + len(p.FirstLine) + len(p.Packet)
	for _, value := range []string{p.DisclosureDigest, p.Approval.Public, p.Approval.ID, string(p.Approval.Role), p.Enrollment.Public, p.Enrollment.ID, string(p.Enrollment.Role), p.Old.Service, p.Old.Stream, p.Old.ActionHash, p.Old.PrincipalID, p.Old.Pin, p.Old.Challenge, p.Old.ChannelDigest, p.New.Service, p.New.Stream, p.New.ActionHash, p.New.PrincipalID, p.New.Pin, p.New.Challenge, p.New.ChannelDigest} {
		if len(value) > wire.LineLimit {
			return nil, wire.Refuse("limit_exceeded")
		}
		n += len(value)
	}
	for name, b := range p.Objects {
		if len(name) > 255 {
			return nil, wire.Refuse("limit_exceeded")
		}
		n += len(name)
		if len(b) > store.SegmentLimit {
			return nil, wire.Refuse("limit_exceeded")
		}
		n += len(b)
	}
	if n > store.SegmentLimit {
		return nil, wire.Refuse("limit_exceeded")
	}
	b, e := json.Marshal(p)
	if e != nil || len(b) > store.SegmentLimit {
		return nil, wire.Refuse("limit_exceeded")
	}
	v, e := ccj.Parse(b, ccj.RegistrationMalformed)
	if e != nil {
		return nil, wire.Refuse("request_malformed")
	}
	return wire.Canonical(map[string]any{"v": int64(1), "evidence": v})
}
