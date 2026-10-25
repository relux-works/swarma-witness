// Package service contains an unserved transaction coordinator. The public
// constructor installs only closed dependencies; synthetic providers live in tests.
package service

import (
	"bytes"
	"encoding/json"

	"github.com/relux-works/swarma-registrar/ccj"
	"github.com/relux-works/swarma-witness/config"
	"github.com/relux-works/swarma-witness/policy"
	"github.com/relux-works/swarma-witness/records"
	"github.com/relux-works/swarma-witness/store"
	"github.com/relux-works/swarma-witness/wire"
)

type entry struct {
	Stream   string      `json:"stream"`
	Seq      int64       `json:"seq"`
	Previous string      `json:"previous"`
	Record   string      `json:"record"`
	Receipt  string      `json:"receipt"`
	Binding  []byte      `json:"binding"`
	Witness  records.Key `json:"witness"`
	Control  string      `json:"control"`
}
type action struct {
	ID      string      `json:"id"`
	Proof   string      `json:"proof"`
	Seq     int64       `json:"seq"`
	Line    string      `json:"line"`
	Receipt string      `json:"receipt"`
	Witness records.Key `json:"witness"`
}
type state struct {
	Version      int64             `json:"v"`
	Revision     int64             `json:"revision"`
	Policy       []byte            `json:"policy"`
	Witness      records.Key       `json:"witness"`
	Entries      []entry           `json:"entries"`
	Actions      []action          `json:"actions"`
	Grants       map[string]string `json:"grants"`
	AuditSeq     int64             `json:"audit_seq"`
	AuditHash    string            `json:"audit_hash"`
	HistoryBytes int64             `json:"history_bytes"`
	AuditBytes   int64             `json:"audit_bytes"`
}

func encodeState(s state) ([]byte, error) {
	b, e := json.Marshal(s)
	if e != nil {
		return nil, wire.Refuse("storage_unavailable")
	}
	if len(b) > store.SegmentLimit {
		return nil, wire.Refuse("limit_exceeded")
	}
	v, e := ccj.Parse(b, ccj.RegistrationMalformed)
	if e != nil {
		return nil, wire.Refuse("storage_unavailable")
	}
	return wire.Canonical(v)
}
func decodeState(b []byte) (state, error) {
	var s state
	if len(b) > store.SegmentLimit || json.Unmarshal(b, &s) != nil {
		return s, wire.Refuse("storage_unavailable")
	}
	raw, e := encodeState(s)
	if e != nil || !bytes.Equal(b, raw) || s.Version != 1 || s.Revision < 0 || s.Revision > wire.MaxInt || s.AuditSeq < 0 || s.AuditSeq > wire.MaxInt || !wire.Hash(s.AuditHash) || len(s.Entries)+len(s.Actions) > 1024 || s.HistoryBytes < 0 || s.HistoryBytes > 100<<30 || s.AuditBytes < 0 || s.AuditBytes > 1<<30 {
		return state{}, wire.Refuse("storage_unavailable")
	}
	heads := map[string]entry{}
	for _, v := range s.Entries {
		old, ok := heads[v.Stream]
		seq, hash := int64(0), wire.ZeroHash
		if ok {
			seq, hash = old.Seq, old.Record
		}
		if !wire.Name(v.Stream) || v.Seq != seq+1 || v.Previous != hash || !wire.Hash(v.Record) || !wire.Hash(v.Receipt) || !wire.Hash(v.Control) {
			return state{}, wire.Refuse("storage_unavailable")
		}
		if _, e := wire.DecodeBinding(v.Binding); e != nil {
			return state{}, wire.Refuse("storage_unavailable")
		}
		heads[v.Stream] = v
	}
	ids := map[string]bool{}
	for j, v := range s.Actions {
		if !wire.RequestID(v.ID) || ids[v.ID] || v.Seq != int64(j+1) || !wire.Hash(v.Line) || !wire.Hash(v.Receipt) || !wire.Hash(v.Proof) {
			return state{}, wire.Refuse("storage_unavailable")
		}
		ids[v.ID] = true
	}
	for k, v := range s.Grants {
		if !wire.Name(k) || !wire.Hash(v) {
			return state{}, wire.Refuse("storage_unavailable")
		}
	}
	return s, nil
}
func policyBytes(s policy.Snapshot) ([]byte, error) {
	bindings := []any{}
	for _, b := range s.Bindings {
		v, e := wire.Parse(b.Bytes(), wire.LineLimit)
		if e != nil {
			return nil, e
		}
		bindings = append(bindings, v)
	}
	principals := []any{}
	for _, p := range s.Principals {
		pins := []any{}
		for _, pin := range p.Pins {
			pins = append(pins, pin)
		}
		principals = append(principals, map[string]any{"id": p.ID, "role": string(p.Role), "transport_pins": pins})
	}
	return wire.Canonical(map[string]any{"service": s.Service, "bindings": bindings, "principals": principals})
}
func snapshot(raw []byte) (policy.Snapshot, error) { p, e := config.Parse(raw); return p.Snapshot(), e }
func (s state) head(stream string) (entry, bool) {
	for i := len(s.Entries) - 1; i >= 0; i-- {
		if s.Entries[i].Stream == stream {
			return s.Entries[i], true
		}
	}
	return entry{Stream: stream, Previous: wire.ZeroHash}, false
}
func (s state) control() (int64, string) {
	if len(s.Actions) == 0 {
		return 0, wire.ZeroHash
	}
	a := s.Actions[len(s.Actions)-1]
	return a.Seq, a.Line
}
