// Package archive declares consumer-local archive operations. None is a WS
// method, URL selector, provider codec or recovery authorization.
package archive

import (
	"context"

	"github.com/relux-works/swarma-witness/wire"
)

type Object struct {
	Kind, Hash string
	Bytes      []byte
}
type Tail struct {
	Seq  int64
	Hash string
}
type Manifest struct {
	Service, Transaction string
	Previous, Next       Tail
	Objects              []Object
}
type Ack struct{ Original []byte }
type Query struct {
	Hash   string
	Length int64
	Cursor []byte
}
type Anchor struct{ Record, Control Tail }
type Approval struct{ Original []byte }
type Continuity struct{ Original []byte }
type CompleteHead struct{ Original []byte }
type DurableAnchor struct{ Original []byte }
type Consumer interface {
	Retain(context.Context, Manifest, Tail) (Ack, error)
	Retrieve(context.Context, Query) ([]byte, error)
	VerifyOffline(context.Context, Anchor, Anchor, Manifest, Approval) (Continuity, error)
	AdvanceAnchor(context.Context, Anchor, Continuity, CompleteHead, Approval) (DurableAnchor, error)
}

// Audit has its own independent monotonic namespace; it cannot be encoded as
// another chain in custodian.Tuple. Verification and fresh reads are mandatory.
type Audit interface {
	ConfirmAudit(context.Context, Manifest) (Ack, error)
	VerifyAudit(Manifest, Ack) error
	CheckAudit(context.Context, string, Tail) error
}
type Closed struct{}

func (Closed) Retain(context.Context, Manifest, Tail) (Ack, error) {
	return Ack{}, wire.Refuse("storage_unavailable")
}
func (Closed) Retrieve(context.Context, Query) ([]byte, error) {
	return nil, wire.Refuse("storage_unavailable")
}
func (Closed) VerifyOffline(context.Context, Anchor, Anchor, Manifest, Approval) (Continuity, error) {
	return Continuity{}, wire.Refuse("profile_unavailable")
}
func (Closed) AdvanceAnchor(context.Context, Anchor, Continuity, CompleteHead, Approval) (DurableAnchor, error) {
	return DurableAnchor{}, wire.Refuse("profile_unavailable")
}
func (Closed) ConfirmAudit(context.Context, Manifest) (Ack, error) {
	return Ack{}, wire.Refuse("storage_unavailable")
}
func (Closed) VerifyAudit(Manifest, Ack) error { return wire.Refuse("storage_unavailable") }
func (Closed) CheckAudit(context.Context, string, Tail) error {
	return wire.Refuse("storage_unavailable")
}
