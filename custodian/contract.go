// Package custodian declares independent authority dependencies, not a provider
// wire codec. Local hashes cannot implement these contracts. All defaults close.
package custodian

import (
	"context"

	"github.com/relux-works/swarma-witness/wire"
)

// Tuple is exactly the WS record/control namespace; audit is a separate contract.
type Tuple struct {
	Service, Chain                       string
	Stream                               *string
	Seq                                  int64
	RecordHash, ReceiptHash, ControlHash string
}
type Request struct {
	Tuple     Tuple
	Challenge [32]byte
}
type Transition struct {
	Previous, Next Tuple
	Transaction    string
}

// Evidence is opaque original provider material, not authority until the
// protected provider verifies its exact request, epoch, ancestry and freshness.
type Evidence struct{ Original []byte }
type Provider interface {
	ReadFresh(context.Context, Request) (Evidence, error)
	VerifyFresh(Request, Evidence) error
	Confirm(context.Context, Transition) (Evidence, error)
	VerifyConfirmation(Transition, Evidence) error
}
type Closed struct{}

func (Closed) ReadFresh(context.Context, Request) (Evidence, error) {
	return Evidence{}, wire.Refuse("storage_unavailable")
}
func (Closed) VerifyFresh(Request, Evidence) error { return wire.Refuse("storage_unavailable") }
func (Closed) Confirm(context.Context, Transition) (Evidence, error) {
	return Evidence{}, wire.Refuse("storage_unavailable")
}
func (Closed) VerifyConfirmation(Transition, Evidence) error {
	return wire.Refuse("storage_unavailable")
}

// Exclusion covers the whole serving lifetime and actual effects, not a local
// flock or a copied lease. No accepting implementation is supplied here.
type Exclusion interface {
	Check(context.Context, string) error
}
type ClosedExclusion struct{}

func (ClosedExclusion) Check(context.Context, string) error {
	return wire.Refuse("profile_unavailable")
}

// Recovery must independently reconcile exact root, record/control and audit
// evidence. The byte arguments are local claims, never proof against rollback.
type Recovery interface {
	Assess(context.Context, string, []byte) error
}
type ClosedRecovery struct{}

func (ClosedRecovery) Assess(context.Context, string, []byte) error {
	return wire.Refuse("profile_unavailable")
}

// Time is an unimplemented native qualification boundary. No G16 codec,
// wall-clock fallback or positive production time path is introduced by S3.
type Time interface {
	Prepare(context.Context, string) (UTC string, err error)
	Publish(context.Context, string) error
	Release(context.Context, string) error
}
type ClosedTime struct{}

func (ClosedTime) Prepare(context.Context, string) (string, error) {
	return "", wire.Refuse("profile_unavailable")
}
func (ClosedTime) Publish(context.Context, string) error { return wire.Refuse("profile_unavailable") }
func (ClosedTime) Release(context.Context, string) error { return wire.Refuse("profile_unavailable") }
