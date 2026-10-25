//go:build linux

// Package qualifiedtime wires the inactive WC1 consuming windows. There is no
// accepting production runtime, original preparer or native deadline enforcer.
package qualifiedtime

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/relux-works/swarma-credential-broker/timeconf"
	"github.com/relux-works/swarma-witness/store"
	"github.com/relux-works/swarma-witness/wire"
)

const MappingVersion = "witness-transition-map:1"
const NativeTransition = "WC1TimeUse/1"
const EnrolledTransition = "WC1TimeUse:1"

// The closed mapping is shared by expectation construction and both codec
// directions. Syntactic ID validity is insufficient; there is no substitution.
func transition(mapping, native, enrolled string) error {
	if mapping != MappingVersion || native != NativeTransition || enrolled != EnrolledTransition {
		return &timeconf.HandoffRefusal{Code: "transition_mapping"}
	}
	return nil
}

type Window string

const (
	P   Window = "P"
	R   Window = "R"
	X   Window = "X"
	TLS Window = "TLS"
)

func profile(w Window) string {
	switch w {
	case P:
		return "state-witness-prepare:1"
	case R:
		return "state-witness-publication:1"
	case X:
		return "state-witness-release:1"
	case TLS:
		return "state-witness-tls:1"
	}
	return ""
}

// NativeSnapshot retains full native values separately from the unused scalar
// revision. TLS compares it before m without modifying its closed operation body.
type NativeSnapshot struct {
	Root, Record, Control, Audit, Policy, Candidate, Confirmation, Reservation string
	Epoch                                                                      string
	UnusedRevision                                                             int64
}

// Intent is installed by the protected operation/connection owner, not decoded
// from H. TLSBody is exactly the existing native TLS body. P/R/X bind the same
// native predecessor, frozen inventory and original deadline in their own codec.
type Intent struct {
	Service, Lineage, Original, Principal, Method, Arguments, Purpose string
	Generation                                                        int64
	Incarnation, Connection                                           string
	Window                                                            Window
	Snapshot                                                          NativeSnapshot
	Enrollment                                                        timeconf.Enrollment
	Run, Challenge                                                    string
	Deadline                                                          timeconf.HandoffDeadline
	Budget                                                            timeconf.HandoffBudget
	XCommitNS, XSendNS                                                int64
	FloorNS, ExpiryNS, UncertaintyCapNS                               int64
	Mapping, NativeVersion, TransitionVersion                         string
	TLSBody, FrozenOutcome                                            []byte
}

func (i Intent) key() store.TimeUseKey {
	return store.TimeUseKey{Lineage: i.Lineage, Original: i.Original, Window: string(i.Window), Slot: 1}
}

func (i Intent) nativeBytes() ([]byte, error) {
	if profile(i.Window) == "" || !wire.Name(i.Service) || !wire.Name(i.Lineage) || !wire.RequestID(i.Original) || i.Run == "" || i.Snapshot.Epoch == "" || i.Run == i.Snapshot.Epoch || i.Snapshot.UnusedRevision < 0 || !wire.Hash(i.Snapshot.Root) || len(i.FrozenOutcome) == 0 || len(i.FrozenOutcome) > 65536 {
		return nil, &timeconf.HandoffRefusal{Code: "native_binding"}
	}
	if err := transition(i.Mapping, i.NativeVersion, i.TransitionVersion); err != nil {
		return nil, err
	}
	for _, value := range []string{i.Snapshot.Record, i.Snapshot.Control, i.Snapshot.Audit, i.Snapshot.Policy, i.Snapshot.Candidate, i.Snapshot.Confirmation, i.Arguments} {
		if !wire.Hash(value) {
			return nil, &timeconf.HandoffRefusal{Code: "native_binding"}
		}
	}
	if !wire.Opaque(i.Principal) || !wire.Name(i.Method) || !wire.Name(i.Purpose) || i.Generation < 1 || i.Generation > wire.MaxInt || i.Incarnation == "" || i.Snapshot.Reservation == "" {
		return nil, &timeconf.HandoffRefusal{Code: "native_binding"}
	}
	if i.Window == X {
		f, err := strconv.ParseInt(string(i.Budget.FinalWorkMaxNS), 10, 64)
		if err != nil || i.XCommitNS <= 0 || i.XSendNS <= 0 || i.XCommitNS > f || i.XSendNS > f-i.XCommitNS {
			return nil, &timeconf.HandoffRefusal{Code: "reserve"}
		}
	}
	if i.Window == TLS {
		v, err := wire.Parse(i.TLSBody, 65536)
		if err != nil {
			return nil, err
		}
		x, err := wire.Object(v, "v", "service", "role", "principal_id", "peer_spki", "chain_digest", "tls_policy_digest", "connection_id", "config_generation")
		if err != nil || !wire.One(x["v"]) || x["service"] != i.Service || x["principal_id"] != i.Principal || x["connection_id"] != i.Original || x["config_generation"] != i.Generation {
			return nil, &timeconf.HandoffRefusal{Code: "native_binding"}
		}
		raw, err := wire.Canonical(v)
		if err != nil || !bytes.Equal(raw, i.TLSBody) {
			return nil, &timeconf.HandoffRefusal{Code: "native_binding"}
		}
		return append([]byte(nil), raw...), nil
	}
	return wire.Canonical(map[string]any{
		"v": int64(1), "codec": "witness-window-intent/1", "service": i.Service,
		"lineage": i.Lineage, "original": i.Original, "principal": i.Principal,
		"method": i.Method, "arguments": i.Arguments, "purpose": i.Purpose,
		"generation": i.Generation, "incarnation": i.Incarnation, "connection": i.Connection,
		"phase": string(i.Window), "slot": int64(1), "epoch": i.Snapshot.Epoch,
		"root": i.Snapshot.Root, "record": i.Snapshot.Record, "control": i.Snapshot.Control,
		"audit": i.Snapshot.Audit, "policy": i.Snapshot.Policy, "candidate": i.Snapshot.Candidate,
		"confirmation": i.Snapshot.Confirmation, "reservation": i.Snapshot.Reservation,
		"unused_revision": i.Snapshot.UnusedRevision,
		"boot":            i.Deadline.Boot, "clock": i.Deadline.Clock, "start": string(i.Deadline.StartNS),
		"deadline": string(i.Deadline.AbsoluteNS), "original_utc": string(i.Deadline.OriginalUTCNS),
		"original_budget": string(i.Deadline.OriginalBudgetNS), "mapping": i.Deadline.MappingDigest,
		"frozen_outcome": store.Hash(i.FrozenOutcome), "x_commit_ns": i.XCommitNS, "x_send_ns": i.XSendNS,
	})
}

func (i Intent) expected() (timeconf.WindowExpected, []byte, error) {
	b, err := i.nativeBytes()
	if err != nil || len(b) > 65536 {
		return timeconf.WindowExpected{}, nil, &timeconf.HandoffRefusal{Code: "native_binding"}
	}
	p := profile(i.Window)
	raw := append([]byte("qualified-time/consumer-operation/1\x00"), binary.BigEndian.AppendUint32(nil, uint32(len(p)))...)
	raw = append(raw, p...)
	raw = binary.BigEndian.AppendUint32(raw, uint32(len(b)))
	raw = append(raw, b...)
	return timeconf.WindowExpected{
		Enrollment: i.Enrollment, Operation: "sha256:" + store.Hash(raw), Challenge: i.Challenge,
		Run: i.Run, Epoch: i.Snapshot.Epoch,
		Window: timeconf.WindowIdentity{Profile: p, Sequence: "1"}, TransitionVersion: EnrolledTransition,
		Deadline: i.Deadline, Budget: i.Budget, JournalFloorNS: i.FloorNS, UncertaintyCapNS: i.UncertaintyCapNS,
	}, b, nil
}

// Encode and Decode are structural only. Neither decoding nor exact original
// comparison authenticates provenance or constructs a private preparation.
func Encode(i Intent, h timeconf.Handoff) ([]byte, error) {
	e, _, err := i.expected()
	if err != nil || h.Handoff.TransitionVersion != e.TransitionVersion || h.Handoff.ConsumerRun != e.Run || h.Handoff.Window != e.Window || h.Handoff.Deadline != e.Deadline || h.Handoff.Budget != e.Budget || h.Receipt.Facts.Scope.OperationDigest != e.Operation || h.Receipt.Facts.Sample.Challenge != e.Challenge {
		return nil, &timeconf.HandoffRefusal{Code: "transition_mapping"}
	}
	return timeconf.EncodeHandoff(h)
}
func Decode(i Intent, raw []byte) (timeconf.Handoff, error) {
	h, err := timeconf.DecodeHandoff(raw)
	if err != nil {
		return timeconf.Handoff{}, err
	}
	if _, err = Encode(i, h); err != nil {
		return timeconf.Handoff{}, err
	}
	return h, nil
}

type Bundle struct {
	Raw       []byte
	Originals [][]byte
	Prepared  timeconf.PreparedHandoff
}

// Only tagged tests construct a runtime. A future native implementation needs
// separate review and qualification. Effects must enforce the retained epoch,
// original D and complete endpoint without another clock/provider call here.
type finalClock interface {
	Capture() (timeconf.FinalCapture, error)
}
type localEffect interface {
	// Execute encloses the complete endpoint, including its durable authority
	// commit. Qualification must cover the whole callback, not just a send.
	Execute(timeconf.ActProtocol) error
	Act() error
}
type runtime struct {
	clock  finalClock
	effect localEffect
}
type engine struct {
	g, s, a *sync.Mutex
	stopped atomic.Bool
	window  Window
	retired map[string]bool
	witness timeconf.RollbackWitness
	reader  timeconf.OriginalReader
	disk    *store.Disk
	native  NativeSnapshot
	runtime *runtime
}

func newEngine(w Window) *engine {
	return &engine{g: &sync.Mutex{}, s: &sync.Mutex{}, a: &sync.Mutex{}, retired: make(map[string]bool, 64), window: w, witness: timeconf.ClosedWitness{}, reader: timeconf.ClosedOriginalReader{}}
}

type PAdapter struct{ e *engine }
type RAdapter struct{ e *engine }
type XAdapter struct{ e *engine }
type TLSAdapter struct{ e *engine }
type Windows struct {
	P   *PAdapter
	R   *RAdapter
	X   *XAdapter
	TLS *TLSAdapter
}

// New has no dependency injection, storage creation, test flag, wall clock or
// accepting witness/reader. Fixture tags cannot enable this constructor.
func New() *Windows {
	w := &Windows{&PAdapter{newEngine(P)}, &RAdapter{newEngine(R)}, &XAdapter{newEngine(X)}, &TLSAdapter{newEngine(TLS)}}
	for _, e := range []*engine{w.R.e, w.X.e, w.TLS.e} {
		e.g, e.s, e.a = w.P.e.g, w.P.e.s, w.P.e.a
	}
	return w
}
func (p *PAdapter) Consume(ctx context.Context, i Intent, b Bundle) error {
	return p.e.consume(ctx, i, b)
}
func (p *RAdapter) Consume(ctx context.Context, i Intent, b Bundle) error {
	return p.e.consume(ctx, i, b)
}
func (p *XAdapter) Consume(ctx context.Context, i Intent, b Bundle) error {
	return p.e.consume(ctx, i, b)
}
func (p *TLSAdapter) Consume(ctx context.Context, i Intent, b Bundle) error {
	return p.e.consume(ctx, i, b)
}
func (w *Windows) Stop() {
	w.P.e.stopped.Store(true)
	w.R.e.stopped.Store(true)
	w.X.e.stopped.Store(true)
	w.TLS.e.stopped.Store(true)
}

func inactive() error { return &timeconf.ActivationRefusal{Reason: "handoff_unqualified"} }

func (e *engine) consume(ctx context.Context, i Intent, b Bundle) error {
	if e == nil || e.runtime == nil || e.disk == nil || e.runtime.clock == nil || e.runtime.effect == nil {
		return inactive()
	}
	if i.Window != e.window || ctx.Err() != nil || e.stopped.Load() {
		return &timeconf.HandoffRefusal{Code: "admission"}
	}
	// All parsing/closure checks and allocations precede the terminal chain.
	i.TLSBody = append([]byte(nil), i.TLSBody...)
	i.FrozenOutcome = append([]byte(nil), i.FrozenOutcome...)
	expected, native, err := i.expected()
	if err != nil {
		return err
	}
	// Bound the complete copied closure before allocation; then validate only
	// owned bytes, so the persisted closure is exactly the checked one.
	if len(b.Raw) > 131072 || len(b.Originals) < 5 || len(b.Originals) > 63 {
		return &timeconf.HandoffRefusal{Code: "original_missing"}
	}
	total := len(b.Raw)
	for _, original := range b.Originals {
		if len(original) > (8<<20)-total {
			return &timeconf.HandoffRefusal{Code: "limit"}
		}
		total += len(original)
	}
	owned := Bundle{Raw: append([]byte(nil), b.Raw...), Prepared: b.Prepared}
	for _, original := range b.Originals {
		owned.Originals = append(owned.Originals, append([]byte(nil), original...))
	}
	h, err := Decode(i, owned.Raw)
	if err != nil {
		return err
	}
	if err = timeconf.CheckHandoffOriginals(h, owned.Originals); err != nil {
		return err
	}
	// No deferred provider, signer, original reader or external callback is
	// invoked in terminal. TLS takes G->L; P/R/X take G->S->A->L.
	retained, err := json.Marshal(struct {
		Version  string
		Mapping  string
		Native   []byte
		Snapshot NativeSnapshot
		Expected timeconf.WindowExpected
	}{NativeTransition, MappingVersion, native, i.Snapshot, expected})
	if err != nil || len(retained) > 65536 {
		return &timeconf.HandoffRefusal{Code: "limit"}
	}
	commitment, err := timeconf.HandoffCommitment(owned.Raw)
	if err != nil {
		return err
	}
	return e.terminal(i, expected, retained, owned, commitment)
}

func (e *engine) terminal(i Intent, expected timeconf.WindowExpected, native []byte, b Bundle, commitment string) error {
	e.g.Lock()
	defer e.g.Unlock()
	if e.window != TLS {
		e.s.Lock()
		defer e.s.Unlock()
		e.a.Lock()
		defer e.a.Unlock()
	}
	// The full native snapshot is compared before m. The broker's Revision is
	// only the exact unused generation; it is not a native hash or truncated ID.
	if e.retired[commitment] || len(e.retired) >= 64 {
		return &timeconf.HandoffRefusal{Code: "retired"}
	}
	// Retiring this private H is transient N3 discipline, never the durable
	// use key. Every final-chain exit retires it, including a failed check.
	e.retired[commitment] = true
	admitted, err := e.disk.AdmitTimeUse(i.key(), i.Snapshot.Root)
	if err != nil {
		return err
	}
	defer admitted.Release()
	if e.native != i.Snapshot || e.stopped.Load() {
		return &timeconf.HandoffRefusal{Code: "native_predecessor"}
	}
	local := timeconf.LockedWindowState{Intent: expected, Revision: timeconf.Generation(strconv.FormatInt(admitted.Revision(), 10)), Epoch: e.native.Epoch, Unused: true, Current: true, FloorNS: i.FloorNS, ExpiryNS: i.ExpiryNS}
	if admitted.Revision() != i.Snapshot.UnusedRevision || admitted.Prior() != i.Snapshot.Root || admitted.Key() != i.key() {
		return &timeconf.HandoffRefusal{Code: "native_predecessor"}
	}
	session := &useReceiver{admitted: admitted, local: local, intent: i, native: native, bundle: b, runtime: e.runtime, commitment: commitment}
	m, err := session.capture()
	if err != nil {
		return err
	}
	candidate, err := timeconf.VerifyWindow(b.Prepared, expected, local, m)
	if err != nil {
		return err
	}
	return session.ConsumeIfUnused(candidate, local, session)
}

type useReceiver struct {
	admitted   *store.TimeUseAdmission
	local      timeconf.LockedWindowState
	intent     Intent
	native     []byte
	bundle     Bundle
	runtime    *runtime
	read       bool
	used       bool
	commitment string
}

func (s *useReceiver) capture() (timeconf.FinalCapture, error) {
	if s.read || !s.admitted.Active() {
		return timeconf.FinalCapture{}, &timeconf.HandoffRefusal{Code: "extra_read"}
	}
	s.read = true
	return s.runtime.clock.Capture()
}

func (s *useReceiver) ConsumeIfUnused(c timeconf.WindowCandidate, local timeconf.LockedWindowState, act timeconf.ActProtocol) error {
	k, h, revision, epoch := c.Use()
	want := timeconf.UseKey{Consumer: local.Intent.Enrollment.Scope.Consumer, Store: local.Intent.Enrollment.Store, Operation: local.Intent.Operation, Window: local.Intent.Window}
	if s.used || !s.read || local != s.local || act != s || k != want || epoch != s.intent.Snapshot.Epoch || revision != local.Revision || c.TransitionVersion() != EnrolledTransition || h == "" || s.admitted.Key() != s.intent.key() || s.admitted.Prior() != s.intent.Snapshot.Root {
		return &timeconf.HandoffRefusal{Code: "use_binding"}
	}
	if s.commitment != h {
		return &timeconf.HandoffRefusal{Code: "use_binding"}
	}
	s.used = true
	u := store.TimeUse{Key: s.intent.key(), State: "burned", Revision: s.admitted.Revision() + 1, Run: local.Intent.Run, Epoch: epoch, Intent: s.native, Handoff: s.bundle.Raw, Originals: s.bundle.Originals}
	if err := s.admitted.Burn(u); err != nil {
		return err
	}
	return act.Act()
}

func (s *useReceiver) Act() error {
	if err := s.runtime.effect.Execute(endpointProtocol{s}); err != nil {
		// Already committed X/TLS authority cannot be overwritten by a later
		// delivery failure. An incomplete burned endpoint remains held.
		_ = s.admitted.Finish("held", nil)
		return err
	}
	return nil
}

type endpointProtocol struct{ receiver *useReceiver }

func (p endpointProtocol) Act() error { return p.receiver.localEndpoint() }

func (s *useReceiver) localEndpoint() error {
	// X commits every authority/recovery binding before any byte. TLS similarly
	// commits the peer admission before opening application authority. A later
	// delivery note has no method here and cannot affect retained authority.
	if s.intent.Window == X || s.intent.Window == TLS {
		out, err := s.outcome()
		if err != nil {
			return err
		}
		if err = s.admitted.Finish("committed", out); err != nil {
			return err
		}
		return s.runtime.effect.Act()
	}
	if err := s.runtime.effect.Act(); err != nil {
		_ = s.admitted.Finish("held", nil)
		return err
	}
	out, err := s.outcome()
	if err != nil {
		return err
	}
	return s.admitted.Finish("committed", out)
}

func (s *useReceiver) outcome() ([]byte, error) {
	kind := "WindowCommitted"
	if s.intent.Window == X {
		kind = "XReleaseCommitted"
	}
	// Exact intent/H/originals live in the same retained use entry. This outcome
	// binds the frozen native endpoint, predecessor and connection in that entry.
	b, err := json.Marshal(struct {
		Version, Kind, Native, Handoff, Root, Epoch, Connection string
		Key                                                     store.TimeUseKey
		Frozen                                                  []byte
	}{NativeTransition, kind, store.Hash(s.native), store.Hash(s.bundle.Raw), s.intent.Snapshot.Root, s.intent.Snapshot.Epoch, s.intent.Connection, s.intent.key(), s.intent.FrozenOutcome})
	return b, err
}

var _ timeconf.ConsumeIfUnused = (*useReceiver)(nil)
var _ timeconf.ActProtocol = (*useReceiver)(nil)
