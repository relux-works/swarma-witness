//go:build linux && swarma_timeconf_fixture

package qualifiedtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/relux-works/swarma-credential-broker/timeconf"
	"github.com/relux-works/swarma-credential-broker/timeconftest"
	"github.com/relux-works/swarma-witness/store"
	"github.com/relux-works/swarma-witness/transport"
	"github.com/relux-works/swarma-witness/wire"
)

type modelClock struct {
	e     *engine
	m     timeconf.FinalCapture
	reads int
	after func()
}

func (c *modelClock) Capture() (timeconf.FinalCapture, error) {
	c.reads++
	if c.e.g.TryLock() {
		c.e.g.Unlock()
		return timeconf.FinalCapture{}, errors.New("capture before final admission")
	}
	if c.reads != 1 {
		return timeconf.FinalCapture{}, errors.New("extra final read")
	}
	if c.after != nil {
		c.after()
	}
	return c.m, nil
}

type modelEffect struct {
	t             *testing.T
	dir           string
	i             Intent
	now, deadline int64
	acts          int
	frame         []byte
	before        func()
}

func diskUse(t *testing.T, dir string, key store.TimeUseKey) store.TimeUse {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "root"))
	if err != nil {
		t.Fatal(err)
	}
	m, _, err := store.Decode(raw, store.RootMagic)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, m.TimeUses+".obj"))
	if err != nil {
		t.Fatal(err)
	}
	var table struct {
		Version string
		Uses    []store.TimeUse
	}
	if err = json.Unmarshal(b, &table); err != nil || table.Version != NativeTransition {
		t.Fatal("retained use codec", err)
	}
	for _, u := range table.Uses {
		if u.Key == key {
			return u
		}
	}
	t.Fatal("stable original key cannot be H")
	return store.TimeUse{}
}

// Execute models enforcement over the entire endpoint callback. This explicit
// deterministic model is not a qualifying native clock or preemption backend.
func (e *modelEffect) Execute(endpoint timeconf.ActProtocol) error {
	if e.now >= e.deadline {
		return &timeconf.HandoffRefusal{Code: "deadline"}
	}
	return endpoint.Act()
}

func (e *modelEffect) Act() error {
	u := diskUse(e.t, e.dir, e.i.key())
	if u.State != "burned" && u.State != "committed" {
		e.t.Error("durable burn must precede act")
		return errors.New("no burn")
	}
	if e.i.Window == X || e.i.Window == TLS {
		if u.State != "committed" || len(u.Outcome) == 0 {
			e.t.Error("durable authority must precede every byte or application admission")
			return errors.New("no authority")
		}
		if e.i.Window == X && !bytes.Contains(u.Outcome, []byte("XReleaseCommitted")) {
			e.t.Error("XReleaseCommitted missing")
		}
	}
	if e.before != nil {
		e.before()
	}
	// This is an explicit deterministic enforcement model. It is no native
	// clock/deadline backend and supplies no production post-read bound proof.
	if e.now >= e.deadline {
		return &timeconf.HandoffRefusal{Code: "deadline"}
	}
	e.acts++
	if e.i.Window == X {
		e.frame = append([]byte(nil), e.i.FrozenOutcome...)
	}
	return nil
}

type windowFixture struct {
	e      *engine
	i      Intent
	b      Bundle
	clock  *modelClock
	effect *modelEffect
	dir    string
}

func (f windowFixture) consume(ctx context.Context, i Intent, b Bundle) error {
	switch f.i.Window {
	case P:
		return (&PAdapter{e: f.e}).Consume(ctx, i, b)
	case R:
		return (&RAdapter{e: f.e}).Consume(ctx, i, b)
	case X:
		return (&XAdapter{e: f.e}).Consume(ctx, i, b)
	case TLS:
		return (&TLSAdapter{e: f.e}).Consume(ctx, i, b)
	}
	panic("unknown fixture window")
}

func localDisk(t *testing.T) (*store.Disk, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	index := []byte("synthetic frozen service index")
	root, err := store.Encode(store.RootMagic, store.Manifest{Service: "test", Transaction: wire.ZeroHash, Phase: "root", Index: store.Hash(index)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"root": root, store.Hash(index) + ".obj": index} {
		if err = os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	fd, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	d, err := store.Inspect(fd, "test", store.Calls{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d, dir
}

func fixture(t *testing.T, w Window) windowFixture {
	t.Helper()
	d, dir := localDisk(t)
	providerDir := t.TempDir()
	if err := os.Chmod(providerDir, 0700); err != nil {
		t.Fatal(err)
	}
	f, err := timeconftest.NewHandoffProvider(providerDir)
	if err != nil {
		t.Fatal(err)
	}
	key := store.TimeUseKey{Lineage: "test-lineage", Original: strings.Repeat("1", 32), Window: string(w), Slot: 1}
	root, _ := d.Snapshot()
	if err = d.AllocateTimeUses(store.Hash(root), []store.TimeUseKey{key}); err != nil {
		t.Fatal("original slot allocation", err)
	}
	root, _ = d.Snapshot()
	originalUTC := time.Now().Add(400 * time.Millisecond)
	digest := f.Enrollment().Authority.TrustRootDigest
	i := Intent{Service: "test", Lineage: key.Lineage, Original: key.Original, Principal: "reader", Method: "append", Arguments: store.Hash([]byte("exact original arguments")), Purpose: "audit", Generation: 1, Incarnation: "writer-incarnation", Connection: key.Original, Window: w,
		Snapshot:   NativeSnapshot{Root: store.Hash(root), Record: wire.ZeroHash, Control: wire.ZeroHash, Audit: wire.ZeroHash, Policy: store.Hash([]byte("policy")), Candidate: store.Hash([]byte("candidate")), Confirmation: store.Hash([]byte("confirmed")), Reservation: "original-reservation", Epoch: "writer:deployment:epoch-42", UnusedRevision: 0},
		Enrollment: f.Enrollment(), Run: strings.Repeat("a", 32), Challenge: strings.Repeat("2", 32),
		Deadline:  timeconf.HandoffDeadline{Boot: "11111111-1111-4111-8111-111111111111", Clock: "CLOCK_BOOTTIME", StartNS: "211000000000", AbsoluteNS: "211250000000", OriginalUTCNS: timeconf.Nanoseconds(strconv.FormatInt(originalUTC.UnixNano(), 10)), OriginalBudgetNS: "250000000", MappingDigest: digest},
		Budget:    timeconf.HandoffBudget{QualificationDigest: digest, TotalDelayNS: "300000000", FinalWorkMaxNS: "20000000", ErrorNS: "1000000", ReservedUncertaintyNS: "500000000"},
		XCommitNS: 10000000, XSendNS: 10000000, FloorNS: 140000000000, ExpiryNS: 300000000000, UncertaintyCapNS: 1500000000, Mapping: MappingVersion, NativeVersion: NativeTransition, TransitionVersion: EnrolledTransition, FrozenOutcome: []byte("exact frozen endpoint bytes")}
	if w == TLS {
		i.TLSBody, err = wire.Canonical(map[string]any{"v": int64(1), "service": i.Service, "role": "client", "principal_id": i.Principal, "peer_spki": "synthetic-pin", "chain_digest": store.Hash([]byte("DER")), "tls_policy_digest": i.Snapshot.Policy, "connection_id": i.Original, "config_generation": i.Generation})
		if err != nil {
			t.Fatal(err)
		}
	}
	expected, _, err := i.expected()
	if err != nil {
		t.Fatal(err)
	}
	packet, err := f.CollectHandoff(context.Background(), timeconf.ConsumptionRequest{Deadline: originalUTC, Expected: i.Enrollment, OperationDigest: expected.Operation, Challenge: i.Challenge, JournalFloor: i.FloorNS}, expected.Window, i.Run, strings.Repeat("3", 32))
	if err != nil {
		t.Fatal("real fixture settlement", err)
	}
	h, err := timeconf.DecodeHandoff(packet.Raw)
	if err != nil {
		t.Fatal(err)
	}
	h.Handoff.TransitionVersion = EnrolledTransition
	raw, err := Encode(i, h)
	if err != nil {
		t.Fatal("native mapping encode", err)
	}
	prepared, err := timeconftest.PrepareHandoff(raw, packet.Originals, expected, 211000000000) // p=s, no pre-lock capture.
	if err != nil {
		t.Fatal("private fixture preparation", err)
	}
	e := newEngine(w)
	e.disk = d
	e.native = i.Snapshot
	clock := &modelClock{e: e, m: packet.Capture}
	effect := &modelEffect{t: t, dir: dir, i: i, now: packet.Capture.NS, deadline: 211250000000}
	e.runtime = &runtime{clock: clock, effect: effect}
	return windowFixture{e: e, i: i, b: Bundle{Raw: raw, Originals: packet.Originals, Prepared: prepared}, clock: clock, effect: effect, dir: dir}
}

// Every window checks timely/late decisions and ordering on virtual time with
// real tagged broker settlement/preparation and local S3 barriers. The endpoint,
// fence and final clock remain synthetic. This proves neither the real-time
// settlement bound nor native qualification. The positive control commits once
// with a stable key; TestWindowRealTimeQualification is selected separately.
func TestWindowTimelyEndpoint(t *testing.T) {
	for _, w := range []Window{P, R, X, TLS} {
		t.Run(string(w), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) { checkTimelyEndpoint(t, w) })
		})
	}
}

// checkTimelyEndpoint shares the unchanged settlement and endpoint assertions
// between virtual-time decisions and separately selected real-time qualification.
func checkTimelyEndpoint(t *testing.T, w Window) {
	t.Helper()
	f := fixture(t, w)
	if err := f.consume(context.Background(), f.i, f.b); err != nil {
		t.Fatal("timely endpoint must commit once", err)
	}
	u := diskUse(t, f.dir, f.i.key())
	if u.State != "committed" || u.Revision != 1 || f.effect.acts != 1 || f.clock.reads != 1 || u.Epoch != f.i.Snapshot.Epoch || u.Run != f.i.Run {
		t.Fatal("timely endpoint must commit once with separate epoch and run", u.State, f.effect.acts, f.clock.reads)
	}
	if len(u.Intent) == 0 || !bytes.Equal(u.Handoff, f.b.Raw) || len(u.Originals) != len(f.b.Originals) {
		t.Fatal("full intent and original closure retained")
	}
	if err := f.consume(context.Background(), f.i, f.b); err == nil || f.effect.acts != 1 || f.clock.reads != 1 {
		t.Fatal("duplicate/restart attempt must not capture or act")
	}
	fd, err := os.Open(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := store.Inspect(fd, "test", store.Calls{})
	if err != nil {
		t.Fatal("committed use must reopen", err)
	}
	defer reopened.Close()
	status, err := reopened.TimeUseStatus(f.i.key())
	if err != nil || status.State != "committed" {
		t.Fatal("exact status only on recovery", err)
	}
	root, _ := reopened.Snapshot()
	if _, err = reopened.AdmitTimeUse(f.i.key(), store.Hash(root)); err == nil {
		t.Fatal("fresh H/run cannot create an unused stable slot")
	}
}

// Stale final capture refuses before burn. A pause after the timely read keeps
// the burn, while the deterministic endpoint enforcer forbids the late effect.
func TestWindowStaleAndPostReadPause(t *testing.T) {
	for _, w := range []Window{P, R, X, TLS} {
		for _, pause := range []bool{false, true} {
			name := "stale"
			if pause {
				name = "post-read"
			}
			t.Run(string(w)+"/"+name, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					f := fixture(t, w)
					if pause {
						f.clock.after = func() { f.effect.now = f.effect.deadline }
					} else {
						f.clock.m.NS = f.effect.deadline
					}
					err := f.consume(context.Background(), f.i, f.b)
					var refusal *timeconf.HandoffRefusal
					if !errors.As(err, &refusal) || refusal.Code != "deadline" || f.effect.acts != 0 || f.clock.reads != 1 {
						t.Fatal("late effect must be prevented", err, f.effect.acts)
					}
					u := diskUse(t, f.dir, f.i.key())
					want := "unused"
					if pause {
						want = "held"
					}
					if u.State != want {
						t.Fatal("post-read failure must retain burn/authority", u.State, want)
					}
				})
			})
		}
	}
}

// Multiple pure checks of one unused snapshot are inert. Exactly one native
// receiver can burn, and a receiver cannot perform a second clock read.
func TestWindowDoubleCheckAndExtraRead(t *testing.T) {
	for _, w := range []Window{P, R, X, TLS} {
		t.Run(string(w), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := fixture(t, w)
				expected, native, err := f.i.expected()
				if err != nil {
					t.Fatal(err)
				}
				local := timeconf.LockedWindowState{Intent: expected, Revision: "0", Epoch: expected.Epoch, Unused: true, Current: true, FloorNS: f.i.FloorNS, ExpiryNS: f.i.ExpiryNS}
				for n := 0; n < 2; n++ {
					if _, err = timeconf.VerifyWindow(f.b.Prepared, expected, local, f.clock.m); err != nil {
						t.Fatal("pure check must not burn", err)
					}
				}
				a, err := f.e.disk.AdmitTimeUse(f.i.key(), f.i.Snapshot.Root)
				if err != nil {
					t.Fatal(err)
				}
				f.e.g.Lock()
				s := &useReceiver{admitted: a, local: local, intent: f.i, native: native, bundle: f.b, runtime: f.e.runtime}
				_, first := s.capture()
				_, second := s.capture()
				f.e.g.Unlock()
				a.Release()
				var refusal *timeconf.HandoffRefusal
				if first != nil || !errors.As(second, &refusal) || refusal.Code != "extra_read" || f.clock.reads != 1 {
					t.Fatal("second read must be refused", first, second)
				}
				f.clock.reads = 0
				if err = f.consume(context.Background(), f.i, f.b); err != nil || f.effect.acts != 1 {
					t.Fatal("double check allows only one act", err)
				}
			})
		})
	}
}

// Full native predecessor/epoch/revision drift refuses before the clock. TLS
// preserves its exact existing operation digest while separately checking these
// fields; P/R/X additionally bind them in their native operation digest.
func TestWindowNativeReadSetAndEpoch(t *testing.T) {
	for _, w := range []Window{P, R, X, TLS} {
		t.Run(string(w), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := fixture(t, w)
				e, _, err := f.i.expected()
				if err != nil {
					t.Fatal(err)
				}
				if e.Epoch == e.Run || e.Epoch != f.i.Snapshot.Epoch {
					t.Fatal("epoch must remain distinct from run")
				}
				if w == TLS {
					want, err := transport.ConsumerOperationDigest(f.i.TLSBody)
					if err != nil || want != e.Operation {
						t.Fatal("TLS operation digest changed", err)
					}
				}
				for _, mutate := range []func(*NativeSnapshot){func(s *NativeSnapshot) { s.Root = wire.ZeroHash }, func(s *NativeSnapshot) { s.Record = store.Hash([]byte("changed")) }, func(s *NativeSnapshot) { s.Epoch = f.i.Run }, func(s *NativeSnapshot) { s.UnusedRevision++ }} {
					f = fixture(t, w)
					mutate(&f.e.native)
					var refusal *timeconf.HandoffRefusal
					if err = f.consume(context.Background(), f.i, f.b); !errors.As(err, &refusal) || refusal.Code != "native_predecessor" || f.clock.reads != 0 || f.effect.acts != 0 {
						t.Fatal("native snapshot must be compared before m", err)
					}
				}
				f = fixture(t, w)
				if err = f.consume(context.Background(), f.i, f.b); err != nil {
					t.Fatal("unchanged native positive", err)
				}
			})
		})
	}
}

// The same closed mapping is required in expected metadata and both codec
// directions. Slash, wrong version, unknown mapping and mismatch never burn.
func TestWindowTransitionMapping(t *testing.T) {
	for _, w := range []Window{P, R, X, TLS} {
		t.Run(string(w), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := fixture(t, w)
				h, err := Decode(f.i, f.b.Raw)
				if err != nil {
					t.Fatal(err)
				}
				if raw, err := Encode(f.i, h); err != nil || !bytes.Equal(raw, f.b.Raw) {
					t.Fatal("exact mapping positive", err)
				}
				for _, version := range []string{NativeTransition, "WC1TimeUse:2", "OtherUse:1"} {
					bad := h
					bad.Handoff.TransitionVersion = version
					if _, err = Encode(f.i, bad); err == nil {
						t.Fatal("encoding mismatch accepted")
					}
					if raw, e := timeconf.EncodeHandoff(bad); e == nil {
						if _, err = Decode(f.i, raw); err == nil {
							t.Fatal("decoding mismatch accepted")
						}
					}
				}
				bad := f.i
				bad.Mapping = "unknown"
				if err = f.consume(context.Background(), bad, f.b); err == nil || f.clock.reads != 0 {
					t.Fatal("unknown mapping reached use")
				}
			})
		})
	}
}

// Synthetic complete-frame delivery followed by every non-authoritative note
// failure preserves the already durable authority byte-for-byte and never
// re-sends on reopen. macOS execution/flush qualification is separately PENDING.
func TestXPostSendAccountingFailure(t *testing.T) {
	for _, fault := range []string{"none", "write", "sync", "readback", "crash"} {
		t.Run(fault, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := fixture(t, X)
				if err := f.consume(context.Background(), f.i, f.b); err != nil || f.effect.acts != 1 {
					t.Fatal("X timely full frame", err)
				}
				before := diskUse(t, f.dir, f.i.key())
				if !bytes.Equal(f.effect.frame, f.i.FrozenOutcome) {
					t.Fatal("full original frame not delivered by model")
				}
				note := deliveryNote(t.TempDir(), fault)
				if fault == "none" && note != nil || fault != "none" && (note == nil || note.Error() != fault) {
					t.Fatal("intended delivery-note fault not exercised", fault, note)
				}
				fd, err := os.Open(f.dir)
				if err != nil {
					t.Fatal(err)
				}
				d, err := store.Inspect(fd, "test", store.Calls{})
				if err != nil {
					t.Fatal(err)
				}
				defer d.Close()
				after, err := d.TimeUseStatus(f.i.key())
				if err != nil {
					t.Fatal(err)
				}
				a, _ := json.Marshal(before)
				b, _ := json.Marshal(after)
				if !bytes.Equal(a, b) || after.State != "committed" {
					t.Fatal("post-send accounting changed release authority")
				}
				root, _ := d.Snapshot()
				if _, err = d.AdmitTimeUse(f.i.key(), store.Hash(root)); err == nil {
					t.Fatal("accounting failure authorized resend")
				}
			})
		})
	}
}

// Separate non-authoritative fixture maintenance: actual local file calls with
// bounded write/sync/readback/crash cuts, never a production late-job protocol.
func deliveryNote(dir, fault string) error {
	path := filepath.Join(dir, "delivery-note")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	b := []byte("non-authoritative delivery accounting")
	if fault == "write" {
		_, _ = f.Write(b[:3])
		return errors.New("write")
	}
	if _, err = f.Write(b); err != nil {
		return err
	}
	if fault == "crash" {
		return errors.New("crash")
	}
	if fault == "sync" {
		return errors.New("sync")
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	actual, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if fault == "readback" {
		actual = []byte("different note")
	}
	if !bytes.Equal(actual, b) {
		return errors.New("readback")
	}
	return nil
}

// H identifies transient preparation only. Retained keys and tombstones use the
// stable protected lineage/original/window/slot, and remain identical after a
// new envelope, run or epoch. A fresh H never grants a new unused slot.
func TestWindowStableKey(t *testing.T) {
	for _, w := range []Window{P, R, X, TLS} {
		t.Run(string(w), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := fixture(t, w)
				if err := f.consume(context.Background(), f.i, f.b); err != nil {
					t.Fatal("stable original slot must accept independently of H", err)
				}
				u := diskUse(t, f.dir, f.i.key())
				if u.Key.Original != f.i.Original || u.Key.Lineage != f.i.Lineage || u.Key.Slot != 1 {
					t.Fatal("stable original key cannot be H")
				}
				root, _ := f.e.disk.Snapshot()
				f.i.Snapshot.Root = store.Hash(root)
				f.i.Snapshot.UnusedRevision = 1
				f.i.Snapshot.Epoch = "replacement:epoch-43"
				f.i.Run = strings.Repeat("b", 32)
				f.e.native = f.i.Snapshot
				h, err := timeconf.DecodeHandoff(f.b.Raw)
				if err != nil {
					t.Fatal(err)
				}
				h.Handoff.ID = strings.Repeat("4", 32)
				h.Handoff.ConsumerRun = f.i.Run
				// P/R/X operation bodies change with the full read set, while TLS's
				// existing body stays fixed. Already-burned slots refuse either way.
				if w == TLS {
					f.b.Raw, err = Encode(f.i, h)
					if err != nil {
						t.Fatal(err)
					}
					e, _, err := f.i.expected()
					if err != nil {
						t.Fatal(err)
					}
					f.b.Prepared, err = timeconftest.PrepareHandoff(f.b.Raw, f.b.Originals, e, 211000000000)
					if err != nil {
						t.Fatal(err)
					}
				}
				if err = f.consume(context.Background(), f.i, f.b); err == nil || f.effect.acts != 1 || f.clock.reads != 1 {
					t.Fatal("fresh H, run or epoch must not redispatch burned slot", err)
				}
			})
		})
	}
}

// Tampered/missing originals and changed expected metadata refuse at their
// named validation boundary with no capture, burn or act. The valid packet
// for each window is exercised by TestWindowTimelyEndpoint.
func TestWindowOriginalsAndBinding(t *testing.T) {
	for _, w := range []Window{P, R, X, TLS} {
		for _, fault := range []string{"missing", "substitute", "deadline", "mapping"} {
			t.Run(string(w)+"/"+fault, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					f := fixture(t, w)
					want := "transition_mapping"
					switch fault {
					case "missing":
						f.b.Originals = f.b.Originals[:len(f.b.Originals)-1]
						want = "original_missing"
					case "substitute":
						f.b.Originals[4] = []byte("substitution")
						want = "original_mismatch"
					case "deadline":
						f.i.Deadline.AbsoluteNS = "211260000000"
					case "mapping":
						f.i.TransitionVersion = "WC1TimeUse:2"
						want = "native_binding"
					}
					var refusal *timeconf.HandoffRefusal
					if err := f.consume(context.Background(), f.i, f.b); !errors.As(err, &refusal) || refusal.Code != want || f.clock.reads != 0 || f.effect.acts != 0 {
						t.Fatal("original/binding refusal must precede capture", fault, err)
					}
					if u := diskUse(t, f.dir, f.i.key()); u.State != "unused" {
						t.Fatal("invalid preparation burned slot")
					}
				})
			})
		}
	}
}

// A failed check retires the private preparation; replaying that same H cannot
// obtain another read or burn even when presented with a favorable synthetic m.
func TestWindowFailedCheckRetires(t *testing.T) {
	for _, w := range []Window{P, R, X, TLS} {
		t.Run(string(w), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := fixture(t, w)
				timely := f.clock.m
				f.clock.m.NS = f.effect.deadline
				var refusal *timeconf.HandoffRefusal
				if err := f.consume(context.Background(), f.i, f.b); !errors.As(err, &refusal) || refusal.Code != "deadline" {
					t.Fatal("expected first check expiry", err)
				}
				f.clock.m = timely
				if err := f.consume(context.Background(), f.i, f.b); !errors.As(err, &refusal) || refusal.Code != "retired" || f.clock.reads != 1 || f.effect.acts != 0 {
					t.Fatal("failed check must retire preparation", err)
				}
				if diskUse(t, f.dir, f.i.key()).State != "unused" {
					t.Fatal("failed check wrote a burn")
				}
			})
		})
	}
}

// X's separate positive commit/send bounds must fit the original total f;
// undefined, zero, overflow and over-budget components never reach admission.
func TestXComponentBounds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := fixture(t, X)
		if _, _, err := f.i.expected(); err != nil {
			t.Fatal("valid split bound", err)
		}
		for _, pair := range [][2]int64{{0, 10000000}, {10000000, 0}, {10000001, 10000000}, {1<<63 - 1, 1}} {
			i := f.i
			i.XCommitNS = pair[0]
			i.XSendNS = pair[1]
			if err := f.consume(context.Background(), i, f.b); err == nil || f.clock.reads != 0 || f.effect.acts != 0 {
				t.Fatal("undefined/over-budget split reached use", err)
			}
		}
	})
}

// A pause before the first authoritative commit must prevent that commit, not
// merely the later send/application effect. Burn remains retained and held.
func TestWindowLateCommitForbidden(t *testing.T) {
	for _, w := range []Window{X, TLS} {
		t.Run(string(w), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := fixture(t, w)
				f.clock.after = func() { f.effect.now = f.effect.deadline }
				if err := f.consume(context.Background(), f.i, f.b); err == nil {
					t.Fatal("late endpoint accepted")
				}
				u := diskUse(t, f.dir, f.i.key())
				if u.State == "committed" || len(u.Outcome) != 0 || f.effect.acts != 0 {
					t.Fatal("late authority commit must be prevented")
				}
			})
		})
	}
}

// A pause at delivery after a timely authority commit retains that exact
// authority, but cannot send a byte or open application admission late.
func TestWindowPostCommitPause(t *testing.T) {
	for _, w := range []Window{X, TLS} {
		t.Run(string(w), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				f := fixture(t, w)
				f.effect.before = func() { f.effect.now = f.effect.deadline }
				var refusal *timeconf.HandoffRefusal
				if err := f.consume(context.Background(), f.i, f.b); !errors.As(err, &refusal) || refusal.Code != "deadline" {
					t.Fatal("late delivery must refuse", err)
				}
				u := diskUse(t, f.dir, f.i.key())
				if u.State != "committed" || len(u.Outcome) == 0 || f.effect.acts != 0 || len(f.effect.frame) != 0 {
					t.Fatal("timely authority must survive late delivery without effects")
				}
			})
		})
	}
}
