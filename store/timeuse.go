package store

import (
	"bytes"
	"encoding/json"
	"math"

	"github.com/relux-works/swarma-registrar/ccj"
	"github.com/relux-works/swarma-witness/wire"
)

// TimeUseKey is the protected original identity, never H, challenge, live run,
// operation digest or epoch. Slots are allocated before provider preparation.
type TimeUseKey struct {
	Lineage, Original, Window string
	Slot                      int64
}

// TimeUse is local WC1TimeUse/1 metadata in the owning S3 root, not a WS member.
// Exact intent and original copies survive cleanup/restart. Committed X means
// release authority, never delivered. Burned/held never authorize redispatch.
type TimeUse struct {
	Key             TimeUseKey
	Revision        int64
	State           string
	Run, Epoch      string
	Intent, Handoff []byte
	Originals       [][]byte
	Outcome         []byte
}

func timeUseBytes(uses []TimeUse) ([]byte, error) {
	if len(uses) > 64 {
		return nil, wire.Refuse("storage_unavailable")
	}
	seen := map[TimeUseKey]bool{}
	for _, u := range uses {
		if !wire.Name(u.Key.Lineage) || !wire.RequestID(u.Key.Original) || u.Key.Slot != 1 || seen[u.Key] || u.Revision < 0 || u.Revision >= math.MaxInt64 {
			return nil, wire.Refuse("storage_unavailable")
		}
		seen[u.Key] = true
		switch u.Key.Window {
		case "P", "R", "X", "TLS":
		default:
			return nil, wire.Refuse("storage_unavailable")
		}
		if u.State == "unused" {
			if u.Revision != 0 || u.Run != "" || u.Epoch != "" || len(u.Intent)+len(u.Handoff)+len(u.Originals)+len(u.Outcome) != 0 {
				return nil, wire.Refuse("storage_unavailable")
			}
		} else {
			if u.Revision != 1 || u.Run == "" || u.Epoch == "" || len(u.Intent) == 0 || len(u.Intent) > 65536 || len(u.Handoff) == 0 || len(u.Handoff) > 131072 || len(u.Originals) < 5 || len(u.Originals) > 63 {
				return nil, wire.Refuse("storage_unavailable")
			}
			for _, b := range u.Originals {
				if len(b) == 0 || len(b) > SegmentLimit {
					return nil, wire.Refuse("storage_unavailable")
				}
			}
			switch u.State {
			case "burned", "held":
				if len(u.Outcome) != 0 {
					return nil, wire.Refuse("storage_unavailable")
				}
			case "committed":
				if len(u.Outcome) == 0 || len(u.Outcome) > 131072 {
					return nil, wire.Refuse("storage_unavailable")
				}
			default:
				return nil, wire.Refuse("storage_unavailable")
			}
		}
	}
	b, e := json.Marshal(struct {
		Version string
		Uses    []TimeUse
	}{"WC1TimeUse/1", uses})
	if e != nil || len(b) > SegmentLimit {
		return nil, wire.Refuse("storage_unavailable")
	}
	v, e := ccj.Parse(b, ccj.RegistrationMalformed)
	if e != nil {
		return nil, wire.Refuse("storage_unavailable")
	}
	return wire.Canonical(v)
}

func decodeTimeUses(b []byte) ([]TimeUse, error) {
	var v struct {
		Version string
		Uses    []TimeUse
	}
	if len(b) > SegmentLimit || json.Unmarshal(b, &v) != nil || v.Version != "WC1TimeUse/1" {
		return nil, wire.Refuse("storage_unavailable")
	}
	exact, e := timeUseBytes(v.Uses)
	if e != nil || !bytes.Equal(exact, b) {
		return nil, wire.Refuse("storage_unavailable")
	}
	return v.Uses, nil
}

// Each S3 root preserves all tombstones. A step is allocation of original
// unused slots, one burn, or one terminal disposition. No deletion or reburn.
func validTimeUseStep(old, next []TimeUse) bool {
	if len(next) < len(old) {
		return false
	}
	changes := 0
	for i, u := range old {
		v := next[i]
		a, _ := json.Marshal(u)
		b, _ := json.Marshal(v)
		if bytes.Equal(a, b) {
			continue
		}
		changes++
		if u.Key != v.Key {
			return false
		}
		if u.State == "unused" && v.State == "burned" && v.Revision == u.Revision+1 {
			continue
		}
		if u.State != "burned" || v.State != "held" && v.State != "committed" {
			return false
		}
		v.State, v.Outcome = u.State, u.Outcome
		b, _ = json.Marshal(v)
		if !bytes.Equal(a, b) {
			return false
		}
	}
	for _, u := range next[len(old):] {
		if u.State != "unused" {
			return false
		}
	}
	return changes <= 1 && (len(next) == len(old) || changes == 0)
}

func (d *Disk) loadTimeUses(hash string) ([]TimeUse, error) {
	if hash == "" {
		return []TimeUse{}, nil
	}
	b, e := d.object(hash, "obj", SegmentLimit)
	if e != nil {
		return nil, e
	}
	return decodeTimeUses(b)
}

// persistTimeUses uses the same immutable segment/prepare/outcome/root order as
// service transactions. It never creates a separately acknowledged ledger or
// changes the frozen service index/audit/WS bytes. Independent use custody is
// still unqualified; these checked local calls do not establish power-loss safety.
func (d *Disk) persistTimeUses(uses []TimeUse) error {
	old, e := d.loadTimeUses(d.manifest.TimeUses)
	if e != nil || !validTimeUseStep(old, uses) {
		return wire.Refuse("storage_unavailable")
	}
	b, e := timeUseBytes(uses)
	if e != nil {
		return e
	}
	m := d.manifest
	m.Prior = Hash(d.root)
	m.TimeUses = Hash(b)
	m.Transaction = Hash(append(append([]byte("WC1TimeUse/1\x00"), d.root...), b...))
	p, e := d.prepareLocked(m, []Object{{Kind: "time-use", Bytes: b}})
	if e == nil {
		e = d.publishLocked(p, nil)
	}
	if e == nil {
		e = d.validateInventory()
	}
	if e == nil {
		var root []byte
		root, e = d.read("root", RootLimit)
		if e == nil && !bytes.Equal(root, d.root) {
			e = wire.Refuse("storage_unavailable")
		}
		if e == nil {
			var exact []byte
			exact, e = d.object(m.TimeUses, "obj", SegmentLimit)
			if e == nil && !bytes.Equal(exact, b) {
				e = wire.Refuse("storage_unavailable")
			}
		}
	}
	if e != nil {
		d.held = true
	}
	return e
}

// AllocateTimeUses is called only by the protected operation/connection owner
// before preparation. It requires exact current root and unused capacity. It
// supplies no authorization, genesis, migration or independent recovery proof.
func (d *Disk) AllocateTimeUses(prior string, keys []TimeUseKey) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.held || prior != Hash(d.root) || !spaceAvailable(d.dir, 16<<20+12*SegmentLimit) || len(keys) == 0 || len(keys) > 4 {
		return wire.Refuse("storage_unavailable")
	}
	uses, e := d.loadTimeUses(d.manifest.TimeUses)
	if e != nil {
		return e
	}
	for _, key := range keys {
		uses = append(uses, TimeUse{Key: key, State: "unused"})
	}
	return d.persistTimeUses(uses)
}

// TimeUseAdmission owns L across selection, the sole capture, check, burn and
// endpoint. Release retires it; it cannot be reacquired using a burned slot.
type TimeUseAdmission struct {
	d      *Disk
	uses   []TimeUse
	index  int
	root   string
	active bool
}

func (d *Disk) AdmitTimeUse(key TimeUseKey, prior string) (*TimeUseAdmission, error) {
	d.mu.Lock()
	refuse := func() (*TimeUseAdmission, error) { d.mu.Unlock(); return nil, wire.Refuse("storage_unavailable") }
	if d.held || prior != Hash(d.root) || !spaceAvailable(d.dir, 16<<20+12*SegmentLimit) {
		return refuse()
	}
	b, e := d.read("root", RootLimit)
	if e != nil || !bytes.Equal(b, d.root) {
		return refuse()
	}
	uses, e := d.loadTimeUses(d.manifest.TimeUses)
	if e != nil {
		return refuse()
	}
	for i, u := range uses {
		if u.Key == key && u.State == "unused" {
			return &TimeUseAdmission{d, uses, i, prior, true}, nil
		}
	}
	return refuse()
}

func (a *TimeUseAdmission) Active() bool    { return a != nil && a.active }
func (a *TimeUseAdmission) Revision() int64 { return a.uses[a.index].Revision }
func (a *TimeUseAdmission) Prior() string   { return a.root }
func (a *TimeUseAdmission) Key() TimeUseKey { return a.uses[a.index].Key }
func (a *TimeUseAdmission) Release() {
	if a != nil && a.active {
		a.active = false
		a.d.mu.Unlock()
	}
}
func (a *TimeUseAdmission) Burn(u TimeUse) error {
	if a == nil || !a.active || a.d.held || a.uses[a.index].State != "unused" || u.Key != a.Key() || u.Revision != a.Revision()+1 || u.State != "burned" {
		return wire.Refuse("storage_unavailable")
	}
	a.uses[a.index] = u
	return a.d.persistTimeUses(a.uses)
}
func (a *TimeUseAdmission) Finish(state string, outcome []byte) error {
	if a == nil || !a.active || a.d.held || a.uses[a.index].State != "burned" || state != "held" && state != "committed" {
		return wire.Refuse("storage_unavailable")
	}
	a.uses[a.index].State = state
	a.uses[a.index].Outcome = append([]byte(nil), outcome...)
	return a.d.persistTimeUses(a.uses)
}

// TimeUseStatus returns owned status data only; it never returns dispatch
// authority. A recovered burned state is held, even if no act was observed.
func (d *Disk) TimeUseStatus(key TimeUseKey) (TimeUse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	uses, e := d.loadTimeUses(d.manifest.TimeUses)
	if e != nil || d.held {
		return TimeUse{}, wire.Refuse("storage_unavailable")
	}
	for _, u := range uses {
		if u.Key == key {
			if u.State == "burned" {
				u.State = "held"
			}
			return u, nil
		}
	}
	return TimeUse{}, wire.Refuse("storage_unavailable")
}
