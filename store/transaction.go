package store

import (
	"bytes"
	"io"
	"os"
	"sync"

	"github.com/relux-works/swarma-witness/wire"
)

// Calls inject the actual filesystem calls in isolated tests. Nil fields use
// native calls. This is not a qualification, clock or production admission seam.
type Calls struct {
	Write   func(*os.File, []byte) (int, error)
	Sync    func(*os.File) error
	Close   func(*os.File) error
	Rename  func(*os.File, string, string, bool) error
	SyncDir func(*os.File) error
}

func NativeCalls() Calls {
	return Calls{func(f *os.File, b []byte) (int, error) { return f.Write(b) }, func(f *os.File) error { return f.Sync() }, func(f *os.File) error { return f.Close() }, nativeRename, func(f *os.File) error { return f.Sync() }}
}

type Disk struct {
	mu       sync.Mutex
	dir      *os.File
	calls    Calls
	root     []byte
	manifest Manifest
	held     bool
}
type Prepared struct {
	manifest         Manifest
	segment, prepare []byte
}

func (p *Prepared) Transaction() string { return p.manifest.Transaction }
func (p *Prepared) Bytes() []byte       { return append([]byte(nil), p.prepare...) }

// Open inspects an existing protected store only. Missing root is not genesis.
// It establishes no readiness: service must independently reconcile before work.
func Open(path, service string, c Calls) (*Disk, error) {
	dir, e := openDirectory(path)
	if e != nil {
		return nil, wire.Refuse("storage_unavailable")
	}
	return inspect(dir, service, c)
}

// Inspect takes ownership of an already protected, provisioned descriptor.
// Its provenance/ancestor custody must be established by the caller's separate
// installation/recovery authority. A request path cannot supply this descriptor.
func Inspect(dir *os.File, service string, c Calls) (*Disk, error) {
	if dir == nil || !directoryValid(dir) {
		return nil, wire.Refuse("storage_unavailable")
	}
	return inspect(dir, service, c)
}
func inspect(dir *os.File, service string, c Calls) (*Disk, error) {
	n := NativeCalls()
	if c.Write == nil {
		c.Write = n.Write
	}
	if c.Sync == nil {
		c.Sync = n.Sync
	}
	if c.Close == nil {
		c.Close = n.Close
	}
	if c.Rename == nil {
		c.Rename = n.Rename
	}
	if c.SyncDir == nil {
		c.SyncDir = n.SyncDir
	}
	d := &Disk{dir: dir, calls: c}
	b, e := d.read("root", RootLimit)
	if e != nil {
		dir.Close()
		return nil, e
	}
	m, objects, e := Decode(b, RootMagic)
	if e != nil || m.Service != service || len(objects) != 0 {
		dir.Close()
		return nil, wire.Refuse("storage_unavailable")
	}
	d.root = b
	d.manifest = m
	if m.Transaction != wire.ZeroHash {
		for _, pair := range []struct{ hash, ext, magic string }{{m.Segment, "seg", SegmentMagic}, {m.Prepare, "jnl", JournalMagic}, {m.Resolution, "jnl", JournalMagic}} {
			x, e := d.object(pair.hash, pair.ext, capFor(pair.magic))
			if e != nil {
				dir.Close()
				return nil, e
			}
			v, _, e := Decode(x, pair.magic)
			if e != nil || v.Transaction != m.Transaction || v.Prior != m.Prior || v.Index != m.Index || v.Audit != m.Audit || v.AuditSeq != m.AuditSeq || v.Policy != m.Policy {
				dir.Close()
				return nil, wire.Refuse("storage_unavailable")
			}
		}
	}
	if e = d.validateInventory(); e != nil {
		dir.Close()
		return nil, e
	}
	return d, nil
}

// An internally coherent older root is still untrusted. This walk only detects
// missing/torn/unpublished local evidence; independent recovery must also agree.
func (d *Disk) validateInventory() error {
	bad := func() error { return wire.Refuse("storage_unavailable") }
	known := map[string]bool{"root": true}
	root := d.root
	for depth := 0; ; depth++ {
		if depth > 1024 {
			return bad()
		}
		m, _, e := Decode(root, RootMagic)
		if e != nil {
			return bad()
		}
		known[m.Index+".obj"] = true
		if _, e = d.object(m.Index, "obj", SegmentLimit); e != nil {
			return e
		}
		if m.Transaction == wire.ZeroHash {
			break
		}
		for _, p := range []struct{ hash, ext, magic, phase string }{{m.Segment, "seg", SegmentMagic, "segment"}, {m.Prepare, "jnl", JournalMagic, "prepare"}, {m.Resolution, "jnl", JournalMagic, "outcome"}} {
			known[p.hash+"."+p.ext] = true
			b, e := d.object(p.hash, p.ext, capFor(p.magic))
			if e != nil {
				return e
			}
			v, objects, e := Decode(b, p.magic)
			if e != nil || v.Phase != p.phase || v.Transaction != m.Transaction || v.Service != m.Service || v.Prior != m.Prior || v.Index != m.Index || v.Policy != m.Policy || v.Audit != m.Audit || v.AuditSeq != m.AuditSeq || v.Chain != m.Chain || v.Stream != m.Stream || v.Seq != m.Seq || v.Previous != m.Previous || v.Head != m.Head {
				return bad()
			}
			for _, o := range objects {
				hash := Hash(o.Bytes)
				known[hash+".obj"] = true
				original, e := d.object(hash, "obj", SegmentLimit)
				if e != nil || !bytes.Equal(original, o.Bytes) {
					return bad()
				}
			}
		}
		known[m.Prior+".obj"] = true
		root, e = d.object(m.Prior, "obj", RootLimit)
		if e != nil {
			return e
		}
	}
	if _, e := d.dir.Seek(0, 0); e != nil {
		return bad()
	}
	count := 0
	for {
		files, e := d.dir.ReadDir(64)
		for _, f := range files {
			count++
			if count > 16384 || !known[f.Name()] {
				return bad()
			}
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return bad()
		}
	}
	return nil
}
func (d *Disk) Close() error { return d.dir.Close() }
func (d *Disk) Snapshot() ([]byte, Manifest) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]byte(nil), d.root...), d.manifest
}
func (d *Disk) ReadObject(hash string) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.object(hash, "obj", SegmentLimit)
}
func (d *Disk) object(hash, ext string, max int) ([]byte, error) {
	if !wire.Hash(hash) {
		return nil, wire.Refuse("storage_unavailable")
	}
	b, e := d.read(hash+"."+ext, max)
	if e != nil || Hash(b) != hash {
		return nil, wire.Refuse("storage_unavailable")
	}
	return b, nil
}
func (d *Disk) read(name string, max int) ([]byte, error) {
	f, e := openFile(d.dir, name, false)
	if e != nil {
		return nil, wire.Refuse("storage_unavailable")
	}
	b, e := io.ReadAll(io.LimitReader(f, int64(max)+1))
	ce := f.Close()
	if e != nil || ce != nil || len(b) > max {
		return nil, wire.Refuse("storage_unavailable")
	}
	return b, nil
}

// Preflight accounts conservatively for all temporary/final copies and leaves
// the fixed health/control reserve untouched. Shared-device hard reservation
// and its bounds still require owner qualification; free-space is not custody.
func (d *Disk) Preflight(bytes int64) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.held || bytes < 0 || bytes > 100<<30 || !spaceAvailable(d.dir, bytes+(16<<20)) {
		return wire.Refuse("storage_unavailable")
	}
	return nil
}
func (d *Disk) install(name string, b []byte, replace bool) error {
	if !replace {
		if prior, e := d.read(name, SegmentLimit); e == nil {
			if bytes.Equal(prior, b) {
				return nil
			}
			return wire.Refuse("storage_unavailable")
		}
	}
	temp := "stage-" + Hash(b) + ".tmp"
	f, e := openFile(d.dir, temp, true)
	if e != nil {
		return wire.Refuse("storage_unavailable")
	}
	for len(b) > 0 {
		n, e := d.calls.Write(f, b)
		if e != nil || n <= 0 || n > len(b) {
			f.Close()
			return wire.Refuse("storage_unavailable")
		}
		b = b[n:]
	}
	if e = d.calls.Sync(f); e != nil {
		f.Close()
		return wire.Refuse("storage_unavailable")
	}
	if e = d.calls.Close(f); e != nil {
		return wire.Refuse("storage_unavailable")
	}
	if e = d.calls.Rename(d.dir, temp, name, replace); e != nil {
		return wire.Refuse("storage_unavailable")
	}
	if e = d.calls.SyncDir(d.dir); e != nil {
		return wire.Refuse("storage_unavailable")
	}
	return nil
}

// CheckPlan bounds the complete segment and prepare closure before any write.
// External acknowledgement bytes are separately bounded by the outcome journal.
func CheckPlan(m Manifest, objects []Object) error {
	m = normalize(m)
	m.Phase = "segment"
	segment, e := Encode(SegmentMagic, m, objects)
	if e != nil {
		return e
	}
	m.Segment = Hash(segment)
	m.Phase = "prepare"
	_, e = Encode(JournalMagic, m, nil)
	return e
}

func (d *Disk) Prepare(m Manifest, objects []Object) (*Prepared, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.held || m.Prior != Hash(d.root) || m.Service != d.manifest.Service {
		return nil, wire.Refuse("storage_unavailable")
	}
	current, e := d.read("root", RootLimit)
	if e != nil || !bytes.Equal(current, d.root) {
		return nil, wire.Refuse("storage_unavailable")
	}
	m = normalize(m)
	m.Phase = "segment"
	segment, e := Encode(SegmentMagic, m, objects)
	if e != nil {
		return nil, e
	}
	m.Segment = Hash(segment)
	m.Phase = "prepare"
	prepare, e := Encode(JournalMagic, m, nil)
	if e != nil {
		return nil, e
	}
	// The reservation is sticky after the first possible write, even on failure.
	d.held = true
	if e = d.install(Hash(d.root)+".obj", d.root, false); e != nil {
		return nil, e
	}
	for _, o := range objects {
		if e = d.install(Hash(o.Bytes)+".obj", o.Bytes, false); e != nil {
			return nil, e
		}
	}
	if e = d.install(Hash(segment)+".seg", segment, false); e != nil {
		return nil, e
	}
	if e = d.install(Hash(prepare)+".jnl", prepare, false); e != nil {
		return nil, e
	}
	return &Prepared{m, segment, prepare}, nil
}

// Publish has no external callbacks. Its caller must validate independent
// confirmation and publication authority outside the storage gate beforehand.
func (d *Disk) Publish(p *Prepared, acks []Object) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if p == nil || !d.held || p.manifest.Prior != Hash(d.root) {
		return wire.Refuse("storage_unavailable")
	}
	current, e := d.read("root", RootLimit)
	if e != nil || !bytes.Equal(current, d.root) {
		return wire.Refuse("storage_unavailable")
	}
	m := p.manifest
	m.Prepare = Hash(p.prepare)
	m.Phase = "outcome"
	out, e := Encode(JournalMagic, m, acks)
	if e != nil {
		return e
	}
	for _, o := range acks {
		if e = d.install(Hash(o.Bytes)+".obj", o.Bytes, false); e != nil {
			return e
		}
	}
	if e = d.install(Hash(out)+".jnl", out, false); e != nil {
		return e
	}
	m.Resolution = Hash(out)
	m.Phase = "root"
	root, e := Encode(RootMagic, m, nil)
	if e != nil {
		return e
	}
	if e = d.install("root", root, true); e != nil {
		return e
	}
	d.root = root
	d.manifest = m
	d.held = false
	return nil
}
