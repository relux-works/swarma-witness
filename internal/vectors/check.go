// Package vectors checks offline corpus bytes and consumer provenance locks.
// These metadata formats do not implement or validate witness wire records.
package vectors

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

const Repository = "github.com/relux-works/swarma-witness"
const metadataLimit = 1 << 20

var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

type Entry struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type Manifest struct {
	Schema int     `json:"schema"`
	Files  []Entry `json:"files"`
}
type Lock struct {
	Schema         int    `json:"schema"`
	Repository     string `json:"repository"`
	Commit         string `json:"commit"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

// decode checks duplicate names and bounded depth before typed closed decoding.
func decode(raw []byte, out any) error {
	if len(raw) > metadataLimit || !utf8.Valid(raw) {
		return fmt.Errorf("metadata_invalid")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	var value func(int) error
	value = func(depth int) error {
		if depth > 16 {
			return fmt.Errorf("metadata_depth")
		}
		token, err := d.Token()
		if err != nil {
			return fmt.Errorf("metadata_invalid")
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				token, err = d.Token()
				if err != nil {
					return fmt.Errorf("metadata_invalid")
				}
				key, ok := token.(string)
				if !ok || seen[key] {
					return fmt.Errorf("metadata_duplicate")
				}
				seen[key] = true
				if err = value(depth + 1); err != nil {
					return err
				}
			}
			token, err = d.Token()
			if err != nil || token != json.Delim('}') {
				return fmt.Errorf("metadata_invalid")
			}
		case '[':
			for d.More() {
				if err = value(depth + 1); err != nil {
					return err
				}
			}
			token, err = d.Token()
			if err != nil || token != json.Delim(']') {
				return fmt.Errorf("metadata_invalid")
			}
		default:
			return fmt.Errorf("metadata_invalid")
		}
		return nil
	}
	if err := value(1); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("metadata_trailing")
	}
	// encoding/json matches struct fields case-insensitively and accepts null as
	// a scalar default. Closed metadata requires exact keys and non-null values.
	fields := func(raw []byte, names ...string) (map[string]json.RawMessage, error) {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil || len(object) != len(names) {
			return nil, fmt.Errorf("metadata_fields")
		}
		for _, name := range names {
			value, ok := object[name]
			if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				return nil, fmt.Errorf("metadata_fields")
			}
		}
		return object, nil
	}
	switch out.(type) {
	case *Manifest:
		object, err := fields(raw, "schema", "files")
		if err != nil {
			return err
		}
		var entries []json.RawMessage
		if err = json.Unmarshal(object["files"], &entries); err != nil {
			return fmt.Errorf("metadata_fields")
		}
		for _, entry := range entries {
			if _, err = fields(entry, "path", "size", "sha256"); err != nil {
				return err
			}
		}
	case *Lock:
		if _, err := fields(raw, "schema", "repository", "commit", "manifest_sha256"); err != nil {
			return err
		}
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return fmt.Errorf("metadata_schema")
	}
	return nil
}

// read never traverses a link in the corpus path. The checkout must be trusted
// and quiescent; this tool is not a hostile multiwriter filesystem sandbox.
func read(root, name string, limit int64) ([]byte, error) {
	if !fs.ValidPath(name) || strings.ContainsAny(name, `\:`) {
		return nil, fmt.Errorf("vector_path")
	}
	path := root
	for _, part := range strings.Split(name, "/") {
		path = filepath.Join(path, part)
		st, err := os.Lstat(path)
		if err != nil || st.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("vector_missing_or_link")
		}
	}
	st, err := os.Stat(path)
	if err != nil || !st.Mode().IsRegular() {
		return nil, fmt.Errorf("vector_not_regular")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("vector_read")
	}
	raw, err := io.ReadAll(io.LimitReader(f, limit+1))
	ce := f.Close()
	if err != nil || ce != nil || int64(len(raw)) > limit {
		return nil, fmt.Errorf("vector_limit")
	}
	return raw, nil
}

// ReadLock loads only the closed metadata object; Check binds it to actual
// checkout identity and exact manifest bytes. No network or code import occurs.
func ReadLock(path string) (Lock, error) {
	f, err := os.Open(path)
	if err != nil {
		return Lock{}, fmt.Errorf("lock_read")
	}
	raw, err := io.ReadAll(io.LimitReader(f, metadataLimit+1))
	ce := f.Close()
	if err != nil || ce != nil {
		return Lock{}, fmt.Errorf("lock_read")
	}
	var lock Lock
	err = decode(raw, &lock)
	return lock, err
}
func digest(raw []byte) string { h := sha256.Sum256(raw); return hex.EncodeToString(h[:]) }

// Check validates the authority's manifest without a lock, or a consumer's
// immutable commit+digest lock when supplied. It reports vector count explicitly.
func Check(root string, lock *Lock, commit string) (int, error) {
	st, err := os.Lstat(root)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return 0, fmt.Errorf("vector_root")
	}
	raw, err := read(root, "manifest.json", metadataLimit)
	if err != nil {
		return 0, err
	}
	if lock != nil {
		if lock.Schema != 1 || lock.Repository != Repository || !commitPattern.MatchString(lock.Commit) || lock.Commit == strings.Repeat("0", 40) || !hashPattern.MatchString(lock.ManifestSHA256) || lock.Commit != commit || lock.ManifestSHA256 != digest(raw) {
			return 0, fmt.Errorf("vector_lock_mismatch")
		}
	}
	var manifest Manifest
	if err = decode(raw, &manifest); err != nil {
		return 0, err
	}
	if manifest.Schema != 1 || manifest.Files == nil || len(manifest.Files) > 1024 {
		return 0, fmt.Errorf("manifest_schema")
	}
	declared := map[string]bool{"manifest.json": true, "README.md": true}
	last := ""
	var total int64
	for _, entry := range manifest.Files {
		if entry.Path <= last || declared[entry.Path] || entry.Size < 0 || entry.Size > 4<<20 || !hashPattern.MatchString(entry.SHA256) {
			return 0, fmt.Errorf("manifest_entry")
		}
		total += entry.Size
		if total > 16<<20 {
			return 0, fmt.Errorf("manifest_limit")
		}
		data, err := read(root, entry.Path, 4<<20)
		if err != nil {
			return 0, err
		}
		if int64(len(data)) != entry.Size || digest(data) != entry.SHA256 {
			return 0, fmt.Errorf("vector_digest_mismatch")
		}
		declared[entry.Path] = true
		last = entry.Path
	}
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return fmt.Errorf("vector_read")
		}
		if path == root {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("vector_link")
		}
		if d.IsDir() {
			return nil
		}
		rel, e := filepath.Rel(root, path)
		if e != nil || !declared[filepath.ToSlash(rel)] || !d.Type().IsRegular() {
			return fmt.Errorf("vector_undeclared")
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return len(manifest.Files), nil
}
