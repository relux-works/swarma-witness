// Package hygiene provides bounded publication checks, not a universal secret scanner.
package hygiene

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Finding struct{ Path, Code string }

func (f Finding) String() string { return f.Code + ": " + f.Path }

var patterns = []struct {
	code    string
	pattern *regexp.Regexp
}{
	{"hygiene_private_key", regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----`)},
	{"hygiene_credential", regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b`)},
	{"hygiene_local_path", regexp.MustCompile(`/(?:home|root|Users|Volumes|private|opt|tmp|var|mnt|etc|run)/`)},
	{"hygiene_identity", regexp.MustCompile(`\b[a-z]+[0-9]+_[a-z0-9_-]+_(?:dev|rev|orch)[0-9]*\b`)},
	{"hygiene_tracking", regexp.MustCompile(`\bTASK-[0-9]{6}-[a-z0-9]+\b|#[a-z]+[0-9]+-[a-z0-9-]+`)},
}

// Check scans a trusted quiescent checkout, excluding Git internals and ignored
// scratch directories. It does not follow links or echo matching content.
func Check(root string, deny []string) ([]Finding, error) {
	findings := []Finding{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("hygiene_read")
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return fmt.Errorf("hygiene_path")
		}
		if rel == "." {
			if !d.IsDir() {
				return fmt.Errorf("hygiene_root")
			}
			return nil
		}
		rel = filepath.ToSlash(rel)
		// Redact forbidden names in every later finding on the same path.
		reportPath := rel
		for _, rule := range patterns {
			if rule.pattern.MatchString(rel) {
				reportPath = "<path>"
				findings = append(findings, Finding{reportPath, rule.code})
			}
		}
		for _, value := range deny {
			if value != "" && strings.Contains(rel, value) {
				reportPath = "<path>"
				findings = append(findings, Finding{reportPath, "hygiene_private_value"})
			}
		}
		if d.Name() == ".task-board" {
			findings = append(findings, Finding{reportPath, "hygiene_private_artifact"})
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.Name() == ".git" || d.IsDir() && (d.Name() == ".temp" || d.Name() == ".tmp") {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			findings = append(findings, Finding{reportPath, "hygiene_link"})
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			findings = append(findings, Finding{reportPath, "hygiene_special"})
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("hygiene_read")
		}
		data, err := io.ReadAll(io.LimitReader(file, (4<<20)+1))
		closeErr := file.Close()
		if err != nil || closeErr != nil {
			return fmt.Errorf("hygiene_read")
		}
		if len(data) > 4<<20 {
			findings = append(findings, Finding{reportPath, "hygiene_limit"})
			return nil
		}
		for _, rule := range patterns {
			if rule.pattern.Match(data) {
				findings = append(findings, Finding{reportPath, rule.code})
			}
		}
		for _, value := range deny {
			if value != "" && bytes.Contains(data, []byte(value)) {
				findings = append(findings, Finding{reportPath, "hygiene_private_value"})
			}
		}
		return nil
	})
	return findings, err
}
