// Package deppolicy validates the deliberately small module-policy grammar.
package deppolicy

import (
	"fmt"
	"regexp"
	"strings"
)

// WaggleVersion is the accepted S3 pin. An unused dependency is not installed.
const WaggleVersion = "v0.0.0-20261024213811-9b42338b8a57"

var goVersion = regexp.MustCompile(`^1\.26\.[0-9]+$`)

// Check permits only the module baseline and explicitly approved exact requires.
// Unknown directives, replacements and unpinned transitive modules fail closed.
func Check(raw []byte) error {
	module, version, block := false, false, false
	seen := map[string]bool{}
	require := func(fields []string) error {
		if len(fields) != 2 || fields[0] != "github.com/relux-works/waggle" || fields[1] != WaggleVersion || seen[fields[0]] {
			return fmt.Errorf("dependency_not_approved")
		}
		seen[fields[0]] = true
		return nil
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line, _, _ = strings.Cut(line, "//")
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if block {
			if len(f) == 1 && f[0] == ")" {
				block = false
				continue
			}
			if err := require(f); err != nil {
				return err
			}
			continue
		}
		switch f[0] {
		case "module":
			if module || len(f) != 2 || f[1] != "github.com/relux-works/swarma-witness" {
				return fmt.Errorf("module_not_approved")
			}
			module = true
		case "go":
			if version || len(f) != 2 || !goVersion.MatchString(f[1]) {
				return fmt.Errorf("go_not_approved")
			}
			version = true
		case "require":
			if len(f) == 2 && f[1] == "(" {
				block = true
				continue
			}
			if err := require(f[1:]); err != nil {
				return err
			}
		default:
			return fmt.Errorf("directive_not_approved")
		}
	}
	if !module || !version || block {
		return fmt.Errorf("module_incomplete")
	}
	return nil
}
