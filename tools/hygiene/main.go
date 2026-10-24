// Command hygiene checks a quiescent checkout before publication.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/relux-works/swarma-witness/internal/deppolicy"
	"github.com/relux-works/swarma-witness/internal/hygiene"
)

func run(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("hygiene", flag.ContinueOnError)
	flags.SetOutput(errOut)
	check := flags.Bool("check", false, "check publication rules")
	root := flags.String("root", ".", "repository directory")
	denyFile := flags.String("deny-file", "", "optional private newline-separated forbidden values")
	if flags.Parse(args) != nil || !*check || flags.NArg() != 0 {
		return 2
	}
	var deny []string
	if *denyFile != "" {
		f, err := os.Open(*denyFile)
		if err != nil {
			fmt.Fprintln(errOut, "deny_file_unavailable")
			return 1
		}
		raw, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
		ce := f.Close()
		if err != nil || ce != nil || len(raw) > 1<<20 {
			fmt.Fprintln(errOut, "deny_file_invalid")
			return 1
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if value := strings.TrimSpace(line); value != "" {
				deny = append(deny, value)
			}
		}
	}
	findings, err := hygiene.Check(*root, deny)
	if err != nil {
		fmt.Fprintln(errOut, "hygiene_check_unavailable")
		return 1
	}
	if len(findings) > 0 {
		for _, f := range findings {
			fmt.Fprintln(errOut, f.String())
		}
		return 1
	}
	raw, err := os.ReadFile(filepath.Join(*root, "go.mod"))
	if err != nil {
		fmt.Fprintln(errOut, "module_unavailable")
		return 1
	}
	if err = deppolicy.Check(raw); err != nil {
		fmt.Fprintln(errOut, "dependency_policy_refused")
		return 1
	}
	fmt.Fprintln(out, "PASS: bounded publication checks; manual review remains required")
	return 0
}
func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
