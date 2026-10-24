// Command vectors checks corpus bytes offline; it grants no service authority.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/relux-works/swarma-witness/internal/vectors"
)

func run(args []string, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("vectors", flag.ContinueOnError)
	flags.SetOutput(errOut)
	check := flags.Bool("check", false, "check fixture integrity")
	root := flags.String("root", ".", "corpus repository checkout")
	lockFile := flags.String("lock", "", "consumer lock with reviewed commit and manifest digest")
	if flags.Parse(args) != nil || !*check || flags.NArg() != 0 {
		return 2
	}
	var lock *vectors.Lock
	commit := ""
	if *lockFile != "" {
		parsed, err := vectors.ReadLock(*lockFile)
		if err != nil {
			fmt.Fprintln(errOut, "vector_lock_invalid")
			return 1
		}
		lock = &parsed
		raw, err := exec.Command("git", "-C", *root, "rev-parse", "--verify", "HEAD").Output()
		if err != nil {
			fmt.Fprintln(errOut, "vector_checkout_unavailable")
			return 1
		}
		commit = strings.TrimSpace(string(raw))
	}
	count, err := vectors.Check(filepath.Join(*root, "testdata", "witness-v1"), lock, commit)
	if err != nil {
		fmt.Fprintln(errOut, "vector_check_refused:", err)
		return 1
	}
	fmt.Fprintf(out, "PASS: manifest integrity (%d vectors)\n", count)
	if count == 0 {
		fmt.Fprintln(out, "PENDING: protocol vectors and consumer conformance are not implemented")
	}
	return 0
}
func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }
