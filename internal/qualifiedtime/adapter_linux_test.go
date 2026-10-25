//go:build linux

package qualifiedtime

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/relux-works/swarma-credential-broker/timeconf"
)

// Both ordinary and fixture-tagged builds must keep every production adapter
// closed, with the broker's exact closed reader/witness and no injected runtime.
func TestProductionDependenciesClosed(t *testing.T) {
	w := New()
	for _, e := range []*engine{w.P.e, w.R.e, w.X.e, w.TLS.e} {
		if _, ok := e.witness.(timeconf.ClosedWitness); !ok {
			t.Fatal("production fixture witness is forbidden")
		}
		if _, ok := e.reader.(timeconf.ClosedOriginalReader); !ok || e.runtime != nil || e.disk != nil {
			t.Fatal("production reader/runtime must remain closed")
		}
		var refusal *timeconf.ActivationRefusal
		if err := e.consume(context.Background(), Intent{}, Bundle{}); !errors.As(err, &refusal) || refusal.Reason != "handoff_unqualified" {
			t.Fatal("production consumption must return handoff_unqualified", err)
		}
	}
	w.P.e.g.Lock()
	w.R.e.a.Lock()
	w.Stop() // Stop does not acquire any dependency or terminal gate.
	w.R.e.a.Unlock()
	w.P.e.g.Unlock()
	if !w.P.e.stopped.Load() || !w.TLS.e.stopped.Load() {
		t.Fatal("independent stop did not fence windows")
	}
}

// The one exact pair is accepted; generic slash substitution, unknown mapping
// and alphabet-valid version drift fail the native mapping predicate.
func TestClosedTransitionMapping(t *testing.T) {
	if err := transition(MappingVersion, NativeTransition, EnrolledTransition); err != nil {
		t.Fatal("exact mapping refused", err)
	}
	for _, c := range [][3]string{
		{MappingVersion, NativeTransition, NativeTransition},
		{MappingVersion, "WC1TimeUse/2", "WC1TimeUse:2"},
		{MappingVersion, NativeTransition, "WC1TimeUse:2"},
		{"witness-transition-map:2", NativeTransition, EnrolledTransition},
		{MappingVersion, "OtherUse/1", "OtherUse:1"},
	} {
		var refusal *timeconf.HandoffRefusal
		if err := transition(c[0], c[1], c[2]); !errors.As(err, &refusal) || refusal.Code != "transition_mapping" {
			t.Fatal("generic slash/version mapping accepted", err)
		}
	}
}

// Source policy covers this fixed terminal call graph, including excluded code.
// It supplements runtime fixture controls; it does not prove arbitrary dynamic
// code or qualify a native endpoint. Controls below plant real forbidden calls.
func terminalPolicy(raw []byte) error {
	f, err := parser.ParseFile(token.NewFileSet(), "adapter.go", raw, 0)
	if err != nil {
		return err
	}
	reads := 0
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		var violation error
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if sel.Sel.Name == "Capture" {
				reads++
				if fn.Name.Name != "capture" {
					violation = errors.New("extra_clock_read")
				}
			}
			if fn.Name.Name == "terminal" || fn.Name.Name == "ConsumeIfUnused" || fn.Name.Name == "Act" || fn.Name.Name == "localEndpoint" || fn.Name.Name == "capture" {
				// These methods contain all terminal code. No provider, original
				// reader, signer, custody, archive or ordinary clock call belongs.
				for _, forbidden := range []string{"Read", "ReadOriginals", "PrepareHandoff", "Sign", "Confirm", "ConfirmAudit", "Now", "Consume", "CompareAndSwap"} {
					if sel.Sel.Name == forbidden {
						violation = errors.New("external_work_under_gates")
					}
				}
			}
			return violation == nil
		})
		if violation != nil {
			return violation
		}
	}
	if reads != 1 {
		return errors.New("extra_clock_read")
	}
	return nil
}

func TestWindowTerminalPurity(t *testing.T) {
	raw, err := os.ReadFile("adapter_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	if err = terminalPolicy(raw); err != nil {
		t.Fatal("terminal purity violation", err)
	}
	for _, c := range []struct{ call, code string }{
		{"_, _ = e.runtime.clock.Capture()", "extra_clock_read"},
		{"_, _ = e.witness.Read(context.Background())", "external_work_under_gates"},
		{"_, _ = e.reader.ReadOriginals(context.Background(), timeconf.OriginalRequest{})", "external_work_under_gates"},
		{"_ = time.Now()", "external_work_under_gates"},
	} {
		plant := strings.Replace(string(raw), "e.g.Lock()", c.call+"\n e.g.Lock()", 1)
		if err = terminalPolicy([]byte(plant)); err == nil || err.Error() != c.code {
			t.Fatal("terminal instrument missed intended plant", c.code, err)
		}
	}
}
