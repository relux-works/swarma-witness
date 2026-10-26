//go:build linux && swarma_timeconf_fixture

package qualifiedtime

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

const lifecycleControlEnv = "SWARMA_WITNESS_LIFECYCLE_CONTROL"

// Bubble return proves that every bubble goroutine, including the private broker
// settlement worker, exited. It does not establish a broker-owned drain API.
// Refusal/Fatal controls use cooperative test workers; the stuck control stays
// in a bounded child process so it cannot strand a worker in the parent.
func TestWindowWorkerLifecycle(t *testing.T) {
	if mode := os.Getenv(lifecycleControlEnv); mode != "" {
		t.Run("child", func(t *testing.T) { lifecycleChild(t, mode) })
		return
	}
	t.Run("settlement-drained", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) { checkTimelyEndpoint(t, P) })
	})
	t.Run("drain-after-refusal", func(t *testing.T) {
		var exited atomic.Bool
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			started := make(chan struct{})
			go func() {
				defer exited.Store(true)
				close(started)
				select {
				case <-time.After(301 * time.Millisecond):
				case <-ctx.Done():
				}
			}()
			<-started
			<-ctx.Done()
			if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
				t.Fatal("worker refusal must be the original deadline")
			}
		})
		if !exited.Load() {
			t.Fatal("refused worker survived bubble return")
		}
	})
	t.Run("drain-after-fatal", func(t *testing.T) {
		output, code := lifecycleProcess(t, "fatal")
		if code != 1 || !strings.Contains(output, "worker lifecycle fatal control") || !strings.Contains(output, "worker lifecycle drained after fatal") || strings.Contains(output, "panic:") || strings.Contains(output, "deadlock:") {
			t.Fatalf("fatal worker must drain before child failure: exit=%d\n%s", code, output)
		}
	})
	t.Run("stuck-child", func(t *testing.T) {
		output, code := lifecycleProcess(t, "stuck")
		if code == 0 || !strings.Contains(output, "worker lifecycle stuck control") || !strings.Contains(output, "deadlock: main bubble goroutine has exited but blocked goroutines remain") {
			t.Fatalf("stuck worker must be detected in child: exit=%d\n%s", code, output)
		}
	})
}

// Only an explicitly selected child runs these intentional failures. The stuck
// worker reproduces the noncancellable 301 ms sleep after a 300 ms refusal; its
// deadlock report is negative evidence, never a successful drain.
func lifecycleChild(t *testing.T, mode string) {
	t.Helper()
	if mode != "fatal" && mode != "stuck" {
		t.Fatal("unknown worker lifecycle control")
	}
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		started, done := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(done)
			close(started)
			if mode == "stuck" {
				time.Sleep(301 * time.Millisecond)
				return
			}
			select {
			case <-time.After(301 * time.Millisecond):
			case <-ctx.Done():
			}
		}()
		<-started
		if mode == "fatal" {
			t.Cleanup(func() {
				cancel()
				<-done
				t.Log("worker lifecycle drained after fatal")
			})
			t.Fatal("worker lifecycle fatal control")
		}
		time.Sleep(300 * time.Millisecond)
		select {
		case <-done:
			t.Fatal("stuck control unexpectedly drained")
		default:
			t.Fatal("worker lifecycle stuck control")
		}
	})
}

// The 2 s child and 3 s parent limits bound this test harness, not the product's
// unchanged 300/400 ms budgets. Unexpected kills/timeouts fail the parent and
// are recorded explicitly; they are not counted as the intended stuck control.
func lifecycleProcess(t *testing.T, mode string) (string, int) {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "-test.run=^TestWindowWorkerLifecycle$/^child$", "-test.count=1", "-test.timeout=2s", "-test.v")
	cmd.Env = append(os.Environ(), lifecycleControlEnv+"="+mode)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err = cmd.Start(); err != nil {
		t.Fatal("worker lifecycle child unavailable", err)
	}
	t.Logf("worker lifecycle child mode=%s pid=%d", mode, cmd.Process.Pid)
	err = cmd.Wait()
	code := -1
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	t.Logf("worker lifecycle child mode=%s exit=%d parent_timeout=%t\n%s", mode, code, ctx.Err() != nil, output.String())
	if ctx.Err() != nil {
		t.Fatal("worker lifecycle child exceeded harness bound; parent killed its PID")
	}
	var failed *exec.ExitError
	if err != nil && !errors.As(err, &failed) {
		t.Fatal("worker lifecycle child failed to run", err)
	}
	if code < 0 {
		t.Fatal("worker lifecycle child terminated by a signal or unavailable status")
	}
	return output.String(), code
}
