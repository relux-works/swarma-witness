//go:build linux

package service

import (
	"context"
	"errors"
	"testing"

	"github.com/relux-works/swarma-credential-broker/timeconf"
	"github.com/relux-works/swarma-witness/config"
	"github.com/relux-works/swarma-witness/internal/qualifiedtime"
)

// The unserved service installs all four closed adapters. Wiring neither opens
// storage nor supplies accepting time; Stop also remains safe on old fixtures.
func TestServiceG16Closed(t *testing.T) {
	s := New(config.Protected{})
	if s.windows == nil || s.disk != nil {
		t.Fatal("service must install only closed windows")
	}
	for _, consume := range []func(context.Context, qualifiedtime.Intent, qualifiedtime.Bundle) error{s.windows.P.Consume, s.windows.R.Consume, s.windows.X.Consume, s.windows.TLS.Consume} {
		var refusal *timeconf.ActivationRefusal
		if err := consume(context.Background(), qualifiedtime.Intent{}, qualifiedtime.Bundle{}); !errors.As(err, &refusal) || refusal.Reason != "handoff_unqualified" {
			t.Fatal("service window activated", err)
		}
	}
	s.Stop()
	if !s.stopped.Load() {
		t.Fatal("service stop not retained")
	}
	(&Service{}).Stop()
}
