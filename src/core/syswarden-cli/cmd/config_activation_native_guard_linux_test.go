//go:build linux

package cmd

import (
	"context"
	"errors"
	"testing"

	"syswarden-cli/config"

	"github.com/spf13/cobra"
)

func TestNativeRecoveryDebtPrecedesActivationAndOperationalPolicy(t *testing.T) {
	oldPreflight, oldCapture := preflightAPKActivation, captureActivationPolicy
	t.Cleanup(func() { preflightAPKActivation, captureActivationPolicy = oldPreflight, oldCapture })
	want := errors.New("retained native completion debt")
	calls := 0
	preflightAPKActivation = func(ctx context.Context) error {
		if ctx == nil {
			t.Fatal("missing activation context")
		}
		calls++
		return want
	}
	captureActivationPolicy = func(context.Context, string) (*config.ActivationPolicy, error) {
		t.Fatal("unresolved native state reached configuration capture")
		return nil, want
	}
	for _, command := range []*cobra.Command{installCmd, reloadCmd, configActivateCmd} {
		command.SetContext(context.Background())
		if err := prepareConfigurationActivation(command); !errors.Is(err, want) {
			t.Fatalf("%s bypassed native recovery: %v", command.Name(), err)
		}
	}
	command := &cobra.Command{Use: "bounded-operational-fixture"}
	if err := consumeApprovedOperationalConfiguration(command); !errors.Is(err, want) {
		t.Fatal("operational consumer bypassed native recovery", err)
	}
	if calls != 4 {
		t.Fatal("missing native preflight", calls)
	}
}
