package cmd

import (
	"path/filepath"
	"reflect"
	"strings"
	"syswarden-cli/config"
	"testing"
)

func TestConfigurationPreviewCobraDoesNotLoadRecoverOrMutate(t *testing.T) {
	preserveConfigMenuPreflightHooks(t)
	root := filepath.Join(t.TempDir(), "config")
	if err := config.InitializeDefaults(root); err != nil {
		t.Fatal(err)
	}
	configEditorRoot = root
	before := snapshotRegularFiles(t, root)
	global, load := config.GlobalConfig, config.CurrentLoadState()
	preflightWireGuardPolicyTransition = func() error { return nil }
	refusePendingFirewallTransactionHook = func() error { return nil }
	output, err := executeRootCobraLifecycle(t, []string{"config", "preview"}, initConfigHook)
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"Validated configuration preview (7 TOML inputs)", "No managed threat list", "runtime not inspected", "No host change was applied", "no activation approval"} {
		if !strings.Contains(output, part) {
			t.Errorf("missing %q", part)
		}
	}
	if !reflect.DeepEqual(before, snapshotRegularFiles(t, root)) || config.GlobalConfig != global || !reflect.DeepEqual(load, config.CurrentLoadState()) {
		t.Fatal("preview changed input/runtime")
	}
}

func TestConfigurationPreviewRefusesPendingRemovalBeforeReading(t *testing.T) {
	preserveConfigMenuPreflightHooks(t)
	configEditorRoot = filepath.Join(t.TempDir(), "absent")
	preflightWireGuardPolicyTransition = func() error { return nil }
	inspectRemovalTombstone = func() (bool, error) { return true, nil }
	refusePendingFirewallTransactionHook = func() error { t.Fatal("blocked preview reached later preflight"); return nil }
	if err := rootCmd.PersistentPreRunE(configPreviewCmd, nil); err == nil || !strings.Contains(err.Error(), "removal is incomplete") {
		t.Fatalf("preview bypassed removal barrier: %v", err)
	}
}
