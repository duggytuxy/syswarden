//go:build freebsd

package cmd

import (
	"errors"
	"strings"
	"testing"
)

func TestPackageHostRestoreRequiresRootAndAllowsDegradedConfig(t *testing.T) {
	if _, ok := degradedConfigAllowlist["package-restore-host-state"]; !ok {
		t.Fatal("package host-state restore is not available for degraded package recovery")
	}
	originalEUID := packageHostRestoreEUID
	originalRestore := restorePackageHostState
	t.Cleanup(func() {
		packageHostRestoreEUID = originalEUID
		restorePackageHostState = originalRestore
	})
	called := false
	restorePackageHostState = func() error {
		called = true
		return nil
	}
	packageHostRestoreEUID = func() int { return 1000 }
	if err := packageHostRestoreCmd.RunE(packageHostRestoreCmd, nil); err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("non-root restore error = %v", err)
	}
	if called {
		t.Fatal("non-root caller reached host-state restore")
	}

	packageHostRestoreEUID = func() int { return 0 }
	want := errors.New("restore failed")
	restorePackageHostState = func() error { return want }
	if err := packageHostRestoreCmd.RunE(packageHostRestoreCmd, nil); !errors.Is(err, want) {
		t.Fatalf("restore error = %v, want %v", err, want)
	}
}
