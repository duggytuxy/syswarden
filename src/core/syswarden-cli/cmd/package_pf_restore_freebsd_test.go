//go:build freebsd

package cmd

import (
	"errors"
	"testing"
)

func TestPackagePFRestoreIsARootDegradedConfigBypass(t *testing.T) {
	if _, ok := degradedConfigAllowlist["package-restore-pf"]; !ok {
		t.Fatal("hidden package PF restore is not available with degraded config")
	}
	if err := enforceValidatedConfiguration(packagePFRestoreCmd); err != nil {
		t.Fatalf("degraded config guard blocked package PF restore: %v", err)
	}

	originalEUID := packagePFRestoreEUID
	originalRestore := restorePackagePFPolicy
	t.Cleanup(func() {
		packagePFRestoreEUID = originalEUID
		restorePackagePFPolicy = originalRestore
	})

	reached := false
	packagePFRestoreEUID = func() int { return 0 }
	restorePackagePFPolicy = func() error {
		reached = true
		return nil
	}
	if err := packagePFRestoreCmd.RunE(packagePFRestoreCmd, nil); err != nil {
		t.Fatalf("root package PF restore failed: %v", err)
	}
	if !reached {
		t.Fatal("root package PF restore did not reach the locked helper")
	}

	reached = false
	packagePFRestoreEUID = func() int { return 1000 }
	if err := packagePFRestoreCmd.RunE(packagePFRestoreCmd, nil); err == nil {
		t.Fatal("non-root package PF restore was accepted")
	}
	if reached {
		t.Fatal("non-root package PF restore reached the locked helper")
	}

	restorePackagePFPolicy = func() error { return errors.New("restore failed") }
	packagePFRestoreEUID = func() int { return 0 }
	if err := packagePFRestoreCmd.RunE(packagePFRestoreCmd, nil); err == nil {
		t.Fatal("PF restore failure was not propagated")
	}
}
