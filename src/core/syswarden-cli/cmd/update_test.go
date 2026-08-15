package cmd

import (
	"errors"
	"strings"
	"testing"
)

func TestUpdateCommandPropagatesUpgradeFailure(t *testing.T) {
	original := runSystemUpgrade
	runSystemUpgrade = func() error { return errors.New("verified package activation failed") }
	t.Cleanup(func() { runSystemUpgrade = original })

	err := updateCmd.RunE(updateCmd, nil)
	if err == nil {
		t.Fatal("update command returned success after the upgrade failed")
	}
	if !strings.Contains(err.Error(), "verified package activation failed") {
		t.Fatalf("update error = %q", err)
	}
}

func TestUpdateCommandReturnsSuccessAfterVerifiedUpgrade(t *testing.T) {
	original := runSystemUpgrade
	runSystemUpgrade = func() error { return nil }
	t.Cleanup(func() { runSystemUpgrade = original })

	if err := updateCmd.RunE(updateCmd, nil); err != nil {
		t.Fatalf("update command error = %v", err)
	}
}
