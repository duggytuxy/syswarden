package cmd

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestPackagedLegacyDynamicBanUpgradeRestartsAndRechecks_SW_FW_001(t *testing.T) {
	previousQuarantine := quarantineLegacyDynamicBanIntervals
	previousRestart := restartCoreServiceForInstall
	t.Cleanup(func() {
		quarantineLegacyDynamicBanIntervals = previousQuarantine
		restartCoreServiceForInstall = previousRestart
	})
	events := make([]string, 0)
	passes := 0
	quarantineLegacyDynamicBanIntervals = func() (bool, error) {
		passes++
		events = append(events, fmt.Sprintf("quarantine:%d", passes))
		return passes == 1, nil
	}
	restartCoreServiceForInstall = func() error {
		events = append(events, "restart")
		return nil
	}
	if err := preparePackagedLegacyDynamicBanUpgrade(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(events, ","); got != "quarantine:1,restart,quarantine:2" {
		t.Fatalf("recovery order = %q", got)
	}
}

func TestPackagedLegacyDynamicBanUpgradePropagatesRestartFailure_SW_FW_001(t *testing.T) {
	previousQuarantine := quarantineLegacyDynamicBanIntervals
	previousRestart := restartCoreServiceForInstall
	t.Cleanup(func() {
		quarantineLegacyDynamicBanIntervals = previousQuarantine
		restartCoreServiceForInstall = previousRestart
	})
	sentinel := errors.New("restart failed")
	quarantineLegacyDynamicBanIntervals = func() (bool, error) { return true, nil }
	restartCoreServiceForInstall = func() error { return sentinel }
	err := preparePackagedLegacyDynamicBanUpgrade()
	if err == nil || !errors.Is(err, sentinel) {
		t.Fatalf("restart failure was not propagated: %v", err)
	}
}

func TestPackagedLegacyDynamicBanUpgradeLeavesCleanStateWithoutRestart_SW_FW_001(t *testing.T) {
	previousQuarantine := quarantineLegacyDynamicBanIntervals
	previousRestart := restartCoreServiceForInstall
	t.Cleanup(func() {
		quarantineLegacyDynamicBanIntervals = previousQuarantine
		restartCoreServiceForInstall = previousRestart
	})
	restarts := 0
	quarantineLegacyDynamicBanIntervals = func() (bool, error) { return false, nil }
	restartCoreServiceForInstall = func() error {
		restarts++
		return nil
	}
	if err := preparePackagedLegacyDynamicBanUpgrade(); err != nil {
		t.Fatal(err)
	}
	if restarts != 0 {
		t.Fatalf("clean state restarted the core %d times", restarts)
	}
}

func TestPackagedLegacyDynamicBanUpgradePropagatesFinalRecheckFailure_SW_FW_001(t *testing.T) {
	previousQuarantine := quarantineLegacyDynamicBanIntervals
	previousRestart := restartCoreServiceForInstall
	t.Cleanup(func() {
		quarantineLegacyDynamicBanIntervals = previousQuarantine
		restartCoreServiceForInstall = previousRestart
	})
	sentinel := errors.New("final recheck failed")
	passes := 0
	quarantineLegacyDynamicBanIntervals = func() (bool, error) {
		passes++
		if passes == 1 {
			return true, nil
		}
		return false, sentinel
	}
	restartCoreServiceForInstall = func() error { return nil }
	err := preparePackagedLegacyDynamicBanUpgrade()
	if err == nil || !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "after core restart") {
		t.Fatalf("final recheck failure was not propagated precisely: %v", err)
	}
}
