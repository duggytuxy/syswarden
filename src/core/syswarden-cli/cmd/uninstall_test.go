package cmd

import (
	"errors"
	"strings"
	"testing"
)

func TestUninstallRefusesBeforeHostMutationWhenServicePreparationFails_SW2_FWBACKEND_001(t *testing.T) {
	previousBegin := beginRemoval
	previousCron := removeOwnedCronStateForRemoval
	previousPrepare := prepareFirewallStateForRemoval
	previousWireGuard := removeOwnedWireGuardStateForRemoval
	previousCleanup := cleanupFirewallStateForRemoval
	previousIntegration := removeOwnedIntegrationArtifactsForRemoval
	previousRemoveServices := removePreparedServiceArtifacts
	previousUninstall := uninstallHostSystem
	t.Cleanup(func() {
		beginRemoval = previousBegin
		removeOwnedCronStateForRemoval = previousCron
		prepareFirewallStateForRemoval = previousPrepare
		removeOwnedWireGuardStateForRemoval = previousWireGuard
		cleanupFirewallStateForRemoval = previousCleanup
		removeOwnedIntegrationArtifactsForRemoval = previousIntegration
		removePreparedServiceArtifacts = previousRemoveServices
		uninstallHostSystem = previousUninstall
	})

	sentinel := errors.New("synthetic WireGuard stop failure")
	cronCalls := 0
	wireGuardCalls := 0
	cleanupCalls := 0
	uninstallCalls := 0
	beginRemoval = func() error { return nil }
	removeOwnedCronStateForRemoval = func() error { cronCalls++; return nil }
	prepareFirewallStateForRemoval = func() error { return sentinel }
	removeOwnedWireGuardStateForRemoval = func() error { wireGuardCalls++; return nil }
	cleanupFirewallStateForRemoval = func() error {
		cleanupCalls++
		return nil
	}
	removePreparedServiceArtifacts = func() error { return nil }
	uninstallHostSystem = func() error {
		uninstallCalls++
		return nil
	}
	err := uninstallCmd.RunE(uninstallCmd, nil)
	if err == nil || !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "before managed firewall services are stopped") {
		t.Fatalf("uninstall preparation refusal = %v", err)
	}
	if cronCalls != 0 || wireGuardCalls != 0 || cleanupCalls != 0 {
		t.Fatalf("state cleanup ran after service preparation failure: cron=%d WireGuard=%d firewall=%d", cronCalls, wireGuardCalls, cleanupCalls)
	}
	if uninstallCalls != 0 {
		t.Fatalf("uninstall reached host mutation after cleanup refusal: %d", uninstallCalls)
	}
}

func TestUninstallRefusesBeforeServiceOrFirewallMutationWhenTombstonePublicationFails_SW2_FWBACKEND_001(t *testing.T) {
	previousBegin := beginRemoval
	previousCron := removeOwnedCronStateForRemoval
	previousPrepare := prepareFirewallStateForRemoval
	previousWireGuard := removeOwnedWireGuardStateForRemoval
	previousCleanup := cleanupFirewallStateForRemoval
	previousRemoveServices := removePreparedServiceArtifacts
	previousUninstall := uninstallHostSystem
	t.Cleanup(func() {
		beginRemoval = previousBegin
		removeOwnedCronStateForRemoval = previousCron
		prepareFirewallStateForRemoval = previousPrepare
		removeOwnedWireGuardStateForRemoval = previousWireGuard
		cleanupFirewallStateForRemoval = previousCleanup
		removePreparedServiceArtifacts = previousRemoveServices
		uninstallHostSystem = previousUninstall
	})

	sentinel := errors.New("synthetic tombstone publication failure")
	prepareCalls := 0
	wireGuardCalls := 0
	cleanupCalls := 0
	uninstallCalls := 0
	beginRemoval = func() error { return sentinel }
	removeOwnedCronStateForRemoval = func() error { return nil }
	prepareFirewallStateForRemoval = func() error { prepareCalls++; return nil }
	removeOwnedWireGuardStateForRemoval = func() error { wireGuardCalls++; return nil }
	cleanupFirewallStateForRemoval = func() error { cleanupCalls++; return nil }
	removePreparedServiceArtifacts = func() error { return nil }
	uninstallHostSystem = func() error { uninstallCalls++; return nil }
	err := uninstallCmd.RunE(uninstallCmd, nil)
	if err == nil || !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "durable removal barrier is published") {
		t.Fatalf("uninstall tombstone refusal = %v", err)
	}
	if prepareCalls != 0 || wireGuardCalls != 0 || cleanupCalls != 0 || uninstallCalls != 0 {
		t.Fatalf("tombstone refusal reached later phases: prepare=%d WireGuard=%d cleanup=%d uninstall=%d", prepareCalls, wireGuardCalls, cleanupCalls, uninstallCalls)
	}
}

func TestUninstallRefusesBeforeHostMutationWhenFirewallCleanupFails_SW2_FWBACKEND_001(t *testing.T) {
	previousBegin := beginRemoval
	previousCron := removeOwnedCronStateForRemoval
	previousPrepare := prepareFirewallStateForRemoval
	previousWireGuard := removeOwnedWireGuardStateForRemoval
	previousCleanup := cleanupFirewallStateForRemoval
	previousRemoveServices := removePreparedServiceArtifacts
	previousUninstall := uninstallHostSystem
	t.Cleanup(func() {
		beginRemoval = previousBegin
		removeOwnedCronStateForRemoval = previousCron
		prepareFirewallStateForRemoval = previousPrepare
		removeOwnedWireGuardStateForRemoval = previousWireGuard
		cleanupFirewallStateForRemoval = previousCleanup
		removePreparedServiceArtifacts = previousRemoveServices
		uninstallHostSystem = previousUninstall
	})

	sentinel := errors.New("synthetic inactive wrapper ownership debt")
	uninstallCalls := 0
	beginRemoval = func() error { return nil }
	removeOwnedCronStateForRemoval = func() error { return nil }
	prepareFirewallStateForRemoval = func() error { return nil }
	removeOwnedWireGuardStateForRemoval = func() error { return nil }
	cleanupFirewallStateForRemoval = func() error { return sentinel }
	removePreparedServiceArtifacts = func() error { return nil }
	uninstallHostSystem = func() error {
		uninstallCalls++
		return nil
	}
	err := uninstallCmd.RunE(uninstallCmd, nil)
	if err == nil || !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "before verified firewall cleanup") {
		t.Fatalf("uninstall cleanup refusal = %v", err)
	}
	if uninstallCalls != 0 {
		t.Fatalf("uninstall reached host mutation after cleanup refusal: %d", uninstallCalls)
	}
}

func TestRemovalScansProcessesBeforeCronStateRemoval_SW2_FWBACKEND_001(t *testing.T) {
	previousBegin := beginRemoval
	previousCron := removeOwnedCronStateForRemoval
	previousPrepare := prepareFirewallStateForRemoval
	previousWireGuard := removeOwnedWireGuardStateForRemoval
	previousCleanup := cleanupFirewallStateForRemoval
	previousRemoveServices := removePreparedServiceArtifacts
	t.Cleanup(func() {
		beginRemoval = previousBegin
		removeOwnedCronStateForRemoval = previousCron
		prepareFirewallStateForRemoval = previousPrepare
		removeOwnedWireGuardStateForRemoval = previousWireGuard
		cleanupFirewallStateForRemoval = previousCleanup
		removePreparedServiceArtifacts = previousRemoveServices
	})

	sentinel := errors.New("synthetic unsafe cron.d artifact")
	processScanCalls := 0
	wireGuardCalls := 0
	cleanupCalls := 0
	beginRemoval = func() error { return nil }
	removeOwnedCronStateForRemoval = func() error { return sentinel }
	prepareFirewallStateForRemoval = func() error { processScanCalls++; return nil }
	removeOwnedWireGuardStateForRemoval = func() error { wireGuardCalls++; return nil }
	cleanupFirewallStateForRemoval = func() error { cleanupCalls++; return nil }
	removePreparedServiceArtifacts = func() error { return nil }
	err := preparePackageRemovalCmd.RunE(preparePackageRemovalCmd, nil)
	if err == nil || !errors.Is(err, sentinel) || !strings.Contains(err.Error(), "before exact cron.d cleanup") {
		t.Fatalf("cron state refusal = %v", err)
	}
	if processScanCalls != 1 || wireGuardCalls != 0 || cleanupCalls != 0 {
		t.Fatalf("cron state refusal ordering: process scans=%d WireGuard=%d cleanup=%d", processScanCalls, wireGuardCalls, cleanupCalls)
	}
}

func TestUninstallRunsHostRemovalOnlyAfterVerifiedFirewallPreparation_SW2_FWBACKEND_001(t *testing.T) {
	previousBegin := beginRemoval
	previousCron := removeOwnedCronStateForRemoval
	previousPrepare := prepareFirewallStateForRemoval
	previousWireGuard := removeOwnedWireGuardStateForRemoval
	previousCleanup := cleanupFirewallStateForRemoval
	previousIntegration := removeOwnedIntegrationArtifactsForRemoval
	previousRemoveServices := removePreparedServiceArtifacts
	previousUninstall := uninstallHostSystem
	t.Cleanup(func() {
		beginRemoval = previousBegin
		removeOwnedCronStateForRemoval = previousCron
		prepareFirewallStateForRemoval = previousPrepare
		removeOwnedWireGuardStateForRemoval = previousWireGuard
		cleanupFirewallStateForRemoval = previousCleanup
		removeOwnedIntegrationArtifactsForRemoval = previousIntegration
		removePreparedServiceArtifacts = previousRemoveServices
		uninstallHostSystem = previousUninstall
	})

	var order []string
	beginRemoval = func() error {
		order = append(order, "tombstone-publish")
		return nil
	}
	removeOwnedCronStateForRemoval = func() error {
		order = append(order, "cron-state-removal")
		return nil
	}
	prepareFirewallStateForRemoval = func() error {
		order = append(order, "service-stop")
		return nil
	}
	removeOwnedWireGuardStateForRemoval = func() error {
		order = append(order, "wireguard-removal")
		return nil
	}
	cleanupFirewallStateForRemoval = func() error {
		order = append(order, "firewall-cleanup")
		return nil
	}
	removeOwnedIntegrationArtifactsForRemoval = func() error {
		order = append(order, "integration-artifact-removal")
		return nil
	}
	removePreparedServiceArtifacts = func() error {
		order = append(order, "service-artifact-removal")
		return nil
	}
	uninstallHostSystem = func() error {
		order = append(order, "host-removal")
		return nil
	}
	if err := uninstallCmd.RunE(uninstallCmd, nil); err != nil {
		t.Fatalf("verified uninstall: %v", err)
	}
	if got := strings.Join(order, ","); got != "tombstone-publish,service-stop,cron-state-removal,wireguard-removal,firewall-cleanup,integration-artifact-removal,service-artifact-removal,host-removal" {
		t.Fatalf("uninstall order = %q", got)
	}
}

func TestPackageRemovalUsesVerifiedFirewallPreparationOnly_SW2_FWBACKEND_001(t *testing.T) {
	previousBegin := beginRemoval
	previousCron := removeOwnedCronStateForRemoval
	previousPrepare := prepareFirewallStateForRemoval
	previousWireGuard := removeOwnedWireGuardStateForRemoval
	previousCleanup := cleanupFirewallStateForRemoval
	previousIntegration := removeOwnedIntegrationArtifactsForRemoval
	previousRemoveServices := removePreparedServiceArtifacts
	t.Cleanup(func() {
		beginRemoval = previousBegin
		removeOwnedCronStateForRemoval = previousCron
		prepareFirewallStateForRemoval = previousPrepare
		removeOwnedWireGuardStateForRemoval = previousWireGuard
		cleanupFirewallStateForRemoval = previousCleanup
		removeOwnedIntegrationArtifactsForRemoval = previousIntegration
		removePreparedServiceArtifacts = previousRemoveServices
	})

	var order []string
	beginRemoval = func() error {
		order = append(order, "tombstone-publish")
		return nil
	}
	removeOwnedCronStateForRemoval = func() error {
		order = append(order, "cron-state-removal")
		return nil
	}
	prepareFirewallStateForRemoval = func() error {
		order = append(order, "service-stop")
		return nil
	}
	removeOwnedWireGuardStateForRemoval = func() error {
		order = append(order, "wireguard-removal")
		return nil
	}
	cleanupFirewallStateForRemoval = func() error {
		order = append(order, "firewall-cleanup")
		return nil
	}
	removeOwnedIntegrationArtifactsForRemoval = func() error {
		order = append(order, "integration-artifact-removal")
		return nil
	}
	removePreparedServiceArtifacts = func() error {
		order = append(order, "service-artifact-removal")
		return nil
	}
	if err := preparePackageRemovalCmd.RunE(preparePackageRemovalCmd, nil); err != nil {
		t.Fatalf("prepare-package-removal: %v", err)
	}
	if got := strings.Join(order, ","); got != "tombstone-publish,service-stop,cron-state-removal,wireguard-removal,firewall-cleanup,integration-artifact-removal,service-artifact-removal" {
		t.Fatalf("package removal preparation order = %q", got)
	}
}

func TestPackageRemovalRetainsBarrierWhenIntegrationCleanupFails_SW2_PKG_001(t *testing.T) {
	previousBegin := beginRemoval
	previousCron := removeOwnedCronStateForRemoval
	previousPrepare := prepareFirewallStateForRemoval
	previousWireGuard := removeOwnedWireGuardStateForRemoval
	previousCleanup := cleanupFirewallStateForRemoval
	previousIntegration := removeOwnedIntegrationArtifactsForRemoval
	previousRemoveServices := removePreparedServiceArtifacts
	t.Cleanup(func() {
		beginRemoval = previousBegin
		removeOwnedCronStateForRemoval = previousCron
		prepareFirewallStateForRemoval = previousPrepare
		removeOwnedWireGuardStateForRemoval = previousWireGuard
		cleanupFirewallStateForRemoval = previousCleanup
		removeOwnedIntegrationArtifactsForRemoval = previousIntegration
		removePreparedServiceArtifacts = previousRemoveServices
	})

	sentinel := errors.New("synthetic rsyslog recovery failure")
	serviceArtifactCalls := 0
	beginRemoval = func() error { return nil }
	prepareFirewallStateForRemoval = func() error { return nil }
	removeOwnedCronStateForRemoval = func() error { return nil }
	removeOwnedWireGuardStateForRemoval = func() error { return nil }
	cleanupFirewallStateForRemoval = func() error { return nil }
	removeOwnedIntegrationArtifactsForRemoval = func() error { return sentinel }
	removePreparedServiceArtifacts = func() error {
		serviceArtifactCalls++
		return nil
	}
	err := preparePackageRemovalCmd.RunE(preparePackageRemovalCmd, nil)
	if err == nil || !errors.Is(err, sentinel) ||
		!strings.Contains(err.Error(), "durable removal barrier is retained") {
		t.Fatalf("integration cleanup refusal = %v", err)
	}
	if serviceArtifactCalls != 0 {
		t.Fatalf("service artifacts removed after integration failure: %d", serviceArtifactCalls)
	}
}

func TestPackageRemovalCommandRemainsInternalAndArgumentFree_SW2_FWBACKEND_001(t *testing.T) {
	if !preparePackageRemovalCmd.Hidden {
		t.Fatal("prepare-package-removal must remain hidden from the operator command surface")
	}
	if preparePackageRemovalCmd.Name() != "prepare-package-removal" {
		t.Fatalf("internal removal command name = %q", preparePackageRemovalCmd.Name())
	}
	if err := preparePackageRemovalCmd.Args(preparePackageRemovalCmd, nil); err != nil {
		t.Fatalf("zero-argument package removal contract: %v", err)
	}
	if err := preparePackageRemovalCmd.Args(preparePackageRemovalCmd, []string{"unexpected"}); err == nil {
		t.Fatal("internal package removal command accepted an argument")
	}
}
