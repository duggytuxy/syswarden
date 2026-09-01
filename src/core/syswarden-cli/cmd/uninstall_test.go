package cmd

import (
	"errors"
	"strings"
	"syswarden-cli/pkg/integration"
	"testing"
)

func TestUninstallRefusesBeforeHostMutationWhenServicePreparationFails_SW2_FWBACKEND_001(t *testing.T) {
	previousBegin := beginRemoval
	previousCron := removeOwnedCronStateForRemoval
	previousPrepare := prepareFirewallStateForRemoval
	previousWireGuard := removeOwnedWireGuardStateForRemoval
	previousCleanup := cleanupFirewallStateForRemoval
	previousIntegration := removeOwnedIntegrationArtifactsForRemoval
	previousSocket := removeExactRuntimeSocketForRemoval
	previousPolicy := removeOwnedRsyslogSELinuxPolicyForRemoval
	previousRemoveServices := removePreparedServiceArtifacts
	previousRemoveRuntimeLock := removePreparedFirewallRuntimeLock
	previousUninstall := uninstallHostSystem
	t.Cleanup(func() {
		beginRemoval = previousBegin
		removeOwnedCronStateForRemoval = previousCron
		prepareFirewallStateForRemoval = previousPrepare
		removeOwnedWireGuardStateForRemoval = previousWireGuard
		cleanupFirewallStateForRemoval = previousCleanup
		removeOwnedIntegrationArtifactsForRemoval = previousIntegration
		removeExactRuntimeSocketForRemoval = previousSocket
		removeOwnedRsyslogSELinuxPolicyForRemoval = previousPolicy
		removePreparedServiceArtifacts = previousRemoveServices
		removePreparedFirewallRuntimeLock = previousRemoveRuntimeLock
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
	removePreparedFirewallRuntimeLock = func() error { return nil }
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
	previousRemoveRuntimeLock := removePreparedFirewallRuntimeLock
	previousUninstall := uninstallHostSystem
	t.Cleanup(func() {
		beginRemoval = previousBegin
		removeOwnedCronStateForRemoval = previousCron
		prepareFirewallStateForRemoval = previousPrepare
		removeOwnedWireGuardStateForRemoval = previousWireGuard
		cleanupFirewallStateForRemoval = previousCleanup
		removePreparedServiceArtifacts = previousRemoveServices
		removePreparedFirewallRuntimeLock = previousRemoveRuntimeLock
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
	removePreparedFirewallRuntimeLock = func() error { return nil }
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
	previousRemoveRuntimeLock := removePreparedFirewallRuntimeLock
	previousUninstall := uninstallHostSystem
	t.Cleanup(func() {
		beginRemoval = previousBegin
		removeOwnedCronStateForRemoval = previousCron
		prepareFirewallStateForRemoval = previousPrepare
		removeOwnedWireGuardStateForRemoval = previousWireGuard
		cleanupFirewallStateForRemoval = previousCleanup
		removePreparedServiceArtifacts = previousRemoveServices
		removePreparedFirewallRuntimeLock = previousRemoveRuntimeLock
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
	removePreparedFirewallRuntimeLock = func() error { return nil }
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
	previousRemoveRuntimeLock := removePreparedFirewallRuntimeLock
	t.Cleanup(func() {
		beginRemoval = previousBegin
		removeOwnedCronStateForRemoval = previousCron
		prepareFirewallStateForRemoval = previousPrepare
		removeOwnedWireGuardStateForRemoval = previousWireGuard
		cleanupFirewallStateForRemoval = previousCleanup
		removePreparedServiceArtifacts = previousRemoveServices
		removePreparedFirewallRuntimeLock = previousRemoveRuntimeLock
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
	removePreparedFirewallRuntimeLock = func() error { return nil }
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
	previousSocket := removeExactRuntimeSocketForRemoval
	previousPolicy := removeOwnedRsyslogSELinuxPolicyForRemoval
	previousCISTombstone := requireRemovalTombstoneForCISPolicyRemoval
	previousCISPolicies := removeExactCISHardeningPoliciesForRemoval
	previousRemoveServices := removePreparedServiceArtifacts
	previousRemoveRuntimeLock := removePreparedFirewallRuntimeLock
	previousUninstall := uninstallHostSystem
	t.Cleanup(func() {
		beginRemoval = previousBegin
		removeOwnedCronStateForRemoval = previousCron
		prepareFirewallStateForRemoval = previousPrepare
		removeOwnedWireGuardStateForRemoval = previousWireGuard
		cleanupFirewallStateForRemoval = previousCleanup
		removeOwnedIntegrationArtifactsForRemoval = previousIntegration
		removeExactRuntimeSocketForRemoval = previousSocket
		removeOwnedRsyslogSELinuxPolicyForRemoval = previousPolicy
		requireRemovalTombstoneForCISPolicyRemoval = previousCISTombstone
		removeExactCISHardeningPoliciesForRemoval = previousCISPolicies
		removePreparedServiceArtifacts = previousRemoveServices
		removePreparedFirewallRuntimeLock = previousRemoveRuntimeLock
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
	removeOwnedIntegrationArtifactsForRemoval = func() (integration.RsyslogPackageRemovalOutcome, error) {
		order = append(order, "rsyslog-artifact-removal-and-restart")
		return integration.RsyslogPackageRemovalActiveQuiesced, nil
	}
	removeExactRuntimeSocketForRemoval = func() error {
		order = append(order, "runtime-socket-removal")
		return nil
	}
	removeOwnedRsyslogSELinuxPolicyForRemoval = func() error {
		order = append(order, "rsyslog-selinux-policy-removal")
		return nil
	}
	requireRemovalTombstoneForCISPolicyRemoval = func() error {
		order = append(order, "tombstone-reattest")
		return nil
	}
	removeExactCISHardeningPoliciesForRemoval = func() error {
		order = append(order, "cis-hardening-policy-removal")
		return nil
	}
	removePreparedServiceArtifacts = func() error {
		order = append(order, "service-artifact-removal")
		return nil
	}
	removePreparedFirewallRuntimeLock = func() error {
		order = append(order, "runtime-lock-removal")
		return nil
	}
	uninstallHostSystem = func() error {
		order = append(order, "host-removal")
		return nil
	}
	if err := uninstallCmd.RunE(uninstallCmd, nil); err != nil {
		t.Fatalf("verified uninstall: %v", err)
	}
	if got := strings.Join(order, ","); got != "tombstone-publish,service-stop,cron-state-removal,wireguard-removal,firewall-cleanup,rsyslog-artifact-removal-and-restart,runtime-socket-removal,rsyslog-selinux-policy-removal,tombstone-reattest,cis-hardening-policy-removal,service-artifact-removal,runtime-lock-removal,host-removal" {
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
	previousSocket := removeExactRuntimeSocketForRemoval
	previousPolicy := removeOwnedRsyslogSELinuxPolicyForRemoval
	previousCISTombstone := requireRemovalTombstoneForCISPolicyRemoval
	previousCISPolicies := removeExactCISHardeningPoliciesForRemoval
	previousRemoveServices := removePreparedServiceArtifacts
	previousRemoveRuntimeLock := removePreparedFirewallRuntimeLock
	t.Cleanup(func() {
		beginRemoval = previousBegin
		removeOwnedCronStateForRemoval = previousCron
		prepareFirewallStateForRemoval = previousPrepare
		removeOwnedWireGuardStateForRemoval = previousWireGuard
		cleanupFirewallStateForRemoval = previousCleanup
		removeOwnedIntegrationArtifactsForRemoval = previousIntegration
		removeExactRuntimeSocketForRemoval = previousSocket
		removeOwnedRsyslogSELinuxPolicyForRemoval = previousPolicy
		requireRemovalTombstoneForCISPolicyRemoval = previousCISTombstone
		removeExactCISHardeningPoliciesForRemoval = previousCISPolicies
		removePreparedServiceArtifacts = previousRemoveServices
		removePreparedFirewallRuntimeLock = previousRemoveRuntimeLock
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
	removeOwnedIntegrationArtifactsForRemoval = func() (integration.RsyslogPackageRemovalOutcome, error) {
		order = append(order, "rsyslog-artifact-removal-and-restart")
		return integration.RsyslogPackageRemovalActiveQuiesced, nil
	}
	removeExactRuntimeSocketForRemoval = func() error {
		order = append(order, "runtime-socket-removal")
		return nil
	}
	removeOwnedRsyslogSELinuxPolicyForRemoval = func() error {
		order = append(order, "rsyslog-selinux-policy-removal")
		return nil
	}
	requireRemovalTombstoneForCISPolicyRemoval = func() error {
		order = append(order, "tombstone-reattest")
		return nil
	}
	removeExactCISHardeningPoliciesForRemoval = func() error {
		order = append(order, "cis-hardening-policy-removal")
		return nil
	}
	removePreparedServiceArtifacts = func() error {
		order = append(order, "service-artifact-removal")
		return nil
	}
	removePreparedFirewallRuntimeLock = func() error {
		order = append(order, "runtime-lock-removal")
		return nil
	}
	if err := preparePackageRemovalCmd.RunE(preparePackageRemovalCmd, nil); err != nil {
		t.Fatalf("prepare-package-removal: %v", err)
	}
	if got := strings.Join(order, ","); got != "tombstone-publish,service-stop,cron-state-removal,wireguard-removal,firewall-cleanup,rsyslog-artifact-removal-and-restart,runtime-socket-removal,rsyslog-selinux-policy-removal,tombstone-reattest,cis-hardening-policy-removal,service-artifact-removal,runtime-lock-removal" {
		t.Fatalf("package removal preparation order = %q", got)
	}
}

func TestPackageRemovalBranchesOnTypedRsyslogOutcome_SW2_PKG_001(t *testing.T) {
	previousBegin := beginRemoval
	previousCron := removeOwnedCronStateForRemoval
	previousPrepare := prepareFirewallStateForRemoval
	previousWireGuard := removeOwnedWireGuardStateForRemoval
	previousCleanup := cleanupFirewallStateForRemoval
	previousIntegration := removeOwnedIntegrationArtifactsForRemoval
	previousSocket := removeExactRuntimeSocketForRemoval
	previousPolicy := removeOwnedRsyslogSELinuxPolicyForRemoval
	previousCISTombstone := requireRemovalTombstoneForCISPolicyRemoval
	previousCISPolicies := removeExactCISHardeningPoliciesForRemoval
	previousRemoveServices := removePreparedServiceArtifacts
	previousRemoveRuntimeLock := removePreparedFirewallRuntimeLock
	t.Cleanup(func() {
		beginRemoval = previousBegin
		removeOwnedCronStateForRemoval = previousCron
		prepareFirewallStateForRemoval = previousPrepare
		removeOwnedWireGuardStateForRemoval = previousWireGuard
		cleanupFirewallStateForRemoval = previousCleanup
		removeOwnedIntegrationArtifactsForRemoval = previousIntegration
		removeExactRuntimeSocketForRemoval = previousSocket
		removeOwnedRsyslogSELinuxPolicyForRemoval = previousPolicy
		requireRemovalTombstoneForCISPolicyRemoval = previousCISTombstone
		removeExactCISHardeningPoliciesForRemoval = previousCISPolicies
		removePreparedServiceArtifacts = previousRemoveServices
		removePreparedFirewallRuntimeLock = previousRemoveRuntimeLock
	})

	configureEarlierPhases := func() {
		beginRemoval = func() error { return nil }
		prepareFirewallStateForRemoval = func() error { return nil }
		removeOwnedCronStateForRemoval = func() error { return nil }
		removeOwnedWireGuardStateForRemoval = func() error { return nil }
		cleanupFirewallStateForRemoval = func() error { return nil }
	}

	t.Run("offline complete skips socket and policy mutators", func(t *testing.T) {
		configureEarlierPhases()
		var order []string
		removeOwnedIntegrationArtifactsForRemoval = func() (integration.RsyslogPackageRemovalOutcome, error) {
			order = append(order, "offline-attestation")
			return integration.RsyslogPackageRemovalOfflineAlreadyComplete, nil
		}
		removeExactRuntimeSocketForRemoval = func() error {
			order = append(order, "forbidden-socket-mutation")
			return nil
		}
		removeOwnedRsyslogSELinuxPolicyForRemoval = func() error {
			order = append(order, "forbidden-policy-mutation")
			return nil
		}
		requireRemovalTombstoneForCISPolicyRemoval = func() error {
			order = append(order, "tombstone-reattest")
			return nil
		}
		removeExactCISHardeningPoliciesForRemoval = func() error {
			order = append(order, "cis-hardening-policy-removal")
			return nil
		}
		removePreparedServiceArtifacts = func() error {
			order = append(order, "service-artifact-removal")
			return nil
		}
		removePreparedFirewallRuntimeLock = func() error {
			order = append(order, "runtime-lock-removal")
			return nil
		}

		if err := prepareVerifiedFirewallRemoval(); err != nil {
			t.Fatalf("offline-complete removal preparation: %v", err)
		}
		if got := strings.Join(order, ","); got != "offline-attestation,tombstone-reattest,cis-hardening-policy-removal,service-artifact-removal,runtime-lock-removal" {
			t.Fatalf("offline-complete order = %q", got)
		}
	})

	t.Run("unknown outcome fails closed", func(t *testing.T) {
		configureEarlierPhases()
		laterCalls := 0
		removeOwnedIntegrationArtifactsForRemoval = func() (integration.RsyslogPackageRemovalOutcome, error) {
			return integration.RsyslogPackageRemovalOutcomeUnknown, nil
		}
		removeExactRuntimeSocketForRemoval = func() error { laterCalls++; return nil }
		removeOwnedRsyslogSELinuxPolicyForRemoval = func() error { laterCalls++; return nil }
		requireRemovalTombstoneForCISPolicyRemoval = func() error { laterCalls++; return nil }
		removeExactCISHardeningPoliciesForRemoval = func() error { laterCalls++; return nil }
		removePreparedServiceArtifacts = func() error { laterCalls++; return nil }
		removePreparedFirewallRuntimeLock = func() error { laterCalls++; return nil }

		err := prepareVerifiedFirewallRemoval()
		if err == nil || !strings.Contains(err.Error(), "unrecognized rsyslog package-removal outcome") ||
			!strings.Contains(err.Error(), "durable removal barrier is retained") {
			t.Fatalf("unknown rsyslog outcome refusal = %v", err)
		}
		if laterCalls != 0 {
			t.Fatalf("unknown rsyslog outcome reached %d later mutators", laterCalls)
		}
	})
}

func TestPackageRemovalRetainsBarrierWhenIntegrationCleanupFails_SW2_PKG_001(t *testing.T) {
	previousBegin := beginRemoval
	previousCron := removeOwnedCronStateForRemoval
	previousPrepare := prepareFirewallStateForRemoval
	previousWireGuard := removeOwnedWireGuardStateForRemoval
	previousCleanup := cleanupFirewallStateForRemoval
	previousIntegration := removeOwnedIntegrationArtifactsForRemoval
	previousSocket := removeExactRuntimeSocketForRemoval
	previousPolicy := removeOwnedRsyslogSELinuxPolicyForRemoval
	previousRemoveServices := removePreparedServiceArtifacts
	previousRemoveRuntimeLock := removePreparedFirewallRuntimeLock
	t.Cleanup(func() {
		beginRemoval = previousBegin
		removeOwnedCronStateForRemoval = previousCron
		prepareFirewallStateForRemoval = previousPrepare
		removeOwnedWireGuardStateForRemoval = previousWireGuard
		cleanupFirewallStateForRemoval = previousCleanup
		removeOwnedIntegrationArtifactsForRemoval = previousIntegration
		removeExactRuntimeSocketForRemoval = previousSocket
		removeOwnedRsyslogSELinuxPolicyForRemoval = previousPolicy
		removePreparedServiceArtifacts = previousRemoveServices
		removePreparedFirewallRuntimeLock = previousRemoveRuntimeLock
	})

	sentinel := errors.New("synthetic rsyslog recovery failure")
	serviceArtifactCalls := 0
	beginRemoval = func() error { return nil }
	prepareFirewallStateForRemoval = func() error { return nil }
	removeOwnedCronStateForRemoval = func() error { return nil }
	removeOwnedWireGuardStateForRemoval = func() error { return nil }
	cleanupFirewallStateForRemoval = func() error { return nil }
	removeOwnedIntegrationArtifactsForRemoval = func() (integration.RsyslogPackageRemovalOutcome, error) {
		return integration.RsyslogPackageRemovalOutcomeUnknown, sentinel
	}
	removePreparedServiceArtifacts = func() error {
		serviceArtifactCalls++
		return nil
	}
	removePreparedFirewallRuntimeLock = func() error { return nil }
	err := preparePackageRemovalCmd.RunE(preparePackageRemovalCmd, nil)
	if err == nil || !errors.Is(err, sentinel) ||
		!strings.Contains(err.Error(), "durable removal barrier is retained") {
		t.Fatalf("integration cleanup refusal = %v", err)
	}
	if serviceArtifactCalls != 0 {
		t.Fatalf("service artifacts removed after integration failure: %d", serviceArtifactCalls)
	}
}

func TestPackageRemovalKeepsSELinuxPolicyUntilProducerAndSocketTeardownSucceed_SW2_PKG_001(t *testing.T) {
	previousBegin := beginRemoval
	previousCron := removeOwnedCronStateForRemoval
	previousPrepare := prepareFirewallStateForRemoval
	previousWireGuard := removeOwnedWireGuardStateForRemoval
	previousCleanup := cleanupFirewallStateForRemoval
	previousIntegration := removeOwnedIntegrationArtifactsForRemoval
	previousSocket := removeExactRuntimeSocketForRemoval
	previousPolicy := removeOwnedRsyslogSELinuxPolicyForRemoval
	previousRemoveServices := removePreparedServiceArtifacts
	previousRemoveRuntimeLock := removePreparedFirewallRuntimeLock
	t.Cleanup(func() {
		beginRemoval = previousBegin
		removeOwnedCronStateForRemoval = previousCron
		prepareFirewallStateForRemoval = previousPrepare
		removeOwnedWireGuardStateForRemoval = previousWireGuard
		cleanupFirewallStateForRemoval = previousCleanup
		removeOwnedIntegrationArtifactsForRemoval = previousIntegration
		removeExactRuntimeSocketForRemoval = previousSocket
		removeOwnedRsyslogSELinuxPolicyForRemoval = previousPolicy
		removePreparedServiceArtifacts = previousRemoveServices
		removePreparedFirewallRuntimeLock = previousRemoveRuntimeLock
	})

	for _, test := range []struct {
		name      string
		failPhase string
		wantOrder string
		wantText  string
	}{
		{
			name:      "runtime socket failure preserves policy",
			failPhase: "socket",
			wantOrder: "rsyslog-restart,socket",
			wantText:  "SELinux policy and durable removal barrier are retained",
		},
		{
			name:      "policy failure stops later cleanup",
			failPhase: "policy",
			wantOrder: "rsyslog-restart,socket,policy",
			wantText:  "runtime socket is absent, and the durable removal barrier is retained",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			sentinel := errors.New("synthetic " + test.failPhase + " teardown failure")
			var order []string
			beginRemoval = func() error { return nil }
			prepareFirewallStateForRemoval = func() error { return nil }
			removeOwnedCronStateForRemoval = func() error { return nil }
			removeOwnedWireGuardStateForRemoval = func() error { return nil }
			cleanupFirewallStateForRemoval = func() error { return nil }
			removeOwnedIntegrationArtifactsForRemoval = func() (integration.RsyslogPackageRemovalOutcome, error) {
				order = append(order, "rsyslog-restart")
				return integration.RsyslogPackageRemovalActiveQuiesced, nil
			}
			removeExactRuntimeSocketForRemoval = func() error {
				order = append(order, "socket")
				if test.failPhase == "socket" {
					return sentinel
				}
				return nil
			}
			removeOwnedRsyslogSELinuxPolicyForRemoval = func() error {
				order = append(order, "policy")
				if test.failPhase == "policy" {
					return sentinel
				}
				return nil
			}
			removePreparedServiceArtifacts = func() error {
				order = append(order, "service-artifacts")
				return nil
			}
			removePreparedFirewallRuntimeLock = func() error {
				order = append(order, "runtime-lock")
				return nil
			}

			err := prepareVerifiedFirewallRemoval()
			if err == nil || !errors.Is(err, sentinel) || !strings.Contains(err.Error(), test.wantText) {
				t.Fatalf("%s refusal = %v", test.failPhase, err)
			}
			if got := strings.Join(order, ","); got != test.wantOrder {
				t.Fatalf("%s failure order = %q, want %q", test.failPhase, got, test.wantOrder)
			}
		})
	}
}

func TestPackageRemovalRefusesCISCleanupWhenTombstoneReattestationFails_SW2_PKG_001(t *testing.T) {
	previousBegin := beginRemoval
	previousCron := removeOwnedCronStateForRemoval
	previousPrepare := prepareFirewallStateForRemoval
	previousWireGuard := removeOwnedWireGuardStateForRemoval
	previousCleanup := cleanupFirewallStateForRemoval
	previousIntegration := removeOwnedIntegrationArtifactsForRemoval
	previousSocket := removeExactRuntimeSocketForRemoval
	previousPolicy := removeOwnedRsyslogSELinuxPolicyForRemoval
	previousCISTombstone := requireRemovalTombstoneForCISPolicyRemoval
	previousCISPolicies := removeExactCISHardeningPoliciesForRemoval
	previousRemoveServices := removePreparedServiceArtifacts
	previousRemoveRuntimeLock := removePreparedFirewallRuntimeLock
	t.Cleanup(func() {
		beginRemoval = previousBegin
		removeOwnedCronStateForRemoval = previousCron
		prepareFirewallStateForRemoval = previousPrepare
		removeOwnedWireGuardStateForRemoval = previousWireGuard
		cleanupFirewallStateForRemoval = previousCleanup
		removeOwnedIntegrationArtifactsForRemoval = previousIntegration
		removeExactRuntimeSocketForRemoval = previousSocket
		removeOwnedRsyslogSELinuxPolicyForRemoval = previousPolicy
		requireRemovalTombstoneForCISPolicyRemoval = previousCISTombstone
		removeExactCISHardeningPoliciesForRemoval = previousCISPolicies
		removePreparedServiceArtifacts = previousRemoveServices
		removePreparedFirewallRuntimeLock = previousRemoveRuntimeLock
	})

	sentinel := errors.New("synthetic removal tombstone loss")
	var order []string
	beginRemoval = func() error { return nil }
	prepareFirewallStateForRemoval = func() error { return nil }
	removeOwnedCronStateForRemoval = func() error { return nil }
	removeOwnedWireGuardStateForRemoval = func() error { return nil }
	cleanupFirewallStateForRemoval = func() error { return nil }
	removeOwnedIntegrationArtifactsForRemoval = func() (integration.RsyslogPackageRemovalOutcome, error) {
		order = append(order, "rsyslog-restart")
		return integration.RsyslogPackageRemovalActiveQuiesced, nil
	}
	removeExactRuntimeSocketForRemoval = func() error {
		order = append(order, "runtime-socket")
		return nil
	}
	removeOwnedRsyslogSELinuxPolicyForRemoval = func() error {
		order = append(order, "rsyslog-selinux-policy")
		return nil
	}
	requireRemovalTombstoneForCISPolicyRemoval = func() error {
		order = append(order, "tombstone-reattest")
		return sentinel
	}
	removeExactCISHardeningPoliciesForRemoval = func() error {
		order = append(order, "forbidden-cis-hardening-policy")
		return nil
	}
	removePreparedServiceArtifacts = func() error {
		order = append(order, "forbidden-service-artifacts")
		return nil
	}
	removePreparedFirewallRuntimeLock = func() error {
		order = append(order, "forbidden-runtime-lock")
		return nil
	}

	err := prepareVerifiedFirewallRemoval()
	if err == nil || !errors.Is(err, sentinel) ||
		!strings.Contains(err.Error(), "durable removal barrier could not be reattested") ||
		!strings.Contains(err.Error(), "CIS policies, prepared service artifacts, and runtime lock are retained") {
		t.Fatalf("CIS tombstone reattestation refusal = %v", err)
	}
	if got := strings.Join(order, ","); got != "rsyslog-restart,runtime-socket,rsyslog-selinux-policy,tombstone-reattest" {
		t.Fatalf("CIS tombstone reattestation failure order = %q", got)
	}
}

func TestPackageRemovalRetainsBarrierWhenCISHardeningPolicyCleanupFails_SW2_PKG_001(t *testing.T) {
	previousBegin := beginRemoval
	previousCron := removeOwnedCronStateForRemoval
	previousPrepare := prepareFirewallStateForRemoval
	previousWireGuard := removeOwnedWireGuardStateForRemoval
	previousCleanup := cleanupFirewallStateForRemoval
	previousIntegration := removeOwnedIntegrationArtifactsForRemoval
	previousSocket := removeExactRuntimeSocketForRemoval
	previousPolicy := removeOwnedRsyslogSELinuxPolicyForRemoval
	previousCISTombstone := requireRemovalTombstoneForCISPolicyRemoval
	previousCISPolicies := removeExactCISHardeningPoliciesForRemoval
	previousRemoveServices := removePreparedServiceArtifacts
	previousRemoveRuntimeLock := removePreparedFirewallRuntimeLock
	t.Cleanup(func() {
		beginRemoval = previousBegin
		removeOwnedCronStateForRemoval = previousCron
		prepareFirewallStateForRemoval = previousPrepare
		removeOwnedWireGuardStateForRemoval = previousWireGuard
		cleanupFirewallStateForRemoval = previousCleanup
		removeOwnedIntegrationArtifactsForRemoval = previousIntegration
		removeExactRuntimeSocketForRemoval = previousSocket
		removeOwnedRsyslogSELinuxPolicyForRemoval = previousPolicy
		requireRemovalTombstoneForCISPolicyRemoval = previousCISTombstone
		removeExactCISHardeningPoliciesForRemoval = previousCISPolicies
		removePreparedServiceArtifacts = previousRemoveServices
		removePreparedFirewallRuntimeLock = previousRemoveRuntimeLock
	})

	sentinel := errors.New("synthetic CIS hardening policy cleanup failure")
	var order []string
	beginRemoval = func() error { return nil }
	prepareFirewallStateForRemoval = func() error { return nil }
	removeOwnedCronStateForRemoval = func() error { return nil }
	removeOwnedWireGuardStateForRemoval = func() error { return nil }
	cleanupFirewallStateForRemoval = func() error { return nil }
	removeOwnedIntegrationArtifactsForRemoval = func() (integration.RsyslogPackageRemovalOutcome, error) {
		order = append(order, "rsyslog-restart")
		return integration.RsyslogPackageRemovalActiveQuiesced, nil
	}
	removeExactRuntimeSocketForRemoval = func() error {
		order = append(order, "runtime-socket")
		return nil
	}
	removeOwnedRsyslogSELinuxPolicyForRemoval = func() error {
		order = append(order, "rsyslog-selinux-policy")
		return nil
	}
	requireRemovalTombstoneForCISPolicyRemoval = func() error {
		order = append(order, "tombstone-reattest")
		return nil
	}
	removeExactCISHardeningPoliciesForRemoval = func() error {
		order = append(order, "cis-hardening-policy")
		return sentinel
	}
	removePreparedServiceArtifacts = func() error {
		order = append(order, "forbidden-service-artifacts")
		return nil
	}
	removePreparedFirewallRuntimeLock = func() error {
		order = append(order, "forbidden-runtime-lock")
		return nil
	}

	err := prepareVerifiedFirewallRemoval()
	if err == nil || !errors.Is(err, sentinel) ||
		!strings.Contains(err.Error(), "before exact CIS hardening policy cleanup") ||
		!strings.Contains(err.Error(), "durable removal barrier") ||
		!strings.Contains(err.Error(), "retained for retry") {
		t.Fatalf("CIS hardening policy cleanup refusal = %v", err)
	}
	if got := strings.Join(order, ","); got != "rsyslog-restart,runtime-socket,rsyslog-selinux-policy,tombstone-reattest,cis-hardening-policy" {
		t.Fatalf("CIS hardening policy cleanup failure order = %q", got)
	}
}

func TestPackageRemovalRetainsBarrierWhenRuntimeLockCleanupFails_SW2_PKG_001(t *testing.T) {
	previousBegin := beginRemoval
	previousCron := removeOwnedCronStateForRemoval
	previousPrepare := prepareFirewallStateForRemoval
	previousWireGuard := removeOwnedWireGuardStateForRemoval
	previousCleanup := cleanupFirewallStateForRemoval
	previousIntegration := removeOwnedIntegrationArtifactsForRemoval
	previousSocket := removeExactRuntimeSocketForRemoval
	previousPolicy := removeOwnedRsyslogSELinuxPolicyForRemoval
	previousCISTombstone := requireRemovalTombstoneForCISPolicyRemoval
	previousCISPolicies := removeExactCISHardeningPoliciesForRemoval
	previousRemoveServices := removePreparedServiceArtifacts
	previousRemoveRuntimeLock := removePreparedFirewallRuntimeLock
	t.Cleanup(func() {
		beginRemoval = previousBegin
		removeOwnedCronStateForRemoval = previousCron
		prepareFirewallStateForRemoval = previousPrepare
		removeOwnedWireGuardStateForRemoval = previousWireGuard
		cleanupFirewallStateForRemoval = previousCleanup
		removeOwnedIntegrationArtifactsForRemoval = previousIntegration
		removeExactRuntimeSocketForRemoval = previousSocket
		removeOwnedRsyslogSELinuxPolicyForRemoval = previousPolicy
		requireRemovalTombstoneForCISPolicyRemoval = previousCISTombstone
		removeExactCISHardeningPoliciesForRemoval = previousCISPolicies
		removePreparedServiceArtifacts = previousRemoveServices
		removePreparedFirewallRuntimeLock = previousRemoveRuntimeLock
	})

	sentinel := errors.New("synthetic busy runtime lock")
	beginRemoval = func() error { return nil }
	prepareFirewallStateForRemoval = func() error { return nil }
	removeOwnedCronStateForRemoval = func() error { return nil }
	removeOwnedWireGuardStateForRemoval = func() error { return nil }
	cleanupFirewallStateForRemoval = func() error { return nil }
	removeOwnedIntegrationArtifactsForRemoval = func() (integration.RsyslogPackageRemovalOutcome, error) {
		return integration.RsyslogPackageRemovalActiveQuiesced, nil
	}
	removeExactRuntimeSocketForRemoval = func() error { return nil }
	removeOwnedRsyslogSELinuxPolicyForRemoval = func() error { return nil }
	requireRemovalTombstoneForCISPolicyRemoval = func() error { return nil }
	removeExactCISHardeningPoliciesForRemoval = func() error { return nil }
	removePreparedServiceArtifacts = func() error { return nil }
	removePreparedFirewallRuntimeLock = func() error { return sentinel }
	err := preparePackageRemovalCmd.RunE(preparePackageRemovalCmd, nil)
	if err == nil || !errors.Is(err, sentinel) ||
		!strings.Contains(err.Error(), "exact runtime lock could not be removed") ||
		!strings.Contains(err.Error(), "durable removal barrier is retained") {
		t.Fatalf("runtime lock cleanup refusal = %v", err)
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
