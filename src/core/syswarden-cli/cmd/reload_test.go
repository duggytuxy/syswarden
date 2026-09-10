package cmd

import (
	"errors"
	"reflect"
	"strings"
	"syswarden-cli/config"
	"testing"
)

func TestReloadRefusesPersistentPolicyInitializationFailureBeforeFirewall(t *testing.T) {
	previousConfig := config.GlobalConfig
	previousCron := hostCronSchedulingPreflight
	previousBackend := hostFirewallBackendPreflight
	previousForwarding := recoverPendingWireGuardForwardingForReload
	previousRecovery := recoverPendingWireGuardForReload
	previousPreflight := preflightWireGuardForReload
	previousApply := applyPoliciesForReload
	previousInitialize := ensurePersistentBlocklistPairForReload
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
		hostCronSchedulingPreflight = previousCron
		hostFirewallBackendPreflight = previousBackend
		recoverPendingWireGuardForwardingForReload = previousForwarding
		recoverPendingWireGuardForReload = previousRecovery
		preflightWireGuardForReload = previousPreflight
		applyPoliciesForReload = previousApply
		ensurePersistentBlocklistPairForReload = previousInitialize
	})
	config.GlobalConfig = &config.Config{FirewallBackend: "keep"}
	hostCronSchedulingPreflight = func(bool) error { return nil }
	hostFirewallBackendPreflight = func(string) error { return nil }
	recoverPendingWireGuardForwardingForReload = func() error { return nil }
	recoverPendingWireGuardForReload = func() error { return nil }
	preflightWireGuardForReload = func() error { return nil }
	initializationFailure := errors.New("persistent blocklist file unexpectedly missing after pair initialization")
	ensurePersistentBlocklistPairForReload = func() error { return initializationFailure }
	applyPoliciesForReload = func() error {
		t.Fatal("reload reached firewall mutation after an initialized family disappeared")
		return nil
	}
	err := reloadCmd.RunE(reloadCmd, nil)
	if !errors.Is(err, initializationFailure) || !strings.Contains(err.Error(), "persistent blocklist initialization failed before policy reload") {
		t.Fatalf("lost initialized family was not refused: %v", err)
	}
}

func TestReloadReconcilesSIEMBeforeWAFAndReportsBothFailures_SW2_PKG_001(t *testing.T) {
	previousWAF := setupWAFForReload
	previousSIEM := setupSIEMForReload
	t.Cleanup(func() {
		setupWAFForReload = previousWAF
		setupSIEMForReload = previousSIEM
	})
	calls := []string{}
	setupWAFForReload = func() error {
		calls = append(calls, "waf")
		return errors.New("synthetic WAF failure")
	}
	setupSIEMForReload = func() error {
		calls = append(calls, "siem")
		return errors.New("synthetic SIEM failure")
	}
	failures := reloadRsyslogIntegrations()
	if !reflect.DeepEqual(calls, []string{"siem", "waf"}) {
		t.Fatalf("rsyslog reload order = %v", calls)
	}
	if len(failures) != 2 {
		t.Fatalf("rsyslog reload failures = %v", failures)
	}
	if failures[0].Error() != "SIEM integration reload: synthetic SIEM failure" ||
		failures[1].Error() != "WAF log bridge reload: synthetic WAF failure" {
		t.Fatalf("rsyslog reload failures = %v", failures)
	}
}

func TestInstallReconcilesSIEMBeforeWAF_SW2_PKG_001(t *testing.T) {
	previousSIEM := setupSIEMForInstall
	previousWAF := setupWAFForInstall
	t.Cleanup(func() {
		setupSIEMForInstall = previousSIEM
		setupWAFForInstall = previousWAF
	})
	calls := []string{}
	setupSIEMForInstall = func() error {
		calls = append(calls, "siem")
		return nil
	}
	setupWAFForInstall = func() error {
		calls = append(calls, "waf")
		return nil
	}
	if err := setupRsyslogIntegrationsForInstall(); err != nil {
		t.Fatalf("install rsyslog integrations: %v", err)
	}
	if !reflect.DeepEqual(calls, []string{"siem", "waf"}) {
		t.Fatalf("rsyslog install order = %v", calls)
	}
}
