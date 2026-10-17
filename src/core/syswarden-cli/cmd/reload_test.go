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

func TestReloadRefusesMissingInitializedWhitelistBeforeFirewall(t *testing.T) {
	previousConfig := config.GlobalConfig
	previousCron := hostCronSchedulingPreflight
	previousBackend := hostFirewallBackendPreflight
	previousForwarding := recoverPendingWireGuardForwardingForReload
	previousRecovery := recoverPendingWireGuardForReload
	previousPreflight := preflightWireGuardForReload
	previousApply := applyPoliciesForReload
	previousInitialize := ensurePersistentWhitelistPairForReload
	previousBlocklists := ensurePersistentBlocklistPairForReload
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
		hostCronSchedulingPreflight = previousCron
		hostFirewallBackendPreflight = previousBackend
		recoverPendingWireGuardForwardingForReload = previousForwarding
		recoverPendingWireGuardForReload = previousRecovery
		preflightWireGuardForReload = previousPreflight
		applyPoliciesForReload = previousApply
		ensurePersistentWhitelistPairForReload = previousInitialize
		ensurePersistentBlocklistPairForReload = previousBlocklists
	})
	config.GlobalConfig = &config.Config{FirewallBackend: "keep"}
	hostCronSchedulingPreflight = func(bool) error { return nil }
	hostFirewallBackendPreflight = func(string) error { return nil }
	recoverPendingWireGuardForwardingForReload = func() error { return nil }
	recoverPendingWireGuardForReload = func() error { return nil }
	preflightWireGuardForReload = func() error { return nil }
	initializationFailure := errors.New("persistent whitelist file unexpectedly missing after pair initialization")
	ensurePersistentBlocklistPairForReload = func() error { return nil }
	ensurePersistentWhitelistPairForReload = func() error { return initializationFailure }
	applyPoliciesForReload = func() error {
		t.Fatal("reload reached firewall mutation after an initialized family disappeared")
		return nil
	}
	err := reloadCmd.RunE(reloadCmd, nil)
	if !errors.Is(err, initializationFailure) || !strings.Contains(err.Error(), "persistent whitelist initialization failed before policy reload") {
		t.Fatalf("lost initialized family was not refused: %v", err)
	}
}

func TestReloadRefusesProducerActivationAfterBridgeFailure(t *testing.T) {
	previousConfig := config.GlobalConfig
	previousCron, previousBackend := hostCronSchedulingPreflight, hostFirewallBackendPreflight
	previousForwarding, previousRecovery := recoverPendingWireGuardForwardingForReload, recoverPendingWireGuardForReload
	previousPreflight, previousApply := preflightWireGuardForReload, applyPoliciesForReload
	previousBlocklists, previousWhitelist := ensurePersistentBlocklistPairForReload, ensurePersistentWhitelistPairForReload
	previousWG, previousSIEM, previousWAF, previousAbuse := setupWireGuardForReload, setupSIEMForReload, setupWAFForReload, setupAbuseForReload
	t.Cleanup(func() {
		config.GlobalConfig = previousConfig
		hostCronSchedulingPreflight, hostFirewallBackendPreflight = previousCron, previousBackend
		recoverPendingWireGuardForwardingForReload, recoverPendingWireGuardForReload = previousForwarding, previousRecovery
		preflightWireGuardForReload, applyPoliciesForReload = previousPreflight, previousApply
		ensurePersistentBlocklistPairForReload, ensurePersistentWhitelistPairForReload = previousBlocklists, previousWhitelist
		setupWireGuardForReload, setupSIEMForReload, setupWAFForReload, setupAbuseForReload = previousWG, previousSIEM, previousWAF, previousAbuse
	})
	config.GlobalConfig = &config.Config{FirewallBackend: "keep", TrustedLogProducers: "/var/log/waf/audit.log=999"}
	hostCronSchedulingPreflight = func(bool) error { return nil }
	hostFirewallBackendPreflight = func(string) error { return nil }
	recoverPendingWireGuardForwardingForReload = func() error { return nil }
	recoverPendingWireGuardForReload = func() error { return nil }
	preflightWireGuardForReload = func() error { return nil }
	applyPoliciesForReload = func() error { return nil }
	ensurePersistentBlocklistPairForReload = func() error { return nil }
	ensurePersistentWhitelistPairForReload = func() error { return nil }
	setupWireGuardForReload = func() error { return nil }
	setupSIEMForReload = func() error { return nil }
	failure := errors.New("bridge replacement not verified")
	setupWAFForReload = func() error { return failure }
	setupAbuseForReload = func() error { t.Fatal("reload continued toward core restart after bridge failure"); return nil }
	if err := reloadCmd.RunE(reloadCmd, nil); !errors.Is(err, failure) || !strings.Contains(err.Error(), "producer policy cannot activate") {
		t.Fatalf("activation failure=%v", err)
	}
}
