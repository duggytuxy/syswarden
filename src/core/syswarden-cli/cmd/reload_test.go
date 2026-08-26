package cmd

import (
	"errors"
	"reflect"
	"testing"
)

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
