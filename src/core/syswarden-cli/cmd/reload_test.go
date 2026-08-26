package cmd

import (
	"errors"
	"reflect"
	"testing"
)

func TestReloadReconcilesWAFBeforeSIEMAndReportsBothFailures_SW2_PKG_001(t *testing.T) {
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
	if !reflect.DeepEqual(calls, []string{"waf", "siem"}) {
		t.Fatalf("rsyslog reload order = %v", calls)
	}
	if len(failures) != 2 {
		t.Fatalf("rsyslog reload failures = %v", failures)
	}
	if failures[0].Error() != "WAF log bridge reload: synthetic WAF failure" ||
		failures[1].Error() != "SIEM integration reload: synthetic SIEM failure" {
		t.Fatalf("rsyslog reload failures = %v", failures)
	}
}
