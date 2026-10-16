package firewall

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHAFirewalldScopeRejectsAmbiguousInput(t *testing.T) {
	for _, value := range []string{" ", "br-api0,", "br-api0,br-api0", "br-api0;id", "abcdefghijklmnop"} {
		if _, err := parseFirewalldPortInterfaces(value); err == nil {
			t.Fatalf("accepted invalid scope %q", value)
		}
	}
}

func TestHAFirewalldScopeRequiresActiveFrontend(t *testing.T) {
	for _, mode := range []string{"missing", "inactive", "ufw"} {
		t.Run(mode, func(t *testing.T) {
			d := t.TempDir()
			t.Setenv("PATH", d)
			useLinuxWrapperStateFile(t, filepath.Join(d, "receipt"))
			if mode == "inactive" {
				writeRootedExecutableTestFile(t, filepath.Join(d, "firewall-cmd"), []byte("#!/bin/sh\nprintf 'not running\\n'\nexit 252\n"))
			}
			if mode == "ufw" {
				writeRootedExecutableTestFile(t, filepath.Join(d, "ufw"), []byte("#!/bin/sh\nprintf 'Status: active\\n'\n"))
			}
			_, err := prepareLinuxFirewallWrapperReconciliationForInterfaces("keep", nil, []string{"64123"}, []string{"br-api0"})
			if err == nil || !strings.Contains(err.Error(), "requires active firewalld") {
				t.Fatalf("scope fell back to an unscoped frontend: %v", err)
			}
			if _, err := os.Stat(linuxWrapperStateFile); !os.IsNotExist(err) {
				t.Fatal("failed preflight wrote ownership")
			}
			if _, err := prepareLinuxFirewallWrapperReconciliationForInterfaces("keep", nil, nil, []string{"br-api0"}); err != nil {
				t.Fatalf("dormant scope blocked cleanup: %v", err)
			}
		})
	}
}

func TestHAFirewalldScopeRecoversPendingOtherZoneAndPreservesAdminPolicy(t *testing.T) {
	f := newPendingFirewalldFixture(t, statefulFirewalldWrapperTestScript)
	f.write(t, f.receipt, linuxWrapperStateVersion+"\nfirewalld\tport\t64123\tpublic\tpending\n")
	t.Setenv("SYSWARDEN_ACTIVE_ZONES_OUTPUT", "public\n  interfaces: eth0\nwork\n  interfaces: br-api0")
	for range 2 {
		plan, err := prepareLinuxFirewallWrapperReconciliationForInterfaces("keep", nil, []string{pendingTestPort}, []string{"br-api0"})
		if err != nil {
			t.Fatal(err)
		}
		if err = reconcileLinuxFirewallWrapperPlan(plan); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{f.rules, f.rules + ".runtime"} {
			got := string(readRootedTestFile(t, path))
			if got != "trusted|port=8443/tcp\nwork|port=64123/tcp\n" {
				t.Fatalf("wrong scope or administrator policy: %q", got)
			}
		}
		f.write(t, f.rules+".runtime", string(readRootedTestFile(t, f.rules)))
	}
	if err := applyLinuxFirewallWrappers(nil, nil); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{f.rules, f.rules + ".runtime"} {
		if string(readRootedTestFile(t, path)) != "trusted|port=8443/tcp\n" {
			t.Fatal("removal damaged administrator policy")
		}
	}
	calls := string(readRootedTestFile(t, f.log))
	for _, line := range strings.Split(calls, "\n") {
		if strings.Contains(line, "--zone=public") && (strings.Contains(line, "--add-") || strings.Contains(line, "--remove-")) {
			t.Fatalf("changed an external permission: %s", line)
		}
	}
}

func TestHAFirewalldIndependentScopeProductionWriter(t *testing.T) {
	for _, scope := range []string{"br-api0", "unset"} {
		t.Run(scope, func(t *testing.T) {
			t.Setenv("SYSWARDEN_TEST_HA_SCOPE", scope)
			t.Setenv("SYSWARDEN_WRAPPER_STATE", "/etc/scoped-rules")
			t.Setenv("SYSWARDEN_WRAPPER_LOG", "/etc/scoped-calls")
			t.Setenv("SYSWARDEN_ACTIVE_ZONES_OUTPUT", "public\n  interfaces: eth-test0 eth-test1\nwork\n  interfaces: br-api0")
			got := runBubblewrapFirewallGolden(t)
			if scope != "unset" && !strings.Contains(string(got), strictAllowForwardSource([]string{"eth-test0", "eth-test1"})) {
				t.Fatal("API scope changed protected forwarding ingress")
			}
		})
	}
}
