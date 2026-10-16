//go:build linux

package firewall

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestFirewalldProtectedInterfaceZoneSelection_SW_FW_001(t *testing.T) {
	for _, test := range []struct {
		name, zones string
		interfaces  []string
		want, fail  string
	}{
		{name: "unscoped multi-zone remains refused", zones: "docker\n  interfaces: docker0\npublic\n  interfaces: eth0", fail: "configure integrations.ha.firewalld_interfaces"},
		{name: "explicit host beside Docker", zones: "docker\n  interfaces: docker0 br-test\npublic (default)\n  interfaces: eth0", interfaces: []string{"eth0"}, want: "public"},
		{name: "custom zone beside Docker", zones: "docker (default)\n  interfaces: docker0\nwork\n  interfaces: eth0", interfaces: []string{"eth0"}, want: "work"},
		{name: "zone names do not imply role", zones: "public\n  interfaces: br-test\ndocker\n  interfaces: eth0", interfaces: []string{"eth0"}, want: "docker"},
		{name: "multiple protected interfaces in same zone", zones: "public\n  interfaces: eth0 eth1\nwork\n  interfaces: eth2", interfaces: []string{"eth0", "eth1"}, want: "public"},
		{name: "protected interfaces span zones", zones: "public\n  interfaces: eth0\nwork\n  interfaces: eth1", interfaces: []string{"eth0", "eth1"}, fail: "span multiple firewalld zones"},
		{name: "missing binding is not a default fallback", zones: "public (default)\n  interfaces: eth1\ndocker\n  interfaces: docker0", interfaces: []string{"eth0"}, fail: "has no active firewalld zone binding"},
		{name: "every protected interface needs a binding", zones: "public\n  interfaces: eth0", interfaces: []string{"eth0", "eth1"}, fail: "has no active firewalld zone binding"},
		{name: "source does not bind interface", zones: "trusted\n  sources: 192.0.2.0/24", interfaces: []string{"eth0"}, fail: "has no active firewalld zone binding"},
		{name: "duplicate cross-zone interface", zones: "public\n  interfaces: eth0\nwork\n  interfaces: eth0", interfaces: []string{"eth0"}, fail: "duplicate bindings"},
		{name: "duplicate same-zone interface", zones: "public\n  interfaces: eth0 eth0", interfaces: []string{"eth0"}, fail: "duplicate bindings"},
		{name: "invalid selected interface", zones: "public\n  interfaces: eth0", interfaces: []string{"eth0;"}, fail: "invalid API firewalld interface"},
		{name: "malformed unselected binding", zones: "public\n  interfaces: eth0\nwork\n  interfaces: bad;", interfaces: []string{"eth0"}, fail: "invalid active firewalld interface"},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			command := filepath.Join(directory, "firewall-cmd")
			writeRootedExecutableTestFile(t, command, []byte(statefulFirewalldWrapperTestScript))
			t.Setenv("SYSWARDEN_ACTIVE_ZONES_OUTPUT", test.zones)
			got, err := resolveFirewalldPortZone(command, test.interfaces)
			if test.fail != "" {
				if err == nil || !strings.Contains(err.Error(), test.fail) || got != "" {
					t.Fatalf("zone=%q error=%v, want refusal containing %q", got, err, test.fail)
				}
			} else if err != nil || got != test.want {
				t.Fatalf("zone=%q error=%v, want %q", got, err, test.want)
			}
		})
	}
}

func TestFirewalldUnrelatedZoneAppearingDuringTransaction_SW_FW_001(t *testing.T) {
	// The sixth probe is the final reinspection after the nft commit and the
	// permanent/runtime port mutations. Earlier probes cover the same race at
	// the precommit and pre-mutation boundaries.
	for _, probe := range []int{2, 3, 4, 5, 6} {
		t.Run(strconv.Itoa(probe), func(t *testing.T) {
			directory := t.TempDir()
			ownership := filepath.Join(directory, "ownership.state")
			useLinuxWrapperStateFile(t, ownership)
			logPath := filepath.Join(directory, "commands.log")
			writeRootedExecutableTestFile(t, filepath.Join(directory, "firewall-cmd"), []byte(statefulFirewalldWrapperTestScript))
			t.Setenv("PATH", directory)
			t.Setenv("SYSWARDEN_WRAPPER_STATE", filepath.Join(directory, "rules"))
			t.Setenv("SYSWARDEN_WRAPPER_LOG", logPath)
			t.Setenv("SYSWARDEN_ACTIVE_ZONE_SEQUENCE_FILE", filepath.Join(directory, "probes"))
			t.Setenv("SYSWARDEN_ACTIVE_ZONES_SWITCH_AT", strconv.Itoa(probe))
			t.Setenv("SYSWARDEN_ACTIVE_ZONES_OUTPUT", "public\n  interfaces: eth0")
			t.Setenv("SYSWARDEN_ACTIVE_ZONES_OUTPUT_AFTER", "docker\n  interfaces: docker0 br-test\npublic (default)\n  interfaces: eth0\ntrusted\n  sources: 192.0.2.0/24")
			verification := minimalVerificationPlan(0)
			runner := newFakeNFTRunner(verification)
			var plan *linuxWrapperReconciliationPlan
			id, err := applyNftablesPolicyWithWrappers(context.Background(), runner, directory, minimalNftRules(), nil, verification,
				func() error {
					var prepareErr error
					plan, prepareErr = prepareLinuxFirewallWrapperReconciliationForInterfaces("keep", nil, []string{"62028"}, []string{"eth0"})
					return prepareErr
				},
				func() error { return reattestLinuxWrapperPlan(plan) },
				func() error { return reconcileLinuxFirewallWrapperPlan(plan) },
			)
			if err != nil || id == "" || runner.mainApplyCalls != 1 || runner.rollbackApplyCalls != 0 {
				t.Fatalf("unrelated zone invalidated the transaction: id=%q apply=%d rollback=%d err=%v", id, runner.mainApplyCalls, runner.rollbackApplyCalls, err)
			}
			if got := string(readRootedTestFile(t, ownership)); got != linuxWrapperStateVersion+"\nfirewalld\tport\t62028\tpublic\towned\n" {
				t.Fatalf("final ownership was not verified: %q", got)
			}
			if got := strings.TrimSpace(string(readRootedTestFile(t, filepath.Join(directory, "probes")))); got != "6" {
				t.Fatalf("final reinspection was not exercised: %q", got)
			}
			commands := string(readRootedTestFile(t, logPath))
			for _, forbidden := range []string{"--zone=docker", "--reload", "--change-interface", "--remove-interface", "--set-default-zone"} {
				if strings.Contains(commands, forbidden) {
					t.Fatalf("unexpected shared policy mutation %q:\n%s", forbidden, commands)
				}
			}
		})
	}
}

func TestFirewalldProtectedInterfaceScopeSurvivesReload_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	statePath := filepath.Join(directory, "ownership.state")
	useLinuxWrapperStateFile(t, statePath)
	rulesPath := filepath.Join(directory, "rules")
	logPath := filepath.Join(directory, "commands.log")
	writeRootedExecutableTestFile(t, filepath.Join(directory, "firewall-cmd"), []byte(statefulFirewalldWrapperTestScript))
	t.Setenv("PATH", directory)
	t.Setenv("SYSWARDEN_WRAPPER_STATE", rulesPath)
	t.Setenv("SYSWARDEN_WRAPPER_LOG", logPath)
	t.Setenv("SYSWARDEN_ACTIVE_ZONES_OUTPUT", "docker\n  interfaces: docker0\npublic\n  interfaces: eth0")
	// Unrelated container policy is present in both firewalld scopes.
	for _, path := range []string{rulesPath, rulesPath + ".runtime"} {
		if err := os.WriteFile(path, []byte("docker|port=8443/tcp\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	interfaces := []string{"eth0"}
	plan, err := prepareLinuxFirewallWrapperReconciliationForInterfaces("keep", nil, []string{"62028"}, interfaces)
	if err != nil {
		t.Fatal(err)
	}
	interfaces[0] = "docker0"
	if err := reattestLinuxWrapperPlan(plan); err != nil {
		t.Fatalf("caller slice changed the pinned scope: %v", err)
	}
	if err := reconcileLinuxFirewallWrapperPlan(plan); err != nil {
		t.Fatal(err)
	}
	// A service restart may recreate runtime policy from permanent state.
	if err := os.WriteFile(rulesPath+".runtime", readRootedTestFile(t, rulesPath), 0600); err != nil {
		t.Fatal(err)
	}
	plan, err = prepareLinuxFirewallWrapperReconciliationForInterfaces("keep", nil, []string{"62028"}, []string{"eth0"})
	if err != nil {
		t.Fatal(err)
	}
	if err := reconcileLinuxFirewallWrapperPlan(plan); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{rulesPath, rulesPath + ".runtime"} {
		got := string(readRootedTestFile(t, path))
		if got != "docker|port=8443/tcp\npublic|port=62028/tcp\n" {
			t.Fatalf("unexpected scoped policy in %s: %q", path, got)
		}
	}
	if got := string(readRootedTestFile(t, statePath)); got != linuxWrapperStateVersion+"\nfirewalld\tport\t62028\tpublic\towned\n" {
		t.Fatalf("ownership escaped the explicit zone: %q", got)
	}
	// Exact removal must not depend on resolving a currently unique port zone.
	if err := applyLinuxFirewallWrappers(nil, nil); err != nil {
		t.Fatalf("remove scoped owned permission: %v", err)
	}
	for _, path := range []string{rulesPath, rulesPath + ".runtime"} {
		if got := string(readRootedTestFile(t, path)); got != "docker|port=8443/tcp\n" {
			t.Fatalf("removal changed unrelated Docker policy in %s: %q", path, got)
		}
	}
	commands := string(readRootedTestFile(t, logPath))
	for _, forbidden := range []string{"--zone=docker", "--reload", "--change-interface", "--remove-interface", "--set-default-zone"} {
		if strings.Contains(commands, forbidden) {
			t.Fatalf("unexpected shared policy mutation %q:\n%s", forbidden, commands)
		}
	}
}

func TestFirewalldProtectedInterfaceRebindingRefusedBeforeNftCommit_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	useLinuxWrapperStateFile(t, filepath.Join(directory, "ownership.state"))
	writeRootedExecutableTestFile(t, filepath.Join(directory, "firewall-cmd"), []byte(statefulFirewalldWrapperTestScript))
	t.Setenv("PATH", directory)
	t.Setenv("SYSWARDEN_WRAPPER_STATE", filepath.Join(directory, "rules"))
	t.Setenv("SYSWARDEN_ACTIVE_ZONE_SEQUENCE_FILE", filepath.Join(directory, "probes"))
	t.Setenv("SYSWARDEN_ACTIVE_ZONES_OUTPUT", "public\n  interfaces: eth0\ndocker\n  interfaces: docker0")
	t.Setenv("SYSWARDEN_ACTIVE_ZONES_OUTPUT_AFTER", "work\n  interfaces: eth0\ndocker\n  interfaces: docker0")
	verification := minimalVerificationPlan(0)
	runner := newFakeNFTRunner(verification)
	var plan *linuxWrapperReconciliationPlan
	_, err := applyNftablesPolicyWithWrappers(context.Background(), runner, directory, minimalNftRules(), nil, verification,
		func() error {
			var prepareErr error
			plan, prepareErr = prepareLinuxFirewallWrapperReconciliationForInterfaces("keep", nil, []string{"62028"}, []string{"eth0"})
			return prepareErr
		},
		func() error { return reattestLinuxWrapperPlan(plan) },
		func() error { return reconcileLinuxFirewallWrapperPlan(plan) },
	)
	if err == nil || !strings.Contains(err.Error(), `active firewalld port zone changed from "public" to "work"`) {
		t.Fatalf("changed binding was not refused: %v", err)
	}
	if runner.mainApplyCalls != 0 || runner.rollbackApplyCalls != 0 {
		t.Fatalf("changed binding mutated nftables: %d/%d", runner.mainApplyCalls, runner.rollbackApplyCalls)
	}
}
