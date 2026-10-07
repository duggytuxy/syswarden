//go:build linux

package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"syswarden-cli/config"
)

func nftRemovalOperatorFixture(t *testing.T, rules ...map[string]any) []byte {
	t.Helper()
	entries := []any{
		map[string]any{"table": map[string]any{"family": "inet", "name": "syswarden", "handle": 1}},
		map[string]any{"chain": map[string]any{"family": "inet", "table": "syswarden", "name": operatorPolicyChainName, "handle": 2}},
		map[string]any{"rule": map[string]any{"family": "inet", "table": "syswarden", "chain": operatorPolicyChainName, "handle": 3, "comment": operatorPolicyReturnComment, "expr": []any{map[string]any{"return": nil}}}},
	}
	for _, rule := range rules {
		entries = append(entries, map[string]any{"rule": rule})
	}
	content, err := json.Marshal(map[string]any{"nftables": entries})
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func nftRemovalOperatorRule() map[string]any {
	return map[string]any{"family": "inet", "table": "syswarden", "chain": operatorPolicyChainName, "handle": 9, "comment": "private administrator rule", "expr": []any{map[string]any{"accept": nil}}}
}

func TestNFTUninstallOperatorPolicyEarlyInspectionIsReadOnly(t *testing.T) {
	oldConfig, oldUID, oldFactory := config.GlobalConfig, firewallCleanupEffectiveUserID, uninstallNFTRunnerFactory
	t.Cleanup(func() {
		config.GlobalConfig, firewallCleanupEffectiveUserID, uninstallNFTRunnerFactory = oldConfig, oldUID, oldFactory
	})
	config.GlobalConfig = config.NewFailSafeConfig()
	base := &fakeUninstallNFTRunner{tables: []nftTableTarget{{family: "inet", name: "syswarden"}}, legacyHandles: []uint64{42}}
	runner := &nftRemovalOperatorRunner{base: base, rulesets: [][]byte{nftRemovalOperatorFixture(t, nftRemovalOperatorRule())}}
	firewallCleanupEffectiveUserID = func() int { return 0 }
	uninstallNFTRunnerFactory = func() (nftCommandRunner, error) { return runner, nil }
	if err := PreflightAdministratorPolicyRemoval(); err == nil {
		t.Fatal("live administrator rule was not detected before service preparation")
	}
	if runner.reads != 1 || len(base.deleteCalls) != 0 {
		t.Fatal("early inspection was not a single read-only observation")
	}
	uninstallNFTRunnerFactory = func() (nftCommandRunner, error) { return base, nil }
	if err := PreflightAdministratorPolicyRemoval(); err != nil {
		t.Fatal("early administrator inspection attempted separate WireGuard recovery", err)
	}
	base.rulesetErr = fmt.Errorf("synthetic unreadable kernel state")
	if err := PreflightAdministratorPolicyRemoval(); err == nil {
		t.Fatal("unreadable live policy accepted")
	}
	firewallCleanupEffectiveUserID = func() int { return 1000 }
	uninstallNFTRunnerFactory = func() (nftCommandRunner, error) { t.Fatal("non-root inspection started"); return nil, nil }
	if err := PreflightAdministratorPolicyRemoval(); err == nil {
		t.Fatal("non-root removal inspection accepted")
	}
}

func TestNFTUninstallOperatorPolicyBoundaryPreservesConfiguredAndLiveProtection(t *testing.T) {
	previous := config.GlobalConfig
	t.Cleanup(func() { config.GlobalConfig = previous })
	config.GlobalConfig = config.NewFailSafeConfig()
	if err := preflightConfiguredOperatorPolicyRemoval(); err != nil {
		t.Fatal(err)
	}
	config.GlobalConfig.OperatorPolicy.Rules = []config.OperatorPolicyRule{validOperatorPolicyRule("operator", config.OperatorPolicyFamilyIPv4, "192.0.2.0/24")}
	if err := preflightConfiguredOperatorPolicyRemoval(); err == nil {
		t.Fatal("configured administrator protection was discarded")
	}
	for _, fixture := range []struct {
		name    string
		body    []byte
		allowed bool
	}{
		{"empty generated scaffold", nftRemovalOperatorFixture(t), true},
		{"administrator rule", nftRemovalOperatorFixture(t, nftRemovalOperatorRule()), false},
		{"unknown expression", []byte(`{"nftables":[{"rule":{"family":"inet","table":"syswarden","chain":"operator-policy","handle":9,"expr":[{"drop":null}]}}]}`), false},
		{"annotated rule outside scaffold", []byte(`{"nftables":[{"rule":{"family":"inet","table":"syswarden","chain":"administrator","handle":9,"comment":"syswarden:operator-policy:v1:retained","expr":[{"accept":null}]}}]}`), false},
		{"unrelated table", []byte(`{"nftables":[{"rule":{"family":"inet","table":"administrator","chain":"operator-policy","handle":9,"expr":[{"accept":null}]}}]}`), true},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			document, err := decodeNFTJSON(fixture.body)
			if err != nil {
				t.Fatal(err)
			}
			err = preflightLiveOperatorPolicyRemoval(document)
			if (err == nil) != fixture.allowed {
				t.Fatal("unexpected administrator preservation decision", err)
			}
			if err != nil && strings.Contains(err.Error(), "private administrator rule") {
				t.Fatal("rule content leaked into refusal")
			}
		})
	}
}

type nftRemovalOperatorRunner struct {
	base     *fakeUninstallNFTRunner
	rulesets [][]byte
	reads    int
}

func (runner *nftRemovalOperatorRunner) Run(ctx context.Context, input []byte, args ...string) ([]byte, error) {
	if reflect.DeepEqual(args, []string{"-j", "list", "ruleset"}) {
		if input != nil || len(runner.rulesets) == 0 {
			return nil, fmt.Errorf("invalid read-only fixture observation")
		}
		index := runner.reads
		runner.reads++
		if index >= len(runner.rulesets) {
			index = len(runner.rulesets) - 1
		}
		return append([]byte(nil), runner.rulesets[index]...), nil
	}
	return runner.base.Run(ctx, input, args...)
}

func TestNFTUninstallOperatorPolicyRefusesBeforeWrapperAndTableDeletion(t *testing.T) {
	oldPrepare := prepareNFTCleanupForUninstall
	oldConfig, oldUID := config.GlobalConfig, firewallCleanupEffectiveUserID
	oldReattest, oldFactory, oldWrappers := firewallRemovalServiceReattest, uninstallNFTRunnerFactory, applyLinuxFirewallWrappersForUninstall
	t.Cleanup(func() {
		prepareNFTCleanupForUninstall = oldPrepare
		config.GlobalConfig, firewallCleanupEffectiveUserID = oldConfig, oldUID
		firewallRemovalServiceReattest, uninstallNFTRunnerFactory, applyLinuxFirewallWrappersForUninstall = oldReattest, oldFactory, oldWrappers
	})
	for _, when := range []string{"configured", "live", "appears after preflight"} {
		t.Run(when, func(t *testing.T) {
			config.GlobalConfig = config.NewFailSafeConfig()
			base := &fakeUninstallNFTRunner{tables: []nftTableTarget{{family: "inet", name: "syswarden"}}}
			runner := &nftRemovalOperatorRunner{base: base, rulesets: [][]byte{nftRemovalOperatorFixture(t, nftRemovalOperatorRule())}}
			if when == "configured" {
				config.GlobalConfig.OperatorPolicy.Rules = []config.OperatorPolicyRule{validOperatorPolicyRule("operator", config.OperatorPolicyFamilyIPv4, "192.0.2.0/24")}
			}
			if when == "appears after preflight" {
				runner.rulesets = append([][]byte{nftRemovalOperatorFixture(t)}, runner.rulesets...)
			}
			prepareNFTCleanupForUninstall = func(ctx context.Context, runner nftCommandRunner) (func() error, func(), error) {
				if err := preflightNFTablesForUninstall(ctx, runner); err != nil {
					return nil, nil, err
				}
				return func() error { return cleanupReservedNFTablesForUninstall(ctx, runner) }, func() {}, nil
			}
			wrapperCalls := 0
			firewallCleanupEffectiveUserID = func() int { return 0 }
			firewallRemovalServiceReattest = func() error { return nil }
			uninstallNFTRunnerFactory = func() (nftCommandRunner, error) { return runner, nil }
			applyLinuxFirewallWrappersForUninstall = func([]string, []string) error { wrapperCalls++; return nil }
			if err := CleanupOwnedCompatibilityRulesForUninstall(); err == nil {
				t.Fatal("administrator policy accepted for deletion")
			}
			if len(base.deleteCalls) != 0 || len(base.tables) != 1 {
				t.Fatal("administrator table was deleted")
			}
			if wrapperCalls != 0 {
				t.Fatal("wrapper cleanup crossed the initial preservation refusal", wrapperCalls)
			}
		})
	}
}

// This opt-in fixture only observes a synthetic ruleset in a separate network
// namespace. It checks the actual kernel refusal path, not product ownership
// or complete native package removal.
func TestNFTUninstallOperatorPolicyLiveFixture(t *testing.T) {
	if os.Getenv("SYSWARDEN_TEST_OPERATOR_REMOVAL_LIVE") != "1" {
		t.Skip("requires a disposable operator-policy network fixture")
	}
	parent := os.Getenv("SYSWARDEN_TEST_PARENT_NETNS")
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil || parent == "" || parent == current || os.Geteuid() != 0 {
		t.Fatal("kernel fixture requires mapped root in a separate network namespace")
	}
	mapping, err := os.ReadFile("/proc/self/uid_map")
	fields := strings.Fields(string(mapping))
	if err != nil || len(fields) != 3 || fields[0] != "0" || fields[2] != "1" {
		t.Fatal("kernel fixture requires a single-user root mapping")
	}
	binary, err := os.ReadFile("/usr/bin/nft")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	if err := root.WriteFile("nft-fixture", binary, 0700); err != nil { // #nosec G306 -- Owner-only copy of the installed binary under the pinned test root.
		t.Fatal(err)
	}
	fixtureLegacyFail2banNFTExecutable(t, filepath.Join(directory, "nft-fixture"))
	runner, err := newExecNFTCommandRunner()
	if err != nil {
		t.Fatal(err)
	}
	previous := config.GlobalConfig
	config.GlobalConfig = config.NewFailSafeConfig()
	t.Cleanup(func() { config.GlobalConfig = previous })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	before, err := runner.Run(ctx, nil, "-j", "list", "ruleset")
	if err != nil {
		t.Fatal(err)
	}
	err = cleanupReservedNFTablesForUninstall(ctx, runner)
	if err == nil || !strings.Contains(err.Error(), "administrator policy") {
		t.Fatal("live administrator policy was not refused", err)
	}
	after, err := runner.Run(ctx, nil, "-j", "list", "ruleset")
	if err != nil || string(before) != string(after) {
		t.Fatal("live refusal changed the synthetic ruleset", err)
	}
}
