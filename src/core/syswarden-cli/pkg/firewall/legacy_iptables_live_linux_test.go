//go:build linux

package firewall

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// This opt-in fixture supplies its own origin observations and never runs in
// the host namespace. It verifies actual xtables serialization and an exact
// rule transaction, not installation, producer authority or package removal.
func TestLegacyIPTablesLiveFixture(t *testing.T) {
	if os.Getenv("SYSWARDEN_TEST_NFT_GENERATION_LIVE") != "1" {
		t.Skip("requires a disposable network namespace")
	}
	parent := os.Getenv("SYSWARDEN_TEST_PARENT_NETNS")
	current, err := os.Readlink("/proc/self/ns/net")
	mapping, mapErr := os.ReadFile("/proc/self/uid_map")
	fields := strings.Fields(string(mapping))
	if err != nil || mapErr != nil || parent == "" || parent == current || os.Geteuid() != 0 || len(fields) != 3 || fields[0] != "0" || fields[2] != "1" {
		t.Fatal("fixture requires a distinct single-user network namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	run := func(name string, args ...string) []byte {
		t.Helper()
		if name != "/usr/bin/nft" && name != "/usr/bin/iptables" && name != "/usr/bin/iptables-save" {
			t.Fatal("unexpected fixture executable")
		}
		output, err := exec.CommandContext(ctx, name, args...).CombinedOutput() // #nosec G204 -- Fixed fixture binaries and synthetic arguments inside a verified disposable network namespace.
		if err != nil {
			t.Fatalf("synthetic compatibility command failed: %v: %s", err, output)
		}
		return output
	}
	if bytes.Contains(run("/usr/bin/nft", "-j", "list", "tables"), []byte(`"table"`)) {
		t.Fatal("fixture namespace is not empty")
	}
	port := func(operation, value string) {
		run("/usr/bin/iptables", operation, "INPUT", "-p", "tcp", "--dport", value, "-m", "comment", "--comment", "SYSWARDEN_CORE", "-j", "ACCEPT")
	}
	port("-A", "62027")
	run("/usr/bin/iptables", "-A", "INPUT", "-s", "192.168.0.0/16", "-j", "ACCEPT")
	run("/usr/bin/iptables", "-A", "INPUT", "-s", "198.51.100.0/24", "-m", "comment", "--comment", "operator-only", "-j", "DROP")
	observe := func() legacyIPTablesObservation {
		t.Helper()
		save := run("/usr/bin/iptables-save", "-t", "filter")
		if !bytes.Contains(save, []byte(" (nf_tables) ")) {
			t.Fatal("fixture requires the nf_tables backend")
		}
		observation, err := observeLegacyIPTables(run("/usr/bin/nft", "-j", "list", "table", "ip", "filter"), save)
		if err != nil {
			t.Fatal(err)
		}
		return observation
	}
	before := observe()
	inputs := legacyIPTablesInputs{HAEnabled: true, HAPeerPort: "62026", LANSubnets: []string{"192.0.2.1/32", "0.0.0.0/0", "192.168.0.0/16"}}
	for range 2 {
		port("-I", "62027")
		port("-I", "62026")
		for _, subnet := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "192.0.2.1/32", "0.0.0.0/0", "192.168.0.0/16"} {
			run("/usr/bin/iptables", "-I", "INPUT", "-s", subnet, "-j", "ACCEPT")
		}
	}
	generated := observe()
	plan, err := prepareLegacyIPTablesPlan(before, generated, generated, inputs, strings.Repeat("a", 64))
	if err != nil || len(plan.targets) != 18 {
		t.Fatal("actual historical generator did not produce the bounded delta", err)
	}
	verify := func() error {
		content, err := legacyIPTablesObservationBytes(observe())
		if err != nil || !bytes.Equal(content, plan.before) {
			return fmt.Errorf("synthetic compatibility state changed")
		}
		return nil
	}
	fence, err := newNFTGenerationRuleFence(ctx, func(context.Context) ([]nftGenerationRuleTarget, error) {
		return plan.targets, verify()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer fence.close()
	if err := fence.apply(ctx, verify); err != nil {
		t.Fatal(err)
	}
	after, err := legacyIPTablesObservationBytes(observe())
	original, originalErr := legacyIPTablesObservationBytes(before)
	if err != nil || originalErr != nil || !bytes.Equal(after, plan.after) || !bytes.Equal(after, original) {
		t.Fatal("actual retirement changed administrator state or retained historical rules", err, originalErr)
	}
	t.Log("Actual iptables generation retired exactly 18 added handles; original identical permissions, administrator rule and shared containers preserved.")
}
