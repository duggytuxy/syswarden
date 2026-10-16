package firewall

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const pendingTestPort = "64123"
const pendingTestReceipt = "firewalld\tport\t64123\twork\tpending\n"

type pendingFirewalldFixture struct {
	directory, receipt, rules, log, command string
}

func newPendingFirewalldFixture(t *testing.T, script string) pendingFirewalldFixture {
	t.Helper()
	d := t.TempDir()
	f := pendingFirewalldFixture{d, filepath.Join(d, "ownership.state"), filepath.Join(d, "rules"), filepath.Join(d, "commands.log"), filepath.Join(d, "firewall-cmd")}
	useLinuxWrapperStateFile(t, f.receipt)
	writeRootedExecutableTestFile(t, f.command, []byte(script))
	t.Setenv("PATH", d)
	t.Setenv("SYSWARDEN_WRAPPER_STATE", f.rules)
	t.Setenv("SYSWARDEN_WRAPPER_LOG", f.log)
	f.write(t, f.receipt, linuxWrapperStateVersion+"\n"+pendingTestReceipt)
	for _, path := range []string{f.rules, f.rules + ".runtime"} {
		f.write(t, path, "trusted|port=8443/tcp\n")
	}
	return f
}

func (f pendingFirewalldFixture) write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func (f pendingFirewalldFixture) assertNoMutation(t *testing.T) {
	t.Helper()
	calls := string(readRootedTestFile(t, f.log))
	for _, forbidden := range []string{"--add-", "--remove-", "--reload", "--change-interface"} {
		if strings.Contains(calls, forbidden) {
			t.Fatalf("unexpected firewall mutation %q:\n%s", forbidden, calls)
		}
	}
}

func TestStalePendingFirewalldPortRecovery_SW_FW_001(t *testing.T) {
	for _, mode := range []string{"no desired port", "already owned other zone", "new desired other zone"} {
		t.Run(mode, func(t *testing.T) {
			f := newPendingFirewalldFixture(t, statefulFirewalldWrapperTestScript)
			var ports []string
			want := "trusted|port=8443/tcp\n"
			wantReceipt := linuxWrapperStateVersion + "\n"
			if mode != "no desired port" {
				ports = []string{pendingTestPort}
				want += "public|port=64123/tcp\n"
				wantReceipt += "firewalld\tport\t64123\tpublic\towned\n"
			}
			if mode == "already owned other zone" {
				f.write(t, f.receipt, wantReceipt+pendingTestReceipt)
				f.write(t, f.rules, want)
				f.write(t, f.rules+".runtime", want)
			}
			for range 2 {
				if err := applyLinuxFirewallWrappers(nil, ports); err != nil {
					t.Fatal(err)
				}
				if got := string(readRootedTestFile(t, f.receipt)); got != wantReceipt {
					t.Fatalf("unexpected receipt: %q", got)
				}
				for _, path := range []string{f.rules, f.rules + ".runtime"} {
					if got := string(readRootedTestFile(t, path)); got != want {
						t.Fatalf("unexpected policy: %q", got)
					}
				}
				// Simulate runtime restoration from persistent policy, not a
				// claim of real firewalld reload or native reboot coverage.
				f.write(t, f.rules+".runtime", string(readRootedTestFile(t, f.rules)))
			}
			if mode != "new desired other zone" {
				f.assertNoMutation(t)
			}
			if strings.Contains(string(readRootedTestFile(t, f.log)), "--remove-") {
				t.Fatal("pending recovery deleted a permission")
			}
		})
	}
}

func TestStalePendingFirewalldPortPresentRefusedBeforeCommit_SW_FW_001(t *testing.T) {
	for _, scope := range []string{"runtime", "permanent", "both"} {
		t.Run(scope, func(t *testing.T) {
			f := newPendingFirewalldFixture(t, statefulFirewalldWrapperTestScript)
			for _, path := range []string{f.rules, f.rules + ".runtime"} {
				if scope == "both" || scope == "runtime" && strings.HasSuffix(path, ".runtime") || scope == "permanent" && path == f.rules {
					f.write(t, path, "trusted|port=8443/tcp\nwork|port=64123/tcp\n")
				}
			}
			verification := minimalVerificationPlan(0)
			runner := newFakeNFTRunner(verification)
			_, err := applyNftablesPolicyWithWrappers(context.Background(), runner, f.directory, minimalNftRules(), nil, verification,
				func() error { _, e := prepareLinuxFirewallWrapperReconciliation(nil, nil); return e }, nil, nil)
			if err == nil || !strings.Contains(err.Error(), "remains present") || runner.mainApplyCalls != 0 || runner.rollbackApplyCalls != 0 {
				t.Fatalf("pending permission was not refused before commit: %v", err)
			}
			if got := string(readRootedTestFile(t, f.receipt)); got != linuxWrapperStateVersion+"\n"+pendingTestReceipt {
				t.Fatalf("refusal changed receipt: %q", got)
			}
			f.assertNoMutation(t)
		})
	}
}

func TestStalePendingFirewalldPortRejectsUnknownObservations_SW_FW_001(t *testing.T) {
	for _, test := range []struct{ name, change string }{
		{"empty negative response", "exit 1"},
		{"permission error", "printf 'not authorized\\n'; exit 1"},
		{"unexpected status", "printf 'no\\n'; exit 2"},
		{"daemon unavailable", "printf 'no\\n'; exit 252"},
		{"contradictory success", "printf 'no\\n'; exit 0"},
		{"mixed output", "printf 'warning\\nno\\n'; exit 1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			script := strings.Replace(statefulFirewalldWrapperTestScript, `selector="$zone|${argument#--query-}"`, `selector="$zone|${argument#--query-}"`+"\n        "+test.change, 1)
			f := newPendingFirewalldFixture(t, script)
			if err := applyLinuxFirewallWrappers(nil, nil); err == nil {
				t.Fatal("unknown observation authorized receipt retirement")
			}
			if got := string(readRootedTestFile(t, f.receipt)); got != linuxWrapperStateVersion+"\n"+pendingTestReceipt {
				t.Fatalf("unknown observation changed receipt: %q", got)
			}
			f.assertNoMutation(t)
		})
	}
}

func TestStalePendingFirewalldPortReappearanceNeverRemoved_SW_FW_001(t *testing.T) {
	// Only the obsolete port is queried in this fixture. Two queries occur at
	// each complete absence gate, including the final pre-receipt-write gate.
	for probe := 3; probe <= 10; probe++ {
		t.Run(strconv.Itoa(probe), func(t *testing.T) {
			f := newPendingFirewalldFixture(t, statefulFirewalldWrapperTestScript)
			t.Setenv("SYSWARDEN_QUERY_SEQUENCE_FILE", filepath.Join(f.directory, "probes"))
			t.Setenv("SYSWARDEN_OPERATOR_APPEAR_QUERY", strconv.Itoa(probe))
			if err := applyLinuxFirewallWrappers(nil, nil); err == nil {
				t.Fatal("reappearing pending permission was forgotten")
			}
			if got := string(readRootedTestFile(t, f.receipt)); got != linuxWrapperStateVersion+"\n"+pendingTestReceipt {
				t.Fatalf("interleaving lost pending evidence: %q", got)
			}
			for _, path := range []string{f.rules, f.rules + ".runtime"} {
				if !strings.Contains(string(readRootedTestFile(t, path)), "work|port=64123/tcp") {
					t.Fatal("concurrent administrator permission was removed")
				}
			}
			f.assertNoMutation(t)
		})
	}
}

func TestStalePendingFirewalldPortChangedReceiptIsPreserved_SW_FW_001(t *testing.T) {
	f := newPendingFirewalldFixture(t, statefulFirewalldWrapperTestScript)
	plan, err := prepareLinuxFirewallWrapperReconciliation(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	changed := linuxWrapperStateVersion + "\n" + pendingTestReceipt + "firewalld\tport\t64124\twork\towned\n"
	f.write(t, f.receipt, changed)
	if err := reconcileLinuxFirewallWrapperPlan(plan); err == nil || !strings.Contains(err.Error(), "ownership state changed") {
		t.Fatalf("changed receipt accepted: %v", err)
	}
	if got := string(readRootedTestFile(t, f.receipt)); got != changed {
		t.Fatalf("changed receipt overwritten: %q", got)
	}
	f.assertNoMutation(t)
}

func TestStalePendingFirewalldPortUnknownFrontendPreservesEvidence_SW_FW_001(t *testing.T) {
	for _, test := range []struct{ name, old, replacement string }{
		{"inactive", "printf 'running\\n'\n    exit 0", "printf 'not running\\n'\n    exit 252"},
		{"missing recorded zone", "printf 'public trusted work\\n'", "printf 'public trusted\\n'"},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newPendingFirewalldFixture(t, strings.Replace(statefulFirewalldWrapperTestScript, test.old, test.replacement, 1))
			if err := applyLinuxFirewallWrappers(nil, nil); err == nil {
				t.Fatal("unavailable frontend or zone accepted as absence")
			}
			if got := string(readRootedTestFile(t, f.receipt)); got != linuxWrapperStateVersion+"\n"+pendingTestReceipt {
				t.Fatalf("unknown frontend discarded receipt: %q", got)
			}
			f.assertNoMutation(t)
		})
	}
}

func TestStalePendingFirewalldPortNftTransactionBoundaries_SW_FW_001(t *testing.T) {
	for _, mode := range []string{"success", "precommit appearance", "postapply appearance", "postcommit appearance", "nft failure"} {
		t.Run(mode, func(t *testing.T) {
			f := newPendingFirewalldFixture(t, statefulFirewalldWrapperTestScript)
			if strings.Contains(mode, "appearance") {
				t.Setenv("SYSWARDEN_QUERY_SEQUENCE_FILE", filepath.Join(f.directory, "probes"))
				probe := "3"
				if mode == "postapply appearance" {
					probe = "5"
				} else if mode == "postcommit appearance" {
					probe = "7"
				}
				t.Setenv("SYSWARDEN_OPERATOR_APPEAR_QUERY", probe)
			}
			verification := minimalVerificationPlan(0)
			runner := newFakeNFTRunner(verification)
			if mode == "nft failure" {
				runner.applyErr = errors.New("injected nft commit failure")
			}
			var plan *linuxWrapperReconciliationPlan
			_, err := applyNftablesPolicyWithWrappers(context.Background(), runner, f.directory, minimalNftRules(), nil, verification,
				func() error {
					var e error
					plan, e = prepareLinuxFirewallWrapperReconciliation(nil, nil)
					return e
				},
				func() error { return reattestLinuxWrapperPlan(plan) },
				func() error { return reconcileLinuxFirewallWrapperPlan(plan) })
			wantReceipt := linuxWrapperStateVersion + "\n" + pendingTestReceipt
			if mode == "success" {
				if err != nil || runner.mainApplyCalls != 1 {
					t.Fatalf("verified recovery failed: %v", err)
				}
				wantReceipt = linuxWrapperStateVersion + "\n"
			} else if err == nil {
				t.Fatal("failed transaction reported success")
			}
			if mode == "precommit appearance" && runner.mainApplyCalls != 0 {
				t.Fatal("changed preflight committed nftables")
			}
			if mode == "postapply appearance" && (runner.mainApplyCalls != 1 || runner.rollbackApplyCalls != 1 || !strings.Contains(err.Error(), "preserved the previous ruleset")) {
				t.Fatalf("pre-persistence rollback outcome was lost: %v", err)
			}
			if mode == "postcommit appearance" && (runner.mainApplyCalls != 1 || runner.rollbackApplyCalls != 0 || !strings.Contains(err.Error(), "committed")) {
				t.Fatalf("committed firewall outcome was lost: %v", err)
			}
			if got := string(readRootedTestFile(t, f.receipt)); got != wantReceipt {
				t.Fatalf("unexpected receipt after %s: %q", mode, got)
			}
			f.assertNoMutation(t)
		})
	}
}
