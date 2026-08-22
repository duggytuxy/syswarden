//go:build linux

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type fakeNFTRunner struct {
	mu                   sync.Mutex
	plan                 nftVerificationPlan
	initialTables        []nftTableTarget
	currentTables        []nftTableTarget
	checkErr             error
	applyErr             error
	verificationErr      error
	verificationCountGap int
	blockCandidateApply  bool
	mainApplyCalls       int
	rollbackApplyCalls   int
	activeApplies        int
	maxActiveApplies     int
	lastCandidate        string
	lastRollback         string
	rulesetDocuments     [][]byte
	rulesetCalls         int
}

type fakeUninstallNFTRunner struct {
	mu                  sync.Mutex
	tables              []nftTableTarget
	listErr             error
	deleteErr           map[nftTableTarget]error
	retain              map[nftTableTarget]bool
	deleteCalls         []nftTableTarget
	legacyHandles       []uint64
	rulesetErr          error
	includeOperatorRule bool
}

func (runner *fakeUninstallNFTRunner) Run(_ context.Context, stdin []byte, args ...string) ([]byte, error) {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	if stdin != nil {
		return nil, fmt.Errorf("unexpected nft input")
	}
	if len(args) == 3 && args[0] == "-j" && args[1] == "list" && args[2] == "tables" {
		if runner.listErr != nil {
			return nil, runner.listErr
		}
		return nftTablesJSON(runner.tables), nil
	}
	if len(args) == 3 && args[0] == "-j" && args[1] == "list" && args[2] == "ruleset" {
		if runner.rulesetErr != nil {
			return nil, runner.rulesetErr
		}
		return nftLegacyWireGuardRulesJSON(runner.legacyHandles, runner.includeOperatorRule), nil
	}
	if len(args) == 4 && args[0] == "delete" && args[1] == "table" {
		target := nftTableTarget{family: args[2], name: args[3]}
		runner.deleteCalls = append(runner.deleteCalls, target)
		if err := runner.deleteErr[target]; err != nil {
			return nil, err
		}
		if runner.retain[target] {
			return nil, nil
		}
		remaining := runner.tables[:0]
		for _, existing := range runner.tables {
			if existing != target {
				remaining = append(remaining, existing)
			}
		}
		runner.tables = append([]nftTableTarget(nil), remaining...)
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected nft command: %q", args)
}

func TestMain(m *testing.M) {
	directory, err := os.MkdirTemp("", "syswarden-firewall-tests-")
	if err != nil {
		panic(err)
	}
	nftRuntimeLockPath = filepath.Join(directory, "firewall.lock")
	linuxWrapperStateFile = filepath.Join(directory, "firewall-wrappers.state")
	linuxWrapperExecutableValidator = validateTestLinuxWrapperExecutable
	linuxWrapperCommandEnvironment = testLinuxWrapperCommandEnvironment
	uninstallNFTRunnerFactory = func() (nftCommandRunner, error) { return &fakeUninstallNFTRunner{}, nil }
	firewallRemovalServiceReattest = func() error { return nil }
	code := m.Run()
	_ = os.RemoveAll(directory)
	os.Exit(code)
}

func testLinuxWrapperCommandEnvironment() []string {
	environment := fixedLinuxWrapperCommandEnvironment()
	for _, entry := range os.Environ() {
		name, _, found := strings.Cut(entry, "=")
		if found && strings.HasPrefix(name, "SYSWARDEN_") {
			environment = append(environment, entry)
		}
	}
	return environment
}

func validateTestLinuxWrapperExecutable(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("test wrapper path is not a clean absolute path")
	}
	for _, target := range []string{path, filepath.Dir(path)} {
		info, err := os.Lstat(target)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 && int64(stat.Uid) != int64(os.Geteuid()) {
			return fmt.Errorf("test wrapper target has unexpected ownership")
		}
		if target == path {
			if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 {
				return fmt.Errorf("test wrapper target is not a trusted executable")
			}
		} else if !info.IsDir() || info.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("test wrapper directory is not trusted")
		}
	}
	return nil
}

func newFakeNFTRunner(plan nftVerificationPlan, initial ...nftTableTarget) *fakeNFTRunner {
	return &fakeNFTRunner{
		plan:          plan,
		initialTables: append([]nftTableTarget(nil), initial...),
		currentTables: append([]nftTableTarget(nil), initial...),
	}
}

func (r *fakeNFTRunner) Run(ctx context.Context, _ []byte, args ...string) ([]byte, error) {
	if len(args) == 3 && args[0] == "-j" && args[1] == "list" && args[2] == "tables" {
		r.mu.Lock()
		tables := append([]nftTableTarget(nil), r.currentTables...)
		r.mu.Unlock()
		return nftTablesJSON(tables), nil
	}
	if len(args) == 4 && args[0] == "list" && args[1] == "table" {
		return []byte(fmt.Sprintf("table %s %s {\n}\n", args[2], args[3])), nil
	}
	if len(args) == 3 && args[0] == "-c" && args[1] == "-f" {
		content, err := readRootedNFTFile(args[2])
		if err != nil {
			return nil, err
		}
		r.mu.Lock()
		r.lastCandidate = string(content)
		err = r.checkErr
		r.mu.Unlock()
		if err != nil {
			return []byte(err.Error()), err
		}
		return nil, nil
	}
	if len(args) == 2 && args[0] == "-f" {
		content, err := readRootedNFTFile(args[1])
		if err != nil {
			return nil, err
		}
		if filepath.Base(args[1]) == "rollback.nft" {
			r.mu.Lock()
			r.rollbackApplyCalls++
			r.lastRollback = string(content)
			r.currentTables = append([]nftTableTarget(nil), r.initialTables...)
			r.mu.Unlock()
			return nil, nil
		}

		r.mu.Lock()
		r.mainApplyCalls++
		r.activeApplies++
		if r.activeApplies > r.maxActiveApplies {
			r.maxActiveApplies = r.activeApplies
		}
		applyErr := r.applyErr
		block := r.blockCandidateApply
		r.mu.Unlock()
		if block {
			select {
			case <-ctx.Done():
				applyErr = ctx.Err()
			case <-time.After(25 * time.Millisecond):
			}
		} else {
			time.Sleep(2 * time.Millisecond)
		}
		r.mu.Lock()
		r.activeApplies--
		if applyErr == nil {
			r.currentTables = expectedTableTargets(r.plan)
		}
		r.mu.Unlock()
		if applyErr != nil {
			return []byte(applyErr.Error()), applyErr
		}
		return nil, nil
	}
	if len(args) == 3 && args[0] == "-j" && args[1] == "list" && args[2] == "ruleset" {
		r.mu.Lock()
		err := r.verificationErr
		gap := r.verificationCountGap
		if len(r.rulesetDocuments) > 0 {
			index := r.rulesetCalls
			if index >= len(r.rulesetDocuments) {
				index = len(r.rulesetDocuments) - 1
			}
			document := append([]byte(nil), r.rulesetDocuments[index]...)
			r.rulesetCalls++
			r.mu.Unlock()
			return document, nil
		}
		r.mu.Unlock()
		if err != nil {
			return []byte(err.Error()), err
		}
		return nftVerificationJSON(r.plan, gap), nil
	}
	return nil, fmt.Errorf("unexpected nft invocation: %s", strings.Join(args, " "))
}

func TestNftablesTransactionPreflightPreservesPreviousState_SW_FW_001(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "invalid syntax", err: errors.New("syntax error")},
		{name: "missing interface", err: errors.New("No such device")},
	} {
		t.Run(test.name, func(t *testing.T) {
			stateDirectory := t.TempDir()
			statePath := filepath.Join(stateDirectory, "syswarden.nft")
			if err := os.WriteFile(statePath, []byte("known-good\n"), 0600); err != nil {
				t.Fatal(err)
			}
			plan := minimalVerificationPlan(0)
			runner := newFakeNFTRunner(plan, nftTableTarget{family: "inet", name: "syswarden"})
			runner.checkErr = test.err
			_, err := applyNftablesTransaction(context.Background(), runner, stateDirectory, minimalNftRules(), nil, plan)
			if err == nil || !strings.Contains(err.Error(), "preserved the previous ruleset") {
				t.Fatalf("transaction error = %v, want explicit preserved-state error", err)
			}
			if runner.mainApplyCalls != 0 || runner.rollbackApplyCalls != 0 {
				t.Fatalf("apply calls = %d, rollback calls = %d after preflight failure", runner.mainApplyCalls, runner.rollbackApplyCalls)
			}
			content, readErr := readRootedNFTFile(statePath)
			if readErr != nil || string(content) != "known-good\n" {
				t.Fatalf("persistent state changed after preflight failure: %q, %v", content, readErr)
			}
		})
	}
}

func TestNftablesTransactionAtomicApplyFailureDoesNotRollback_SW_FW_001(t *testing.T) {
	stateDirectory := t.TempDir()
	statePath := filepath.Join(stateDirectory, "syswarden.nft")
	if err := os.WriteFile(statePath, []byte("known-good\n"), 0600); err != nil {
		t.Fatal(err)
	}
	plan := minimalVerificationPlan(0)
	runner := newFakeNFTRunner(plan, nftTableTarget{family: "inet", name: "syswarden"})
	runner.applyErr = errors.New("netlink transaction failed")
	_, err := applyNftablesTransaction(context.Background(), runner, stateDirectory, minimalNftRules(), nil, plan)
	if err == nil {
		t.Fatal("transaction unexpectedly succeeded")
	}
	if runner.mainApplyCalls != 1 || runner.rollbackApplyCalls != 0 {
		t.Fatalf("apply calls = %d, rollback calls = %d, want 1/0", runner.mainApplyCalls, runner.rollbackApplyCalls)
	}
	content, readErr := readRootedNFTFile(statePath)
	if readErr != nil || string(content) != "known-good\n" {
		t.Fatalf("persistent state changed after apply failure: %q, %v", content, readErr)
	}
}

func TestNftablesTransactionPopulationMismatchRollsBack_SW_FW_002(t *testing.T) {
	stateDirectory := t.TempDir()
	plan := minimalVerificationPlan(2)
	runner := newFakeNFTRunner(plan)
	runner.verificationCountGap = -1
	populations := []nftSetPopulation{{name: "fixture_set", entries: []string{"192.0.2.1", "192.0.2.2"}}}
	_, err := applyNftablesTransaction(context.Background(), runner, stateDirectory, minimalNftRules(), populations, plan)
	if err == nil || !strings.Contains(err.Error(), "contains 1 elements, expected 2") {
		t.Fatalf("transaction error = %v, want exact cardinality mismatch", err)
	}
	if runner.rollbackApplyCalls != 1 {
		t.Fatalf("rollback calls = %d, want 1 after post-apply verification failure", runner.rollbackApplyCalls)
	}
	if _, statErr := os.Stat(filepath.Join(stateDirectory, "syswarden.nft")); !os.IsNotExist(statErr) {
		t.Fatalf("unverified persistent ruleset was published: %v", statErr)
	}
}

func TestNftablesVerificationAllowsConcurrentDynamicBans_SW_FW_001(t *testing.T) {
	plan := minimalVerificationPlan(0)
	plan.sets[nftObjectKey{family: "inet", table: "syswarden", name: "banned_ips"}] = -1
	runner := newFakeNFTRunner(plan)
	if err := verifyNftablesState(context.Background(), runner, plan); err != nil {
		t.Fatalf("dynamic ban population caused a false reload failure: %v", err)
	}
}

func TestNftablesTransactionAtomicTimeoutDoesNotRollback_SW_FW_001(t *testing.T) {
	stateDirectory := t.TempDir()
	plan := minimalVerificationPlan(0)
	runner := newFakeNFTRunner(plan)
	runner.blockCandidateApply = true
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	_, err := applyNftablesTransaction(ctx, runner, stateDirectory, minimalNftRules(), nil, plan)
	if err == nil || !strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("transaction error = %v, want deadline error", err)
	}
	if runner.rollbackApplyCalls != 0 {
		t.Fatalf("rollback calls = %d, want 0 after failed atomic apply", runner.rollbackApplyCalls)
	}
}

func TestNftablesConcurrentReloadsAreSerialized_SW_FW_001(t *testing.T) {
	stateDirectory := t.TempDir()
	plan := minimalVerificationPlan(0)
	runner := newFakeNFTRunner(plan)
	const reloads = 12
	errorsChannel := make(chan error, reloads)
	var wait sync.WaitGroup
	for range reloads {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := applyNftablesTransaction(context.Background(), runner, stateDirectory, minimalNftRules(), nil, plan)
			errorsChannel <- err
		}()
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			t.Fatal(err)
		}
	}
	if runner.maxActiveApplies != 1 {
		t.Fatalf("maximum concurrent kernel applies = %d, want 1", runner.maxActiveApplies)
	}
	if runner.mainApplyCalls != reloads {
		t.Fatalf("kernel applies = %d, want %d", runner.mainApplyCalls, reloads)
	}
	info, err := os.Stat(filepath.Join(stateDirectory, "syswarden.nft"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("published ruleset mode = %04o, want 0600", info.Mode().Perm())
	}
}

func TestNftablesRuntimeLockRejectsSymlink_SW_FW_001(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, nil, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "firewall.lock")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if lock, err := openNFTReloadLock(link); err == nil {
		closeNFTReloadLock(lock)
		t.Fatal("reload lock followed a symbolic link")
	}
}

func TestNftablesTransactionPreservesDynamicBansAndRemainingExpiry_SW_FW_001(t *testing.T) {
	stateDirectory := t.TempDir()
	plan := minimalVerificationPlan(0)
	plan.tables[nftObjectKey{family: "netdev", name: "syswarden_hw_drop"}] = struct{}{}
	for _, key := range nftDynamicBanSets {
		plan.sets[key] = -1
	}
	runner := newFakeNFTRunner(plan,
		nftTableTarget{family: "inet", name: "syswarden"},
		nftTableTarget{family: "netdev", name: "syswarden_hw_drop"},
	)
	runner.rulesetDocuments = [][]byte{
		nftVerificationJSONWithDynamicBans(plan, time.Hour),
		nftVerificationJSONWithDynamicBans(plan, time.Hour-time.Second),
	}
	if _, err := applyNftablesTransaction(context.Background(), runner, stateDirectory, minimalNftRules(), nil, plan); err != nil {
		t.Fatalf("reload with active dynamic bans: %v", err)
	}
	for _, fragment := range []string{
		"add element inet syswarden banned_ips { 198.51.100.0-198.51.100.255 timeout 3600s expires",
		"add element inet syswarden banned_ips6 { 2001:db8::-2001:db8::ffff:ffff:ffff:ffff timeout 3600s expires",
		"add element netdev syswarden_hw_drop banned_ips { 198.51.100.0-198.51.100.255 timeout 3600s expires",
		"add element netdev syswarden_hw_drop banned_ips6 { 2001:db8::-2001:db8::ffff:ffff:ffff:ffff timeout 3600s expires",
		"203.0.113.9",
	} {
		if !strings.Contains(runner.lastCandidate, fragment) {
			t.Fatalf("candidate omitted preserved dynamic fragment %q:\n%s", fragment, runner.lastCandidate)
		}
	}
	if strings.Contains(runner.lastCandidate, "expires 3600s") {
		t.Fatalf("reload extended a one-hour ban instead of rounding remaining expiry down:\n%s", runner.lastCandidate)
	}
	persistent, err := readRootedNFTFile(filepath.Join(stateDirectory, "syswarden.nft"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(persistent, []byte("timeout 3600s")) || bytes.Contains(persistent, []byte("203.0.113.9")) {
		t.Fatalf("ephemeral dynamic bans leaked into reboot-persistent policy:\n%s", persistent)
	}
}

func TestNftablesRollbackPreservesDynamicBansWithoutExtendingExpiry_SW_FW_001(t *testing.T) {
	stateDirectory := t.TempDir()
	plan := minimalVerificationPlan(1)
	plan.tables[nftObjectKey{family: "netdev", name: "syswarden_hw_drop"}] = struct{}{}
	for _, key := range nftDynamicBanSets {
		plan.sets[key] = -1
	}
	badPlan := minimalVerificationPlan(0)
	badPlan.tables[nftObjectKey{family: "netdev", name: "syswarden_hw_drop"}] = struct{}{}
	for _, key := range nftDynamicBanSets {
		badPlan.sets[key] = -1
	}
	runner := newFakeNFTRunner(plan,
		nftTableTarget{family: "inet", name: "syswarden"},
		nftTableTarget{family: "netdev", name: "syswarden_hw_drop"},
	)
	runner.rulesetDocuments = [][]byte{
		nftVerificationJSONWithDynamicBans(plan, time.Hour),
		nftVerificationJSONWithDynamicBans(badPlan, time.Hour-2*time.Second),
	}
	_, err := applyNftablesTransaction(
		context.Background(),
		runner,
		stateDirectory,
		minimalNftRules(),
		[]nftSetPopulation{{name: "fixture_set", entries: []string{"192.0.2.1"}}},
		plan,
	)
	if err == nil || !strings.Contains(err.Error(), "contains 0 elements, expected 1") {
		t.Fatalf("transaction error = %v, want forced post-apply mismatch", err)
	}
	if runner.rollbackApplyCalls != 1 {
		t.Fatalf("rollback calls = %d, want 1", runner.rollbackApplyCalls)
	}
	if strings.Contains(runner.lastRollback, "expires 3600s") {
		t.Fatalf("rollback extended a captured one-hour ban:\n%s", runner.lastRollback)
	}
	if got := strings.Count(runner.lastRollback, "delete element "); got != 8 {
		t.Fatalf("rollback dynamic delete statements = %d, want 8:\n%s", got, runner.lastRollback)
	}
	if got := strings.Count(runner.lastRollback, "add element "); got != 8 {
		t.Fatalf("rollback dynamic add statements = %d, want 8:\n%s", got, runner.lastRollback)
	}
}

func TestPopulateSetAggregatesRequiredAndFamilyErrors_SW_FW_002(t *testing.T) {
	root := t.TempDir()
	empty := filepath.Join(root, "required-empty.ipv6")
	wrongFamily := filepath.Join(root, "wrong-family.ipv6")
	if err := os.WriteFile(empty, []byte("# empty\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wrongFamily, []byte("192.0.2.10\ninvalid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	population, err := populateSet(context.Background(), []nftListSource{
		{path: filepath.Join(root, "optional-missing.ipv6")},
		{path: empty, required: true},
		{path: wrongFamily, required: true},
	}, "fixture_set6")
	if err == nil {
		t.Fatal("populateSet() accepted empty, wrong-family and invalid required inputs")
	}
	for _, fragment := range []string{"contains no valid entries", "address family", "invalid IP address or CIDR"} {
		if !strings.Contains(err.Error(), fragment) {
			t.Fatalf("aggregated error %q does not contain %q", err, fragment)
		}
	}
	if len(population.entries) != 0 {
		t.Fatalf("invalid entries reached the candidate: %#v", population.entries)
	}
}

func TestApplyChunkPropagatesValidationErrors_SW_FW_002(t *testing.T) {
	var builder strings.Builder
	if err := applyChunk(&builder, "invalid set", []string{"192.0.2.1"}); err == nil {
		t.Fatal("applyChunk() accepted an unsafe set name")
	}
	if err := applyChunk(&builder, "fixture_set", []string{"192.0.2.1; drop table inet syswarden"}); err == nil {
		t.Fatal("applyChunk() accepted an injected element")
	}
}

func TestReservedNFTablesUninstallCleanupIsExactAndVerified_SW2_FWBACKEND_001(t *testing.T) {
	operatorTable := nftTableTarget{family: "inet", name: "operator_table"}
	runner := &fakeUninstallNFTRunner{
		tables:              append(append([]nftTableTarget(nil), syswardenNFTTables...), operatorTable),
		includeOperatorRule: true,
	}
	if err := cleanupReservedNFTablesForUninstall(context.Background(), runner); err != nil {
		t.Fatalf("cleanupReservedNFTablesForUninstall() error = %v", err)
	}
	if !reflect.DeepEqual(runner.deleteCalls, syswardenNFTTables) {
		t.Fatalf("delete calls = %#v, want %#v", runner.deleteCalls, syswardenNFTTables)
	}
	if !reflect.DeepEqual(runner.tables, []nftTableTarget{operatorTable}) {
		t.Fatalf("remaining tables = %#v, want only operator table", runner.tables)
	}
}

func TestReservedNFTablesUninstallCleanupFailsClosed_SW2_FWBACKEND_001(t *testing.T) {
	target := reservedNFTTablesForUninstall[0]
	tests := []struct {
		name            string
		runner          *fakeUninstallNFTRunner
		wantDeleteCalls int
	}{
		{
			name:            "ruleset inventory failure",
			runner:          &fakeUninstallNFTRunner{rulesetErr: errors.New("ruleset unavailable")},
			wantDeleteCalls: 0,
		},
		{
			name: "unowned legacy WireGuard rule",
			runner: &fakeUninstallNFTRunner{
				legacyHandles: []uint64{31},
			},
			wantDeleteCalls: 0,
		},
		{
			name: "unowned reserved WireGuard table",
			runner: &fakeUninstallNFTRunner{
				tables: []nftTableTarget{{family: "inet", name: "syswarden_wg"}},
			},
			wantDeleteCalls: 0,
		},
		{
			name:            "inventory failure",
			runner:          &fakeUninstallNFTRunner{listErr: errors.New("inventory unavailable")},
			wantDeleteCalls: 0,
		},
		{
			name: "delete failure",
			runner: &fakeUninstallNFTRunner{
				tables:    []nftTableTarget{target},
				deleteErr: map[nftTableTarget]error{target: errors.New("delete denied")},
			},
			wantDeleteCalls: 1,
		},
		{
			name: "residual table",
			runner: &fakeUninstallNFTRunner{
				tables: []nftTableTarget{target},
				retain: map[nftTableTarget]bool{target: true},
			},
			wantDeleteCalls: 1,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := cleanupReservedNFTablesForUninstall(context.Background(), test.runner); err == nil {
				t.Fatal("cleanupReservedNFTablesForUninstall() unexpectedly succeeded")
			}
			if got := len(test.runner.deleteCalls); got != test.wantDeleteCalls {
				t.Fatalf("delete calls = %d, want %d", got, test.wantDeleteCalls)
			}
		})
	}
}

func TestUninstallFirewallCleanupIsBracketedByServiceReattestation_SW2_FWBACKEND_001(t *testing.T) {
	previousUID := firewallCleanupEffectiveUserID
	previousReattest := firewallRemovalServiceReattest
	previousWrapperCleanup := applyLinuxFirewallWrappersForUninstall
	previousRunnerFactory := uninstallNFTRunnerFactory
	t.Cleanup(func() {
		firewallCleanupEffectiveUserID = previousUID
		firewallRemovalServiceReattest = previousReattest
		applyLinuxFirewallWrappersForUninstall = previousWrapperCleanup
		uninstallNFTRunnerFactory = previousRunnerFactory
	})

	var order []string
	reattestCalls := 0
	firewallCleanupEffectiveUserID = func() int { return 0 }
	firewallRemovalServiceReattest = func() error {
		reattestCalls++
		order = append(order, fmt.Sprintf("reattest-%d", reattestCalls))
		return nil
	}
	applyLinuxFirewallWrappersForUninstall = func(_, _ []string) error {
		order = append(order, "wrapper-cleanup")
		return nil
	}
	uninstallNFTRunnerFactory = func() (nftCommandRunner, error) {
		order = append(order, "nft-cleanup")
		return &fakeUninstallNFTRunner{}, nil
	}

	if err := CleanupOwnedCompatibilityRulesForUninstall(); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(order, ","); got != "reattest-1,wrapper-cleanup,nft-cleanup,reattest-2" {
		t.Fatalf("cleanup order = %q", got)
	}
}

func TestExecNFTRunnerUsesPinnedTrustedPathAndMinimalEnvironment_SW2_FWBACKEND_001(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nft-fixture")
	content := "#!/bin/sh\nprintf '%s\\n' \"${LD_PRELOAD-unset}|${PYTHONPATH-unset}|${LC_ALL-unset}|${PATH-unset}\"\n"
	if err := os.WriteFile(path, []byte(content), 0700); err != nil {
		t.Fatal(err)
	}
	previousLookPath := nftExecutableLookPath
	previousValidator := nftExecutableValidator
	nftExecutableLookPath = func(name string) (string, error) {
		if name != "nft" {
			t.Fatalf("lookup name = %q, want nft", name)
		}
		return path, nil
	}
	nftExecutableValidator = validateTestLinuxWrapperExecutable
	t.Cleanup(func() {
		nftExecutableLookPath = previousLookPath
		nftExecutableValidator = previousValidator
	})

	runner, err := newExecNFTCommandRunner()
	if err != nil {
		t.Fatal(err)
	}
	output, err := runner.Run(context.Background(), nil, "-j", "list", "tables")
	if err != nil {
		t.Fatal(err)
	}
	want := "unset|unset|C|/usr/sbin:/usr/bin:/sbin:/bin\n"
	if string(output) != want {
		t.Fatalf("nft child environment = %q, want %q", output, want)
	}
}

func TestExecNFTRunnerReattestsExecutableAndBoundsOutput_SW2_FWBACKEND_001(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nft-fixture")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf '123456789'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	previousValidator := nftExecutableValidator
	previousLimit := nftCommandOutputLimit
	t.Cleanup(func() {
		nftExecutableValidator = previousValidator
		nftCommandOutputLimit = previousLimit
	})

	sentinel := errors.New("executable identity changed")
	nftExecutableValidator = func(string) error { return sentinel }
	if _, err := (execNFTCommandRunner{path: path}).Run(context.Background(), nil, "-j", "list", "tables"); err == nil || !errors.Is(err, sentinel) {
		t.Fatalf("nft executable reattestation error = %v", err)
	}

	nftExecutableValidator = validateTestLinuxWrapperExecutable
	nftCommandOutputLimit = 4
	output, err := (execNFTCommandRunner{path: path}).Run(context.Background(), nil, "-j", "list", "tables")
	if err == nil || !strings.Contains(err.Error(), "output exceeds 4 bytes") {
		t.Fatalf("bounded nft output error = %v", err)
	}
	if string(output) != "1234" {
		t.Fatalf("bounded nft output = %q, want 1234", output)
	}
}

func minimalVerificationPlan(elementCount int) nftVerificationPlan {
	return nftVerificationPlan{
		tables: map[nftObjectKey]struct{}{{family: "inet", name: "syswarden"}: {}},
		chains: map[nftObjectKey]string{{family: "inet", table: "syswarden", name: "input"}: "input"},
		sets:   map[nftObjectKey]int{{family: "inet", table: "syswarden", name: "fixture_set"}: elementCount},
	}
}

func minimalNftRules() string {
	return "table inet syswarden {\n\tset fixture_set { type ipv4_addr; }\n\tchain input { type filter hook input priority 0; }\n}\n"
}

func expectedTableTargets(plan nftVerificationPlan) []nftTableTarget {
	targets := make([]nftTableTarget, 0, len(plan.tables))
	for key := range plan.tables {
		targets = append(targets, nftTableTarget{family: key.family, name: key.name})
	}
	return targets
}

func nftTablesJSON(tables []nftTableTarget) []byte {
	entries := make([]map[string]any, 0, len(tables))
	for _, table := range tables {
		entries = append(entries, map[string]any{"table": map[string]any{"family": table.family, "name": table.name}})
	}
	content, _ := json.Marshal(map[string]any{"nftables": entries})
	return content
}

func nftLegacyWireGuardRulesJSON(handles []uint64, includeOperatorRule bool) []byte {
	entries := make([]map[string]any, 0, len(handles)+1)
	for index, handle := range handles {
		key := "iifname"
		if index%2 == 1 {
			key = "oifname"
		}
		entries = append(entries, map[string]any{"rule": map[string]any{
			"family": "inet",
			"table":  "filter",
			"chain":  "forward",
			"handle": handle,
			"expr": []any{
				map[string]any{"match": map[string]any{
					"op":    "==",
					"left":  map[string]any{"meta": map[string]any{"key": key}},
					"right": "wg-syswarden",
				}},
				map[string]any{"accept": nil},
			},
		}})
	}
	if includeOperatorRule {
		entries = append(entries, map[string]any{"rule": map[string]any{
			"family": "inet",
			"table":  "filter",
			"chain":  "forward",
			"handle": uint64(9000),
			"expr": []any{
				map[string]any{"match": map[string]any{
					"op":    "==",
					"left":  map[string]any{"meta": map[string]any{"key": "iifname"}},
					"right": "operator0",
				}},
				map[string]any{"accept": nil},
			},
		}})
	}
	content, _ := json.Marshal(map[string]any{"nftables": entries})
	return content
}

func nftVerificationJSON(plan nftVerificationPlan, countGap int) []byte {
	entries := make([]map[string]any, 0, len(plan.tables)+len(plan.chains)+len(plan.sets))
	for key := range plan.tables {
		entries = append(entries, map[string]any{"table": map[string]any{"family": key.family, "name": key.name}})
	}
	for key, hook := range plan.chains {
		entries = append(entries, map[string]any{"chain": map[string]any{
			"family": key.family, "table": key.table, "name": key.name, "hook": hook,
		}})
	}
	gapApplied := false
	for key, count := range plan.sets {
		reportedCount := count
		if reportedCount < 0 {
			reportedCount = 3
		}
		if countGap != 0 && !gapApplied && count >= 0 {
			reportedCount += countGap
			if reportedCount < 0 {
				reportedCount = 0
			}
			gapApplied = true
		}
		elements := make([]any, reportedCount)
		for index := range elements {
			elements[index] = fmt.Sprintf("element-%d", index)
		}
		entries = append(entries, map[string]any{"set": map[string]any{
			"family": key.family, "table": key.table, "name": key.name, "elem": elements,
		}})
	}
	content, _ := json.Marshal(map[string]any{"nftables": entries})
	return content
}

func nftVerificationJSONWithDynamicBans(plan nftVerificationPlan, expires time.Duration) []byte {
	var document struct {
		NFTables []map[string]any `json:"nftables"`
	}
	if err := json.Unmarshal(nftVerificationJSON(plan, 0), &document); err != nil {
		panic(err)
	}
	for _, entry := range document.NFTables {
		set, ok := entry["set"].(map[string]any)
		if !ok {
			continue
		}
		name, _ := set["name"].(string)
		if name == "banned_ips" || name == "banned_ips6" {
			set["elem"] = []any{}
		}
	}
	for _, key := range nftDynamicBanSets {
		var timedValue any = map[string]any{"prefix": map[string]any{"addr": "198.51.100.0", "len": 24}}
		permanentValue := "203.0.113.9"
		if strings.HasSuffix(key.name, "6") {
			timedValue = map[string]any{"prefix": map[string]any{"addr": "2001:db8::", "len": 64}}
			permanentValue = "2001:db8:ffff::9"
		}
		document.NFTables = append(document.NFTables, map[string]any{"element": map[string]any{
			"family": key.family,
			"table":  key.table,
			"name":   key.name,
			"elem": []any{
				permanentValue,
				map[string]any{"elem": map[string]any{
					"val":     timedValue,
					"timeout": int64(time.Hour / time.Millisecond),
					"expires": int64(expires / time.Millisecond),
				}},
			},
		}})
	}
	content, _ := json.Marshal(document)
	return content
}
