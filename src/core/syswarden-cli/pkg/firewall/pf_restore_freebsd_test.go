//go:build freebsd

package firewall

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"syswarden-cli/config"
)

func readPFTestFile(t *testing.T, path string) []byte {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	content, err := root.ReadFile(filepath.Base(path))
	if err != nil {
		t.Fatal(err)
	}
	return content
}

type pfSnapshotTestState struct {
	root        string
	logPath     string
	statePath   string
	rulesPath   string
	natPath     string
	tablesPath  string
	entriesPath string
	statesPath  string
	modulePath  string
	sourcePath  string
}

func preparePFSnapshotTest(t *testing.T, configuredStatus, runtimeStatus string) pfSnapshotTestState {
	t.Helper()
	root := t.TempDir()
	tools := filepath.Join(root, "tools")
	if err := os.Mkdir(tools, 0750); err != nil {
		t.Fatal(err)
	}
	state := pfSnapshotTestState{
		root:        root,
		logPath:     filepath.Join(root, "pfctl.log"),
		statePath:   filepath.Join(root, "pf-state"),
		rulesPath:   filepath.Join(root, "pf-rules"),
		natPath:     filepath.Join(root, "pf-nat"),
		tablesPath:  filepath.Join(root, "pf-tables"),
		entriesPath: filepath.Join(root, "pf-table-entries"),
		statesPath:  filepath.Join(root, "pf-states"),
		modulePath:  filepath.Join(root, "pf-module-state"),
		sourcePath:  filepath.Join(root, "operator-pf.conf"),
	}
	for path, content := range map[string]string{
		state.statePath:   runtimeStatus + "\n",
		state.rulesPath:   "pass in on vtnet0\n",
		state.natPath:     "nat on vtnet0 from 10.0.0.0/24 to any -> 192.0.2.1\n",
		state.tablesPath:  "operator_allow\n",
		state.entriesPath: "198.51.100.40\n2001:db8::40\n",
		state.statesPath:  "all tcp 192.0.2.10:22 <- 198.51.100.10:50000 ESTABLISHED:ESTABLISHED\n",
		state.modulePath:  string(PFInitialKernelAvailable) + "\n",
		state.sourcePath:  "pass in on vtnet0\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeFreeBSDExecutable(t, filepath.Join(tools, "sysrc"), `#!/bin/sh
if [ "$1" = "-n" ] && [ "$2" = "pf_enable" ]; then
    printf '%s\n' "$SYSWARDEN_TEST_PF_ENABLE"
    exit 0
fi
if [ "$1" = "-n" ] && [ "$2" = "pf_rules" ]; then
    printf '%s\n' "$SYSWARDEN_TEST_PF_SOURCE"
    exit 0
fi
exit 1
`)
	writeFreeBSDExecutable(t, filepath.Join(tools, "pfctl"), `#!/bin/sh
printf '%s\n' "$*" >> "$SYSWARDEN_TEST_PF_LOG"
case "$*" in
    '-nf -')
        /bin/cat > "$SYSWARDEN_TEST_PF_VALIDATED"
		if [ "${SYSWARDEN_TEST_PF_DRIFT_AFTER_VALIDATE:-0}" = states ]; then
			printf '%s\n' 'all tcp 203.0.113.10:22 <- 198.51.100.10:50000 ESTABLISHED:ESTABLISHED' > "$SYSWARDEN_TEST_PF_STATES"
		fi
        if [ "${SYSWARDEN_TEST_PF_BLOCK_MARKER:-0}" = 1 ]; then
			: > "$SYSWARDEN_TEST_PF_SNAPSHOT_TMP"
		fi
        [ "${SYSWARDEN_TEST_PF_VALIDATE_FAIL:-0}" = 0 ]
        ;;
    '-f -')
        /bin/cat > "$SYSWARDEN_TEST_PF_LOADED"
        : > "$SYSWARDEN_TEST_PF_RULES"
        : > "$SYSWARDEN_TEST_PF_NAT"
        : > "$SYSWARDEN_TEST_PF_TABLES"
        while IFS= read -r line; do
            case "$line" in
                table\ \<*\>\ persist)
                    printf '%s\n' "$line" | /usr/bin/sed -n 's/^table <\([^>]*\)> persist$/\1/p' >> "$SYSWARDEN_TEST_PF_TABLES"
                    ;;
                nat\ *) printf '%s\n' "$line" >> "$SYSWARDEN_TEST_PF_NAT" ;;
                '') ;;
                *) printf '%s\n' "$line" >> "$SYSWARDEN_TEST_PF_RULES" ;;
            esac
        done < "$SYSWARDEN_TEST_PF_LOADED"
        ;;
    '-s info') printf 'Status: %s\n' "$(/bin/cat "$SYSWARDEN_TEST_PF_STATE")" ;;
    '-sr') /bin/cat "$SYSWARDEN_TEST_PF_RULES" ;;
    '-sn') /bin/cat "$SYSWARDEN_TEST_PF_NAT" ;;
	'-s Tables') /bin/cat "$SYSWARDEN_TEST_PF_TABLES" ;;
	'-s Anchors') : ;;
	'-ss') /bin/cat "$SYSWARDEN_TEST_PF_STATES" ;;
	'-F all')
		[ "${SYSWARDEN_TEST_PF_FLUSH_FAIL:-0}" = 0 ] || exit 1
		: > "$SYSWARDEN_TEST_PF_RULES"
		: > "$SYSWARDEN_TEST_PF_NAT"
		: > "$SYSWARDEN_TEST_PF_TABLES"
		: > "$SYSWARDEN_TEST_PF_ENTRIES"
		: > "$SYSWARDEN_TEST_PF_STATES"
		;;
    '-e') printf 'Enabled\n' > "$SYSWARDEN_TEST_PF_STATE" ;;
    '-d') printf 'Disabled\n' > "$SYSWARDEN_TEST_PF_STATE" ;;
    *) exit 91 ;;
esac
`)
	writeFreeBSDExecutable(t, filepath.Join(tools, "kldstat"), `#!/bin/sh
if [ "$*" = "-q -m pf" ]; then
    exit "${SYSWARDEN_TEST_KLDSTAT_RC:-0}"
fi
exit 92
`)
	writeFreeBSDExecutable(t, filepath.Join(tools, "kldload"), `#!/bin/sh
printf '%s\n' "$*" >> "$SYSWARDEN_TEST_KLD_LOG"
[ "$*" = "-n -q pf" ] || exit 93
[ -f "$SYSWARDEN_TEST_PF_SNAPSHOT" ] || exit 94
[ "${SYSWARDEN_TEST_KLDLOAD_RC:-0}" = 0 ] || exit "$SYSWARDEN_TEST_KLDLOAD_RC"
printf '%s\n' available > "$SYSWARDEN_TEST_PF_MODULE_STATE"
`)
	writeFreeBSDExecutable(t, filepath.Join(tools, "kldunload"), `#!/bin/sh
printf '%s\n' "$*" >> "$SYSWARDEN_TEST_KLD_LOG"
[ "$*" = "-n pf" ] || exit 95
[ "${SYSWARDEN_TEST_KLDUNLOAD_RC:-0}" = 0 ] || exit "$SYSWARDEN_TEST_KLDUNLOAD_RC"
printf '%s\n' module_absent > "$SYSWARDEN_TEST_PF_MODULE_STATE"
`)
	writeFreeBSDExecutable(t, filepath.Join(tools, "route"), `#!/bin/sh
printf '%s\n' '   route to: default' '  interface: vtnet-test0'
`)
	writeFreeBSDExecutable(t, filepath.Join(tools, "sockstat"), `#!/bin/sh
printf '%s\n' 'USER COMMAND PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS'
`)
	t.Setenv("PATH", tools)
	t.Setenv("SYSWARDEN_TEST_PF_ENABLE", configuredStatus)
	t.Setenv("SYSWARDEN_TEST_PF_SOURCE", state.sourcePath)
	t.Setenv("SYSWARDEN_TEST_PF_LOG", state.logPath)
	t.Setenv("SYSWARDEN_TEST_PF_STATE", state.statePath)
	t.Setenv("SYSWARDEN_TEST_PF_RULES", state.rulesPath)
	t.Setenv("SYSWARDEN_TEST_PF_NAT", state.natPath)
	t.Setenv("SYSWARDEN_TEST_PF_TABLES", state.tablesPath)
	t.Setenv("SYSWARDEN_TEST_PF_ENTRIES", state.entriesPath)
	t.Setenv("SYSWARDEN_TEST_PF_STATES", state.statesPath)
	t.Setenv("SYSWARDEN_TEST_PF_MODULE_STATE", state.modulePath)
	t.Setenv("SYSWARDEN_TEST_PF_VALIDATED", filepath.Join(root, "validated.pf"))
	t.Setenv("SYSWARDEN_TEST_PF_LOADED", filepath.Join(root, "loaded.pf"))
	t.Setenv("SYSWARDEN_TEST_KLD_LOG", filepath.Join(root, "kld.log"))
	originalSnapshotDirectory := pfSnapshotDirectory
	originalSnapshotName := pfSnapshotName
	originalOwner := pfExpectedOwner
	originalLock := pfRuntimeLockPath
	originalDynamicRunner := runDynamicPFCommand
	originalControlDevice := pfControlDevicePath
	originalPFCTLCommand := newPFCTLCommand
	originalSysrcCommand := newPFSysrcCommand
	originalKLDStatCommand := newPFKLDStatCommand
	originalKLDLoadCommand := newPFKLDLoadCommand
	originalKLDUnloadCommand := newPFKLDUnloadCommand
	originalInspectKernelState := inspectPFKernelState
	pfSnapshotDirectory = filepath.Join(root, "snapshot")
	pfSnapshotName = "pf-policy-snapshot.json"
	pfExpectedOwner = os.Geteuid
	pfRuntimeLockPath = filepath.Join(root, "syswarden-firewall.lock")
	pfControlDevicePath = "/dev/null"
	t.Setenv("SYSWARDEN_TEST_PF_SNAPSHOT", filepath.Join(pfSnapshotDirectory, pfSnapshotName))
	t.Setenv("SYSWARDEN_TEST_PF_SNAPSHOT_TMP", filepath.Join(pfSnapshotDirectory, pfSnapshotTemporaryName))
	newPFCTLCommand = func(arguments ...string) *exec.Cmd {
		return exec.Command(filepath.Join(tools, "pfctl"), arguments...) // #nosec G204 -- executable is an owner-only fixture rooted in t.TempDir
	}
	newPFSysrcCommand = func(arguments ...string) *exec.Cmd {
		return exec.Command(filepath.Join(tools, "sysrc"), arguments...) // #nosec G204 -- executable is an owner-only fixture rooted in t.TempDir
	}
	newPFKLDStatCommand = func(arguments ...string) *exec.Cmd {
		return exec.Command(filepath.Join(tools, "kldstat"), arguments...) // #nosec G204 -- executable is an owner-only fixture rooted in t.TempDir
	}
	newPFKLDLoadCommand = func(arguments ...string) *exec.Cmd {
		return exec.Command(filepath.Join(tools, "kldload"), arguments...) // #nosec G204 -- executable is an owner-only fixture rooted in t.TempDir
	}
	newPFKLDUnloadCommand = func(arguments ...string) *exec.Cmd {
		return exec.Command(filepath.Join(tools, "kldunload"), arguments...) // #nosec G204 -- executable is an owner-only fixture rooted in t.TempDir
	}
	inspectPFKernelState = func() (PFInitialKernelState, error) {
		content, err := os.ReadFile(state.modulePath)
		if err != nil {
			return "", err
		}
		switch PFInitialKernelState(strings.TrimSpace(string(content))) {
		case PFInitialKernelAvailable:
			return PFInitialKernelAvailable, nil
		case PFInitialKernelModuleAbsent:
			return PFInitialKernelModuleAbsent, nil
		default:
			return "", fmt.Errorf("invalid test PF module state %q", strings.TrimSpace(string(content)))
		}
	}
	runDynamicPFCommand = func(operation pfDynamicOperation, anchor, table string, input []byte) ([]byte, error) {
		if anchor != "" {
			return nil, nil
		}
		switch operation {
		case pfDynamicTableShow:
			return os.ReadFile(state.entriesPath)
		case pfDynamicTableReplace:
			return nil, os.WriteFile(state.entriesPath, input, 0600)
		default:
			return nil, nil
		}
	}
	t.Cleanup(func() {
		pfSnapshotDirectory = originalSnapshotDirectory
		pfSnapshotName = originalSnapshotName
		pfExpectedOwner = originalOwner
		pfRuntimeLockPath = originalLock
		runDynamicPFCommand = originalDynamicRunner
		pfControlDevicePath = originalControlDevice
		newPFCTLCommand = originalPFCTLCommand
		newPFSysrcCommand = originalSysrcCommand
		newPFKLDStatCommand = originalKLDStatCommand
		newPFKLDLoadCommand = originalKLDLoadCommand
		newPFKLDUnloadCommand = originalKLDUnloadCommand
		inspectPFKernelState = originalInspectKernelState
	})
	return state
}

func mutatePFState(t *testing.T, state pfSnapshotTestState) {
	t.Helper()
	for path, content := range map[string]string{
		state.statePath:   "Enabled\n",
		state.rulesPath:   "block from <syswarden_blacklist>\n",
		state.natPath:     "nat from <banned_ips>\n",
		state.tablesPath:  "syswarden_blacklist\nbanned_ips\n",
		state.entriesPath: "203.0.113.99\n",
		state.statesPath:  "all tcp 203.0.113.99:62027 <- 198.51.100.50:40000 ESTABLISHED:ESTABLISHED\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func emptyPFState(t *testing.T, state pfSnapshotTestState) {
	t.Helper()
	for _, path := range []string{state.rulesPath, state.natPath, state.tablesPath, state.entriesPath, state.statesPath} {
		if err := os.WriteFile(path, nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func setPFModuleState(t *testing.T, state pfSnapshotTestState, moduleState PFInitialKernelState) {
	t.Helper()
	if err := os.WriteFile(state.modulePath, []byte(moduleState+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
}

func setMinimalPFApplyConfig(t *testing.T) {
	t.Helper()
	previous := config.GlobalConfig
	t.Cleanup(func() { config.GlobalConfig = previous })
	config.GlobalConfig = &config.Config{SSHPort: "2222"}
}

func snapshotExists(t *testing.T) bool {
	t.Helper()
	_, err := os.Lstat(filepath.Join(pfSnapshotDirectory, pfSnapshotName))
	if err == nil {
		return true
	}
	if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return false
}

func optionalPFTestFile(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path) // #nosec G304 -- every caller supplies a path rooted in this test's t.TempDir
	if err == nil {
		return string(content)
	}
	if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return ""
}

func TestExactLivePFSnapshotRejectsNonEmptyOrEnabledHostBeforeMutation(t *testing.T) {
	state := preparePFSnapshotTest(t, "NO", "Enabled")
	if err := CapturePFPolicySnapshot(PFSnapshotExactLive); err == nil ||
		!strings.Contains(err.Error(), "disabled empty host policy") {
		t.Fatalf("non-empty enabled PF host was not rejected explicitly: %v", err)
	}
	if got := string(readPFTestFile(t, state.rulesPath)); got != "pass in on vtnet0\n" {
		t.Fatalf("rejected capture mutated live PF rules: %q", got)
	}
}

func TestExactLivePFSnapshotRejectsNonEmptyStateTable(t *testing.T) {
	state := preparePFSnapshotTest(t, "NO", "Disabled")
	for _, path := range []string{state.rulesPath, state.natPath, state.tablesPath, state.entriesPath} {
		if err := os.WriteFile(path, nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := CapturePFPolicySnapshot(PFSnapshotExactLive); err == nil ||
		!strings.Contains(err.Error(), "state table") {
		t.Fatalf("non-empty PF state table was not rejected explicitly: %v", err)
	}
	if snapshotExists(t) {
		t.Fatal("rejected state-table capture published a snapshot")
	}
}

func TestExactAbsentPFSnapshotNeverLoadsOrInvokesPFCTL(t *testing.T) {
	state := preparePFSnapshotTest(t, "NO", "Disabled")
	setPFModuleState(t, state, PFInitialKernelModuleAbsent)
	if err := CapturePFPolicySnapshot(PFSnapshotExactLive); err != nil {
		t.Fatal(err)
	}
	snapshot, err := readPFSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.SchemaVersion != 2 || snapshot.InitialKernelState != PFInitialKernelModuleAbsent ||
		snapshot.ConfiguredStatus != "Disabled" || snapshot.RuntimeStatus != "Disabled" ||
		snapshot.MutationStarted || !emptyPFLivePolicy(snapshot.LivePolicy) {
		t.Fatalf("absent PF baseline was not encoded exactly: %+v", snapshot)
	}
	if got := optionalPFTestFile(t, state.logPath); got != "" {
		t.Fatalf("absent PF capture invoked pfctl:\n%s", got)
	}
	if got := optionalPFTestFile(t, filepath.Join(state.root, "kld.log")); got != "" {
		t.Fatalf("absent PF capture loaded a module:\n%s", got)
	}
	if err := RestorePersistedPFPolicy(); err != nil {
		t.Fatal(err)
	}
	if snapshotExists(t) {
		t.Fatal("consumed absent PF snapshot remains")
	}
	if got := optionalPFTestFile(t, state.logPath); got != "" {
		t.Fatalf("absent never-loaded restore invoked pfctl:\n%s", got)
	}
	if got := optionalPFTestFile(t, filepath.Join(state.root, "kld.log")); got != "" {
		t.Fatalf("absent never-loaded restore changed the module:\n%s", got)
	}
}

func TestExactAbsentPFSnapshotRejectsConfiguredEnabled(t *testing.T) {
	state := preparePFSnapshotTest(t, "YES", "Disabled")
	setPFModuleState(t, state, PFInitialKernelModuleAbsent)
	if err := CapturePFPolicySnapshot(PFSnapshotExactLive); err == nil ||
		!strings.Contains(err.Error(), "absent while configured PF is enabled") {
		t.Fatalf("enabled configured state with absent module was not rejected: %v", err)
	}
	if snapshotExists(t) {
		t.Fatal("inconsistent absent/enabled capture published a snapshot")
	}
	if got := optionalPFTestFile(t, state.logPath); got != "" {
		t.Fatalf("inconsistent absent/enabled capture invoked pfctl:\n%s", got)
	}
}

func TestPFKernelStateDriftBeforeMutationIsRejected(t *testing.T) {
	t.Run("absent baseline becomes available", func(t *testing.T) {
		state := preparePFSnapshotTest(t, "NO", "Disabled")
		setPFModuleState(t, state, PFInitialKernelModuleAbsent)
		if err := CapturePFPolicySnapshot(PFSnapshotExactLive); err != nil {
			t.Fatal(err)
		}
		setPFModuleState(t, state, PFInitialKernelAvailable)
		if err := ensurePFKernelReadyForMutationLocked(); err == nil ||
			!strings.Contains(err.Error(), "changed before the first policy mutation") {
			t.Fatalf("absent-to-available drift was not rejected: %v", err)
		}
	})
	t.Run("available baseline disappears", func(t *testing.T) {
		state := preparePFSnapshotTest(t, "NO", "Disabled")
		emptyPFState(t, state)
		if err := CapturePFPolicySnapshot(PFSnapshotExactLive); err != nil {
			t.Fatal(err)
		}
		setPFModuleState(t, state, PFInitialKernelModuleAbsent)
		if err := ensurePFKernelReadyForMutationLocked(); err == nil ||
			!strings.Contains(err.Error(), "changed before the first policy mutation") {
			t.Fatalf("available-to-absent drift was not rejected: %v", err)
		}
	})
}

func TestCandidateValidationFailureAfterModuleLoadRollsBackModule(t *testing.T) {
	state := preparePFSnapshotTest(t, "NO", "Disabled")
	emptyPFState(t, state)
	setPFModuleState(t, state, PFInitialKernelModuleAbsent)
	setMinimalPFApplyConfig(t)
	t.Setenv("SYSWARDEN_TEST_PF_VALIDATE_FAIL", "1")
	err := ApplyPolicies()
	if err == nil || !strings.Contains(err.Error(), "candidate validation failed") {
		t.Fatalf("candidate validation failure was not propagated: %v", err)
	}
	snapshot, readErr := readPFSnapshot()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if snapshot.MutationStarted {
		t.Fatal("candidate validation failure crossed the mutation boundary")
	}
	if got := optionalPFTestFile(t, state.logPath); strings.Contains("\n"+got, "\n-f -\n") {
		t.Fatalf("candidate validation failure applied PF rules:\n%s", got)
	}
	if module, moduleErr := inspectPFKernelState(); moduleErr != nil || module != PFInitialKernelAvailable {
		t.Fatalf("successful kldload was not visible before rollback: %s, %v", module, moduleErr)
	}
	t.Setenv("SYSWARDEN_TEST_PF_VALIDATE_FAIL", "0")
	if err := RestorePersistedPFPolicy(); err != nil {
		t.Fatal(err)
	}
	if module, moduleErr := inspectPFKernelState(); moduleErr != nil || module != PFInitialKernelModuleAbsent {
		t.Fatalf("rollback did not restore absent module state: %s, %v", module, moduleErr)
	}
	if snapshotExists(t) {
		t.Fatal("successful rollback retained its snapshot")
	}
	if got := optionalPFTestFile(t, filepath.Join(state.root, "kld.log")); got != "-n -q pf\n-n pf\n" {
		t.Fatalf("module rollback did not use exact load and nonforced unload commands:\n%s", got)
	}
}

func TestMutationMarkerFailurePreventsPolicyApply(t *testing.T) {
	state := preparePFSnapshotTest(t, "NO", "Disabled")
	emptyPFState(t, state)
	setMinimalPFApplyConfig(t)
	t.Setenv("SYSWARDEN_TEST_PF_BLOCK_MARKER", "1")
	err := ApplyPolicies()
	if err == nil || !strings.Contains(err.Error(), "create temporary PF snapshot") {
		t.Fatalf("mutation marker replacement failure was not propagated: %v", err)
	}
	snapshot, readErr := readPFSnapshot()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if snapshot.MutationStarted {
		t.Fatal("failed marker replacement changed the durable mutation boundary")
	}
	if got := optionalPFTestFile(t, state.logPath); strings.Contains("\n"+got, "\n-f -\n") {
		t.Fatalf("marker failure applied PF rules:\n%s", got)
	}
	if _, statErr := os.Lstat(filepath.Join(state.root, "loaded.pf")); !os.IsNotExist(statErr) {
		t.Fatalf("marker failure produced applied candidate output: %v", statErr)
	}
}

func TestPFDriftDuringCandidateValidationPreventsPolicyApply(t *testing.T) {
	state := preparePFSnapshotTest(t, "NO", "Disabled")
	emptyPFState(t, state)
	setMinimalPFApplyConfig(t)
	t.Setenv("SYSWARDEN_TEST_PF_DRIFT_AFTER_VALIDATE", "states")
	err := ApplyPolicies()
	if err == nil || !strings.Contains(err.Error(), "revalidate exact live PF state before mutation") {
		t.Fatalf("PF state drift during candidate validation was not rejected: %v", err)
	}
	snapshot, readErr := readPFSnapshot()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if snapshot.MutationStarted {
		t.Fatal("candidate-validation drift crossed the mutation boundary")
	}
	if got := optionalPFTestFile(t, state.logPath); strings.Contains("\n"+got, "\n-f -\n") {
		t.Fatalf("candidate-validation drift applied PF rules:\n%s", got)
	}
}

func TestRestoreRejectsDisappearedModuleAfterMutation(t *testing.T) {
	state := preparePFSnapshotTest(t, "NO", "Disabled")
	emptyPFState(t, state)
	if err := CapturePFPolicySnapshot(PFSnapshotExactLive); err != nil {
		t.Fatal(err)
	}
	if err := markPFMutationStartedLocked(); err != nil {
		t.Fatal(err)
	}
	before := optionalPFTestFile(t, state.logPath)
	setPFModuleState(t, state, PFInitialKernelModuleAbsent)
	err := RestorePersistedPFPolicy()
	if err == nil || !strings.Contains(err.Error(), "disappeared after an available baseline") {
		t.Fatalf("post-mutation module disappearance was not rejected: %v", err)
	}
	if !snapshotExists(t) {
		t.Fatal("failed post-mutation restore consumed its snapshot")
	}
	if after := optionalPFTestFile(t, state.logPath); after != before {
		t.Fatalf("restore invoked pfctl after discovering an absent module:\nbefore=%q\nafter=%q", before, after)
	}
}

func TestRestoreNeverConsumesMutatedAbsentBaselineWhenModuleDisappears(t *testing.T) {
	state := preparePFSnapshotTest(t, "NO", "Disabled")
	emptyPFState(t, state)
	setPFModuleState(t, state, PFInitialKernelModuleAbsent)
	if err := CapturePFPolicySnapshot(PFSnapshotExactLive); err != nil {
		t.Fatal(err)
	}
	if err := ensurePFKernelReadyForMutationLocked(); err != nil {
		t.Fatal(err)
	}
	if err := markPFMutationStartedLocked(); err != nil {
		t.Fatal(err)
	}
	setPFModuleState(t, state, PFInitialKernelModuleAbsent)
	before := optionalPFTestFile(t, state.logPath)
	err := RestorePersistedPFPolicy()
	if err == nil || !strings.Contains(err.Error(), "disappeared after policy mutation started") {
		t.Fatalf("mutated absent baseline with missing module was not rejected: %v", err)
	}
	if !snapshotExists(t) {
		t.Fatal("mutated absent baseline failure consumed its snapshot")
	}
	if after := optionalPFTestFile(t, state.logPath); after != before {
		t.Fatalf("missing-module restore invoked pfctl:\nbefore=%q\nafter=%q", before, after)
	}
}

func TestPFUnloadFailureRetainsSnapshot(t *testing.T) {
	state := preparePFSnapshotTest(t, "NO", "Disabled")
	emptyPFState(t, state)
	setPFModuleState(t, state, PFInitialKernelModuleAbsent)
	if err := CapturePFPolicySnapshot(PFSnapshotExactLive); err != nil {
		t.Fatal(err)
	}
	if err := ensurePFKernelReadyForMutationLocked(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SYSWARDEN_TEST_KLDUNLOAD_RC", "1")
	err := RestorePersistedPFPolicy()
	if err == nil || !strings.Contains(err.Error(), "unload PF kernel module") {
		t.Fatalf("kldunload failure was not propagated: %v", err)
	}
	if !snapshotExists(t) {
		t.Fatal("kldunload failure consumed the recovery snapshot")
	}
	if got := optionalPFTestFile(t, filepath.Join(state.root, "kld.log")); got != "-n -q pf\n-n pf\n" {
		t.Fatalf("unexpected module commands during unload failure:\n%s", got)
	}
}

func TestNativePFKernelStateClassification(t *testing.T) {
	tests := []struct {
		name       string
		deviceMode string
		moduleRC   string
		want       PFInitialKernelState
		wantError  string
	}{
		{name: "available", deviceMode: "character", moduleRC: "0", want: PFInitialKernelAvailable},
		{name: "absent", deviceMode: "missing", moduleRC: "1", want: PFInitialKernelModuleAbsent},
		{name: "module without device", deviceMode: "missing", moduleRC: "0", wantError: "module is present"},
		{name: "device without module", deviceMode: "character", moduleRC: "1", wantError: "device exists"},
		{name: "symlink device", deviceMode: "symlink", moduleRC: "0", wantError: "nonsymlink character device"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := preparePFSnapshotTest(t, "NO", "Disabled")
			t.Setenv("SYSWARDEN_TEST_KLDSTAT_RC", test.moduleRC)
			switch test.deviceMode {
			case "missing":
				pfControlDevicePath = filepath.Join(state.root, "missing-pf-device")
			case "character":
				pfControlDevicePath = "/dev/null"
			case "symlink":
				pfControlDevicePath = filepath.Join(state.root, "pf-device-link")
				if err := os.Symlink("/dev/null", pfControlDevicePath); err != nil {
					t.Fatal(err)
				}
			default:
				t.Fatalf("unsupported test device mode %q", test.deviceMode)
			}
			got, err := inspectPFInitialKernelStateNative()
			if test.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantError) {
					t.Fatalf("kernel/device inconsistency was not rejected: state=%s error=%v", got, err)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("kernel state classification mismatch: got=%s want=%s error=%v", got, test.want, err)
			}
		})
	}
}

func TestExactLivePFSnapshotRestoresDisabledEmptyPolicy(t *testing.T) {
	state := preparePFSnapshotTest(t, "YES", "Disabled")
	emptyPFState(t, state)
	sourceBefore, err := os.Lstat(state.sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := CapturePFPolicySnapshot(PFSnapshotExactLive); err != nil {
		t.Fatal(err)
	}
	if err := markPFMutationStartedLocked(); err != nil {
		t.Fatal(err)
	}
	mutatePFState(t, state)
	if err := RestorePersistedPFPolicy(); err != nil {
		t.Fatal(err)
	}
	sourceAfter, err := os.Lstat(state.sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(sourceBefore, sourceAfter) {
		t.Fatal("PF restore replaced an already identical operator source inode")
	}
	status, err := os.ReadFile(state.statePath)
	if err != nil || string(status) != "Disabled\n" {
		t.Fatalf("disabled state was not restored: %q, %v", status, err)
	}
}

func TestExactLivePFSnapshotSupportsAbsentSourceOnlyForEmptyDisabledPolicy(t *testing.T) {
	state := preparePFSnapshotTest(t, "NO", "Disabled")
	if err := os.Remove(state.sourcePath); err != nil {
		t.Fatal(err)
	}
	emptyPFState(t, state)
	if err := CapturePFPolicySnapshot(PFSnapshotExactLive); err != nil {
		t.Fatal(err)
	}
	snapshot, err := readPFSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Source.Exists || snapshot.Source.Path != state.sourcePath {
		t.Fatalf("missing source was not represented exactly: %+v", snapshot.Source)
	}
	if err := markPFMutationStartedLocked(); err != nil {
		t.Fatal(err)
	}
	mutatePFState(t, state)
	if err := RestorePersistedPFPolicy(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(state.sourcePath); !os.IsNotExist(err) {
		t.Fatalf("restore invented missing PF source: %v", err)
	}
}

func TestLegacyDerivedSnapshotDoesNotClaimDestroyedLiveViews(t *testing.T) {
	state := preparePFSnapshotTest(t, "NO", "Enabled")
	mutatePFState(t, state)
	if err := CapturePFPolicySnapshot(PFSnapshotLegacyDerived); err != nil {
		t.Fatal(err)
	}
	snapshot, err := readPFSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Provenance != PFSnapshotLegacyDerived || snapshot.RuntimeStatus != "Disabled" ||
		!emptyPFLivePolicy(snapshot.LivePolicy) {
		t.Fatalf("legacy snapshot overstates live evidence: %+v", snapshot)
	}
	if err := RestorePersistedPFPolicy(); err != nil {
		t.Fatal(err)
	}
	log := string(readPFTestFile(t, state.logPath))
	if !strings.Contains(log, "-F all") || strings.Contains(log, "-f -") {
		t.Fatalf("disabled legacy restore loaded policy instead of flushing it:\n%s", log)
	}
}

func TestPFObjectNamesAcceptNativeDynamicTablesAndAuthpfAnchors(t *testing.T) {
	for _, table := range []string{"egress:network", "em0:broadcast", "tun0:peer", "vtnet0:0"} {
		if !validPFObjectName(table, false) {
			t.Fatalf("valid dynamic PF table %q was rejected", table)
		}
	}
	if !validPFObjectName("authpf/smith(1234)", true) {
		t.Fatal("valid authpf anchor name was rejected")
	}
}

func TestPFSnapshotRejectsUnsafeSourceAndConcurrentEdit(t *testing.T) {
	state := preparePFSnapshotTest(t, "NO", "Disabled")
	emptyPFState(t, state)
	if err := syscall.Chmod(state.sourcePath, 0666); err != nil {
		t.Fatal(err)
	}
	if err := CapturePFPolicySnapshot(PFSnapshotExactLive); err == nil {
		t.Fatal("writable PF source was accepted")
	}
	if err := os.Chmod(state.sourcePath, 0600); err != nil {
		t.Fatal(err)
	}
	if err := CapturePFPolicySnapshot(PFSnapshotExactLive); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(state.sourcePath, []byte("block all\n"), 0600); err != nil {
		t.Fatal(err)
	}
	mutatePFState(t, state)
	if err := RestorePersistedPFPolicy(); err == nil {
		t.Fatal("concurrent operator edit was overwritten")
	}
}

func TestPFSnapshotRejectsSymlinkOversizeAndWrongOwnerSource(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, pfSnapshotTestState)
	}{
		{
			name: "symlink",
			mutate: func(t *testing.T, state pfSnapshotTestState) {
				t.Helper()
				target := state.sourcePath + ".target"
				if err := os.Rename(state.sourcePath, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, state.sourcePath); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "oversize",
			mutate: func(t *testing.T, state pfSnapshotTestState) {
				t.Helper()
				if err := os.Truncate(state.sourcePath, maxPersistedPFConfigBytes+1); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "wrong owner",
			mutate: func(t *testing.T, _ pfSnapshotTestState) {
				t.Helper()
				pfExpectedOwner = func() int { return os.Geteuid() + 1 }
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := preparePFSnapshotTest(t, "NO", "Disabled")
			emptyPFState(t, state)
			test.mutate(t, state)
			if err := CapturePFPolicySnapshot(PFSnapshotExactLive); err == nil {
				t.Fatal("unsafe PF source was accepted")
			}
		})
	}
}

func TestPFRestoreUsesSharedLockAndPropagatesFlushFailure(t *testing.T) {
	state := preparePFSnapshotTest(t, "NO", "Disabled")
	emptyPFState(t, state)
	if err := CapturePFPolicySnapshot(PFSnapshotExactLive); err != nil {
		t.Fatal(err)
	}
	if err := markPFMutationStartedLocked(); err != nil {
		t.Fatal(err)
	}
	mutatePFState(t, state)
	lockFile, err := openRootedPFRuntimeFile(pfRuntimeLockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lockFile.Close() }()
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- RestorePersistedPFPolicy() }()
	select {
	case err := <-done:
		t.Fatalf("restore bypassed the shared lock: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SYSWARDEN_TEST_PF_FLUSH_FAIL", "1")
	if err := <-done; err == nil {
		t.Fatal("PF flush failure was ignored")
	}
	log, err := os.ReadFile(state.logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(log), "-F all") {
		t.Fatalf("fresh exact-live restore did not exercise bounded flush:\n%s", log)
	}
}
