//go:build freebsd

package firewall

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
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
		sourcePath:  filepath.Join(root, "operator-pf.conf"),
	}
	for path, content := range map[string]string{
		state.statePath:   runtimeStatus + "\n",
		state.rulesPath:   "pass in on vtnet0\n",
		state.natPath:     "nat on vtnet0 from 10.0.0.0/24 to any -> 192.0.2.1\n",
		state.tablesPath:  "operator_allow\n",
		state.entriesPath: "198.51.100.40\n2001:db8::40\n",
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
	'-F all')
		[ "${SYSWARDEN_TEST_PF_FLUSH_FAIL:-0}" = 0 ] || exit 1
		: > "$SYSWARDEN_TEST_PF_RULES"
		: > "$SYSWARDEN_TEST_PF_NAT"
		: > "$SYSWARDEN_TEST_PF_TABLES"
		: > "$SYSWARDEN_TEST_PF_ENTRIES"
		;;
    '-e') printf 'Enabled\n' > "$SYSWARDEN_TEST_PF_STATE" ;;
    '-d') printf 'Disabled\n' > "$SYSWARDEN_TEST_PF_STATE" ;;
    *) exit 91 ;;
esac
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
	t.Setenv("SYSWARDEN_TEST_PF_VALIDATED", filepath.Join(root, "validated.pf"))
	t.Setenv("SYSWARDEN_TEST_PF_LOADED", filepath.Join(root, "loaded.pf"))
	originalSnapshotDirectory := pfSnapshotDirectory
	originalSnapshotName := pfSnapshotName
	originalOwner := pfExpectedOwner
	originalLock := pfRuntimeLockPath
	originalDynamicRunner := runDynamicPFCommand
	pfSnapshotDirectory = filepath.Join(root, "snapshot")
	pfSnapshotName = "pf-policy-snapshot.json"
	pfExpectedOwner = os.Geteuid
	pfRuntimeLockPath = filepath.Join(root, "syswarden-firewall.lock")
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
	} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func emptyPFState(t *testing.T, state pfSnapshotTestState) {
	t.Helper()
	for _, path := range []string{state.rulesPath, state.natPath, state.tablesPath, state.entriesPath} {
		if err := os.WriteFile(path, nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
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
