package firewall

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFreeBSDPFRestoreIsLockedValidatedAndFailClosed_SW_PKG_001(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	root, err := os.OpenRoot(filepath.Dir(currentFile))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	content, err := root.ReadFile("pf_restore_freebsd.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(content)
	for _, required := range []string{
		`acquirePFRuntimeLock()`,
		`pfSnapshotSchemaVersion   = 2`,
		`PFSnapshotExactLive`,
		`PFSnapshotLegacyDerived`,
		`PFInitialKernelAvailable`,
		`PFInitialKernelModuleAbsent`,
		`ConfiguredStatus`,
		`MutationStarted`,
		`exec.Command("/usr/sbin/sysrc", arguments...)`,
		`exec.Command("/sbin/pfctl", arguments...)`,
		`exec.Command("/sbin/kldstat", arguments...)`,
		`exec.Command("/sbin/kldload", arguments...)`,
		`exec.Command("/sbin/kldunload", arguments...)`,
		`newPFCTLCommand("-nf", "-")`,
		`newPFCTLCommand("-f", "-")`,
		`newPFCTLCommand("-s", "Tables")`,
		`newPFCTLCommand("-ss")`,
		`newPFKLDStatCommand("-q", "-m", pfModuleName)`,
		`newPFKLDLoadCommand("-n", "-q", pfModuleName)`,
		`newPFKLDUnloadCommand("-n", pfModuleName)`,
		`fresh exact-live PF is supported only for a disabled empty host policy and state table`,
		`fresh empty PF policy was not restored exactly`,
		`SysWarden PF state remains after restore`,
		`sync published PF snapshot directory`,
		`sync consumed PF snapshot directory`,
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("FreeBSD PF restore lacks %q", required)
		}
	}
	applyContent, err := root.ReadFile("firewall_freebsd.go")
	if err != nil {
		t.Fatal(err)
	}
	applySource := string(applyContent)
	captureOffset := strings.Index(applySource, `capturePFPolicySnapshotLocked(PFSnapshotExactLive)`)
	ensureOffset := strings.Index(applySource, `ensurePFKernelReadyForMutationLocked()`)
	validateOffset := strings.Index(applySource, `newPFCTLCommand("-nf", "-")`)
	markOffset := strings.Index(applySource, `markPFMutationStartedLocked()`)
	applyOffset := strings.Index(applySource, `newPFCTLCommand("-f", "-")`)
	if captureOffset < 0 || ensureOffset <= captureOffset || validateOffset <= ensureOffset ||
		markOffset <= validateOffset || applyOffset <= markOffset {
		t.Fatal("FreeBSD PF transaction order must be capture, ensure kernel, validate, mark mutation, apply")
	}
}
