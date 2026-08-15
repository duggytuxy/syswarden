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
		`PFSnapshotExactLive`,
		`PFSnapshotLegacyDerived`,
		`exec.Command("sysrc", "-n", "pf_rules")`,
		`exec.Command("sysrc", "-n", "pf_enable")`,
		`exec.Command("pfctl", "-nf", "-")`,
		`exec.Command("pfctl", "-f", "-")`,
		`exec.Command("pfctl", "-s", "Tables")`,
		`fresh exact-live PF is supported only for a disabled empty host policy`,
		`fresh empty PF policy was not restored exactly`,
		`SysWarden PF state remains after restore`,
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("FreeBSD PF restore lacks %q", required)
		}
	}
}
