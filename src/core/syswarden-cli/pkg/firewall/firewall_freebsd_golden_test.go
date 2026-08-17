//go:build freebsd

package firewall

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"syswarden-cli/config"
)

func TestPFRulesGolden_SW_QA_001(t *testing.T) {
	for _, path := range []string{
		"/etc/syswarden/lists/syswarden_saas_monitors.ipv4",
		"/etc/syswarden/lists/syswarden_saas_monitors.ipv6",
	} {
		if fileExists(path) {
			t.Fatalf("FreeBSD golden requires a clean VM without optional fixture file %s", path)
		}
	}

	root := t.TempDir()
	toolDir := filepath.Join(root, "tools")
	if err := os.MkdirAll(toolDir, 0750); err != nil {
		t.Fatal(err)
	}
	captured := filepath.Join(root, "captured.pf")
	operatorPolicy := filepath.Join(root, "operator.pf")
	pfState := filepath.Join(root, "pf-state")
	if err := os.WriteFile(operatorPolicy, []byte("pass in on vtnet-test0\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pfState, []byte("Disabled\n"), 0600); err != nil {
		t.Fatal(err)
	}
	writeFreeBSDExecutable(t, filepath.Join(toolDir, "route"), `#!/bin/sh
/bin/cat <<'EOF'
   route to: default
  interface: vtnet-test0
EOF
`)
	writeFreeBSDExecutable(t, filepath.Join(toolDir, "sockstat"), `#!/bin/sh
/bin/cat <<'EOF'
USER COMMAND PID FD PROTO LOCAL ADDRESS FOREIGN ADDRESS
root daemon 1 3 tcp4 *:443 *:*
root daemon 1 4 tcp4 127.0.0.1:5432 *:*
root daemon 1 5 udp4 *:53 *:*
EOF
`)
	writeFreeBSDExecutable(t, filepath.Join(toolDir, "pfctl"), `#!/bin/sh
case "$*" in
    '-nf -') /bin/cat >/dev/null ;;
    '-f -') /bin/cat > "$SYSWARDEN_PF_TEST_CAPTURE" ;;
    '-s info') printf 'Status: %s\n' "$(/bin/cat "$SYSWARDEN_PF_TEST_STATE")" ;;
    '-sr'|'-sn'|'-ss'|'-s Tables'|'-s Anchors') : ;;
    '-e') printf '%s\n' Enabled > "$SYSWARDEN_PF_TEST_STATE" ;;
    *) exit 91 ;;
esac
`)
	writeFreeBSDExecutable(t, filepath.Join(toolDir, "sysrc"), `#!/bin/sh
if [ "$1" = "-n" ] && [ "$2" = "pf_rules" ]; then
    printf '%s\n' "$SYSWARDEN_PF_TEST_SOURCE"
    exit 0
fi
if [ "$1" = "-n" ] && [ "$2" = "pf_enable" ]; then
    printf '%s\n' YES
    exit 0
fi
exit 1
`)
	writeFreeBSDExecutable(t, filepath.Join(toolDir, "kldstat"), `#!/bin/sh
[ "$*" = "-q -m pf" ]
`)
	t.Setenv("PATH", toolDir)
	t.Setenv("SYSWARDEN_PF_TEST_CAPTURE", captured)
	t.Setenv("SYSWARDEN_PF_TEST_SOURCE", operatorPolicy)
	t.Setenv("SYSWARDEN_PF_TEST_STATE", pfState)
	previousLockPath := pfRuntimeLockPath
	previousSnapshotDirectory := pfSnapshotDirectory
	previousExpectedOwner := pfExpectedOwner
	previousControlDevice := pfControlDevicePath
	previousPFCTLCommand := newPFCTLCommand
	previousSysrcCommand := newPFSysrcCommand
	previousKLDStatCommand := newPFKLDStatCommand
	previousInspectKernelState := inspectPFKernelState
	pfRuntimeLockPath = filepath.Join(root, "syswarden-firewall.lock")
	pfSnapshotDirectory = filepath.Join(root, "snapshot")
	pfExpectedOwner = os.Geteuid
	pfControlDevicePath = "/dev/null"
	newPFCTLCommand = func(arguments ...string) *exec.Cmd {
		return exec.Command(filepath.Join(toolDir, "pfctl"), arguments...) // #nosec G204 -- executable is an owner-only fixture rooted in t.TempDir
	}
	newPFSysrcCommand = func(arguments ...string) *exec.Cmd {
		return exec.Command(filepath.Join(toolDir, "sysrc"), arguments...) // #nosec G204 -- executable is an owner-only fixture rooted in t.TempDir
	}
	newPFKLDStatCommand = func(arguments ...string) *exec.Cmd {
		return exec.Command(filepath.Join(toolDir, "kldstat"), arguments...) // #nosec G204 -- executable is an owner-only fixture rooted in t.TempDir
	}
	inspectPFKernelState = inspectPFInitialKernelStateNative
	t.Cleanup(func() {
		pfRuntimeLockPath = previousLockPath
		pfSnapshotDirectory = previousSnapshotDirectory
		pfExpectedOwner = previousExpectedOwner
		pfControlDevicePath = previousControlDevice
		newPFCTLCommand = previousPFCTLCommand
		newPFSysrcCommand = previousSysrcCommand
		newPFKLDStatCommand = previousKLDStatCommand
		inspectPFKernelState = previousInspectKernelState
	})

	previous := config.GlobalConfig
	t.Cleanup(func() { config.GlobalConfig = previous })
	config.GlobalConfig = &config.Config{
		SSHPort:    "2222",
		HAEnabled:  true,
		HAPeerPort: "62026",
	}
	if err := ApplyPolicies(); err != nil {
		t.Fatalf("ApplyPolicies() with fake pfctl: %v", err)
	}
	got, err := os.ReadFile(captured) // #nosec G304 -- captured is rooted in t.TempDir
	if err != nil {
		t.Fatalf("read captured PF rules: %v", err)
	}
	wantPath := filepath.Join("..", "..", "..", "..", "..", "testdata", "firewall", "pf-v4.02.8.conf")
	if os.Getenv("SYSWARDEN_UPDATE_CONTRACT_GOLDENS") == "1" {
		if err := os.WriteFile(wantPath, got, 0600); err != nil { // #nosec G703 -- wantPath is a fixed repository fixture behind the explicit golden-update gate
			t.Fatalf("update PF golden: %v", err)
		}
		return
	}
	want, err := os.ReadFile(wantPath) // #nosec G304 -- wantPath is a fixed repository fixture
	if err != nil {
		t.Fatalf("read PF golden: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("PF rules changed; review and approve the complete golden diff before updating %s", wantPath)
	}
}

func writeFreeBSDExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0700); err != nil { // #nosec G302 -- the owner-only test fixture must be executable by the FreeBSD contract test
		t.Fatal(err)
	}
}
