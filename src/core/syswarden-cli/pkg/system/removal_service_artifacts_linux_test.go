//go:build linux

package system

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type preparedSystemdServiceArtifactTestPaths struct {
	coreUnit       string
	firewallUnit   string
	coreEnablement string
	firewallEnable string
	dropIn         string
}

func containsEveryRemovalTestValue(value string, expected ...string) bool {
	for _, item := range expected {
		if !strings.Contains(value, item) {
			return false
		}
	}
	return true
}

func newPreparedSystemdServiceArtifactTestHost(
	t *testing.T,
) (preparedSystemdServiceArtifactHost, preparedSystemdServiceArtifactTestPaths, *int) {
	return newPreparedSystemdServiceArtifactTestHostWithUnitMode(t, sourceSystemdUnitMode)
}

func newPreparedSystemdServiceArtifactTestHostWithUnitMode(
	t *testing.T,
	unitMode os.FileMode,
) (preparedSystemdServiceArtifactHost, preparedSystemdServiceArtifactTestPaths, *int) {
	t.Helper()
	root := t.TempDir()
	unitDirectory := filepath.Join(root, "etc", "systemd", "system")
	wantsDirectory := filepath.Join(unitDirectory, "multi-user.target.wants")
	dropInDirectory := filepath.Join(root, "usr", "lib", "systemd", "system", "syswarden-firewall.service.d")
	for _, directory := range []string{unitDirectory, wantsDirectory, dropInDirectory} {
		if err := os.MkdirAll(directory, 0755); err != nil { // #nosec G301 -- private fixture models trusted service directories
			t.Fatal(err)
		}
	}
	paths := preparedSystemdServiceArtifactTestPaths{
		coreUnit:       filepath.Join(unitDirectory, "syswarden-core.service"),
		firewallUnit:   filepath.Join(unitDirectory, "syswarden-firewall.service"),
		coreEnablement: filepath.Join(wantsDirectory, "syswarden-core.service"),
		firewallEnable: filepath.Join(wantsDirectory, "syswarden-firewall.service"),
		dropIn:         filepath.Join(dropInDirectory, "10-syswarden-wireguard-ordering.conf"),
	}
	for _, fixture := range []struct {
		path    string
		content string
		mode    os.FileMode
	}{
		{paths.coreUnit, systemdCoreService, unitMode},
		{paths.firewallUnit, systemdFirewallService, unitMode},
		{paths.dropIn, systemdFirewallWireGuardOrderingDropIn, 0644},
	} {
		if err := os.WriteFile(fixture.path, []byte(fixture.content), fixture.mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("../syswarden-core.service", paths.coreEnablement); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../syswarden-firewall.service", paths.firewallEnable); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		t.Fatal(err)
	}
	reloads := 0
	host := preparedSystemdServiceArtifactHost{
		artifacts: []preparedSystemdServiceArtifact{
			{
				path: paths.coreUnit, content: systemdCoreService, mode: sourceSystemdUnitMode,
				allowedModes: []os.FileMode{sourceSystemdUnitMode, historicalSourceSystemdUnitMode},
			},
			{
				path: paths.firewallUnit, content: systemdFirewallService, mode: sourceSystemdUnitMode,
				allowedModes: []os.FileMode{sourceSystemdUnitMode, historicalSourceSystemdUnitMode},
			},
			{
				path: paths.coreEnablement, allowedTargets: []string{"../syswarden-core.service"},
				requiredServicePath: paths.coreUnit,
			},
			{
				path: paths.firewallEnable, allowedTargets: []string{"../syswarden-firewall.service"},
				requiredServicePath: paths.firewallUnit,
			},
			{
				path: paths.dropIn, content: systemdFirewallWireGuardOrderingDropIn,
				mode: 0644, packageDropIn: true, optionalParent: true,
			},
		},
		trustedRoot: root,
		expectedUID: systemTestUID(t),
		expectedGID: systemTestGID(t),
		classifyRuntime: func(bool) (serviceManagerState, error) {
			return serviceManagerActive, nil
		},
		executor: firewallManagerExecutor{
			lookPath: func(name string) (string, error) {
				if name != "systemctl" {
					return "", fmt.Errorf("unexpected executable %s", name)
				}
				return executable, nil
			},
			validate: func(path string) error {
				if path != executable {
					return fmt.Errorf("unexpected executable path %s", path)
				}
				return nil
			},
			output: func(path string, arguments ...string) ([]byte, error) {
				if path != executable || len(arguments) != 1 || arguments[0] != "daemon-reload" {
					return nil, fmt.Errorf("unexpected systemd recovery command %s %v", path, arguments)
				}
				reloads++
				return nil, nil
			},
		},
		processScan: func() error { return nil },
		attestPackageDrop: func(_ firewallManagerExecutor, path string) (string, error) {
			if path != paths.dropIn {
				return "", fmt.Errorf("unexpected package drop-in path %s", path)
			}
			return "syswarden@4.04.3#test", nil
		},
	}
	return host, paths, &reloads
}

func TestPreparedServiceEnablementRemovalIsExactAndPreservesLookalikes_SW2_FWBACKEND_001(t *testing.T) {
	root := t.TempDir()
	serviceDirectory := filepath.Join(root, "system")
	wantsDirectory := filepath.Join(serviceDirectory, "multi-user.target.wants")
	if err := os.MkdirAll(wantsDirectory, 0755); err != nil { // #nosec G301 -- fixture models a systemd wants directory under a private test root
		t.Fatal(err)
	}
	servicePath := filepath.Join(serviceDirectory, "syswarden-core.service")
	if err := os.WriteFile(servicePath, []byte(systemdCoreService), 0600); err != nil {
		t.Fatal(err)
	}
	enablementPath := filepath.Join(wantsDirectory, "syswarden-core.service")
	if err := os.Symlink("../syswarden-core.service", enablementPath); err != nil {
		t.Fatal(err)
	}
	if err := removePreparedServiceEnablement(
		enablementPath,
		servicePath,
		systemdCoreService,
		0600,
		"../syswarden-core.service",
	); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(enablementPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("exact enablement remains: %v", err)
	}

	if err := os.Symlink("../operator.service", enablementPath); err != nil {
		t.Fatal(err)
	}
	if err := removePreparedServiceEnablement(
		enablementPath,
		servicePath,
		systemdCoreService,
		0600,
		"../syswarden-core.service",
	); err == nil {
		t.Fatal("operator enablement target was removed")
	}
	if target, err := os.Readlink(enablementPath); err != nil || target != "../operator.service" {
		t.Fatalf("operator enablement changed: target=%q error=%v", target, err)
	}
}

func TestInterruptedSystemdServiceArtifactRemovalRecoversEveryMonotonicBoundary_SW2_PKG_001(t *testing.T) {
	removalOrder := func(paths preparedSystemdServiceArtifactTestPaths) []string {
		return []string{
			paths.coreEnablement,
			paths.firewallEnable,
			paths.coreUnit,
			paths.firewallUnit,
			paths.dropIn,
		}
	}
	for removed := 1; removed <= 5; removed++ {
		t.Run(fmt.Sprintf("after-%d-removals", removed), func(t *testing.T) {
			host, paths, reloads := newPreparedSystemdServiceArtifactTestHost(t)
			for _, path := range removalOrder(paths)[:removed] {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			if err := host.recoverInterruptedRemoval(); err != nil {
				t.Fatalf("recover monotonic removal boundary: %v", err)
			}
			if *reloads != 1 {
				t.Fatalf("systemd reloads = %d, want 1", *reloads)
			}
		})
	}
}

func TestInterruptedSystemdServiceArtifactRemovalRecoversLegacyDropInFirstBoundary_SW2_PKG_001(t *testing.T) {
	host, paths, reloads := newPreparedSystemdServiceArtifactTestHost(t)
	if err := os.Remove(paths.dropIn); err != nil {
		t.Fatal(err)
	}
	if err := host.recoverInterruptedRemoval(); err != nil {
		t.Fatalf("recover legacy drop-in-first boundary: %v", err)
	}
	if *reloads != 1 {
		t.Fatalf("systemd reloads = %d, want 1", *reloads)
	}
}

func TestInterruptedSystemdServiceArtifactRemovalAcceptsStableAbsentSourceDropInDirectory_SW2_PKG_001(t *testing.T) {
	host, paths, reloads := newPreparedSystemdServiceArtifactTestHost(t)
	directory := filepath.Dir(paths.dropIn)
	if err := os.Remove(paths.dropIn); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(directory); err != nil {
		t.Fatal(err)
	}
	if err := host.recoverInterruptedRemoval(); err != nil {
		t.Fatalf("recover source installation without package drop-in directory: %v", err)
	}
	if *reloads != 1 {
		t.Fatalf("source installation recovery reloads = %d, want 1", *reloads)
	}
	if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source drop-in directory was created during recovery: %v", err)
	}
}

func TestInterruptedSystemdServiceArtifactRemovalRetriesFailedReloadWithoutDiskMutation_SW2_PKG_001(t *testing.T) {
	host, paths, reloads := newPreparedSystemdServiceArtifactTestHost(t)
	if err := os.Remove(paths.coreEnablement); err != nil {
		t.Fatal(err)
	}
	originalOutput := host.executor.output
	sentinel := errors.New("synthetic daemon-reload failure")
	host.executor.output = func(path string, arguments ...string) ([]byte, error) {
		if *reloads == 0 {
			*reloads++
			return nil, sentinel
		}
		return originalOutput(path, arguments...)
	}
	if err := host.recoverInterruptedRemoval(); err == nil || !errors.Is(err, sentinel) {
		t.Fatalf("first recovery error = %v", err)
	}
	if _, err := os.Lstat(paths.coreEnablement); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed recovery changed absent enablement: %v", err)
	}
	if err := host.recoverInterruptedRemoval(); err != nil {
		t.Fatalf("retry recovery: %v", err)
	}
	if *reloads != 2 {
		t.Fatalf("systemd reload attempts = %d, want 2", *reloads)
	}
}

func TestInterruptedSystemdServiceArtifactRemovalRejectsModifiedLinkBeforeReload_SW2_PKG_001(t *testing.T) {
	host, paths, reloads := newPreparedSystemdServiceArtifactTestHost(t)
	if err := os.Remove(paths.coreEnablement); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../operator.service", paths.coreEnablement); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(paths.dropIn); err != nil {
		t.Fatal(err)
	}
	err := host.recoverInterruptedRemoval()
	if err == nil || !containsEveryRemovalTestValue(err.Error(), "unexpected systemd service enablement target", "operator.service") {
		t.Fatalf("modified enablement refusal = %v", err)
	}
	if *reloads != 0 {
		t.Fatalf("modified enablement triggered %d reloads", *reloads)
	}
	if target, err := os.Readlink(paths.coreEnablement); err != nil || target != "../operator.service" {
		t.Fatalf("modified enablement changed: target=%q error=%v", target, err)
	}
}

func TestInterruptedSystemdServiceArtifactRemovalRejectsUnitAbsenceWithLiveEnablement_SW2_PKG_001(t *testing.T) {
	host, paths, reloads := newPreparedSystemdServiceArtifactTestHost(t)
	if err := os.Remove(paths.coreUnit); err != nil {
		t.Fatal(err)
	}
	err := host.recoverInterruptedRemoval()
	if err == nil || !containsEveryRemovalTestValue(err.Error(), "without its exact service file", paths.coreUnit) {
		t.Fatalf("orphaned enablement refusal = %v", err)
	}
	if *reloads != 0 {
		t.Fatalf("orphaned enablement triggered %d reloads", *reloads)
	}
}

func TestInterruptedSystemdServiceArtifactRemovalRejectsHardlinkedUnitBeforeReload_SW2_PKG_001(t *testing.T) {
	host, paths, reloads := newPreparedSystemdServiceArtifactTestHost(t)
	hardlink := filepath.Join(filepath.Dir(paths.coreUnit), "operator-hardlink.service")
	if err := os.Link(paths.coreUnit, hardlink); err != nil {
		t.Fatal(err)
	}
	err := host.recoverInterruptedRemoval()
	if err == nil || !containsEveryRemovalTestValue(err.Error(), "unsafe single-link service file", paths.coreUnit) {
		t.Fatalf("hardlinked unit refusal = %v", err)
	}
	if *reloads != 0 {
		t.Fatalf("hardlinked unit triggered %d reloads", *reloads)
	}
	for _, path := range []string{paths.coreUnit, hardlink} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("hardlinked unit path %s changed: %v", path, err)
		}
	}
}

func TestInterruptedSystemdServiceArtifactRemovalRejectsHardlinkedEnablementBeforeReload_SW2_PKG_001(t *testing.T) {
	host, paths, reloads := newPreparedSystemdServiceArtifactTestHost(t)
	hardlink := filepath.Join(filepath.Dir(paths.coreEnablement), "operator-hardlink.service")
	if err := os.Link(paths.coreEnablement, hardlink); err != nil {
		t.Fatal(err)
	}
	err := host.recoverInterruptedRemoval()
	if err == nil || !containsEveryRemovalTestValue(err.Error(), "unsafe systemd service enablement", paths.coreEnablement) {
		t.Fatalf("hardlinked enablement refusal = %v", err)
	}
	if *reloads != 0 {
		t.Fatalf("hardlinked enablement triggered %d reloads", *reloads)
	}
	for _, path := range []string{paths.coreEnablement, hardlink} {
		if target, err := os.Readlink(path); err != nil || target != "../syswarden-core.service" {
			t.Fatalf("hardlinked enablement %s changed: target=%q error=%v", path, target, err)
		}
	}
}

func TestInterruptedSystemdServiceArtifactRemovalRejectsInventoryRaceBeforeReload_SW2_PKG_001(t *testing.T) {
	host, paths, reloads := newPreparedSystemdServiceArtifactTestHost(t)
	if err := os.Remove(paths.coreEnablement); err != nil {
		t.Fatal(err)
	}
	mutated := false
	host.afterFirstCapture = func() {
		if mutated {
			return
		}
		mutated = true
		if err := os.Remove(paths.firewallUnit); err != nil {
			t.Fatalf("remove raced unit: %v", err)
		}
		if err := os.WriteFile(paths.firewallUnit, []byte(systemdFirewallService), 0600); err != nil {
			t.Fatalf("replace raced unit: %v", err)
		}
	}
	err := host.recoverInterruptedRemoval()
	if err == nil || !containsEveryRemovalTestValue(err.Error(), "inventory changed", "recovery attestation") {
		t.Fatalf("inventory race refusal = %v", err)
	}
	if *reloads != 0 {
		t.Fatalf("inventory race triggered %d reloads", *reloads)
	}
}

func TestInterruptedSystemdServiceArtifactRemovalRejectsUnsafeParentBeforeReload_SW2_PKG_001(t *testing.T) {
	host, paths, reloads := newPreparedSystemdServiceArtifactTestHost(t)
	if err := os.Remove(paths.coreEnablement); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(paths.dropIn), 0777); err != nil { // #nosec G302 -- adversarial fixture deliberately proves a world-writable parent is rejected
		t.Fatal(err)
	}
	err := host.recoverInterruptedRemoval()
	if err == nil || !containsEveryRemovalTestValue(err.Error(), "parent", "not trusted") {
		t.Fatalf("unsafe parent refusal = %v", err)
	}
	if *reloads != 0 {
		t.Fatalf("unsafe parent triggered %d reloads", *reloads)
	}
}

func TestInterruptedSystemdServiceArtifactRemovalRefusesManagerTransitionAfterReload_SW2_PKG_001(t *testing.T) {
	host, paths, reloads := newPreparedSystemdServiceArtifactTestHost(t)
	if err := os.Remove(paths.coreEnablement); err != nil {
		t.Fatal(err)
	}
	classifications := 0
	host.classifyRuntime = func(bool) (serviceManagerState, error) {
		classifications++
		if classifications == 1 {
			return serviceManagerActive, nil
		}
		return serviceManagerOffline, nil
	}
	err := host.recoverInterruptedRemoval()
	if err == nil || !containsEveryRemovalTestValue(err.Error(), "changed to OFFLINE", "recovery") {
		t.Fatalf("manager transition refusal = %v", err)
	}
	if *reloads != 1 {
		t.Fatalf("manager transition reloads = %d, want 1", *reloads)
	}
}

func TestInterruptedSystemdServiceArtifactRemovalNeverReloadsOfflineManager_SW2_PKG_001(t *testing.T) {
	host, paths, reloads := newPreparedSystemdServiceArtifactTestHost(t)
	if err := os.Remove(paths.coreEnablement); err != nil {
		t.Fatal(err)
	}
	host.classifyRuntime = func(bool) (serviceManagerState, error) {
		return serviceManagerOffline, nil
	}
	if err := host.recoverInterruptedRemoval(); err != nil {
		t.Fatalf("offline recovery: %v", err)
	}
	if *reloads != 0 {
		t.Fatalf("offline recovery triggered %d reloads", *reloads)
	}
}

func TestInterruptedSystemdServiceArtifactRemovalDoesNotReloadCompleteInventory_SW2_PKG_001(t *testing.T) {
	host, _, reloads := newPreparedSystemdServiceArtifactTestHost(t)
	if err := host.recoverInterruptedRemoval(); err != nil {
		t.Fatalf("complete inventory recovery: %v", err)
	}
	if *reloads != 0 {
		t.Fatalf("complete inventory triggered %d reloads", *reloads)
	}
}

func TestHistoricalSystemdServiceArtifactsAtMode0644AreCapturedAndExactlyRemoved_SW2_PKG_001(t *testing.T) {
	host, paths, _ := newPreparedSystemdServiceArtifactTestHostWithUnitMode(t, historicalSourceSystemdUnitMode)
	before, absent, err := host.captureStable()
	if err != nil {
		t.Fatalf("capture exact historical service artifacts: %v", err)
	}
	if absent != 0 || len(before) != len(host.artifacts) {
		t.Fatalf("historical service artifact capture = %d snapshots, %d absent", len(before), absent)
	}
	for _, path := range []string{paths.coreUnit, paths.firewallUnit} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode().Perm() != historicalSourceSystemdUnitMode {
			t.Fatalf("historical unit %s mode = %v, error = %v", path, info.Mode().Perm(), err)
		}
	}

	allowedModes := []os.FileMode{sourceSystemdUnitMode, historicalSourceSystemdUnitMode}
	if err := removePreparedServiceEnablementModes(
		paths.coreEnablement, paths.coreUnit, systemdCoreService, allowedModes, "../syswarden-core.service",
	); err != nil {
		t.Fatalf("remove historical core enablement: %v", err)
	}
	if err := removePreparedServiceEnablementModes(
		paths.firewallEnable, paths.firewallUnit, systemdFirewallService, allowedModes,
		"../syswarden-firewall.service",
	); err != nil {
		t.Fatalf("remove historical firewall enablement: %v", err)
	}
	if err := removePreparedExactServiceFileModes(paths.coreUnit, systemdCoreService, allowedModes); err != nil {
		t.Fatalf("remove historical core unit: %v", err)
	}
	if err := removePreparedExactServiceFileModes(paths.firewallUnit, systemdFirewallService, allowedModes); err != nil {
		t.Fatalf("remove historical firewall unit: %v", err)
	}
	for _, path := range []string{paths.coreEnablement, paths.firewallEnable, paths.coreUnit, paths.firewallUnit} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("exact historical artifact remains at %s: %v", path, err)
		}
	}
}

func TestHistoricalSystemdServiceArtifactCaptureRejectsModeRace_SW2_PKG_001(t *testing.T) {
	host, paths, reloads := newPreparedSystemdServiceArtifactTestHostWithUnitMode(
		t, historicalSourceSystemdUnitMode,
	)
	mutated := false
	host.afterFirstCapture = func() {
		if mutated {
			return
		}
		mutated = true
		if err := os.Chmod(paths.firewallUnit, sourceSystemdUnitMode); err != nil {
			t.Fatalf("change unit mode during double capture: %v", err)
		}
	}
	err := host.recoverInterruptedRemoval()
	if err == nil || !containsEveryRemovalTestValue(err.Error(), "inventory changed", "recovery attestation") {
		t.Fatalf("historical mode race refusal = %v", err)
	}
	if *reloads != 0 {
		t.Fatalf("historical mode race triggered %d reloads", *reloads)
	}
	if target, err := os.Readlink(paths.firewallEnable); err != nil || target != "../syswarden-firewall.service" {
		t.Fatalf("historical mode race changed enablement: target=%q error=%v", target, err)
	}
}

func TestHistoricalSystemdServiceArtifactRemovalRejectsUnsafeLookalikes_SW2_PKG_001(t *testing.T) {
	allowedModes := []os.FileMode{sourceSystemdUnitMode, historicalSourceSystemdUnitMode}
	for _, testCase := range []struct {
		name   string
		mode   os.FileMode
		mutate func(*testing.T, string)
	}{
		{name: "unsupported mode", mode: 0640},
		{name: "modified content", mode: historicalSourceSystemdUnitMode, mutate: func(t *testing.T, path string) {
			t.Helper()
			if err := os.WriteFile(path, []byte("operator service\n"), historicalSourceSystemdUnitMode); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "hardlink", mode: historicalSourceSystemdUnitMode, mutate: func(t *testing.T, path string) {
			t.Helper()
			if err := os.Link(path, path+".operator"); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "syswarden-firewall.service")
			if err := os.WriteFile(path, []byte(systemdFirewallService), testCase.mode); err != nil {
				t.Fatal(err)
			}
			if testCase.mutate != nil {
				testCase.mutate(t, path)
			}
			if err := removePreparedExactServiceFileModes(path, systemdFirewallService, allowedModes); err == nil {
				t.Fatal("unsafe historical systemd unit was removed")
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatalf("refused historical systemd unit changed: %v", err)
			}
		})
	}
}

func TestPreparedExactServiceFileRemovalIsExactIdempotentAndPreservesModifiedFiles_SW2_PKG_001(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "syswarden-firewall.service")
	if err := os.WriteFile(path, []byte(systemdFirewallService), 0600); err != nil {
		t.Fatal(err)
	}
	if err := removePreparedExactServiceFile(path, systemdFirewallService, 0600); err != nil {
		t.Fatal(err)
	}
	if err := removePreparedExactServiceFile(path, systemdFirewallService, 0600); err != nil {
		t.Fatalf("idempotent removal: %v", err)
	}
	if err := os.WriteFile(path, []byte("operator content\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := removePreparedExactServiceFile(path, systemdFirewallService, 0600); err == nil {
		t.Fatal("modified service file was removed")
	}
	content, err := os.ReadFile(path) // #nosec G304 -- path is confined to the private test fixture root
	if err != nil || string(content) != "operator content\n" {
		t.Fatalf("modified service file changed: content=%q error=%v", content, err)
	}
}

func TestPreparedExactServiceFileRemovalPreservesHardlinkedFile_SW2_PKG_001(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "syswarden-firewall.service")
	hardlink := filepath.Join(root, "operator-hardlink.service")
	if err := os.WriteFile(path, []byte(systemdFirewallService), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(path, hardlink); err != nil {
		t.Fatal(err)
	}
	if err := removePreparedExactServiceFile(path, systemdFirewallService, 0600); err == nil {
		t.Fatal("hardlinked service file was removed")
	}
	for _, candidate := range []string{path, hardlink} {
		if content, err := os.ReadFile(candidate); err != nil || string(content) != systemdFirewallService { // #nosec G304 -- candidates are fixed files beneath the private test fixture root
			t.Fatalf("hardlinked service file %s changed: content=%q error=%v", candidate, content, err)
		}
	}
}

func TestPreparedServiceEnablementRemovalPreservesLinkWhenServiceFileIsHardlinked_SW2_PKG_001(t *testing.T) {
	root := t.TempDir()
	serviceDirectory := filepath.Join(root, "system")
	wantsDirectory := filepath.Join(serviceDirectory, "multi-user.target.wants")
	if err := os.MkdirAll(wantsDirectory, 0755); err != nil { // #nosec G301 -- private fixture models systemd directories
		t.Fatal(err)
	}
	servicePath := filepath.Join(serviceDirectory, "syswarden-core.service")
	hardlink := filepath.Join(serviceDirectory, "operator-hardlink.service")
	enablementPath := filepath.Join(wantsDirectory, "syswarden-core.service")
	if err := os.WriteFile(servicePath, []byte(systemdCoreService), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(servicePath, hardlink); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../syswarden-core.service", enablementPath); err != nil {
		t.Fatal(err)
	}
	if err := removePreparedServiceEnablement(
		enablementPath, servicePath, systemdCoreService, 0600, "../syswarden-core.service",
	); err == nil {
		t.Fatal("enablement was removed for a hardlinked service definition")
	}
	if target, err := os.Readlink(enablementPath); err != nil || target != "../syswarden-core.service" {
		t.Fatalf("enablement changed after hardlinked service refusal: target=%q error=%v", target, err)
	}
}

func TestExistingPinnedServiceDirectoryNeverCreatesMissingPath_SW2_PKG_001(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "service.d")
	if directory, err := openExistingPinnedServiceDirectory(path); err == nil {
		directory.close()
		t.Fatal("missing service directory was accepted")
	}
	if _, err := os.Lstat(filepath.Join(filepath.Dir(path), "..", "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only service directory pin created a path: %v", err)
	}
}
