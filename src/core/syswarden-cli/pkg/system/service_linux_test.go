//go:build linux

package system

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func withServiceRuntimeTestState(t *testing.T, packageInstall string) string {
	t.Helper()
	root := t.TempDir()
	oldSystemd := serviceSystemdRuntimePath
	oldOpenRC := serviceOpenRCRuntimePath
	oldEnvironment := servicePackageEnvironment
	serviceSystemdRuntimePath = filepath.Join(root, "run", "systemd", "system")
	serviceOpenRCRuntimePath = filepath.Join(root, "run", "openrc")
	servicePackageEnvironment = func(name string) string {
		if name == "SYSWARDEN_PKG_INSTALL" {
			return packageInstall
		}
		return ""
	}
	if err := os.MkdirAll(filepath.Join(root, "run"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		serviceSystemdRuntimePath = oldSystemd
		serviceOpenRCRuntimePath = oldOpenRC
		servicePackageEnvironment = oldEnvironment
	})
	return root
}

func TestClassifyServiceManagerRuntime(t *testing.T) {
	tests := []struct {
		name           string
		alpine         bool
		packageInstall string
		prepare        func(t *testing.T, root string)
		want           serviceManagerState
		wantErr        bool
	}{
		{name: "systemd-active", prepare: func(t *testing.T, root string) {
			t.Helper()
			mustSeedSystemdRuntime(t, root, serviceSystemdRuntimePath)
		}, want: serviceManagerActive},
		{name: "systemd-stale-directory", packageInstall: "1", prepare: func(t *testing.T, _ string) { t.Helper(); mustMkdirAll(t, serviceSystemdRuntimePath) }, want: serviceManagerAmbiguous, wantErr: true},
		{name: "openrc-active", alpine: true, prepare: func(t *testing.T, root string) { t.Helper(); mustSeedOpenRCRuntime(t, root, serviceOpenRCRuntimePath) }, want: serviceManagerActive},
		{name: "openrc-stale-directory", alpine: true, packageInstall: "1", prepare: func(t *testing.T, _ string) { t.Helper(); mustMkdirAll(t, serviceOpenRCRuntimePath) }, want: serviceManagerAmbiguous, wantErr: true},
		{name: "openrc-pid1-mismatch", alpine: true, packageInstall: "1", prepare: func(t *testing.T, root string) {
			t.Helper()
			mustSeedOpenRCRuntime(t, root, serviceOpenRCRuntimePath)
			mustWriteFile(t, filepath.Join(root, "proc", "1", "comm"), "systemd\n")
		}, want: serviceManagerAmbiguous, wantErr: true},
		{name: "openrc-writable-runtime", alpine: true, packageInstall: "1", prepare: func(t *testing.T, root string) {
			t.Helper()
			mustSeedOpenRCRuntime(t, root, serviceOpenRCRuntimePath)
			mustChmodTestPath(t, serviceOpenRCRuntimePath, 0775)
		}, want: serviceManagerAmbiguous, wantErr: true},
		{name: "systemd-offline-package", packageInstall: "1", want: serviceManagerOffline},
		{name: "openrc-offline-package", alpine: true, packageInstall: "1", want: serviceManagerOffline},
		{name: "missing-outside-package", want: serviceManagerAmbiguous, wantErr: true},
		{name: "wrong-package-marker", packageInstall: "true", want: serviceManagerAmbiguous, wantErr: true},
		{name: "conflicting-runtime", packageInstall: "1", prepare: func(t *testing.T, _ string) { t.Helper(); mustMkdirAll(t, serviceOpenRCRuntimePath) }, want: serviceManagerAmbiguous, wantErr: true},
		{name: "symlinked-runtime", packageInstall: "1", prepare: func(t *testing.T, root string) {
			t.Helper()
			mustMkdirAll(t, filepath.Dir(serviceSystemdRuntimePath))
			if err := os.Symlink(filepath.Join(root, "run"), serviceSystemdRuntimePath); err != nil {
				t.Fatal(err)
			}
		}, want: serviceManagerAmbiguous, wantErr: true},
		{name: "symlinked-systemd-parent", packageInstall: "1", prepare: func(t *testing.T, root string) {
			t.Helper()
			if err := os.Symlink(filepath.Join(root, "run"), filepath.Dir(serviceSystemdRuntimePath)); err != nil {
				t.Fatal(err)
			}
		}, want: serviceManagerAmbiguous, wantErr: true},
		{name: "regular-runtime", packageInstall: "1", prepare: func(t *testing.T, _ string) { t.Helper(); mustWriteFile(t, serviceSystemdRuntimePath, "unsafe") }, want: serviceManagerAmbiguous, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := withServiceRuntimeTestState(t, test.packageInstall)
			if test.prepare != nil {
				test.prepare(t, root)
			}
			got, err := classifyServiceManagerRuntime(test.alpine)
			if got != test.want || (err != nil) != test.wantErr {
				t.Fatalf("classifyServiceManagerRuntime() = %q, %v; want %q, error=%v", got, err, test.want, test.wantErr)
			}
		})
	}
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	mustMkdirAll(t, filepath.Dir(path))
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func mustChmodTestPath(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := root.Chmod(filepath.Base(path), mode); err != nil {
		t.Fatal(err)
	}
}

func mustReadTestFile(t *testing.T, path string) []byte {
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

func mustSeedOpenRCRuntime(t *testing.T, root, runtimePath string) {
	t.Helper()
	mustWriteFile(t, filepath.Join(runtimePath, "softlevel"), "default\n")
	mustWriteFile(t, filepath.Join(root, "proc", "1", "comm"), "init\n")
}

func mustSeedSystemdRuntime(t *testing.T, root, runtimePath string) {
	t.Helper()
	mustMkdirAll(t, runtimePath)
	mustWriteFile(t, filepath.Join(root, "proc", "1", "comm"), "systemd\n")
	executable := filepath.Join(root, "proc", "1", "exe")
	if err := os.Symlink("/usr/lib/systemd/systemd", executable); err != nil {
		t.Fatal(err)
	}
}

func TestPublishExactServiceArtifacts(t *testing.T) {
	root := t.TempDir()
	unit := filepath.Join(root, "system", "syswarden-core.service")
	enablement := filepath.Join(root, "wants", "syswarden-core.service")
	if _, err := publishExactServiceFile(unit, systemdCoreService, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := publishExactServiceEnablement(enablement, "../syswarden-core.service"); err != nil {
		t.Fatal(err)
	}
	if _, err := publishExactServiceFile(unit, systemdCoreService, 0600); err != nil {
		t.Fatalf("idempotent file publication failed: %v", err)
	}
	if _, err := publishExactServiceEnablement(enablement, "../syswarden-core.service"); err != nil {
		t.Fatalf("idempotent link publication failed: %v", err)
	}
	content := mustReadTestFile(t, unit)
	if string(content) != systemdCoreService {
		t.Fatal("published unit differs")
	}
	if info, err := os.Lstat(unit); err != nil || info.Mode().Perm() != 0600 || !info.Mode().IsRegular() {
		t.Fatalf("published unit metadata differs: %v, %v", info, err)
	}
	if target, err := os.Readlink(enablement); err != nil || target != "../syswarden-core.service" {
		t.Fatalf("published link = %q, %v", target, err)
	}
}

func TestPublishExactServiceArtifactsRefusesModifiedTargets(t *testing.T) {
	root := t.TempDir()
	unit := filepath.Join(root, "system", "syswarden-core.service")
	enablement := filepath.Join(root, "wants", "syswarden-core.service")
	mustWriteFile(t, unit, "operator content\n")
	if _, err := publishExactServiceFile(unit, systemdCoreService, 0600); err == nil {
		t.Fatal("expected modified service file refusal")
	}
	mustMkdirAll(t, filepath.Dir(enablement))
	if err := os.Symlink("../operator.service", enablement); err != nil {
		t.Fatal(err)
	}
	if _, err := publishExactServiceEnablement(enablement, "../syswarden-core.service"); err == nil {
		t.Fatal("expected modified service enablement refusal")
	}
}

func TestPublishExactServiceArtifactsRejectsUnsafeDirectory(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "units")
	mustMkdirAll(t, directory)
	mustChmodTestPath(t, directory, 0777)
	if _, err := publishExactServiceFile(filepath.Join(directory, "syswarden-core.service"), systemdCoreService, 0600); err == nil {
		t.Fatal("group/other-writable service directory was accepted")
	}
}

func TestPinnedServiceDirectorySurvivesPathSwap(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "units")
	mustMkdirAll(t, directory)
	pinned, err := openPinnedServiceDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer pinned.close()
	moved := filepath.Join(root, "pinned-units")
	if err := os.Rename(directory, moved); err != nil {
		t.Fatal(err)
	}
	mustMkdirAll(t, directory)
	if err := pinned.root.WriteFile("proof", []byte("pinned\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(moved, "proof")); err != nil {
		t.Fatalf("pinned directory did not retain identity: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(directory, "proof")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement directory received pinned mutation: %v", err)
	}
}

func TestPublishServiceArtifactsRollsBackOnlyNewArtifacts(t *testing.T) {
	root := t.TempDir()
	created := filepath.Join(root, "units", "syswarden-core.service")
	modified := filepath.Join(root, "units", "syswarden-firewall.service")
	mustWriteFile(t, modified, "operator content\n")
	err := publishServiceArtifacts([]serviceArtifact{
		{path: created, content: systemdCoreService, mode: 0600},
		{path: modified, content: systemdFirewallService, mode: 0600},
	})
	if err == nil {
		t.Fatal("expected transactional publication failure")
	}
	if _, err := os.Lstat(created); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("new artifact survived rollback: %v", err)
	}
	content := mustReadTestFile(t, modified)
	if string(content) != "operator content\n" {
		t.Fatalf("pre-existing modified artifact changed: %q", content)
	}
}

func TestCoreServiceRequiresSuccessfulFirewallLoaderAtBoot_SW2_FWBACKEND_001(t *testing.T) {
	for _, required := range []string{
		"Requires=syswarden-firewall.service\n",
		"After=network.target rsyslog.service syswarden-firewall.service\n",
	} {
		if !strings.Contains(systemdCoreService, required) {
			t.Fatalf("systemd core unit lacks %q", required)
		}
	}
	if !strings.Contains(openRCCoreService, "need net rsyslog syswarden-firewall\n") {
		t.Fatal("OpenRC core unit does not require the firewall loader")
	}
}

func withSystemdPublicationTestPaths(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	unitDirectory := filepath.Join(root, "system")
	wantsDirectory := filepath.Join(root, "multi-user.target.wants")
	oldUnitDirectory := serviceSystemdUnitDir
	oldWantsDirectory := serviceSystemdWantsDir
	serviceSystemdUnitDir = unitDirectory
	serviceSystemdWantsDir = wantsDirectory
	t.Cleanup(func() {
		serviceSystemdUnitDir = oldUnitDirectory
		serviceSystemdWantsDir = oldWantsDirectory
	})
	return unitDirectory, wantsDirectory
}

func seedLegacySystemdPublication(t *testing.T, unitDirectory, wantsDirectory string) {
	t.Helper()
	mustWriteFile(t, filepath.Join(unitDirectory, "syswarden-core.service"), systemdCoreService)
	mustWriteFile(t, filepath.Join(unitDirectory, "syswarden-firewall.service"), systemdFirewallService)
	mustMkdirAll(t, wantsDirectory)
	if err := os.Symlink(
		"/etc/systemd/system/syswarden-core.service",
		filepath.Join(wantsDirectory, "syswarden-core.service"),
	); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(
		"/etc/systemd/system/syswarden-firewall.service",
		filepath.Join(wantsDirectory, "syswarden-firewall.service"),
	); err != nil {
		t.Fatal(err)
	}
}

func assertServiceEnablementTarget(t *testing.T, path, expected string) {
	t.Helper()
	target, err := os.Readlink(path)
	if err != nil || target != expected {
		t.Fatalf("service enablement %s = %q, %v; want %q", path, target, err, expected)
	}
}

func TestPublishSystemdServicesPreservesExactV4028Enablements(t *testing.T) {
	unitDirectory, wantsDirectory := withSystemdPublicationTestPaths(t)
	seedLegacySystemdPublication(t, unitDirectory, wantsDirectory)
	corePath := filepath.Join(wantsDirectory, "syswarden-core.service")
	firewallPath := filepath.Join(wantsDirectory, "syswarden-firewall.service")
	coreBefore, err := os.Lstat(corePath)
	if err != nil {
		t.Fatal(err)
	}
	firewallBefore, err := os.Lstat(firewallPath)
	if err != nil {
		t.Fatal(err)
	}

	if err := publishSystemdServices(); err != nil {
		t.Fatal(err)
	}
	assertServiceEnablementTarget(t, corePath, "/etc/systemd/system/syswarden-core.service")
	assertServiceEnablementTarget(t, firewallPath, "/etc/systemd/system/syswarden-firewall.service")
	coreAfter, err := os.Lstat(corePath)
	if err != nil || !os.SameFile(coreBefore, coreAfter) {
		t.Fatalf("legacy core enablement was mutated: %v", err)
	}
	firewallAfter, err := os.Lstat(firewallPath)
	if err != nil || !os.SameFile(firewallBefore, firewallAfter) {
		t.Fatalf("legacy firewall enablement was mutated: %v", err)
	}
	entries, err := os.ReadDir(wantsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("migration left unexpected enablement artifacts: %v", entries)
	}
}

func TestPublishSystemdServicesCreatesCanonicalRelativeEnablements(t *testing.T) {
	_, wantsDirectory := withSystemdPublicationTestPaths(t)
	if err := publishSystemdServices(); err != nil {
		t.Fatal(err)
	}
	assertServiceEnablementTarget(t, filepath.Join(wantsDirectory, "syswarden-core.service"), "../syswarden-core.service")
	assertServiceEnablementTarget(t, filepath.Join(wantsDirectory, "syswarden-firewall.service"), "../syswarden-firewall.service")
}

func TestPublishSystemdServicesRefusesOperatorEnablement(t *testing.T) {
	unitDirectory, wantsDirectory := withSystemdPublicationTestPaths(t)
	seedLegacySystemdPublication(t, unitDirectory, wantsDirectory)
	coreEnablement := filepath.Join(wantsDirectory, "syswarden-core.service")
	if err := os.Remove(coreEnablement); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../operator.service", coreEnablement); err != nil {
		t.Fatal(err)
	}

	if err := publishSystemdServices(); err == nil {
		t.Fatal("operator-controlled systemd enablement was accepted")
	}
	assertServiceEnablementTarget(t, coreEnablement, "../operator.service")
	assertServiceEnablementTarget(
		t,
		filepath.Join(wantsDirectory, "syswarden-firewall.service"),
		"/etc/systemd/system/syswarden-firewall.service",
	)
}

func TestPublishSystemdServicesRequiresExactLegacyUnit(t *testing.T) {
	unitDirectory, wantsDirectory := withSystemdPublicationTestPaths(t)
	seedLegacySystemdPublication(t, unitDirectory, wantsDirectory)
	coreUnit := filepath.Join(unitDirectory, "syswarden-core.service")
	if err := os.WriteFile(coreUnit, []byte("operator content\n"), 0600); err != nil {
		t.Fatal(err)
	}

	if err := publishSystemdServices(); err == nil {
		t.Fatal("legacy systemd enablement with a modified unit was accepted")
	}
	if content := string(mustReadTestFile(t, coreUnit)); content != "operator content\n" {
		t.Fatalf("modified unit changed: %q", content)
	}
	assertServiceEnablementTarget(
		t,
		filepath.Join(wantsDirectory, "syswarden-core.service"),
		"/etc/systemd/system/syswarden-core.service",
	)
}

func TestPublishSystemdServicesRollsBackLegacyMigration(t *testing.T) {
	unitDirectory, wantsDirectory := withSystemdPublicationTestPaths(t)
	seedLegacySystemdPublication(t, unitDirectory, wantsDirectory)
	firewallEnablement := filepath.Join(wantsDirectory, "syswarden-firewall.service")
	if err := os.Remove(firewallEnablement); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../operator.service", firewallEnablement); err != nil {
		t.Fatal(err)
	}

	if err := publishSystemdServices(); err == nil {
		t.Fatal("expected the second enablement to fail publication")
	}
	assertServiceEnablementTarget(
		t,
		filepath.Join(wantsDirectory, "syswarden-core.service"),
		"/etc/systemd/system/syswarden-core.service",
	)
	assertServiceEnablementTarget(t, firewallEnablement, "../operator.service")
}

func TestRemoveCreatedServiceEnablementRestoresConcurrentSubstitution(t *testing.T) {
	root := t.TempDir()
	enablement := filepath.Join(root, "syswarden-core.service")
	expectedTarget := "../syswarden-core.service"
	operatorTarget := "../operator.service"
	if err := os.Symlink(expectedTarget, enablement); err != nil {
		t.Fatal(err)
	}
	calls := 0
	rename := func(oldDirectory int, oldName string, newDirectory int, newName string, flags uint) error {
		calls++
		if calls == 1 {
			if err := os.Remove(enablement); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(operatorTarget, enablement); err != nil {
				t.Fatal(err)
			}
		}
		return unix.Renameat2(oldDirectory, oldName, newDirectory, newName, flags)
	}
	err := removeCreatedServiceArtifactUsing(serviceArtifact{path: enablement, target: expectedTarget}, rename)
	if err == nil {
		t.Fatal("concurrent substitution was accepted")
	}
	assertServiceEnablementTarget(t, enablement, operatorTarget)
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(enablement) {
		t.Fatalf("concurrent substitution cleanup changed operator state: %v", entries)
	}
}

func TestRemoveCreatedServiceFileRestoresConcurrentSubstitution(t *testing.T) {
	root := t.TempDir()
	unit := filepath.Join(root, "syswarden-core.service")
	mustWriteFile(t, unit, systemdCoreService)
	calls := 0
	rename := func(oldDirectory int, oldName string, newDirectory int, newName string, flags uint) error {
		calls++
		if calls == 1 {
			if err := os.Remove(unit); err != nil {
				t.Fatal(err)
			}
			mustWriteFile(t, unit, "operator content\n")
		}
		return unix.Renameat2(oldDirectory, oldName, newDirectory, newName, flags)
	}
	err := removeCreatedServiceArtifactUsing(
		serviceArtifact{path: unit, content: systemdCoreService, mode: 0600},
		rename,
	)
	if err == nil {
		t.Fatal("concurrent substitution was accepted")
	}
	if content := string(mustReadTestFile(t, unit)); content != "operator content\n" {
		t.Fatalf("operator service file was not restored: %q", content)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != filepath.Base(unit) {
		t.Fatalf("concurrent substitution cleanup changed operator state: %v", entries)
	}
}

func TestRemoveCreatedServiceArtifactNeverDeletesQuarantinedOperatorOnRestoreFailure(t *testing.T) {
	root := t.TempDir()
	enablement := filepath.Join(root, "syswarden-core.service")
	expectedTarget := "../syswarden-core.service"
	operatorTarget := "../operator.service"
	if err := os.Symlink(expectedTarget, enablement); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected quarantine restoration failure")
	calls := 0
	rename := func(oldDirectory int, oldName string, newDirectory int, newName string, flags uint) error {
		calls++
		if calls == 1 {
			if err := os.Remove(enablement); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(operatorTarget, enablement); err != nil {
				t.Fatal(err)
			}
			return unix.Renameat2(oldDirectory, oldName, newDirectory, newName, flags)
		}
		return injected
	}
	err := removeCreatedServiceArtifactUsing(serviceArtifact{path: enablement, target: expectedTarget}, rename)
	if !errors.Is(err, injected) {
		t.Fatalf("restoration failure was not propagated: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	operatorPreserved := false
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".syswarden-quarantine-") {
			continue
		}
		target, readErr := os.Readlink(filepath.Join(root, entry.Name()))
		if readErr == nil && target == operatorTarget {
			operatorPreserved = true
		}
	}
	if !operatorPreserved {
		t.Fatalf("quarantined operator dentry was deleted: %v", entries)
	}
}

func serviceManagerRecorder(failAt int, failure error) (serviceManagerRunner, *[]string) {
	calls := make([]string, 0, 3)
	run := func(name string, args ...string) error {
		calls = append(calls, strings.Join(append([]string{name}, args...), " "))
		if len(calls)-1 == failAt {
			return failure
		}
		return nil
	}
	return run, &calls
}

func TestActivateOpenRCServicePropagatesEveryFailure(t *testing.T) {
	failure := errors.New("injected service-manager failure")
	tests := []struct {
		name      string
		failAt    int
		wantCalls []string
		wantText  string
	}{
		{
			name:      "enable",
			failAt:    0,
			wantCalls: []string{"rc-update add syswarden-core default"},
			wantText:  "enable OpenRC service syswarden-core",
		},
		{
			name:      "restart",
			failAt:    1,
			wantCalls: []string{"rc-update add syswarden-core default", "rc-service syswarden-core restart"},
			wantText:  "restart OpenRC service syswarden-core",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			run, calls := serviceManagerRecorder(test.failAt, failure)
			err := activateOpenRCService(run, "syswarden-core", "restart")
			if !errors.Is(err, failure) {
				t.Fatalf("expected injected failure, got %v", err)
			}
			if !strings.Contains(err.Error(), test.wantText) {
				t.Fatalf("error %q does not identify failed operation %q", err, test.wantText)
			}
			if !reflect.DeepEqual(*calls, test.wantCalls) {
				t.Fatalf("unexpected calls: got %v, want %v", *calls, test.wantCalls)
			}
		})
	}
}

func TestActivateOpenRCServicePreservesSuccessfulStart(t *testing.T) {
	run, calls := serviceManagerRecorder(-1, nil)
	if err := activateOpenRCService(run, "syswarden-firewall", "start"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"rc-update add syswarden-firewall default",
		"rc-service syswarden-firewall start",
	}
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("unexpected calls: got %v, want %v", *calls, want)
	}
}

func TestActivateSystemdServicePropagatesEveryFailure(t *testing.T) {
	failure := errors.New("injected service-manager failure")
	allCalls := []string{
		"systemctl daemon-reload",
		"systemctl enable --now syswarden-core.service",
		"systemctl restart syswarden-core.service",
	}
	for failAt, operation := range []string{"reload systemd", "enable and start systemd service", "restart systemd service"} {
		t.Run(fmt.Sprintf("step-%d", failAt+1), func(t *testing.T) {
			run, calls := serviceManagerRecorder(failAt, failure)
			err := activateSystemdService(run, "syswarden-core.service", true)
			if !errors.Is(err, failure) {
				t.Fatalf("expected injected failure, got %v", err)
			}
			if !strings.Contains(err.Error(), operation) {
				t.Fatalf("error %q does not identify failed operation %q", err, operation)
			}
			if !reflect.DeepEqual(*calls, allCalls[:failAt+1]) {
				t.Fatalf("unexpected calls: got %v, want %v", *calls, allCalls[:failAt+1])
			}
		})
	}
}

func TestActivateSystemdServicePreservesNonRestartingService(t *testing.T) {
	run, calls := serviceManagerRecorder(-1, nil)
	if err := activateSystemdService(run, "syswarden-firewall.service", false); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"systemctl daemon-reload",
		"systemctl enable --now syswarden-firewall.service",
	}
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("unexpected calls: got %v, want %v", *calls, want)
	}
}
