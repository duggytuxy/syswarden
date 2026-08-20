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
