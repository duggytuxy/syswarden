//go:build linux

package system

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
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
		{name: "openrc-standard-group-writable-runtime", alpine: true, prepare: func(t *testing.T, root string) {
			t.Helper()
			mustSeedOpenRCRuntime(t, root, serviceOpenRCRuntimePath)
			mustChmodTestPath(t, serviceOpenRCRuntimePath, 0775)
		}, want: serviceManagerActive},
		{name: "openrc-stale-directory", alpine: true, packageInstall: "1", prepare: func(t *testing.T, _ string) { t.Helper(); mustMkdirAll(t, serviceOpenRCRuntimePath) }, want: serviceManagerAmbiguous, wantErr: true},
		{name: "openrc-pid1-mismatch", alpine: true, packageInstall: "1", prepare: func(t *testing.T, root string) {
			t.Helper()
			mustSeedOpenRCRuntime(t, root, serviceOpenRCRuntimePath)
			mustWriteFile(t, filepath.Join(root, "proc", "1", "comm"), "systemd\n")
		}, want: serviceManagerAmbiguous, wantErr: true},
		{name: "openrc-nonstandard-owner-only-mode", alpine: true, packageInstall: "1", prepare: func(t *testing.T, root string) {
			t.Helper()
			mustSeedOpenRCRuntime(t, root, serviceOpenRCRuntimePath)
			mustChmodTestPath(t, serviceOpenRCRuntimePath, 0700)
		}, want: serviceManagerAmbiguous, wantErr: true},
		{name: "openrc-nonstandard-group-mode", alpine: true, packageInstall: "1", prepare: func(t *testing.T, root string) {
			t.Helper()
			mustSeedOpenRCRuntime(t, root, serviceOpenRCRuntimePath)
			mustChmodTestPath(t, serviceOpenRCRuntimePath, 0770)
		}, want: serviceManagerAmbiguous, wantErr: true},
		{name: "openrc-world-writable-runtime", alpine: true, packageInstall: "1", prepare: func(t *testing.T, root string) {
			t.Helper()
			mustSeedOpenRCRuntime(t, root, serviceOpenRCRuntimePath)
			mustChmodTestPath(t, serviceOpenRCRuntimePath, 0777)
		}, want: serviceManagerAmbiguous, wantErr: true},
		{name: "openrc-sticky-runtime", alpine: true, packageInstall: "1", prepare: func(t *testing.T, root string) {
			t.Helper()
			mustSeedOpenRCRuntime(t, root, serviceOpenRCRuntimePath)
			mustChmodTestPath(t, serviceOpenRCRuntimePath, os.ModeSticky|0775)
		}, want: serviceManagerAmbiguous, wantErr: true},
		{name: "openrc-setgid-runtime", alpine: true, packageInstall: "1", prepare: func(t *testing.T, root string) {
			t.Helper()
			mustSeedOpenRCRuntime(t, root, serviceOpenRCRuntimePath)
			mustChmodTestPath(t, serviceOpenRCRuntimePath, os.ModeSetgid|0775)
		}, want: serviceManagerAmbiguous, wantErr: true},
		{name: "openrc-setuid-runtime", alpine: true, packageInstall: "1", prepare: func(t *testing.T, root string) {
			t.Helper()
			mustSeedOpenRCRuntime(t, root, serviceOpenRCRuntimePath)
			mustChmodTestPath(t, serviceOpenRCRuntimePath, os.ModeSetuid|0775)
		}, want: serviceManagerAmbiguous, wantErr: true},
		{name: "systemd-offline-package", packageInstall: "1", want: serviceManagerOffline},
		{name: "openrc-offline-package", alpine: true, packageInstall: "1", want: serviceManagerOffline},
		{name: "missing-outside-package", want: serviceManagerAmbiguous, wantErr: true},
		{name: "wrong-package-marker", packageInstall: "true", want: serviceManagerAmbiguous, wantErr: true},
		{name: "conflicting-runtime", packageInstall: "1", prepare: func(t *testing.T, _ string) { t.Helper(); mustMkdirAll(t, serviceOpenRCRuntimePath) }, want: serviceManagerAmbiguous, wantErr: true},
		{name: "competing-openrc-standard-mode-remains-unsafe", packageInstall: "1", prepare: func(t *testing.T, _ string) {
			t.Helper()
			mustMkdirAll(t, serviceOpenRCRuntimePath)
			mustChmodTestPath(t, serviceOpenRCRuntimePath, 0775)
		}, want: serviceManagerAmbiguous, wantErr: true},
		{name: "systemd-runtime-keeps-generic-mode-policy", packageInstall: "1", prepare: func(t *testing.T, root string) {
			t.Helper()
			mustSeedSystemdRuntime(t, root, serviceSystemdRuntimePath)
			mustChmodTestPath(t, serviceSystemdRuntimePath, 0775)
		}, want: serviceManagerAmbiguous, wantErr: true},
		{name: "symlinked-runtime", packageInstall: "1", prepare: func(t *testing.T, root string) {
			t.Helper()
			mustMkdirAll(t, filepath.Dir(serviceSystemdRuntimePath))
			if err := os.Symlink(filepath.Join(root, "run"), serviceSystemdRuntimePath); err != nil {
				t.Fatal(err)
			}
		}, want: serviceManagerAmbiguous, wantErr: true},
		{name: "symlinked-openrc-runtime", alpine: true, packageInstall: "1", prepare: func(t *testing.T, root string) {
			t.Helper()
			realRuntime := filepath.Join(root, "real-openrc")
			mustSeedOpenRCRuntime(t, root, realRuntime)
			if err := os.Symlink(realRuntime, serviceOpenRCRuntimePath); err != nil {
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
	mustChmodTestPath(t, runtimePath, 0755)
	mustWriteFile(t, filepath.Join(root, "proc", "1", "comm"), "init\n")
}

func TestOpenRCRuntimeDirectoryAttestationRejectsOwnershipMismatch(t *testing.T) {
	root := t.TempDir()
	runtimePath := filepath.Join(root, "run", "openrc")
	mustSeedOpenRCRuntime(t, root, runtimePath)
	info, err := os.Lstat(runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("OpenRC runtime ownership is unavailable")
	}
	for _, test := range []struct {
		name string
		uid  uint32
		gid  uint32
	}{
		{name: "uid", uid: stat.Uid ^ 1, gid: stat.Gid},
		{name: "gid", uid: stat.Uid, gid: stat.Gid ^ 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			proof, present, err := beginOpenRCRuntimeDirectoryAttestation(
				runtimePath,
				test.uid,
				test.gid,
			)
			if err == nil || present || proof != nil ||
				!strings.Contains(err.Error(), "refusing unsafe service-manager runtime") {
				t.Fatalf("ownership mismatch = %v, %v, %v", proof, present, err)
			}
		})
	}
}

func TestOpenRCRuntimeDirectoryAttestationRejectsNonCanonicalPath(t *testing.T) {
	root := t.TempDir()
	runtimePath := filepath.Join(root, "run", "openrc")
	mustSeedOpenRCRuntime(t, root, runtimePath)
	info, err := os.Lstat(runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("OpenRC runtime ownership is unavailable")
	}
	proof, present, err := beginOpenRCRuntimeDirectoryAttestation(
		runtimePath+"/../openrc",
		stat.Uid,
		stat.Gid,
	)
	if err == nil || present || proof != nil ||
		!strings.Contains(err.Error(), "refusing non-canonical service-manager runtime") {
		t.Fatalf("non-canonical OpenRC runtime path = %v, %v, %v", proof, present, err)
	}
}

func TestOpenRCRuntimeDirectoryAttestationRejectsMetadataAndIdentityDrift(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, root, runtimePath string)
	}{
		{
			name: "mode",
			mutate: func(t *testing.T, _, runtimePath string) {
				t.Helper()
				mustChmodTestPath(t, runtimePath, 0770)
			},
		},
		{
			name: "replacement",
			mutate: func(t *testing.T, root, runtimePath string) {
				t.Helper()
				if err := os.Rename(runtimePath, runtimePath+".original"); err != nil {
					t.Fatal(err)
				}
				mustSeedOpenRCRuntime(t, root, runtimePath)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			runtimePath := filepath.Join(root, "run", "openrc")
			mustSeedOpenRCRuntime(t, root, runtimePath)
			rootInfo, err := os.Lstat(root)
			if err != nil {
				t.Fatal(err)
			}
			rootStat, ok := rootInfo.Sys().(*syscall.Stat_t)
			if !ok {
				t.Fatal("test root ownership is unavailable")
			}
			proof, present, err := beginOpenRCRuntimeDirectoryAttestation(
				runtimePath,
				rootStat.Uid,
				rootStat.Gid,
			)
			if err != nil || !present || proof == nil {
				t.Fatalf("begin OpenRC runtime attestation = %v, %v, %v", proof, present, err)
			}
			defer func() { _ = proof.directory.Close() }()
			test.mutate(t, root, runtimePath)
			if err := proof.reattest(rootStat.Uid, rootStat.Gid); err == nil ||
				!strings.Contains(err.Error(), "changed while attesting") {
				t.Fatalf("OpenRC runtime drift was accepted: %v", err)
			}
		})
	}
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

func TestSystemdFirewallServiceWaitsForInstalledCronProviderAtBoot(t *testing.T) {
	const ordering = "After=network-online.target rsyslog.service cron.service crond.service\n"
	if strings.Count(systemdFirewallService, ordering) != 1 {
		t.Fatalf("systemd firewall unit lacks exact cron provider ordering %q", ordering)
	}
	for _, dependency := range []string{
		"Wants=cron.service",
		"Wants=crond.service",
		"Requires=cron.service",
		"Requires=crond.service",
	} {
		if strings.Contains(systemdFirewallService, dependency) {
			t.Fatalf("systemd firewall unit must not pull in an absent cron provider alias via %q", dependency)
		}
	}
}

func TestOpenRCFirewallServiceRequiresExactRuntimeProvidersAtBoot(t *testing.T) {
	const dependencies = "\tneed net rsyslog cronie\n"
	if strings.Count(openRCFirewallService, dependencies) != 1 {
		t.Fatalf("OpenRC firewall service lacks exact runtime provider dependencies %q", dependencies)
	}
	if !strings.Contains(openRCFirewallService, "\tbefore syswarden-core\n") {
		t.Fatal("OpenRC firewall service does not start before the core service")
	}
}

func TestHistoricalV4028ServiceAnchors(t *testing.T) {
	tests := []struct {
		name       string
		content    string
		wantLength int
		wantSHA256 string
	}{
		{
			name:       "systemd-core",
			content:    historicalV4028SystemdCoreService,
			wantLength: historicalV4028SystemdCoreServiceLength,
			wantSHA256: historicalV4028SystemdCoreServiceSHA256,
		},
		{
			name:       "openrc-core",
			content:    historicalV4028OpenRCCoreService,
			wantLength: historicalV4028OpenRCCoreServiceLength,
			wantSHA256: historicalV4028OpenRCCoreServiceSHA256,
		},
		{
			name:       "systemd-firewall",
			content:    historicalV4028SystemdFirewallService,
			wantLength: historicalV4028SystemdFirewallServiceLength,
			wantSHA256: historicalV4028SystemdFirewallServiceSHA256,
		},
		{
			name:       "openrc-firewall",
			content:    historicalV4028OpenRCFirewallService,
			wantLength: historicalV4028OpenRCFirewallServiceLength,
			wantSHA256: historicalV4028OpenRCFirewallServiceSHA256,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			digest := sha256.Sum256([]byte(test.content))
			if got := len([]byte(test.content)); got != test.wantLength {
				t.Fatalf("historical content length = %d, want %d", got, test.wantLength)
			}
			if got := fmt.Sprintf("%x", digest); got != test.wantSHA256 {
				t.Fatalf("historical content SHA-256 = %s, want %s", got, test.wantSHA256)
			}
		})
	}
}

func assertNoServiceMigrationArtifacts(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".syswarden-service-") ||
			strings.HasPrefix(entry.Name(), ".syswarden-quarantine-") {
			t.Fatalf("unexpected service migration artifact %s", filepath.Join(directory, entry.Name()))
		}
	}
}

func systemdCoreMigrationArtifact(path string) serviceArtifact {
	return serviceArtifact{
		path:                    path,
		content:                 systemdCoreService,
		mode:                    0600,
		historicalContent:       historicalV4028SystemdCoreService,
		historicalContentLength: historicalV4028SystemdCoreServiceLength,
		historicalContentSHA256: historicalV4028SystemdCoreServiceSHA256,
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

func withOpenRCPublicationTestPaths(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	unitDirectory := filepath.Join(root, "init.d")
	runlevelDirectory := filepath.Join(root, "runlevels", "default")
	oldUnitDirectory := serviceOpenRCUnitDir
	oldRunlevelDirectory := serviceOpenRCRunlevelDir
	serviceOpenRCUnitDir = unitDirectory
	serviceOpenRCRunlevelDir = runlevelDirectory
	t.Cleanup(func() {
		serviceOpenRCUnitDir = oldUnitDirectory
		serviceOpenRCRunlevelDir = oldRunlevelDirectory
	})
	return unitDirectory, runlevelDirectory
}

func seedLegacySystemdPublication(t *testing.T, unitDirectory, wantsDirectory string) {
	t.Helper()
	mustWriteFile(t, filepath.Join(unitDirectory, "syswarden-core.service"), historicalV4028SystemdCoreService)
	mustWriteFile(t, filepath.Join(unitDirectory, "syswarden-firewall.service"), historicalV4028SystemdFirewallService)
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

func seedLegacyOpenRCPublication(t *testing.T, unitDirectory, runlevelDirectory string) {
	t.Helper()
	corePath := filepath.Join(unitDirectory, "syswarden-core")
	firewallPath := filepath.Join(unitDirectory, "syswarden-firewall")
	mustWriteFile(t, corePath, historicalV4028OpenRCCoreService)
	mustWriteFile(t, firewallPath, historicalV4028OpenRCFirewallService)
	mustChmodTestPath(t, corePath, 0755)
	mustChmodTestPath(t, firewallPath, 0755)
	mustMkdirAll(t, runlevelDirectory)
	if err := os.Symlink("/etc/init.d/syswarden-core", filepath.Join(runlevelDirectory, "syswarden-core")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/init.d/syswarden-firewall", filepath.Join(runlevelDirectory, "syswarden-firewall")); err != nil {
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

func TestPublishSystemdServicesMigratesExactV4028UnitsAtomicallyAndIdempotently(t *testing.T) {
	unitDirectory, wantsDirectory := withSystemdPublicationTestPaths(t)
	seedLegacySystemdPublication(t, unitDirectory, wantsDirectory)
	corePath := filepath.Join(unitDirectory, "syswarden-core.service")
	firewallPath := filepath.Join(unitDirectory, "syswarden-firewall.service")
	historicalCore, err := os.Lstat(corePath)
	if err != nil {
		t.Fatal(err)
	}
	historicalFirewall, err := os.Lstat(firewallPath)
	if err != nil {
		t.Fatal(err)
	}

	if err := publishSystemdServices(); err != nil {
		t.Fatal(err)
	}
	migratedCore, err := os.Lstat(corePath)
	if err != nil {
		t.Fatal(err)
	}
	migratedFirewall, err := os.Lstat(firewallPath)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(historicalCore, migratedCore) {
		t.Fatal("historical systemd core inode was not atomically replaced")
	}
	if os.SameFile(historicalFirewall, migratedFirewall) {
		t.Fatal("historical systemd firewall inode was not atomically replaced")
	}
	if got := string(mustReadTestFile(t, corePath)); got != systemdCoreService {
		t.Fatalf("migrated systemd core = %q", got)
	}
	if got := string(mustReadTestFile(t, firewallPath)); got != systemdFirewallService {
		t.Fatalf("migrated systemd firewall = %q", got)
	}
	if migratedCore.Mode().Perm() != 0600 || !serviceFileHasSingleLink(migratedCore) {
		t.Fatalf("migrated systemd core metadata = %v", migratedCore.Mode())
	}
	if migratedFirewall.Mode().Perm() != 0600 || !serviceFileHasSingleLink(migratedFirewall) {
		t.Fatalf("migrated systemd firewall metadata = %v", migratedFirewall.Mode())
	}
	assertNoServiceMigrationArtifacts(t, unitDirectory)

	if err := publishSystemdServices(); err != nil {
		t.Fatalf("idempotent systemd publication failed: %v", err)
	}
	reattestedCore, err := os.Lstat(corePath)
	if err != nil || !os.SameFile(migratedCore, reattestedCore) {
		t.Fatalf("idempotent systemd publication replaced the current core unit: %v", err)
	}
	reattestedFirewall, err := os.Lstat(firewallPath)
	if err != nil || !os.SameFile(migratedFirewall, reattestedFirewall) {
		t.Fatalf("idempotent systemd publication replaced the current firewall unit: %v", err)
	}
	assertNoServiceMigrationArtifacts(t, unitDirectory)
}

func TestPublishOpenRCServicesMigratesExactV4028UnitsAtomicallyAndIdempotently(t *testing.T) {
	unitDirectory, runlevelDirectory := withOpenRCPublicationTestPaths(t)
	seedLegacyOpenRCPublication(t, unitDirectory, runlevelDirectory)
	corePath := filepath.Join(unitDirectory, "syswarden-core")
	firewallPath := filepath.Join(unitDirectory, "syswarden-firewall")
	historicalCore, err := os.Lstat(corePath)
	if err != nil {
		t.Fatal(err)
	}
	historicalFirewall, err := os.Lstat(firewallPath)
	if err != nil {
		t.Fatal(err)
	}

	if err := publishOpenRCServices(); err != nil {
		t.Fatal(err)
	}
	migratedCore, err := os.Lstat(corePath)
	if err != nil {
		t.Fatal(err)
	}
	migratedFirewall, err := os.Lstat(firewallPath)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(historicalCore, migratedCore) {
		t.Fatal("historical OpenRC core inode was not atomically replaced")
	}
	if os.SameFile(historicalFirewall, migratedFirewall) {
		t.Fatal("historical OpenRC firewall inode was not atomically replaced")
	}
	if got := string(mustReadTestFile(t, corePath)); got != openRCCoreService {
		t.Fatalf("migrated OpenRC core = %q", got)
	}
	if got := string(mustReadTestFile(t, firewallPath)); got != openRCFirewallService {
		t.Fatalf("migrated OpenRC firewall = %q", got)
	}
	if migratedCore.Mode().Perm() != 0755 || !serviceFileHasSingleLink(migratedCore) {
		t.Fatalf("migrated OpenRC core metadata = %v", migratedCore.Mode())
	}
	if migratedFirewall.Mode().Perm() != 0755 || !serviceFileHasSingleLink(migratedFirewall) {
		t.Fatalf("migrated OpenRC firewall metadata = %v", migratedFirewall.Mode())
	}
	assertNoServiceMigrationArtifacts(t, unitDirectory)

	if err := publishOpenRCServices(); err != nil {
		t.Fatalf("idempotent OpenRC publication failed: %v", err)
	}
	reattestedCore, err := os.Lstat(corePath)
	if err != nil || !os.SameFile(migratedCore, reattestedCore) {
		t.Fatalf("idempotent OpenRC publication replaced the current core unit: %v", err)
	}
	reattestedFirewall, err := os.Lstat(firewallPath)
	if err != nil || !os.SameFile(migratedFirewall, reattestedFirewall) {
		t.Fatalf("idempotent OpenRC publication replaced the current firewall unit: %v", err)
	}
	assertNoServiceMigrationArtifacts(t, unitDirectory)
}

func TestPublishMigratableServiceFileRefusesNonExactHistoricalState(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(t *testing.T, path string) string
	}{
		{
			name: "one-byte-variation",
			prepare: func(t *testing.T, path string) string {
				t.Helper()
				content := []byte(historicalV4028SystemdCoreService)
				content[len(content)-2] ^= 1
				mustWriteFile(t, path, string(content))
				return string(content)
			},
		},
		{
			name: "wrong-mode",
			prepare: func(t *testing.T, path string) string {
				t.Helper()
				mustWriteFile(t, path, historicalV4028SystemdCoreService)
				mustChmodTestPath(t, path, 0644)
				return historicalV4028SystemdCoreService
			},
		},
		{
			name: "special-mode",
			prepare: func(t *testing.T, path string) string {
				t.Helper()
				mustWriteFile(t, path, historicalV4028SystemdCoreService)
				if err := os.Chmod(path, 0600|os.ModeSetuid); err != nil {
					t.Fatal(err)
				}
				return historicalV4028SystemdCoreService
			},
		},
		{
			name: "multiple-links",
			prepare: func(t *testing.T, path string) string {
				t.Helper()
				mustWriteFile(t, path, historicalV4028SystemdCoreService)
				if err := os.Link(path, path+".operator-link"); err != nil {
					t.Fatal(err)
				}
				return historicalV4028SystemdCoreService
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "syswarden-core.service")
			before := test.prepare(t, path)
			if err := publishServiceArtifacts([]serviceArtifact{systemdCoreMigrationArtifact(path)}); err == nil {
				t.Fatal("non-exact historical service state was accepted")
			}
			if got := string(mustReadTestFile(t, path)); got != before {
				t.Fatalf("refused historical service state changed: %q", got)
			}
			assertNoServiceMigrationArtifacts(t, directory)
		})
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
	if got := string(mustReadTestFile(t, filepath.Join(unitDirectory, "syswarden-core.service"))); got != historicalV4028SystemdCoreService {
		t.Fatalf("historical systemd core was not restored after bundle failure: %q", got)
	}
	if got := string(mustReadTestFile(t, filepath.Join(unitDirectory, "syswarden-firewall.service"))); got != historicalV4028SystemdFirewallService {
		t.Fatalf("historical systemd firewall was not restored after bundle failure: %q", got)
	}
	assertServiceEnablementTarget(
		t,
		filepath.Join(wantsDirectory, "syswarden-core.service"),
		"/etc/systemd/system/syswarden-core.service",
	)
	assertServiceEnablementTarget(t, firewallEnablement, "../operator.service")
	assertNoServiceMigrationArtifacts(t, unitDirectory)
}

func TestPublishSystemdServicesKeepsFirewallUnitStrictAndRollsBackCore(t *testing.T) {
	unitDirectory, wantsDirectory := withSystemdPublicationTestPaths(t)
	seedLegacySystemdPublication(t, unitDirectory, wantsDirectory)
	corePath := filepath.Join(unitDirectory, "syswarden-core.service")
	firewallPath := filepath.Join(unitDirectory, "syswarden-firewall.service")
	mustWriteFile(t, firewallPath, "operator firewall service\n")

	if err := publishSystemdServices(); err == nil {
		t.Fatal("modified firewall unit was accepted")
	}
	if got := string(mustReadTestFile(t, corePath)); got != historicalV4028SystemdCoreService {
		t.Fatalf("core migration was not rolled back after firewall refusal: %q", got)
	}
	if got := string(mustReadTestFile(t, firewallPath)); got != "operator firewall service\n" {
		t.Fatalf("operator firewall unit changed: %q", got)
	}
	assertNoServiceMigrationArtifacts(t, unitDirectory)
}

func TestPublishOpenRCServicesKeepsFirewallUnitStrictAndRollsBackCore(t *testing.T) {
	unitDirectory, runlevelDirectory := withOpenRCPublicationTestPaths(t)
	seedLegacyOpenRCPublication(t, unitDirectory, runlevelDirectory)
	corePath := filepath.Join(unitDirectory, "syswarden-core")
	firewallPath := filepath.Join(unitDirectory, "syswarden-firewall")
	mustWriteFile(t, firewallPath, "operator firewall service\n")
	mustChmodTestPath(t, firewallPath, 0755)

	if err := publishOpenRCServices(); err == nil {
		t.Fatal("modified OpenRC firewall service was accepted")
	}
	if got := string(mustReadTestFile(t, corePath)); got != historicalV4028OpenRCCoreService {
		t.Fatalf("OpenRC core migration was not rolled back after firewall refusal: %q", got)
	}
	if got := string(mustReadTestFile(t, firewallPath)); got != "operator firewall service\n" {
		t.Fatalf("operator OpenRC firewall service changed: %q", got)
	}
	assertNoServiceMigrationArtifacts(t, unitDirectory)
}

func TestPublishMigratableServiceFileCleansUpOnExchangeFault(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "syswarden-core.service")
	mustWriteFile(t, path, historicalV4028SystemdCoreService)
	injected := errors.New("injected migration exchange failure")
	failed := false
	rename := func(oldDirectory int, oldName string, newDirectory int, newName string, flags uint) error {
		if flags == unix.RENAME_EXCHANGE && !failed {
			failed = true
			return injected
		}
		return unix.Renameat2(oldDirectory, oldName, newDirectory, newName, flags)
	}

	if _, err := publishMigratableServiceFileUsing(systemdCoreMigrationArtifact(path), rename); !errors.Is(err, injected) {
		t.Fatalf("exchange failure was not propagated: %v", err)
	}
	if got := string(mustReadTestFile(t, path)); got != historicalV4028SystemdCoreService {
		t.Fatalf("historical unit changed after exchange failure: %q", got)
	}
	assertNoServiceMigrationArtifacts(t, directory)
}

func TestPublishMigratableServiceFileRollsBackOnQuarantineFault(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "syswarden-core.service")
	mustWriteFile(t, path, historicalV4028SystemdCoreService)
	injected := errors.New("injected migration quarantine failure")
	exchanged := false
	failed := false
	rename := func(oldDirectory int, oldName string, newDirectory int, newName string, flags uint) error {
		if flags == unix.RENAME_EXCHANGE {
			err := unix.Renameat2(oldDirectory, oldName, newDirectory, newName, flags)
			if err == nil {
				exchanged = true
			}
			return err
		}
		if exchanged && !failed && flags == unix.RENAME_NOREPLACE &&
			strings.HasPrefix(oldName, ".syswarden-service-") &&
			strings.HasPrefix(newName, ".syswarden-quarantine-") {
			failed = true
			return injected
		}
		return unix.Renameat2(oldDirectory, oldName, newDirectory, newName, flags)
	}

	if _, err := publishMigratableServiceFileUsing(systemdCoreMigrationArtifact(path), rename); !errors.Is(err, injected) {
		t.Fatalf("quarantine failure was not propagated: %v", err)
	}
	if got := string(mustReadTestFile(t, path)); got != historicalV4028SystemdCoreService {
		t.Fatalf("historical unit was not restored after quarantine failure: %q", got)
	}
	assertNoServiceMigrationArtifacts(t, directory)
}

func TestPublishMigratableServiceFileNeverRepublishesMutatedQuarantine(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "syswarden-core.service")
	mustWriteFile(t, path, historicalV4028SystemdCoreService)
	mutated := []byte(historicalV4028SystemdCoreService)
	mutated[len(mutated)-2] ^= 1
	mutatedQuarantine := false
	rename := func(oldDirectory int, oldName string, newDirectory int, newName string, flags uint) error {
		err := unix.Renameat2(oldDirectory, oldName, newDirectory, newName, flags)
		if err == nil && flags == unix.RENAME_EXCHANGE && !mutatedQuarantine {
			mutatedQuarantine = true
			if writeErr := os.WriteFile(filepath.Join(directory, oldName), mutated, 0600); writeErr != nil {
				t.Fatal(writeErr)
			}
		}
		return err
	}

	if _, err := publishMigratableServiceFileUsing(systemdCoreMigrationArtifact(path), rename); err == nil {
		t.Fatal("mutated historical quarantine was accepted")
	}
	if got := string(mustReadTestFile(t, path)); got != systemdCoreService {
		t.Fatalf("exact replacement was not preserved at the target: %q", got)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	foundMutatedQuarantine := false
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".syswarden-service-") {
			t.Fatalf("unclassified migration temporary survived: %s", entry.Name())
		}
		if !strings.HasPrefix(entry.Name(), ".syswarden-quarantine-") {
			continue
		}
		if got := mustReadTestFile(t, filepath.Join(directory, entry.Name())); reflect.DeepEqual(got, mutated) {
			foundMutatedQuarantine = true
		}
	}
	if !foundMutatedQuarantine {
		t.Fatalf("mutated historical object was not preserved in quarantine: %v", entries)
	}
}

func TestRollbackMigratedServiceFileRefusesConcurrentTargetSubstitution(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "syswarden-core.service")
	mustWriteFile(t, path, historicalV4028SystemdCoreService)
	change, err := publishMigratableServiceFileUsing(systemdCoreMigrationArtifact(path), unix.Renameat2)
	if err != nil || change.migration == nil {
		t.Fatalf("prepare migration = %+v, %v", change, err)
	}
	defer change.migration.close()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, path, "operator replacement\n")

	if err := rollbackMigratedServiceFile(change.migration); err == nil {
		t.Fatal("concurrent target substitution was accepted during rollback")
	}
	if got := string(mustReadTestFile(t, path)); got != "operator replacement\n" {
		t.Fatalf("operator replacement changed during refused rollback: %q", got)
	}
	if got := string(mustReadTestFile(t, filepath.Join(directory, change.migration.quarantineName))); got != historicalV4028SystemdCoreService {
		t.Fatalf("historical quarantine changed during refused rollback: %q", got)
	}
}

func TestRollbackMigratedServiceFileReversesHistoricalQuarantineMutation(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "syswarden-core.service")
	mustWriteFile(t, path, historicalV4028SystemdCoreService)
	mutated := []byte(historicalV4028SystemdCoreService)
	mutated[len(mutated)-2] ^= 1
	exchanges := 0
	rename := func(oldDirectory int, oldName string, newDirectory int, newName string, flags uint) error {
		err := unix.Renameat2(oldDirectory, oldName, newDirectory, newName, flags)
		if err == nil && flags == unix.RENAME_EXCHANGE {
			exchanges++
			if exchanges == 2 {
				if writeErr := os.WriteFile(path, mutated, 0600); writeErr != nil {
					t.Fatal(writeErr)
				}
			}
		}
		return err
	}
	change, err := publishMigratableServiceFileUsing(systemdCoreMigrationArtifact(path), rename)
	if err != nil || change.migration == nil {
		t.Fatalf("prepare migration = %+v, %v", change, err)
	}
	defer change.migration.close()

	if err := rollbackMigratedServiceFile(change.migration); err == nil {
		t.Fatal("historical quarantine mutation during rollback was accepted")
	}
	if got := string(mustReadTestFile(t, path)); got != systemdCoreService {
		t.Fatalf("replacement was not restored after reversing raced rollback: %q", got)
	}
	if got := mustReadTestFile(t, filepath.Join(directory, change.migration.quarantineName)); !reflect.DeepEqual(got, mutated) {
		t.Fatalf("mutated historical object was not preserved in quarantine: %q", got)
	}
}

func TestMigrationCommitNeverAttemptsRollbackAfterPostUnlinkFault(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "syswarden-core.service")
	mustWriteFile(t, path, historicalV4028SystemdCoreService)
	change, err := publishMigratableServiceFileUsing(systemdCoreMigrationArtifact(path), unix.Renameat2)
	if err != nil || change.migration == nil {
		t.Fatalf("prepare migration = %+v, %v", change, err)
	}
	injected := errors.New("injected post-unlink directory sync failure")
	syncCalls := 0
	commit := func(migration *migratedServiceFile) (bool, error) {
		return commitMigratedServiceFileUsing(
			migration,
			unix.Unlinkat,
			func() error {
				syncCalls++
				if syncCalls == 2 {
					return injected
				}
				return migration.directory.sync()
			},
		)
	}

	err = commitServiceArtifactChangesUsing([]serviceArtifactChange{change}, commit)
	if !errors.Is(err, injected) || !strings.Contains(err.Error(), "cannot roll back") {
		t.Fatalf("post-unlink failure did not expose the irreversible boundary: %v", err)
	}
	if !change.migration.closed {
		t.Fatal("migration directory remained open after irreversible commit failure")
	}
	if got := string(mustReadTestFile(t, path)); got != systemdCoreService {
		t.Fatalf("committed replacement was rolled back after historical unlink: %q", got)
	}
	if _, statErr := os.Lstat(filepath.Join(directory, change.migration.quarantineName)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("historical quarantine survived successful unlink: %v", statErr)
	}
	assertNoServiceMigrationArtifacts(t, directory)
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
