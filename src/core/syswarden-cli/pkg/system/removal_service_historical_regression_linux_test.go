//go:build linux

package system

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreparedRemovalRecognizesExactHistoricalSystemdTemplates(t *testing.T) {
	for _, test := range []struct {
		name     string
		core     string
		firewall string
	}{
		{"v4028", historicalV4028SystemdCoreService, historicalV4028SystemdFirewallService},
		{"v4043", historicalV4043SystemdCoreService, systemdFirewallService},
	} {
		for _, mode := range []os.FileMode{0600, 0644} {
			t.Run(test.name+"/"+mode.String(), func(t *testing.T) {
				host, paths, reloads := newPreparedSystemdServiceArtifactTestHostWithUnitMode(t, mode)
				for path, content := range map[string]string{
					paths.coreUnit: test.core, paths.firewallUnit: test.firewall,
				} {
					if err := os.WriteFile(path, []byte(content), mode); err != nil {
						t.Fatal(err)
					}
				}
				var err error
				host.artifacts[0].content, err = selectExactSystemdRemovalContent(
					paths.coreUnit, systemdCoreService, historicalSystemdCoreRemovalTemplates(), systemTestUID(t), systemTestGID(t),
				)
				if err != nil {
					t.Fatal(err)
				}
				host.artifacts[1].content, err = selectExactSystemdRemovalContent(
					paths.firewallUnit, systemdFirewallService, historicalSystemdFirewallRemovalTemplates(), systemTestUID(t), systemTestGID(t),
				)
				if err != nil {
					t.Fatal(err)
				}
				_, err = host.capture()
				if *reloads != 0 {
					t.Fatal("read-only inspection invoked a service-manager mutation")
				}
				for path, content := range map[string]string{
					paths.coreUnit: test.core, paths.firewallUnit: test.firewall,
				} {
					if got := string(mustReadTestFile(t, path)); got != content {
						t.Fatal("historical service changed during inspection")
					}
				}
				if err != nil {
					t.Fatalf("recognized official historical service rejected: %v", err)
				}
				foreign := filepath.Join(filepath.Dir(paths.coreUnit), "operator.service")
				if err := os.WriteFile(foreign, []byte("operator-managed service\n"), 0600); err != nil {
					t.Fatal(err)
				}
				allowedModes := []os.FileMode{sourceSystemdUnitMode, historicalSourceSystemdUnitMode}
				for _, artifact := range []struct {
					enablement string
					unit       string
					content    string
					target     string
				}{
					{paths.coreEnablement, paths.coreUnit, host.artifacts[0].content, "../syswarden-core.service"},
					{paths.firewallEnable, paths.firewallUnit, host.artifacts[1].content, "../syswarden-firewall.service"},
				} {
					if err := removePreparedServiceEnablementModes(artifact.enablement, artifact.unit, artifact.content, allowedModes, artifact.target); err != nil {
						t.Fatal(err)
					}
					if err := removePreparedExactServiceFileModes(artifact.unit, artifact.content, allowedModes); err != nil {
						t.Fatal(err)
					}
					for _, path := range []string{artifact.enablement, artifact.unit} {
						if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
							t.Fatalf("historical service artifact remains at %s: %v", path, err)
						}
					}
				}
				if string(mustReadTestFile(t, foreign)) != "operator-managed service\n" {
					t.Fatal("historical removal changed an unrelated service")
				}
			})
		}
	}
}

func TestHistoricalSystemdRemovalSelectionRefusesUnsafeOrModifiedFiles(t *testing.T) {
	for _, name := range []string{"modified content", "symlink", "hardlink", "writable mode", "owner mismatch"} {
		t.Run(name, func(t *testing.T) {
			host, paths, reloads := newPreparedSystemdServiceArtifactTestHost(t)
			if err := os.WriteFile(paths.coreUnit, []byte(historicalV4028SystemdCoreService), 0600); err != nil {
				t.Fatal(err)
			}
			uid := systemTestUID(t)
			readPath := paths.coreUnit
			switch name {
			case "modified content":
				if err := os.WriteFile(paths.coreUnit, []byte(historicalV4028SystemdCoreService+"# local customization\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := filepath.Join(filepath.Dir(paths.coreUnit), "operator.service")
				readPath = target
				if err := os.Rename(paths.coreUnit, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, paths.coreUnit); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(paths.coreUnit, filepath.Join(filepath.Dir(paths.coreUnit), "operator.service")); err != nil {
					t.Fatal(err)
				}
			case "writable mode":
				if err := os.Chmod(paths.coreUnit, 0666); err != nil { // #nosec G302 -- deliberate unsafe service fixture must be rejected
					t.Fatal(err)
				}
			case "owner mismatch":
				uid++
			}
			before, err := os.Lstat(paths.coreUnit)
			if err != nil {
				t.Fatal(err)
			}
			original := mustReadTestFile(t, readPath)
			_, err = selectExactSystemdRemovalContent(paths.coreUnit, systemdCoreService, historicalSystemdCoreRemovalTemplates(), uid, systemTestGID(t))
			if err == nil {
				t.Fatal("unsafe or customized service was admitted")
			}
			after, statErr := os.Lstat(paths.coreUnit)
			if statErr != nil || !sameServiceFileMetadata(before, after) || string(original) != string(mustReadTestFile(t, readPath)) || *reloads != 0 {
				t.Fatal("rejected service was changed")
			}
			if _, err := host.capture(); err == nil {
				t.Fatal("unselected historical or modified content was admitted by exact capture")
			}
		})
	}
}

func TestHistoricalRemovalSelectionDoesNotFollowLaterTemplateChanges(t *testing.T) {
	host, paths, reloads := newPreparedSystemdServiceArtifactTestHost(t)
	if err := os.WriteFile(paths.coreUnit, []byte(historicalV4028SystemdCoreService), 0600); err != nil {
		t.Fatal(err)
	}
	selected, err := selectExactSystemdRemovalContent(paths.coreUnit, systemdCoreService, historicalSystemdCoreRemovalTemplates(), systemTestUID(t), systemTestGID(t))
	if err != nil {
		t.Fatal(err)
	}
	host.artifacts[0].content = selected
	if err := os.WriteFile(paths.coreUnit, []byte(systemdCoreService), 0600); err != nil {
		t.Fatal(err)
	}
	if err := host.recoverInterruptedRemoval(); err == nil || !strings.Contains(err.Error(), "modified service file") {
		t.Fatalf("changed selected service was not rejected: %v", err)
	}
	if *reloads != 0 || string(mustReadTestFile(t, paths.coreUnit)) != systemdCoreService {
		t.Fatal("race refusal mutated the live service")
	}
}

func TestHistoricalRemovalSelectionRequiresConsistentFrozenAnchors(t *testing.T) {
	_, paths, _ := newPreparedSystemdServiceArtifactTestHost(t)
	for _, change := range []string{"length", "digest", "content"} {
		t.Run(change, func(t *testing.T) {
			templates := historicalSystemdCoreRemovalTemplates()
			switch change {
			case "length":
				templates[0].length++
			case "digest":
				templates[0].sha256 = strings.Repeat("0", 64)
			case "content":
				templates[0].content += "\n"
			}
			if _, err := selectExactSystemdRemovalContent(paths.coreUnit, systemdCoreService, templates, systemTestUID(t), systemTestGID(t)); err == nil {
				t.Fatal("inconsistent historical anchor admitted a service")
			}
		})
	}
}
