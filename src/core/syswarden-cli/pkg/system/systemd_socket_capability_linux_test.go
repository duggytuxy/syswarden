//go:build linux

package system

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeSocketPolicyPreservesLegacyUnitAndEffectiveCapabilities(t *testing.T) {
	packaged := mustReadTestFile(t, filepath.Join("..", "..", "..", "..", "init", "systemd", "syswarden-core.service.d", "10-syswarden-socket-ownership.conf"))
	if string(packaged) != systemdCoreSocketCapabilityDropIn {
		t.Fatal("compiled socket policy differs from the package payload")
	}
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(historicalV4043SystemdCoreService))); got != "8d84f0eeb3bf912055eadee1173b5b354b7e03f9bef34ab43546b06458e980bd" {
		t.Fatal("native base unit no longer matches the immutable v4.04.3 unit")
	}
	capabilities := func(text string) string {
		var values []string
		for _, line := range strings.Split(text, "\n") {
			if value, ok := strings.CutPrefix(line, "CapabilityBoundingSet="); ok {
				values = append(values, value)
			}
		}
		return strings.Join(values, " ")
	}
	// systemd merges these positive directives by union, with no reset or
	// ambient capability added by the package policy.
	if capabilities(historicalV4043SystemdCoreService+systemdCoreSocketCapabilityDropIn) != capabilities(systemdCoreService) {
		t.Fatal("native compatibility layout changes the effective capability set")
	}
}

func TestNativeCorePublicationSupportsRollbackWithoutAcceptingModifiedUnits(t *testing.T) {
	for _, previous := range []string{historicalV4043SystemdCoreService, systemdCoreService} {
		for _, mode := range []os.FileMode{0600, 0644} {
			for _, modified := range []bool{false, true} {
				t.Run(fmt.Sprintf("size-%d-mode-%04o-modified-%t", len(previous), mode, modified), func(t *testing.T) {
					directory, wants := withSystemdPublicationTestPaths(t)
					core := filepath.Join(directory, "syswarden-core.service")
					input := previous
					if modified {
						input += "# Operator customization\n"
					}
					mustWriteFile(t, core, input)
					mustChmodTestPath(t, core, mode)
					mustWriteFile(t, filepath.Join(directory, "syswarden-firewall.service"), systemdFirewallService)
					mustMkdirAll(t, wants)
					err := publishSystemdServicesWithCore(historicalV4043SystemdCoreService)
					if modified {
						if err == nil || string(mustReadTestFile(t, core)) != input {
							t.Fatalf("modified unit was not refused and preserved: %v", err)
						}
					} else if err != nil {
						t.Fatal(err)
					} else if string(mustReadTestFile(t, core)) != historicalV4043SystemdCoreService {
						t.Fatal("native unit is not byte-compatible with the legacy installer")
					}
					assertNoServiceMigrationArtifacts(t, directory)
				})
			}
		}
	}
}

func TestCoreSocketPolicySelectionRequiresExactStablePackageOwnership(t *testing.T) {
	for _, scenario := range []string{"dpkg", "rpm", "absent", "modified", "mode", "symlink", "hardlink", "unowned", "dual-owner", "owner-drift", "file-drift"} {
		t.Run(scenario, func(t *testing.T) {
			root, path, uid, gid := testSysWardenSystemdOrderingFixture(t)
			mustWriteFile(t, path, systemdCoreSocketCapabilityDropIn)
			mustChmodTestPath(t, path, 0644)
			calls := 0
			executor := testSysWardenOrderingPackageExecutor(t, path,
				scenario != "rpm" && scenario != "unowned",
				scenario == "rpm" || scenario == "dual-owner",
				func(manager string) string {
					calls++
					if scenario == "owner-drift" && calls > 1 {
						return "4.04.3"
					}
					if scenario == "file-drift" {
						mustWriteFile(t, path, systemdCoreSocketCapabilityDropIn+"# changed\n")
					}
					if manager == "rpm" {
						return "4.10.0-1"
					}
					return "4.10.0"
				})
			switch scenario {
			case "absent", "symlink":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if scenario == "symlink" {
					if err := os.Symlink("missing", path); err != nil {
						t.Fatal(err)
					}
				}
			case "modified":
				mustWriteFile(t, path, strings.ReplaceAll(systemdCoreSocketCapabilityDropIn, "CAP_CHOWN", "CAP_KILL"))
			case "mode":
				mustChmodTestPath(t, path, 0600)
			case "hardlink":
				if err := os.Link(path, filepath.Join(root, "alias")); err != nil {
					t.Fatal(err)
				}
			}
			content, err := selectSystemdCoreServiceContentAt(executor, path, root, uid, gid)
			switch scenario {
			case "dpkg", "rpm":
				if err != nil || content != historicalV4043SystemdCoreService {
					t.Fatalf("authenticated native policy was not selected: %v", err)
				}
			case "absent":
				if err != nil || content != systemdCoreService || calls != 0 {
					t.Fatalf("absent policy did not retain the self-contained source unit: %v", err)
				}
			default:
				if err == nil || content != "" {
					t.Fatal("untrusted native policy selected a legacy base unit")
				}
			}
		})
	}
}
