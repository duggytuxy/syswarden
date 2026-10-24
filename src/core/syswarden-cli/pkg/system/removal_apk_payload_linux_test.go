//go:build linux

package system

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAPKRecoveryCopySurvivesPayloadEraseAndReusesExactBackup(t *testing.T) {
	base, root, expected := standalonePayloadFixture(t)
	source, backups := filepath.Join(base, "syswarden"), filepath.Join(base, "backups")
	// An operator file next to the package is neither copied nor adopted.
	if err := root.WriteFile("syswarden/operator.conf", []byte("private operator data"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := root.Stat("syswarden/bin/syswarden-cli")
	if err != nil {
		t.Fatal(err)
	}
	path, err := preserveAPKPayload(source, backups, expected, nil)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(path, "bin/syswarden-cli"))
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, info) {
		t.Fatal("recovery copy shares mutable package inode")
	}
	second, err := preserveAPKPayload(source, backups, expected, nil)
	if err != nil || second != path {
		t.Fatal("recovery copy was not reusable", second, err)
	}
	again, err := os.Stat(filepath.Join(path, "bin/syswarden-cli"))
	if err != nil || !os.SameFile(info, again) {
		t.Fatal("existing backup was replaced")
	}
	if _, err := os.Stat(filepath.Join(path, "operator.conf")); !os.IsNotExist(err) {
		t.Fatal("operator file copied", err)
	}
	if err := root.RemoveAll("syswarden"); err != nil {
		t.Fatal(err)
	}
	saved, err := openExistingPinnedServiceDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	defer saved.close()
	snapshot, err := inspectStandalonePayload(saved, expected)
	if err != nil || filepath.Base(path) != "apk-payload-"+snapshot.digest {
		t.Fatal("recovery lost compiled bindings", err)
	}
}

func TestAPKRecoveryRefusesUnsafeInputsAndNeverOverwritesBackup(t *testing.T) {
	for _, scenario := range []string{"changed-source", "source-symlink", "source-hardlink", "missing-binding", "unsafe-parent", "backup-symlink", "backup-changed", "source-raced", "parent-raced", "existing-extra"} {
		t.Run(scenario, func(t *testing.T) {
			base, root, expected := standalonePayloadFixture(t)
			source, backups := filepath.Join(base, "syswarden"), filepath.Join(base, "backups")
			var race func()
			switch scenario {
			case "changed-source":
				if err := root.WriteFile("syswarden/bin/syswarden-core", []byte("changed"), 0750); err != nil {
					t.Fatal(err)
				}
			case "source-symlink":
				if err := root.Remove("syswarden/bin/syswarden-cli"); err != nil {
					t.Fatal(err)
				}
				if err := root.Symlink("syswarden-core", "syswarden/bin/syswarden-cli"); err != nil {
					t.Fatal(err)
				}
			case "source-hardlink":
				if err := root.Link("syswarden/bin/syswarden-core", "other"); err != nil {
					t.Fatal(err)
				}
			case "missing-binding":
				delete(expected, "bin/syswarden-core")
			case "unsafe-parent":
				if err := root.Chmod("backups", 0777); err != nil {
					t.Fatal(err)
				}
			case "source-raced":
				race = func() {
					if err := root.WriteFile("syswarden/bin/syswarden-core", []byte("changed"), 0750); err != nil {
						t.Fatal(err)
					}
				}
			case "parent-raced":
				race = func() {
					if err := root.Rename("backups", "displaced"); err != nil {
						t.Fatal(err)
					}
					if err := root.Mkdir("backups", 0750); err != nil {
						t.Fatal(err)
					}
				}
			default:
				path, err := preserveAPKPayload(source, backups, expected, nil)
				if err != nil {
					t.Fatal(err)
				}
				switch scenario {
				case "backup-symlink":
					if err := os.Rename(path, path+"-original"); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(path+"-original", path); err != nil {
						t.Fatal(err)
					}
				case "backup-changed":
					if err := os.WriteFile(filepath.Join(path, "bin/syswarden-cli"), []byte("changed"), 0600); err != nil {
						t.Fatal(err)
					} // #nosec G304 -- Private fixture path returned by the tested writer.
				case "existing-extra":
					if err := os.WriteFile(filepath.Join(path, "extra"), []byte("retain"), 0600); err != nil {
						t.Fatal(err)
					} // #nosec G304 -- Private fixture path returned by the tested writer.
				}
			}
			if path, err := preserveAPKPayload(source, backups, expected, race); err == nil || path != "" {
				t.Fatal("unsafe recovery copy accepted", path, err)
			}
		})
	}
}

func TestAPKRecoveryScannerRefusesUnboundDeletedOriginalProcesses(t *testing.T) {
	for _, binary := range []string{"syswarden-cli", "syswarden-tui", "syswarden-core"} {
		t.Run(binary, func(t *testing.T) {
			base, root, _ := standalonePayloadFixture(t)
			if err := root.Mkdir("proc", 0700); err != nil {
				t.Fatal(err)
			}
			original := filepath.Join(base, "syswarden/bin", binary)
			// A different inode with the original deleted alias must not be ignored.
			other := filepath.Join(base, "other")
			if err := root.WriteFile("other", []byte("other executable"), 0750); err != nil {
				t.Fatal(err)
			}
			proc := filepath.Join(base, "proc")
			writeFirewallRemovalProcessFixture(t, proc, "501", other, []string{original, "reload"}, true)
			scanner := newFirewallRemovalProcessScannerForTest(t, proc, filepath.Join(base, "syswarden/bin/syswarden-cli"), 999, "")
			scanner.rejectCore = true
			readlink := scanner.readlink
			scanner.readlink = func(path string) (string, error) {
				if path == filepath.Join(proc, "501/exe") {
					return original + " (deleted)", nil
				}
				return readlink(path)
			}
			if err := scanner.scan(); err == nil || !strings.Contains(err.Error(), "process 501") {
				t.Fatal("unbound original process escaped", err)
			}
		})
	}
}
