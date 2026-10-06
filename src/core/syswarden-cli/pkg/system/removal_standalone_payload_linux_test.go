//go:build linux

package system

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func standalonePayloadFixture(t *testing.T) (string, *os.Root, map[string]string) {
	t.Helper()
	base := t.TempDir()
	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	for _, name := range []string{"syswarden", "syswarden/bin", "backups"} {
		if err := root.Mkdir(name, 0750); err != nil {
			t.Fatal(err)
		}
	}
	expected := map[string]string{}
	for _, name := range []string{"bin/syswarden-cli", "bin/syswarden-core", "bin/syswarden-tui", "signatures.json"} {
		wire := []byte("Exact fixture payload for " + name + "\n")
		mode := os.FileMode(0750)
		if name == "signatures.json" {
			mode = 0640
		}
		if err := root.WriteFile("syswarden/"+name, wire, mode); err != nil {
			t.Fatal(err)
		}
		expected[name] = fmt.Sprintf("%x", sha256.Sum256(wire))
	}
	return base, root, expected
}

func TestRetainedStandaloneProcessScanRejectsOriginalAndRelocatedMutators(t *testing.T) {
	for _, binary := range []string{"syswarden-cli", "syswarden-core", "syswarden-tui"} {
		for _, deletedAlias := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/deleted=%t", binary, deletedAlias), func(t *testing.T) {
				base, root, _ := standalonePayloadFixture(t)
				if err := root.Mkdir("proc", 0700); err != nil {
					t.Fatal(err)
				}
				if err := root.Rename("syswarden", "retained"); err != nil {
					t.Fatal(err)
				}
				original := filepath.Join(base, "syswarden/bin", binary)
				retained := filepath.Join(base, "retained/bin", binary)
				args := []string{original}
				if binary == "syswarden-cli" {
					args = append(args, "reload")
				}
				proc := filepath.Join(base, "proc")
				writeFirewallRemovalProcessFixture(t, proc, "501", retained, args, true)
				scanner := newFirewallRemovalProcessScannerForTest(t, proc, filepath.Join(base, "syswarden/bin/syswarden-cli"), 999, "")
				scanner.rejectCore = true
				if deletedAlias {
					readlink := scanner.readlink
					scanner.readlink = func(path string) (string, error) {
						if path == filepath.Join(proc, "501/exe") {
							return original + " (deleted)", nil
						}
						return readlink(path)
					}
				}
				scanner = bindRetainedStandaloneProcessScanner(scanner, filepath.Join(base, "retained"))
				if err := scanner.scan(); err == nil || !strings.Contains(err.Error(), "process 501") {
					t.Fatal("retained executable escaped concurrent process detection", err)
				}
				scanner.selfPID = 501
				if err := scanner.scan(); err != nil {
					t.Fatal("current finalizer was not excluded", err)
				}
			})
		}
	}
}

func TestStandalonePayloadRetirementUsesExactCompanionBindings(t *testing.T) {
	for _, scenario := range []string{"exact", "modified", "unbound", "extra", "nested-extra", "symlink", "hardlink", "permissions", "concurrent-entry"} {
		t.Run(scenario, func(t *testing.T) {
			base, root, expected := standalonePayloadFixture(t)
			before, err := root.Stat("syswarden")
			if err != nil {
				t.Fatal(err)
			}
			name := "syswarden/bin/syswarden-core"
			switch scenario {
			case "modified":
				err = root.WriteFile(name, []byte("Operator replacement.\n"), 0750)
			case "unbound":
				expected["bin/syswarden-core"] = ""
			case "extra":
				err = root.WriteFile("syswarden/operator.conf", []byte("keep"), 0600)
			case "nested-extra":
				err = root.WriteFile("syswarden/bin/operator-helper", []byte("keep"), 0700)
			case "symlink":
				err = root.Rename(name, "operator-original")
				if err == nil {
					err = root.Symlink("../../operator-original", name)
				}
			case "hardlink":
				err = root.Link(name, "operator-link")
			case "permissions":
				err = root.Chmod(name, 0770)
			}
			if err != nil {
				t.Fatal(err)
			}
			original, err := root.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			checks := 0
			guard := func() error {
				checks++
				if scenario == "concurrent-entry" && checks == 2 {
					return root.WriteFile("syswarden/bin/operator-helper", []byte("keep"), 0700)
				}
				return nil
			}
			inspect := func(directory *pinnedServiceDirectory) (retainedDirectorySnapshot, error) {
				return inspectStandalonePayload(directory, expected)
			}
			backup, err := retireAttestedDirectory(base, "syswarden", filepath.Join(base, "backups"), "standalone-payload", guard, inspect, unix.Renameat2)
			if scenario != "exact" {
				if err == nil {
					t.Fatal("unproven payload was retired")
				}
				got, readErr := root.ReadFile(name)
				if readErr != nil || string(got) != string(original) {
					t.Fatal("refused payload changed", readErr)
				}
				if _, statErr := root.Stat("syswarden/bin/syswarden-cli"); statErr != nil {
					t.Fatal("recovery CLI was lost", statErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			after, err := os.Stat(backup)
			if err != nil || !os.SameFile(before, after) {
				t.Fatal("original payload tree was not retained", err)
			}
			saved, err := openExistingPinnedServiceDirectory(backup)
			if err != nil {
				t.Fatal(err)
			}
			defer saved.close()
			if _, err := inspect(saved); err != nil {
				t.Fatal("retained payload lost its exact bindings", err)
			}
			if _, err := root.Lstat("syswarden"); !os.IsNotExist(err) {
				t.Fatal("active payload remains", err)
			}
		})
	}
}
