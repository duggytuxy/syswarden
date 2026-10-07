//go:build linux

package firewall

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func fixtureLegacyFail2banInventory(t *testing.T) (string, nftPersistenceFilesystem) {
	t.Helper()
	root, host := fixtureNFTPersistenceFilesystem(t)
	for _, directory := range []string{"jail.d", "action.d", "filter.d", "filter.d/custom.d"} {
		if err := os.MkdirAll(filepath.Join(root, legacyFail2banDirectory, directory), 0755); err != nil { // #nosec G301 -- Models system-directory permissions inside a private temporary root for ownership checks.
			t.Fatal(err)
		}
	}
	for path, content := range map[string]string{
		"jail.conf":                        "[DEFAULT]\nenabled = false\n",
		"jail.d/administrator.local":       "[administrator-web]\nenabled = true\n",
		"jail.d/.private-copy":             "[administrator-disabled]\nenabled = false\n",
		"filter.d/custom.d/settings.local": "[Definition]\nignoreregex =\n",
	} {
		writeNFTPersistenceFixture(t, root, legacyFail2banDirectory+"/"+path, content)
	}
	writeNFTPersistenceFixture(t, root, legacyFail2banDirectory+"/jail.d/syswarden-portscan.conf", string(readLegacyFail2banFixture(t, "portscan-pre_v2.conf")))
	return root, host
}

func readLegacyFail2banInventoryFixture(t *testing.T, host nftPersistenceFilesystem) legacyFail2banInventory {
	t.Helper()
	inventory, err := inspectLegacyFail2banInventory(host)
	if err != nil {
		t.Fatal(err)
	}
	return inventory
}

func TestLegacyFail2banInventoryIncludesHiddenAndDisabledSources(t *testing.T) {
	_, host := fixtureLegacyFail2banInventory(t)
	before := readLegacyFail2banInventoryFixture(t, host)
	after := readLegacyFail2banInventoryFixture(t, host)
	if !before.present || len(before.sources) != 5 || len(before.directories) != 5 {
		t.Fatalf("incomplete source tree: %d files, %d directories", len(before.sources), len(before.directories))
	}
	if err := verifyLegacyFail2banInventoryRetirement(before, after, nil); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyFail2banInventoryDetectsNewConfigurationAfterAbsence(t *testing.T) {
	root, host := fixtureNFTPersistenceFilesystem(t)
	before := readLegacyFail2banInventoryFixture(t, host)
	if before.present {
		t.Fatal("absent root reported present")
	}
	if err := verifyLegacyFail2banInventoryRetirement(before, readLegacyFail2banInventoryFixture(t, host), nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, legacyFail2banDirectory), 0755); err != nil { // #nosec G301 -- Models system-directory permissions inside a private temporary root for ownership checks.
		t.Fatal(err)
	}
	if err := verifyLegacyFail2banInventoryRetirement(before, readLegacyFail2banInventoryFixture(t, host), nil); err == nil {
		t.Fatal("new configuration root accepted as continued absence")
	}
}

func TestLegacyFail2banInventoryGuardPreservesAdministratorFilesDuringRetirement(t *testing.T) {
	root, host, record := fixtureLegacyFileRetirement(t)
	before := readLegacyFail2banInventoryFixture(t, host)
	retiring := []nftPersistenceRetiredSource{{path: record.Source.Path}}
	// Bind the exact source by path, independently of traversal order.
	for _, source := range before.sources {
		if source.path == record.Source.Path {
			retiring[0].sha256 = source.sha256
		}
	}
	guard := func(retired bool) error {
		current, err := inspectLegacyFail2banInventory(host)
		if err != nil {
			return err
		}
		if retired {
			return verifyLegacyFail2banInventoryRetirement(before, current, retiring)
		}
		return verifyLegacyFail2banInventoryRetirement(before, current, nil)
	}
	if err := retireLegacyConfigurationFileUsing(host, record, guard, defaultLegacyRetirementFileOps()); err != nil {
		t.Fatal(err)
	}
	assertLegacyRetirementComplete(t, root, host, record)
	if err := guard(true); err != nil {
		t.Fatal(err)
	}
}

func TestLegacyFail2banInventoryRejectsUnreviewedChanges(t *testing.T) {
	for _, change := range []string{"new_override", "new_hidden_file", "removed_admin", "rewrite_admin", "replace_same_bytes", "mode", "replace_directory", "new_directory", "missing_directory"} {
		t.Run(change, func(t *testing.T) {
			root, host := fixtureLegacyFail2banInventory(t)
			before := readLegacyFail2banInventoryFixture(t, host)
			admin := filepath.Join(root, legacyFail2banDirectory, "jail.d/administrator.local")
			var err error
			switch change {
			case "new_override":
				writeNFTPersistenceFixture(t, root, legacyFail2banDirectory+"/jail.d/syswarden-portscan.local", "[syswarden-portscan]\naction = custom\n")
			case "new_hidden_file":
				writeNFTPersistenceFixture(t, root, legacyFail2banDirectory+"/jail.d/.new", "private configuration\n")
			case "removed_admin":
				err = os.Remove(admin)
			case "rewrite_admin":
				err = os.WriteFile(admin, []byte("[administrator-web]\nenabled = false\n"), 0600)
			case "replace_same_bytes":
				content, readErr := os.ReadFile(admin) // #nosec G304 -- The path is constructed solely from this test's private temporary root and controlled fixture names.
				if readErr != nil {
					t.Fatal(readErr)
				}
				if err := os.Rename(admin, filepath.Join(root, "saved-admin")); err != nil {
					t.Fatal(err)
				}
				err = os.WriteFile(admin, content, 0600) // #nosec G703 -- The path is constructed solely from this test's private temporary root and controlled fixture names.
			case "mode":
				err = os.Chmod(admin, 0640) // #nosec G302 -- Deliberately varies synthetic metadata inside a private temporary root to test validation.
			case "replace_directory":
				path := filepath.Join(root, legacyFail2banDirectory, "action.d")
				if err := os.Rename(path, filepath.Join(root, "saved-actions")); err != nil {
					t.Fatal(err)
				}
				err = os.Mkdir(path, 0755) // #nosec G301 -- Models system-directory permissions inside a private temporary root for ownership checks.
			case "new_directory":
				err = os.Mkdir(filepath.Join(root, legacyFail2banDirectory, "custom.d"), 0755) // #nosec G301 -- Models system-directory permissions inside a private temporary root for ownership checks.
			case "missing_directory":
				err = os.Remove(filepath.Join(root, legacyFail2banDirectory, "action.d"))
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyLegacyFail2banInventoryRetirement(before, readLegacyFail2banInventoryFixture(t, host), nil); err == nil {
				t.Fatal("unreviewed configuration change was accepted")
			}
		})
	}
}

func TestLegacyFail2banInventoryRejectsUnsafeEntries(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "fifo", "writable", "linked_root"} {
		t.Run(kind, func(t *testing.T) {
			root, host := fixtureLegacyFail2banInventory(t)
			path := filepath.Join(root, legacyFail2banDirectory, "jail.d/administrator.local")
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink(path, path+".link")
			case "hardlink":
				err = os.Link(path, path+".link")
			case "fifo":
				err = syscall.Mkfifo(path+".fifo", 0600)
			case "writable":
				err = os.Chmod(filepath.Dir(path), 0777) // #nosec G302 -- Deliberately varies synthetic metadata inside a private temporary root to test validation.
			case "linked_root":
				path = filepath.Join(root, legacyFail2banDirectory)
				if err := os.Rename(path, path+".saved"); err != nil {
					t.Fatal(err)
				}
				err = os.Symlink(path+".saved", path)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := inspectLegacyFail2banInventory(host); err == nil {
				t.Fatal("unsafe configuration entry accepted")
			}
		})
	}
}

func TestLegacyFail2banInventoryRechecksEarlierFilesAndDirectoryMembership(t *testing.T) {
	for _, kind := range []string{"earlier_file", "new_file"} {
		t.Run(kind, func(t *testing.T) {
			root, host := fixtureLegacyFail2banInventory(t)
			reads := 0
			host.afterRead = func() {
				reads++
				if reads != 3 {
					return
				}
				path := "/filter.d/custom.d/settings.local"
				if kind == "new_file" {
					path = "/filter.d/custom.d/new.local"
				}
				writeNFTPersistenceFixture(t, root, legacyFail2banDirectory+path, "[Definition]\nignoreregex = changed\n")
			}
			if _, err := inspectLegacyFail2banInventory(host); err == nil {
				t.Fatal("change during inventory was missed")
			}
		})
	}
}

func TestLegacyFail2banInventoryRequiresUniqueRetirementDigests(t *testing.T) {
	root, host := fixtureLegacyFail2banInventory(t)
	before := readLegacyFail2banInventoryFixture(t, host)
	var target nftPersistenceRetiredSource
	for _, source := range before.sources {
		if strings.HasSuffix(source.path, "/syswarden-portscan.conf") {
			target = nftPersistenceRetiredSource{source.path, source.sha256}
		}
	}
	if target.path == "" {
		t.Fatal("missing target")
	}
	if err := os.Rename(filepath.Join(root, target.path), filepath.Join(root, "retired-file")); err != nil {
		t.Fatal(err)
	}
	after := readLegacyFail2banInventoryFixture(t, host)
	if err := verifyLegacyFail2banInventoryRetirement(before, after, []nftPersistenceRetiredSource{target}); err != nil {
		t.Fatal(err)
	}
	for _, plan := range [][]nftPersistenceRetiredSource{nil, {target, target}, {{target.path, sha256.Sum256([]byte("wrong"))}}, {{target.path + ".local", target.sha256}}} {
		if err := verifyLegacyFail2banInventoryRetirement(before, after, plan); err == nil {
			t.Fatal("unbound retirement plan accepted")
		}
	}
}

func TestLegacyFail2banInventoryBoundsTreeSize(t *testing.T) {
	for _, kind := range []string{"depth", "entries", "bytes"} {
		t.Run(kind, func(t *testing.T) {
			root, host := fixtureLegacyFail2banInventory(t)
			directory := filepath.Join(root, legacyFail2banDirectory, "action.d")
			switch kind {
			case "depth":
				if err := os.MkdirAll(filepath.Join(directory, strings.Repeat("nested/", maximumLegacyFail2banTreeDepth+1)), 0755); err != nil { // #nosec G301 -- Models system-directory permissions inside a private temporary root for ownership checks.
					t.Fatal(err)
				}
			case "entries":
				for index := 0; index <= maximumLegacyFail2banFiles; index++ {
					if err := os.WriteFile(filepath.Join(directory, fmt.Sprintf("%04d.conf", index)), nil, 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "bytes":
				for index := 0; index < 3; index++ {
					file, err := os.OpenFile(filepath.Join(directory, fmt.Sprintf("%d.conf", index)), os.O_CREATE|os.O_WRONLY, 0600) // #nosec G304 -- The path is constructed solely from this test's private temporary root and controlled fixture names.
					if err != nil {
						t.Fatal(err)
					}
					err = file.Truncate(maximumNFTPersistenceBytes)
					closeErr := file.Close()
					if err != nil || closeErr != nil {
						t.Fatal(err, closeErr)
					}
				}
			}
			if _, err := inspectLegacyFail2banInventory(host); err == nil {
				t.Fatal("unbounded configuration tree accepted")
			}
		})
	}
}
