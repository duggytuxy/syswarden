//go:build linux

package firewall

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func pendingFirewallTree(t *testing.T, host nftPersistenceFilesystem) map[string]os.FileInfo {
	t.Helper()
	result := make(map[string]os.FileInfo)
	if err := fs.WalkDir(host.root.FS(), ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := host.root.Lstat(path)
		if err == nil {
			result[path] = info
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return result
}

func assertPendingFirewallTreeUnchanged(t *testing.T, host nftPersistenceFilesystem, before map[string]os.FileInfo) {
	t.Helper()
	after := pendingFirewallTree(t, host)
	if len(before) != len(after) {
		t.Fatalf("read-only inspection changed inventory: before=%d after=%d", len(before), len(after))
	}
	for path, original := range before {
		current, exists := after[path]
		if !exists || !sameNFTPersistenceIdentity(original, current) {
			t.Errorf("read-only inspection changed %s", path)
		}
	}
}

func TestPendingFirewallInspectionDoesNotCreateStateOrLock(t *testing.T) {
	for _, stateExists := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing_state", true: "existing_state"}[stateExists], func(t *testing.T) {
			root, host := fixtureNFTPersistenceFilesystem(t)
			if !stateExists {
				if err := host.root.Remove("etc/syswarden"); err != nil {
					t.Fatal(err)
				}
			}
			oldLock := nftRuntimeLockPath
			nftRuntimeLockPath = filepath.Join(root, "run", "must-not-be-created.lock")
			t.Cleanup(func() { nftRuntimeLockPath = oldLock })
			before := pendingFirewallTree(t, host)
			if err := refusePendingAuthoritativeTransaction(host); err != nil {
				t.Fatal(err)
			}
			assertPendingFirewallTreeUnchanged(t, host, before)
			if _, err := host.root.Lstat("run"); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("inspection created a runtime lock directory: %v", err)
			}
		})
	}
}

func TestPendingFirewallInspectionRefusesEveryJournalShapeWithoutOpeningIt(t *testing.T) {
	for _, kind := range []string{"regular", "empty", "malformed", "directory", "symlink", "dangling_symlink", "fifo", "hardlink", "unreadable", "writable", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			root, host := fixtureNFTPersistenceFilesystem(t)
			logical := "etc/syswarden/" + nftTransactionJournalName
			path := filepath.Join(root, logical)
			var err error
			switch kind {
			case "directory":
				err = host.root.Mkdir(logical, 0700)
			case "symlink", "dangling_symlink":
				if kind == "symlink" {
					writeNFTPersistenceFixture(t, root, "etc/syswarden/original", "private journal bytes\n")
				}
				err = host.root.Symlink("original", logical)
			case "fifo":
				err = syscall.Mkfifo(path, 0600)
			default:
				content := "{\"version\":1}\n"
				if kind == "empty" {
					content = ""
				} else if kind == "malformed" {
					content = "not a journal\n"
				}
				writeNFTPersistenceFixture(t, root, logical, content)
				switch kind {
				case "hardlink":
					err = host.root.Link(logical, "etc/syswarden/other-link")
				case "unreadable":
					err = host.root.Chmod(logical, 0000)
				case "writable":
					err = host.root.Chmod(logical, 0660) // #nosec G302 -- Deliberately unsafe synthetic metadata tests no-follow refusal.
				case "oversized":
					var file *os.File
					file, err = host.root.OpenFile(logical, os.O_WRONLY, 0)
					if err == nil {
						err = errors.Join(file.Truncate(1<<30), file.Close())
					}
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			before := pendingFirewallTree(t, host)
			if err := refusePendingAuthoritativeTransaction(host); err == nil {
				t.Fatal("journal presence was accepted")
			}
			assertPendingFirewallTreeUnchanged(t, host, before)
		})
	}
}

func TestPendingFirewallInspectionRefusesUnsafeStatePath(t *testing.T) {
	for _, kind := range []string{"symlink", "file", "writable_state", "writable_parent", "linked_parent", "wrong_owner", "wrong_group", "missing_parent"} {
		t.Run(kind, func(t *testing.T) {
			root, host := fixtureNFTPersistenceFilesystem(t)
			var err error
			switch kind {
			case "symlink", "file":
				err = host.root.Rename("etc/syswarden", "etc/saved-state")
				if err == nil && kind == "symlink" {
					err = host.root.Symlink("saved-state", "etc/syswarden")
				} else if err == nil {
					writeNFTPersistenceFixture(t, root, "etc/syswarden", "not a directory\n")
				}
			case "writable_state":
				err = host.root.Chmod("etc/syswarden", 0770) // #nosec G302 -- Deliberately unsafe synthetic directory metadata.
			case "writable_parent":
				err = host.root.Chmod("etc", 0770) // #nosec G302 -- Deliberately unsafe synthetic directory metadata.
			case "linked_parent", "missing_parent":
				err = host.root.Rename("etc", "saved-etc")
				if err == nil && kind == "linked_parent" {
					err = host.root.Symlink("saved-etc", "etc")
				}
			case "wrong_owner":
				host.expectedUID++
			case "wrong_group":
				host.expectedGID++
			}
			if err != nil {
				t.Fatal(err)
			}
			before := pendingFirewallTree(t, host)
			if err := refusePendingAuthoritativeTransaction(host); err == nil {
				t.Fatal("unsafe state path proved journal absence")
			}
			assertPendingFirewallTreeUnchanged(t, host, before)
		})
	}
}

func TestPendingFirewallInspectionRefusesLateStateDrift(t *testing.T) {
	for _, kind := range []string{"journal_appears", "state_replaced", "state_removed", "mode_changed", "parent_replaced", "missing_state_appears", "missing_state_parent_replaced"} {
		t.Run(kind, func(t *testing.T) {
			root, host := fixtureNFTPersistenceFilesystem(t)
			if kind == "missing_state_appears" || kind == "missing_state_parent_replaced" {
				if err := host.root.Remove("etc/syswarden"); err != nil {
					t.Fatal(err)
				}
			}
			var afterDrift map[string]os.FileInfo
			host.afterRead = func() {
				var err error
				switch kind {
				case "journal_appears":
					writeNFTPersistenceFixture(t, root, "etc/syswarden/"+nftTransactionJournalName, "pending\n")
				case "state_replaced":
					err = host.root.Rename("etc/syswarden", "etc/saved-state")
					if err == nil {
						err = host.root.Mkdir("etc/syswarden", 0700)
					}
				case "state_removed":
					err = host.root.Remove("etc/syswarden")
				case "mode_changed":
					err = host.root.Chmod("etc/syswarden", 0700)
				case "parent_replaced", "missing_state_parent_replaced":
					err = host.root.Rename("etc", "saved-etc")
					if err == nil {
						err = host.root.Mkdir("etc", 0700)
					}
					if err == nil && kind == "parent_replaced" {
						err = host.root.Mkdir("etc/syswarden", 0700)
					}
				case "missing_state_appears":
					err = host.root.Mkdir("etc/syswarden", 0700)
				}
				if err != nil {
					t.Fatal(err)
				}
				afterDrift = pendingFirewallTree(t, host)
			}
			if err := refusePendingAuthoritativeTransaction(host); err == nil {
				t.Fatal("changed state proved stable journal absence")
			}
			if afterDrift == nil {
				t.Fatal("late observation hook was not reached")
			}
			assertPendingFirewallTreeUnchanged(t, host, afterDrift)
		})
	}
}
