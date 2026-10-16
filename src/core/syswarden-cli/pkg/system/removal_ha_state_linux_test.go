//go:build linux

package system

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func haRetentionFixture(t *testing.T) (string, string, *os.Root) {
	t.Helper()
	base := t.TempDir()
	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	for _, name := range []string{"state", "state/ha", "state/ha/fence", "backups"} {
		if err := root.Mkdir(name, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"server.crt", "server.key", "bans.json", "fence/native-sync-fence.json", "fence/native-sync-fence-epochs.json", "replication-v2.json", "replication-v2.wal.json", "replication-v2.json.anchor.json", "replication-v2.json.head.wal.json"} {
		if err := root.WriteFile("state/ha/"+name, []byte("Private opaque recovery bytes: "+name+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"fence/native-sync-fence.lock", "replication-v2.json.instance.lock"} {
		if err := root.WriteFile("state/ha/"+name, nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(base, "state"), filepath.Join(base, "backups"), root
}

func inspectHARetentionFixture(t *testing.T, parent string) (LegacyLogRetentionPlan, string) {
	t.Helper()
	dir, err := openExistingPinnedServiceDirectory(filepath.Join(parent, "ha"))
	if err != nil {
		t.Fatal(err)
	}
	defer dir.close()
	_, plan, err := inspectHAStateRetention(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := LegacyLogRetentionPlanSHA256(plan)
	if err != nil {
		t.Fatal(err)
	}
	return plan, digest
}

func TestHAStateRetentionPreservesWholeOriginalTreeAndResumes(t *testing.T) {
	parent, backups, root := haRetentionFixture(t)
	plan, digest := inspectHARetentionFixture(t, parent)
	wire, err := json.Marshal(plan)
	if err != nil || bytes.Contains(wire, []byte("Private opaque recovery bytes")) {
		t.Fatal("plan disclosed private content", err)
	}
	if len(plan.Files) != 12 {
		t.Fatalf("incomplete HA inventory: %d", len(plan.Files))
	}
	before := map[string]os.FileInfo{}
	for _, entry := range plan.Files {
		if entry.CreationProvenance {
			t.Fatal("explicit retention invented ownership")
		}
		relative, err := filepath.Rel(haRetentionDirectory, entry.Path)
		if err != nil {
			t.Fatal(err)
		}
		before[relative], err = root.Lstat("state/ha/" + relative)
		if err != nil {
			t.Fatal(err)
		}
	}
	guard := func() error { return nil }
	_, backup, err := applyLegacyRetention(parent, backups, digest, guard, unix.Renameat2, haRetentionProfile())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.Lstat("state/ha"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("active HA state remains", err)
	}
	retained, err := os.OpenRoot(backup)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = retained.Close() })
	for name, info := range before {
		saved, err := retained.Lstat(name)
		if err != nil || !os.SameFile(info, saved) {
			t.Fatal("original inode lost", name, err)
		}
		if info.Mode().IsRegular() {
			content, err := retained.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			expected := "Private opaque recovery bytes: " + name + "\n"
			if strings.HasSuffix(name, ".lock") {
				expected = ""
			}
			if string(content) != expected {
				t.Fatal("private bytes changed", name)
			}
		}
	}
	_, again, err := applyLegacyRetention(parent, backups, digest, guard, unix.Renameat2, haRetentionProfile())
	if err != nil || again != backup {
		t.Fatal("completed retention did not resume", err)
	}
	if err := retained.WriteFile("server.key", []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := applyLegacyRetention(parent, backups, digest, guard, unix.Renameat2, haRetentionProfile()); err == nil {
		t.Fatal("changed retained key was accepted")
	}
}

func TestHAStateRetentionRejectsUnsafeOrChangedInventory(t *testing.T) {
	for _, scenario := range []string{"digest", "confirmation-scope", "content-change", "nested-addition", "root-addition", "hardlink", "symlink", "fence-symlink", "public-key-mode", "public-fence-mode", "lock-content", "oversized-key", "guard", "late-nested-addition"} {
		t.Run(scenario, func(t *testing.T) {
			parent, backups, root := haRetentionFixture(t)
			_, digest := inspectHARetentionFixture(t, parent)
			var err error
			switch scenario {
			case "digest":
				digest = strings.Repeat("0", 64)
			case "confirmation-scope":
				digest = strings.Repeat("A", 64)
			case "content-change":
				err = root.WriteFile("state/ha/server.key", []byte("changed"), 0600)
			case "nested-addition":
				err = root.WriteFile("state/ha/fence/admin.json", []byte("keep"), 0600)
			case "root-addition":
				err = root.WriteFile("state/ha/admin.conf", []byte("keep"), 0600)
			case "hardlink":
				err = root.Link("state/ha/server.key", "shared-key")
			case "symlink":
				err = root.Rename("state/ha/server.key", "administrator-key")
				if err == nil {
					err = root.Symlink("../../administrator-key", "state/ha/server.key")
				}
			case "fence-symlink":
				err = root.Rename("state/ha/fence", "administrator-fence")
				if err == nil {
					err = root.Symlink("../../administrator-fence", "state/ha/fence")
				}
			case "public-key-mode":
				err = root.Chmod("state/ha/server.key", 0644)
			case "public-fence-mode":
				err = root.Chmod("state/ha/fence", 0755)
			case "lock-content":
				err = root.WriteFile("state/ha/fence/native-sync-fence.lock", []byte("keep"), 0600)
			case "oversized-key":
				err = root.WriteFile("state/ha/server.key", bytes.Repeat([]byte("x"), (1<<20)+1), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			guard := func() error {
				calls++
				if scenario == "guard" {
					return errors.New("live product state remains")
				}
				if scenario == "late-nested-addition" && calls == 3 {
					return root.WriteFile("state/ha/fence/admin.json", []byte("keep"), 0600)
				}
				return nil
			}
			if _, _, err := applyLegacyRetention(parent, backups, digest, guard, unix.Renameat2, haRetentionProfile()); err == nil {
				t.Fatal("unsafe HA state was moved")
			}
			if _, err := root.Lstat("state/ha"); err != nil {
				t.Fatal("active path was lost", err)
			}
		})
	}
}

func TestHAStateRetentionRestoresTreeAfterRenameRace(t *testing.T) {
	parent, backups, root := haRetentionFixture(t)
	_, digest := inspectHARetentionFixture(t, parent)
	first := true
	rename := func(oldfd int, old string, newfd int, new string, flags uint) error {
		if err := unix.Renameat2(oldfd, old, newfd, new, flags); err != nil {
			return err
		}
		if first {
			first = false
			return root.WriteFile("backups/syswarden-retired-v1/"+new+"/fence/admin.json", []byte("concurrent administrator bytes"), 0600)
		}
		return nil
	}
	if _, _, err := applyLegacyRetention(parent, backups, digest, func() error { return nil }, rename, haRetentionProfile()); err == nil {
		t.Fatal("rename race accepted")
	}
	content, err := root.ReadFile("state/ha/fence/admin.json")
	if err != nil || string(content) != "concurrent administrator bytes" {
		t.Fatal("concurrent content lost", err)
	}
}

func TestHAStateRetentionRequiresRuntimeAbsenceVerifier(t *testing.T) {
	if err := haRetentionGuard(nil); err == nil {
		t.Fatal("missing runtime verifier accepted")
	}
}
