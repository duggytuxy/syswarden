//go:build linux

package system

import (
	"bytes"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func legacyConfigFixture(t *testing.T) (string, string, *os.Root, LegacyLogRetentionPlan, string) {
	t.Helper()
	base := t.TempDir()
	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	for _, path := range []string{"product", "backups"} {
		if err := root.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"syswarden-auto.conf.bak", "syswarden-auto.conf", "administrator.conf"} {
		if err := root.WriteFile("product/"+name, []byte("PRIVATE_FIXTURE_VALUE=kept\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	directory := filepath.Join(base, "product")
	pinned, err := openExistingPinnedServiceDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer pinned.close()
	plan, err := inspectLegacyConfigRetention(pinned)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := LegacyLogRetentionPlanSHA256(plan)
	if err != nil {
		t.Fatal(err)
	}
	return directory, filepath.Join(base, "backups"), root, plan, digest
}

func TestLegacyConfigRetentionPreservesOriginalAndDoesNotAdoptNeighbors(t *testing.T) {
	directory, backups, root, plan, digest := legacyConfigFixture(t)
	wire, err := json.Marshal(plan)
	if err != nil || bytes.Contains(wire, []byte("PRIVATE_FIXTURE_VALUE")) {
		t.Fatal("inspection exposed contents", err)
	}
	if len(plan.Files) != 1 || plan.Files[0].CreationProvenance {
		t.Fatal("inspection claimed ownership")
	}
	if entries, err := os.ReadDir(backups); err != nil || len(entries) != 0 {
		t.Fatal("inspection mutated backup storage", err)
	}
	before, err := root.Lstat("product/syswarden-auto.conf.bak")
	if err != nil {
		t.Fatal(err)
	}
	guard := func() error { return nil }
	_, backup, err := applyLegacyConfigRetention(directory, backups, digest, guard, unix.Renameat2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := root.Lstat("product/syswarden-auto.conf.bak"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("inactive source remains", err)
	}
	retained, err := os.OpenRoot(backup)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = retained.Close() }()
	after, err := retained.Lstat("syswarden-auto.conf.bak")
	if err != nil || !os.SameFile(before, after) || before.ModTime() != after.ModTime() || before.Mode() != after.Mode() {
		t.Fatal("retention changed original metadata", err)
	}
	content, err := retained.ReadFile("syswarden-auto.conf.bak")
	if err != nil || string(content) != "PRIVATE_FIXTURE_VALUE=kept\n" {
		t.Fatal("retention changed original bytes", err)
	}
	for _, name := range []string{"syswarden-auto.conf", "administrator.conf"} {
		content, err := root.ReadFile("product/" + name)
		if err != nil || string(content) != "PRIVATE_FIXTURE_VALUE=kept\n" {
			t.Fatal("retention modified adjacent configuration", err)
		}
	}
	if _, repeated, err := applyLegacyConfigRetention(directory, backups, digest, guard, unix.Renameat2); err != nil || repeated != backup {
		t.Fatal("verified retry failed", err)
	}
	if err := root.WriteFile("product/syswarden-auto.conf.bak", []byte("NEW_ADMINISTRATOR_VALUE=keep\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := applyLegacyConfigRetention(directory, backups, digest, guard, unix.Renameat2); err == nil {
		t.Fatal("old plan adopted a recreated source")
	}
}

func TestLegacyConfigRetentionRejectsStaleOrUnsafeSourcesBeforeMutation(t *testing.T) {
	for _, kind := range []string{"digest", "content", "mode", "hardlink", "symlink", "fifo", "oversize", "guard", "lease"} {
		t.Run(kind, func(t *testing.T) {
			directory, backups, root, _, digest := legacyConfigFixture(t)
			guard := func() error { return nil }
			var mutationErr error
			switch kind {
			case "digest":
				digest = strings.Repeat("0", 64)
			case "content":
				mutationErr = root.WriteFile("product/syswarden-auto.conf.bak", []byte("NEW=keep\n"), 0600)
			case "mode":
				mutationErr = root.Chmod("product/syswarden-auto.conf.bak", 0640)
			case "hardlink":
				mutationErr = root.Link("product/syswarden-auto.conf.bak", "product/duplicate")
			case "symlink", "fifo":
				if err := root.Remove("product/syswarden-auto.conf.bak"); err != nil {
					t.Fatal(err)
				}
				if kind == "symlink" {
					mutationErr = root.Symlink("administrator.conf", "product/syswarden-auto.conf.bak")
				} else {
					mutationErr = unix.Mkfifo(filepath.Join(directory, "syswarden-auto.conf.bak"), 0600)
				}
			case "oversize":
				mutationErr = root.WriteFile("product/syswarden-auto.conf.bak", bytes.Repeat([]byte("x"), (1<<20)+1), 0600)
			case "guard":
				guard = func() error { return errors.New("fixture removal barrier lost") }
			case "lease":
				pinned, err := openExistingPinnedServiceDirectory(directory)
				if err != nil {
					t.Fatal(err)
				}
				defer pinned.close()
				if err := unix.Flock(pinned.fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
					t.Fatal(err)
				}
			}
			if mutationErr != nil {
				t.Fatal(mutationErr)
			}
			if _, _, err := applyLegacyConfigRetention(directory, backups, digest, guard, unix.Renameat2); err == nil {
				t.Fatal("unsafe retention succeeded")
			}
			if _, err := root.Lstat("product/syswarden-auto.conf.bak"); err != nil {
				t.Fatal("refusal removed source", err)
			}
			if entries, err := os.ReadDir(backups); err != nil || len(entries) != 0 {
				t.Fatal("unreviewed plan staged backup state", err)
			}
		})
	}
}

func TestLegacyConfigRetentionResumesBeforeAndAfterMove(t *testing.T) {
	for _, afterMove := range []bool{false, true} {
		t.Run(map[bool]string{false: "before", true: "after"}[afterMove], func(t *testing.T) {
			directory, backups, _, _, digest := legacyConfigFixture(t)
			calls := 0
			guard := func() error {
				calls++
				if !afterMove && calls == 2 || afterMove && calls == 3 {
					return errors.New("fixture interrupted guard")
				}
				return nil
			}
			if _, _, err := applyLegacyConfigRetention(directory, backups, digest, guard, unix.Renameat2); err == nil {
				t.Fatal("interrupted operation reported success")
			}
			if _, _, err := applyLegacyConfigRetention(directory, backups, digest, func() error { return nil }, unix.Renameat2); err != nil {
				t.Fatal("exact interrupted transaction did not resume", err)
			}
		})
	}
}

func TestLegacyConfigRetentionDetectsRenameRaceAndRestoresDisplacedUpdate(t *testing.T) {
	directory, backups, root, _, digest := legacyConfigFixture(t)
	calls := 0
	rename := func(oldfd int, oldname string, newfd int, newname string, flags uint) error {
		calls++
		if calls == 1 {
			if err := root.WriteFile("product/syswarden-auto.conf.bak", []byte("CONCURRENT_UPDATE=preserved\n"), 0600); err != nil {
				return err
			}
		}
		return unix.Renameat2(oldfd, oldname, newfd, newname, flags)
	}
	if _, _, err := applyLegacyConfigRetention(directory, backups, digest, func() error { return nil }, rename); err == nil {
		t.Fatal("rename race was accepted")
	}
	content, err := root.ReadFile("product/syswarden-auto.conf.bak")
	if err != nil || string(content) != "CONCURRENT_UPDATE=preserved\n" {
		t.Fatal("concurrent update was lost", err)
	}
}

func TestLegacyConfigRetentionRefusesModifiedBackupAndChangedParents(t *testing.T) {
	for _, kind := range []string{"content", "plan", "extra", "exposed", "source-parent", "backup-parent"} {
		t.Run(kind, func(t *testing.T) {
			directory, backups, root, _, digest := legacyConfigFixture(t)
			guard := func() error { return nil }
			_, backup, err := applyLegacyConfigRetention(directory, backups, digest, guard, unix.Renameat2)
			if err != nil {
				t.Fatal(err)
			}
			saved, err := os.OpenRoot(backup)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = saved.Close() }()
			switch kind {
			case "content":
				err = saved.WriteFile("syswarden-auto.conf.bak", []byte("CHANGED=kept\n"), 0600)
			case "plan":
				err = saved.WriteFile("plan.json", []byte("{}"), 0600)
			case "extra":
				err = saved.WriteFile("extra", []byte("keep"), 0600)
			case "exposed":
				err = root.Chmod("backups/syswarden-retired-v1", 0750)
			case "source-parent":
				err = root.Rename("product", "original")
				if err == nil {
					err = root.Mkdir("product", 0700)
				}
			case "backup-parent":
				err = root.Rename("backups/syswarden-retired-v1", "backups/original")
				if err == nil {
					err = root.Symlink("original", "backups/syswarden-retired-v1")
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := applyLegacyConfigRetention(directory, backups, digest, guard, unix.Renameat2); err == nil {
				t.Fatal("changed evidence was accepted")
			}
			if _, err := saved.Lstat("syswarden-auto.conf.bak"); err != nil {
				t.Fatal("refusal lost private original", err)
			}
		})
	}
}

func TestLegacyConfigRetentionRequiresASeparatePlanForEachBackup(t *testing.T) {
	directory, backups, root, _, digest := legacyConfigFixture(t)
	if err := root.WriteFile("product/syswarden-auto.conf.migrated", []byte("SECOND=kept\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := applyLegacyConfigRetention(directory, backups, digest, func() error { return nil }, unix.Renameat2); err != nil {
		t.Fatal(err)
	}
	if _, err := root.Lstat("product/syswarden-auto.conf.migrated"); err != nil {
		t.Fatal("unreviewed second backup was moved", err)
	}
	pinned, err := openExistingPinnedServiceDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer pinned.close()
	plan, err := inspectLegacyConfigRetention(pinned)
	if err != nil || plan.Files[0].Path != legacyConfigDirectory+"/syswarden-auto.conf.migrated" {
		t.Fatal("second backup was not offered separately", err)
	}
}

func TestLegacyConfigRetentionNeverOverwritesOrCopiesOnRenameFailure(t *testing.T) {
	for _, collision := range []bool{false, true} {
		t.Run(map[bool]string{false: "cross-device", true: "collision"}[collision], func(t *testing.T) {
			directory, backups, root, _, digest := legacyConfigFixture(t)
			rename := func(oldfd int, oldname string, newfd int, newname string, flags uint) error {
				if !collision {
					return unix.EXDEV
				}
				fd, err := unix.Openat(newfd, newname, unix.O_CREAT|unix.O_EXCL|unix.O_WRONLY|unix.O_CLOEXEC, 0600)
				if err != nil {
					return err
				}
				if err := unix.Close(fd); err != nil {
					return err
				}
				return unix.Renameat2(oldfd, oldname, newfd, newname, flags)
			}
			if _, _, err := applyLegacyConfigRetention(directory, backups, digest, func() error { return nil }, rename); err == nil {
				t.Fatal("rename failure was bypassed")
			}
			content, err := root.ReadFile("product/syswarden-auto.conf.bak")
			if err != nil || string(content) != "PRIVATE_FIXTURE_VALUE=kept\n" {
				t.Fatal("failed rename changed source", err)
			}
		})
	}
}

func TestLegacyConfigRetentionPreservesExtendedAttributes(t *testing.T) {
	directory, backups, root, _, _ := legacyConfigFixture(t)
	file, err := root.Open("product/syswarden-auto.conf.bak")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if err := unix.Fsetxattr(int(file.Fd()), "user.fixture", []byte("retain-exactly"), 0); errors.Is(err, unix.ENOTSUP) {
		t.Skip("fixture filesystem does not support attributes")
	} else if err != nil {
		t.Fatal(err)
	}
	pinned, err := openExistingPinnedServiceDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := inspectLegacyConfigRetention(pinned)
	pinned.close()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := LegacyLogRetentionPlanSHA256(plan)
	if err != nil {
		t.Fatal(err)
	}
	_, backup, err := applyLegacyConfigRetention(directory, backups, digest, func() error { return nil }, unix.Renameat2)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := os.OpenRoot(backup)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = saved.Close() }()
	original, err := saved.Open("syswarden-auto.conf.bak")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = original.Close() }()
	var data [64]byte
	n, err := unix.Fgetxattr(int(original.Fd()), "user.fixture", data[:])
	if err != nil || string(data[:n]) != "retain-exactly" {
		t.Fatal("retention lost original attributes", err)
	}
}

func TestLegacyConfigRetentionKeepsNativeAndStandaloneReadinessStrict(t *testing.T) {
	directory, backups, root, _, digest := legacyConfigFixture(t)
	for _, name := range []string{"syswarden-auto.conf", "administrator.conf"} {
		if err := root.Remove("product/" + name); err != nil {
			t.Fatal(err)
		}
	}
	check := func() error {
		return attestRuntimeRetirementRoot(directory, "/opt/syswarden", systemTestUID(t), systemTestGID(t), nil)
	}
	if err := check(); err == nil || !strings.Contains(err.Error(), "--retain-legacy-config") {
		t.Fatal("pre-erase did not offer bounded recovery", err)
	}
	if _, _, err := applyLegacyConfigRetention(directory, backups, digest, func() error { return nil }, unix.Renameat2); err != nil {
		t.Fatal(err)
	}
	if err := check(); err != nil {
		t.Fatal("verified archival did not unblock readiness", err)
	}
	if err := root.WriteFile("product/unrecognized.conf", []byte("ADMIN=preserve\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := check(); err == nil {
		t.Fatal("retention bypassed an unrelated final-removal refusal")
	}
}
