//go:build linux

package system

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const legacyCronFixtureOperator = "MAILTO=operator@example.invalid\n* * * * * /usr/local/sbin/operator-canary\n# retained trailing comment\n"
const legacyCronFixtureRecord = "17 * * * * /opt/syswarden/bin/syswarden-cli update-feeds >/dev/null 2>&1\n"

func legacyCronFixture(t *testing.T) (string, string, LegacyCronRetirementPlan, string) {
	t.Helper()
	base := t.TempDir()
	spool, backups := filepath.Join(base, "spool"), filepath.Join(base, "backups")
	for _, path := range []string{spool, backups} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(spool, "root"), []byte(legacyCronFixtureRecord+legacyCronFixtureOperator), 0600); err != nil {
		t.Fatal(err)
	}
	directory, err := openPinnedSharedRemovalParent(spool, systemTestUID(t))
	if err != nil {
		t.Fatal(err)
	}
	defer directory.close()
	plan, _, err := inspectLegacyCronDirectory(directory, systemTestUID(t))
	if err != nil {
		t.Fatal(err)
	}
	digest, err := LegacyCronRetirementPlanSHA256(plan)
	if err != nil {
		t.Fatal(err)
	}
	return spool, backups, plan, digest
}

func readCronFixture(t *testing.T, path, name string) []byte {
	t.Helper()
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	content, err := root.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func TestLegacyCronRetirementPreservesOtherRecordsAndOriginalInode(t *testing.T) {
	spool, backups, _, digest := legacyCronFixture(t)
	before, err := os.Stat(filepath.Join(spool, "root"))
	if err != nil {
		t.Fatal(err)
	}
	prepareCalls := 0
	prepare := func() error { prepareCalls++; return nil }
	guard := func() error { return nil }
	if _, _, err := applyLegacyCronRetirement(spool, backups, strings.Repeat("0", 64), systemTestUID(t), prepare, guard, unix.Renameat2); err == nil || prepareCalls != 0 {
		t.Fatal("unreviewed plan mutated product services", err)
	}
	plan, backup, err := applyLegacyCronRetirement(spool, backups, digest, systemTestUID(t), prepare, guard, unix.Renameat2)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.RemovedLines) != 1 || plan.RemovedLines[0] != 1 || prepareCalls != 1 {
		t.Fatal("wrong retirement scope")
	}
	if string(readCronFixture(t, spool, "root")) != legacyCronFixtureOperator {
		t.Fatal("unrelated records changed")
	}
	if string(readCronFixture(t, backup, "root-crontab")) != legacyCronFixtureRecord+legacyCronFixtureOperator {
		t.Fatal("original bytes were not retained")
	}
	saved, err := os.Stat(filepath.Join(backup, "root-crontab"))
	if err != nil || !os.SameFile(before, saved) {
		t.Fatal("original inode was not retained", err)
	}
	if _, repeated, err := applyLegacyCronRetirement(spool, backups, digest, systemTestUID(t), prepare, guard, unix.Renameat2); err != nil || repeated != backup {
		t.Fatal("completed operation did not resume", err)
	}
}

func TestLegacyCronRetirementRefusesChangedSharedAndUntrustedState(t *testing.T) {
	for _, mutation := range []string{"changed", "hardlink", "symlink", "mode", "attribute", "prepare", "guard"} {
		t.Run(mutation, func(t *testing.T) {
			spool, backups, _, digest := legacyCronFixture(t)
			path := filepath.Join(spool, "root")
			prepare, guard := func() error { return nil }, func() error { return nil }
			var err error
			switch mutation {
			case "changed":
				err = os.WriteFile(path, []byte(legacyCronFixtureRecord+legacyCronFixtureOperator+"# newer administrator edit\n"), 0600)
			case "hardlink":
				err = os.Link(path, filepath.Join(backups, "shared"))
			case "symlink":
				if err = os.Rename(path, filepath.Join(spool, "original")); err == nil {
					err = os.Symlink("original", path)
				}
			case "mode":
				err = os.Chmod(path, 0640) // #nosec G302 -- Deliberately tests rejection of non-private backup permissions inside a temporary fixture.
			case "attribute":
				err = unix.Setxattr(path, "user.operator", []byte("preserve"), 0)
			case "prepare":
				prepare = func() error { return os.ErrPermission }
			case "guard":
				guard = func() error { return os.ErrPermission }
			}
			if err != nil {
				t.Fatal(err)
			}
			before := readCronFixture(t, spool, "root")
			if _, _, err := applyLegacyCronRetirement(spool, backups, digest, systemTestUID(t), prepare, guard, unix.Renameat2); err == nil {
				t.Fatal("unsafe recovery succeeded")
			}
			if string(readCronFixture(t, spool, "root")) != string(before) {
				t.Fatal("refusal changed active administrator records")
			}
		})
	}
}

func TestLegacyCronRetirementResumesUncertainExchangeAndRestoresConcurrentEdit(t *testing.T) {
	for _, scenario := range []string{"interrupted", "concurrent-edit"} {
		t.Run(scenario, func(t *testing.T) {
			spool, backups, _, digest := legacyCronFixture(t)
			first := true
			newer := legacyCronFixtureRecord + legacyCronFixtureOperator + "# concurrent administrator record\n"
			rename := func(oldFD int, oldName string, newFD int, newName string, flags uint) error {
				if first && scenario == "concurrent-edit" {
					if err := os.WriteFile(filepath.Join(spool, "root"), []byte(newer), 0600); err != nil {
						return err
					}
				}
				err := unix.Renameat2(oldFD, oldName, newFD, newName, flags)
				if first && scenario == "interrupted" && err == nil {
					first = false
					return errors.New("simulated interruption after kernel exchange")
				}
				first = false
				return err
			}
			noop := func() error { return nil }
			if _, _, err := applyLegacyCronRetirement(spool, backups, digest, systemTestUID(t), noop, noop, rename); err == nil {
				t.Fatal("interruption or concurrent mutation went unnoticed")
			}
			if scenario == "concurrent-edit" {
				if string(readCronFixture(t, spool, "root")) != newer {
					t.Fatal("concurrent administrator bytes were not restored")
				}
				return
			}
			if _, _, err := applyLegacyCronRetirement(spool, backups, digest, systemTestUID(t), noop, noop, unix.Renameat2); err != nil {
				t.Fatal("durable exchange did not resume", err)
			}
			if string(readCronFixture(t, spool, "root")) != legacyCronFixtureOperator {
				t.Fatal("resumption changed administrator records")
			}
		})
	}
}

func TestLegacyCronRetirementRefusesChangedPrivateBackupOnRetry(t *testing.T) {
	for _, mutation := range []string{"parent-mode", "extra-file"} {
		t.Run(mutation, func(t *testing.T) {
			spool, backups, _, digest := legacyCronFixture(t)
			noop := func() error { return nil }
			_, backup, err := applyLegacyCronRetirement(spool, backups, digest, systemTestUID(t), noop, noop, unix.Renameat2)
			if err != nil {
				t.Fatal(err)
			}
			if mutation == "parent-mode" {
				err = os.Chmod(filepath.Dir(backup), 0755) // #nosec G302 -- Deliberately tests rejection of an exposed backup parent inside a temporary fixture.
			} else {
				err = os.WriteFile(filepath.Join(backup, "operator-file"), []byte("preserve"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := applyLegacyCronRetirement(spool, backups, digest, systemTestUID(t), noop, noop, unix.Renameat2); err == nil {
				t.Fatal("changed private backup was accepted")
			}
			if string(readCronFixture(t, spool, "root")) != legacyCronFixtureOperator {
				t.Fatal("retry changed administrator records")
			}
		})
	}
}
