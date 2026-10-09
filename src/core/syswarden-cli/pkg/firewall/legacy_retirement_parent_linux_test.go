//go:build linux

package firewall

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestNFTOwnedPolicyRetiresWithoutPreexistingBackupParent(t *testing.T) {
	host, plan, guard := fixtureNFTOwnedPolicyPlan(t, fixtureNFTCurrentFiles(t)[7], "independent")
	if err := host.root.Remove("var/backups"); err != nil {
		t.Fatal(err)
	}
	if err := host.root.WriteFile("var/administrator-sentinel", []byte("preserve me\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectNFTPersistenceGraphState(host, plan.graph); err != nil {
		t.Fatal(err)
	}
	if _, err := host.root.Lstat("var/backups"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("read-only graph inspection created shared storage", err)
	}
	if err := applyNFTHistoricalPersistencePlan(host, plan, plan.sha256, guard, defaultLegacyRetirementFileOps()); err != nil {
		t.Fatal("retirement requires a distribution-specific backup parent", err)
	}
	if _, err := host.root.Stat(legacyNFTIncludePath[1:]); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("owned policy remained active", err)
	}
	if _, err := currentNFTRetiredSource(host, plan); err != nil {
		t.Fatal("original policy was not preserved in its exact private backup", err)
	}
	for path, expected := range map[string]string{
		"var/administrator-sentinel":       "preserve me\n",
		"etc/nftables.d/administrator.nft": nftOwnedPolicyAdministratorSource,
	} {
		got, err := host.root.ReadFile(path)
		if err != nil || string(got) != expected {
			t.Fatal("administrator state changed", path, err)
		}
	}
}

func TestLegacyRetirementMissingBackupParentDoesNotChangeReadOnlyInspection(t *testing.T) {
	_, host := fixtureNFTPersistenceFilesystem(t)
	if err := host.root.Mkdir("var", 0700); err != nil {
		t.Fatal(err)
	}
	path := legacyFail2banPlanPath(strings.Repeat("a", 64))
	if err := prepareLegacyRetirementPrivateDirectory(host, path, defaultLegacyRetirementFileOps(), false); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing recovery storage must remain a missing-evidence error", err)
	}
	if _, err := host.root.Lstat("var/backups"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("read-only inspection created a shared directory", err)
	}
}

func TestNFTOwnedPolicyMissingBackupParentResumesAfterDurabilityFailure(t *testing.T) {
	for _, phase := range []string{"backup-parent-before-create", "backup-parent-created", "sync-child", "sync-parent", "backup-parent-durable"} {
		t.Run(phase, func(t *testing.T) {
			host, plan, guard := fixtureNFTOwnedPolicyPlan(t, fixtureNFTCurrentFiles(t)[7], "independent")
			if err := host.root.Remove("var/backups"); err != nil {
				t.Fatal(err)
			}
			ops := defaultLegacyRetirementFileOps()
			injected := errors.New("synthetic backup-parent interruption")
			ops.checkpoint = func(at string) error {
				if at == phase {
					return injected
				}
				return nil
			}
			syncCalls := 0
			ops.sync = func(file *os.File) error {
				syncCalls++
				if phase == "sync-child" && syncCalls == 1 || phase == "sync-parent" && syncCalls == 2 {
					return injected
				}
				return file.Sync()
			}
			if err := applyNFTHistoricalPersistencePlan(host, plan, plan.sha256, guard, ops); !errors.Is(err, injected) {
				t.Fatal("expected interruption was not preserved", err)
			}
			if _, err := host.root.Stat(legacyNFTIncludePath[1:]); err != nil {
				t.Fatal("source moved before backup-parent durability", err)
			}
			if _, err := host.root.Lstat(legacyRetirementBackupRoot[1:]); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("private journals created before shared-parent durability", err)
			}
			if err := applyNFTHistoricalPersistencePlan(host, plan, plan.sha256, guard, defaultLegacyRetirementFileOps()); err != nil {
				t.Fatal("safe retry could not complete", err)
			}
			if _, err := currentNFTRetiredSource(host, plan); err != nil {
				t.Fatal("retry lost original recovery evidence", err)
			}
		})
	}
}

func TestLegacyRetirementBackupParentRejectsUnsafePathsAndRaces(t *testing.T) {
	for _, change := range []string{"var-symlink", "backup-symlink", "backup-file", "backup-writable", "var-writable", "var-replaced", "backup-replaced", "concurrent-create"} {
		t.Run(change, func(t *testing.T) {
			_, host := fixtureNFTPersistenceFilesystem(t)
			for _, path := range []string{"var", "unrelated"} {
				if err := host.root.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := host.root.WriteFile("unrelated/sentinel", []byte("keep\n"), 0600); err != nil {
				t.Fatal(err)
			}
			ops := defaultLegacyRetirementFileOps()
			var err error
			switch change {
			case "var-symlink":
				err = host.root.Rename("var", "old-var")
				if err == nil {
					err = host.root.Symlink("unrelated", "var")
				}
			case "backup-symlink":
				err = host.root.Symlink("../unrelated", "var/backups")
			case "backup-file":
				err = host.root.WriteFile("var/backups", []byte("administrator file\n"), 0600)
			case "backup-writable":
				err = host.root.Mkdir("var/backups", 0700)
				if err == nil {
					err = host.root.Chmod("var/backups", 0777)
				}
			case "var-writable":
				err = host.root.Chmod("var", 0777)
			default:
				ops.checkpoint = func(at string) error {
					switch {
					case change == "var-replaced" && at == "backup-parent-before-create":
						if err := host.root.Rename("var", "old-var"); err != nil {
							return err
						}
						return host.root.Mkdir("var", 0700)
					case change == "backup-replaced" && at == "backup-parent-created":
						if err := host.root.Rename("var/backups", "var/original-backups"); err != nil {
							return err
						}
						return host.root.Mkdir("var/backups", 0700)
					case change == "concurrent-create" && at == "backup-parent-before-create":
						return host.root.Mkdir("var/backups", 0700)
					}
					return nil
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := ensureLegacyRetirementPrivateDirectory(host, legacyFail2banPlanPath(strings.Repeat("a", 64)), ops); err == nil {
				t.Fatal("unsafe shared-parent path or race was accepted")
			}
			got, err := host.root.ReadFile("unrelated/sentinel")
			if err != nil || string(got) != "keep\n" {
				t.Fatal("unrelated data changed", err)
			}
			if _, err := host.root.Lstat("unrelated/backups"); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("creation followed the replaced shared parent", err)
			}
		})
	}
}

func TestLegacyRetirementBackupParentPreservesExistingSharedStorage(t *testing.T) {
	_, host := fixtureNFTPersistenceFilesystem(t)
	if err := host.root.MkdirAll("var/backups", 0700); err != nil {
		t.Fatal(err)
	}
	if err := host.root.Chmod("var/backups", 0750); err != nil {
		t.Fatal(err)
	}
	if err := host.root.WriteFile("var/backups/administrator", []byte("existing backup\n"), 0600); err != nil {
		t.Fatal(err)
	}
	before, err := host.root.Stat("var/backups")
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureLegacyRetirementPrivateDirectory(host, legacyFail2banPlanPath(strings.Repeat("a", 64)), defaultLegacyRetirementFileOps()); err != nil {
		t.Fatal(err)
	}
	after, err := host.root.Stat("var/backups")
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
		t.Fatal("existing shared directory was replaced or chmodded", err)
	}
	got, err := host.root.ReadFile("var/backups/administrator")
	if err != nil || string(got) != "existing backup\n" {
		t.Fatal("administrator backup changed", err)
	}
}

func TestLegacyFail2banJournalRetiresWithoutPreexistingBackupParent(t *testing.T) {
	_, host, plan := fixtureLegacyFail2banJournal(t)
	if err := host.root.Remove("var/backups"); err != nil {
		t.Fatal(err)
	}
	if err := persistLegacyFail2banPlanUsing(host, plan, acceptLegacyFail2banJournalFixture, defaultLegacyRetirementFileOps()); err != nil {
		t.Fatal("journal publication requires a distribution-specific directory", err)
	}
	if err := resumeLegacyFail2banPlanUsing(host, plan.sha256, acceptLegacyFail2banJournalFixture, defaultLegacyRetirementFileOps()); err != nil {
		t.Fatal(err)
	}
	assertLegacyFail2banJournalComplete(t, host, plan)
}
