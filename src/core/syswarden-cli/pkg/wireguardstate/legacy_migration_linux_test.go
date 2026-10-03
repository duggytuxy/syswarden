//go:build linux

package wireguardstate

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestLegacyMigrationCrashProcessHelper(t *testing.T) {
	point := os.Getenv("SYSWARDEN_TEST_LEGACY_MIGRATION_CRASH")
	if point == "" {
		t.Skip("private subprocess crash fixture only")
	}
	marker, err := os.ReadFile(".migration-test-only")
	if err != nil || string(marker) != "isolated legacy migration crash fixture\n" {
		t.Fatal("refusing crash helper outside its fixture")
	}
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	uid, gid := wireGuardStateTestIdentity(t)
	snapshot, err := InspectLegacyMigration(root, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	legacyMigrationFault = func(current string) error {
		if current == point {
			os.Exit(73)
		}
		return nil
	}
	if err := BeginLegacyMigration(root, snapshot, exactTestServerConfiguration(), uid, gid); err != nil {
		t.Fatal(err)
	}
	snapshot, err = InspectLegacyMigration(root, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	if err := ContinueLegacyMigration(root, snapshot, exactTestServerConfiguration(), uid, gid); err != nil {
		t.Fatal(err)
	}
	t.Fatal("requested crash boundary was not reached")
}

func TestLegacyMigrationSurvivesAbruptProcessExit(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, point := range []string{"journal", "backup:0", "backup:1", "backup:2", "stage", "exchange", "original-archive", "manifest", "receipt"} {
		t.Run(point, func(t *testing.T) {
			root, uid, gid := migrationFixture(t)
			files := legacyTestFiles(t, root)
			if err := files.WriteFile(".migration-test-only", []byte("isolated legacy migration crash fixture\n"), 0600); err != nil {
				t.Fatal(err)
			}
			command := exec.Command(binary, "-test.run=^TestLegacyMigrationCrashProcessHelper$")
			command.Dir = root
			command.Env = append(os.Environ(), "SYSWARDEN_TEST_LEGACY_MIGRATION_CRASH="+point)
			output, err := command.CombinedOutput()
			var exited *exec.ExitError
			if !errors.As(err, &exited) || exited.ExitCode() != 73 {
				t.Fatalf("crash boundary not reached: %v %s", err, output)
			}
			snapshot, err := InspectLegacyMigration(root, uid, gid)
			if err != nil {
				t.Fatal(err)
			}
			if point != "receipt" {
				if _, err := Inspect(root); err == nil {
					t.Fatal("crashed transaction did not block ordinary mutation")
				}
			}
			if err := ContinueLegacyMigration(root, snapshot, exactTestServerConfiguration(), uid, gid); err != nil {
				t.Fatal(err)
			}
			final, err := InspectLegacyMigration(root, uid, gid)
			if err != nil || !final.Completed() {
				t.Fatal("process crash recovery incomplete", err)
			}
			for path, original := range testOwnedContents() {
				backup, err := files.ReadFile(strings.TrimPrefix(LegacyMigrationBackupPath(path), "/"))
				if err != nil || !bytes.Equal(backup, original) {
					t.Fatal("process crash lost private backup", err)
				}
			}
		})
	}
}

func migrationFixture(t *testing.T) (string, uint32, uint32) {
	t.Helper()
	root, uid, gid := prepareStateRoot(t)
	for path, content := range testOwnedContents() {
		if err := os.WriteFile(filepath.Join(root, path), content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root, uid, gid
}

func TestLegacyMigrationResumesEveryDurableBoundary(t *testing.T) {
	for _, point := range []string{"journal", "backup:0", "backup:1", "backup:2", "stage", "exchange", "original-archive", "manifest", "receipt"} {
		t.Run(point, func(t *testing.T) {
			root, uid, gid := migrationFixture(t)
			target := exactTestServerConfiguration()
			original, err := InspectLegacyMigration(root, uid, gid)
			if err != nil {
				t.Fatal(err)
			}
			previous := legacyMigrationFault
			t.Cleanup(func() { legacyMigrationFault = previous })
			injected := errors.New("injected interruption")
			hits := 0
			legacyMigrationFault = func(current string) error {
				if current == point {
					hits++
					return injected
				}
				return nil
			}
			err = BeginLegacyMigration(root, original, target, uid, gid)
			if err == nil {
				current, inspectErr := InspectLegacyMigration(root, uid, gid)
				if inspectErr != nil {
					t.Fatal(inspectErr)
				}
				err = ContinueLegacyMigration(root, current, target, uid, gid)
			}
			if !errors.Is(err, injected) || hits != 1 {
				t.Fatalf("interruption %s not reached: %v", point, err)
			}
			if point != "receipt" {
				if _, err := Inspect(root); err == nil {
					t.Fatal("ordinary inventory accepted pending migration")
				}
			}
			legacyMigrationFault = previous
			current, err := InspectLegacyMigration(root, uid, gid)
			if err != nil {
				t.Fatal(err)
			}
			if err := ContinueLegacyMigration(root, current, target, uid, gid); err != nil {
				t.Fatal(err)
			}
			final, err := InspectLegacyMigration(root, uid, gid)
			if err != nil || !final.Completed() {
				t.Fatal("migration not complete", err)
			}
			if _, err := ReadAndVerify(root, uid, gid); err != nil {
				t.Fatal(err)
			}
			for path, content := range testOwnedContents() {
				backup, err := legacyTestFiles(t, root).ReadFile(strings.TrimPrefix(LegacyMigrationBackupPath(path), "/"))
				if err != nil || !bytes.Equal(backup, content) {
					t.Fatal("private backup changed", err)
				}
				if path != ServerConfigurationPath {
					actual, err := legacyTestFiles(t, root).ReadFile(strings.TrimPrefix(path, "/"))
					if err != nil || !bytes.Equal(actual, content) {
						t.Fatal("migration changed a companion artifact", err)
					}
				}
			}
			if err := ContinueLegacyMigration(root, final, target, uid, gid); err != nil {
				t.Fatal(err)
			}
			repeated, err := InspectLegacyMigration(root, uid, gid)
			if err != nil || !reflect.DeepEqual(final, repeated) {
				t.Fatal("completed migration was not idempotent", err)
			}
		})
	}
}

func TestLegacyMigrationRejectsChangedEvidenceAndBackupCollision(t *testing.T) {
	for _, kind := range []string{"backup-before-begin", "client-after-journal", "wrong-target", "backup-after-journal", "stage-symlink", "journal-symlink", "corrupt-journal"} {
		t.Run(kind, func(t *testing.T) {
			root, uid, gid := migrationFixture(t)
			initial, err := InspectLegacyMigration(root, uid, gid)
			if err != nil {
				t.Fatal(err)
			}
			server := exactTestServerConfiguration()
			if kind == "backup-before-begin" {
				if err := os.WriteFile(filepath.Join(root, LegacyMigrationBackupPath(ServerConfigurationPath)), []byte("foreign backup\n"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := BeginLegacyMigration(root, initial, server, uid, gid); err == nil {
					t.Fatal("overwrote foreign backup")
				}
				return
			}
			if err := BeginLegacyMigration(root, initial, server, uid, gid); err != nil {
				t.Fatal(err)
			}
			planned, err := InspectLegacyMigration(root, uid, gid)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "client-after-journal":
				err = os.WriteFile(filepath.Join(root, ClientConfigurationPath), []byte("changed client\n"), 0600)
			case "wrong-target":
				server = bytes.Replace(server, []byte("ListenPort = 51820"), []byte("ListenPort = 51821"), 1)
			case "backup-after-journal":
				err = os.WriteFile(filepath.Join(root, LegacyMigrationBackupPath(ClientConfigurationPath)), []byte("foreign backup\n"), 0600)
			case "stage-symlink":
				err = os.Symlink("missing", filepath.Join(root, legacyMigrationStage))
			case "journal-symlink":
				if err = os.Remove(filepath.Join(root, LegacyMigrationPath)); err == nil {
					err = os.Symlink("missing", filepath.Join(root, LegacyMigrationPath))
				}
			case "corrupt-journal":
				err = os.WriteFile(filepath.Join(root, LegacyMigrationPath), []byte("{}"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := ContinueLegacyMigration(root, planned, server, uid, gid); err == nil {
				t.Fatal("continued with changed migration evidence")
			}
			actual, err := legacyTestFiles(t, root).ReadFile(strings.TrimPrefix(ServerConfigurationPath, "/"))
			if err != nil || !bytes.Equal(actual, testOwnedContents()[ServerConfigurationPath]) {
				t.Fatal("changed original server on refusal", err)
			}
		})
	}
}

func TestPendingLegacyMigrationBlocksOrdinaryLifecycleMutation(t *testing.T) {
	root, uid, gid := migrationFixture(t)
	initial, err := InspectLegacyMigration(root, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	if err := BeginLegacyMigration(root, initial, exactTestServerConfiguration(), uid, gid); err != nil {
		t.Fatal(err)
	}
	pending, err := InspectLegacyMigration(root, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Recover(root, uid, gid); err == nil {
		t.Fatal("general recovery bypassed migration")
	}
	if _, err := RecoverRemoval(root, uid, gid); err == nil {
		t.Fatal("removal recovery bypassed migration")
	}
	if _, err := PrepareRemoval(root, uid, gid); err == nil {
		t.Fatal("removal preparation bypassed migration")
	}
	if _, err := FinalizeRemoval(root, uid, gid); err == nil {
		t.Fatal("removal finalization bypassed migration")
	}
	if err := RemoveOwnedArtifacts(root, uid, gid); err == nil {
		t.Fatal("removal bypassed migration")
	}
	if _, err := StageOwnedArtifacts(root, testOwnedContents(), uid, gid); err == nil {
		t.Fatal("publication bypassed migration")
	}
	after, err := InspectLegacyMigration(root, uid, gid)
	if err != nil || !reflect.DeepEqual(after, pending) {
		t.Fatal("ordinary lifecycle changed migration evidence", err)
	}
}
