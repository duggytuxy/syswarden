//go:build linux

package firewall

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func fixtureLegacyFileRetirement(t *testing.T) (string, nftPersistenceFilesystem, legacyRetirementFileRecord) {
	t.Helper()
	root, host := fixtureNFTPersistenceFilesystem(t)
	path := "/etc/fail2ban/jail.d/syswarden-portscan.conf"
	if err := os.MkdirAll(filepath.Join(root, filepath.Dir(path)), 0755); err != nil { // #nosec G301 -- Models system-directory permissions inside a private temporary root for ownership checks.
		t.Fatal(err)
	}
	content := readLegacyFail2banFixture(t, "portscan-v1013-aligned.conf")
	if err := os.WriteFile(filepath.Join(root, path), content, 0600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := host.snapshot(path)
	if err != nil {
		t.Fatal(err)
	}
	record, err := makeLegacyRetirementFileRecord(path, strings.Repeat("a", 64), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(root, legacyRetirementBackupDirectory(record))
	if err := os.MkdirAll(backup, 0700); err != nil {
		t.Fatal(err)
	}
	writeNFTPersistenceFixture(t, root, "etc/fail2ban/jail.d/administrator.local", "# private administrator configuration\n")
	return root, host, record
}

func acceptLegacyRetirementFixture(bool) error { return nil }

func assertLegacyRetirementComplete(t *testing.T, root string, host nftPersistenceFilesystem, record legacyRetirementFileRecord) {
	t.Helper()
	retired, err := legacyRetirementSourceState(host, record)
	if err != nil || !retired {
		t.Fatalf("retirement is not exactly complete: %v", err)
	}
	intent, err := readLegacyRetirementFileRecord(host, legacyRetirementBackupDirectory(record))
	if err != nil || intent != record {
		t.Fatalf("intent changed: %v", err)
	}
	content, err := os.ReadFile(filepath.Join(root, "etc/fail2ban/jail.d/administrator.local")) // #nosec G304 -- The path is constructed solely from this test's private temporary root and controlled fixture names.
	if err != nil || string(content) != "# private administrator configuration\n" {
		t.Fatal("administrator configuration changed")
	}
}

func TestLegacyRetirementFilePreservesOriginalInodeAndBytes(t *testing.T) {
	root, host, record := fixtureLegacyFileRetirement(t)
	path := filepath.Join(root, record.Source.Path)
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	xattrErr := unix.Setxattr(path, "user.syswarden-retirement-test", []byte("original metadata"), 0)
	if xattrErr != nil && !errors.Is(xattrErr, unix.EOPNOTSUPP) {
		t.Fatal(xattrErr)
	}
	ops := defaultLegacyRetirementFileOps()
	if err := retireLegacyConfigurationFileUsing(host, record, acceptLegacyRetirementFixture, ops); err != nil {
		t.Fatal(err)
	}
	assertLegacyRetirementComplete(t, root, host, record)
	backup := filepath.Join(root, legacyRetirementBackupDirectory(record), "original")
	after, err := os.Stat(backup)
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("original inode or metadata was not retained")
	}
	if xattrErr == nil {
		value := make([]byte, 64)
		size, err := unix.Getxattr(backup, "user.syswarden-retirement-test", value)
		if err != nil || string(value[:size]) != "original metadata" {
			t.Fatal("original extended attribute was not retained")
		}
	}
	if err := retireLegacyConfigurationFileUsing(host, record, acceptLegacyRetirementFixture, ops); err != nil {
		t.Fatalf("verified retry is not idempotent: %v", err)
	}
	assertLegacyRetirementComplete(t, root, host, record)
}

func TestLegacyRetirementSourceIdentityAllowsOnlyUUIDBoundDeviceRenumbering(t *testing.T) {
	_, host, initial := fixtureLegacyFileRetirement(t)
	snapshot, err := host.snapshot(initial.Source.Path)
	if err != nil {
		t.Fatal(err)
	}
	// Deliberate identity inputs isolate the comparison from the test host's
	// filesystem support. Native reboot acceptance is a separate release gate.
	snapshot.filesystemUUID = strings.Repeat("c", 32)
	record, err := makeLegacyRetirementFileRecord(initial.Source.Path, initial.PlanSHA256, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	record.Source.Device ^= 4096
	if !matchesLegacyRetirementSource(record, snapshot) {
		t.Fatal("exact UUID-bound identity rejected device renumbering")
	}
	for _, field := range []string{"uuid", "missing_uuid", "inode", "mode", "uid", "gid", "links", "digest", "size", "mtime"} {
		changed := record
		actual := snapshot
		switch field {
		case "uuid":
			changed.Source.FilesystemUUID = strings.Repeat("d", 32)
		case "missing_uuid":
			actual.filesystemUUID = ""
		case "inode":
			changed.Source.Inode++
		case "mode":
			changed.Source.Mode ^= 0040
		case "uid":
			changed.Source.UID++
		case "gid":
			changed.Source.GID++
		case "links":
			changed.Source.NLink++
		case "digest":
			changed.Source.SHA256 = strings.Repeat("0", 64)
		case "size":
			changed.Size++
		case "mtime":
			changed.ModifiedNS++
		}
		if matchesLegacyRetirementSource(changed, actual) {
			t.Fatalf("accepted changed identity field %s", field)
		}
	}
	record.Source.FilesystemUUID = ""
	if matchesLegacyRetirementSource(record, snapshot) {
		t.Fatal("legacy identity without UUID accepted a changed device")
	}
}

func TestLegacyRetirementFileResumesAfterEveryCheckpoint(t *testing.T) {
	for _, phase := range []string{"intent-staged", "intent-published", "source-retired", "retirement-durable"} {
		t.Run(phase, func(t *testing.T) {
			root, host, record := fixtureLegacyFileRetirement(t)
			ops := defaultLegacyRetirementFileOps()
			injected := errors.New("injected interruption")
			ops.checkpoint = func(name string) error {
				if name == phase {
					return injected
				}
				return nil
			}
			if err := retireLegacyConfigurationFileUsing(host, record, acceptLegacyRetirementFixture, ops); !errors.Is(err, injected) {
				t.Fatalf("did not reach checkpoint: %v", err)
			}
			if err := retireLegacyConfigurationFileUsing(host, record, acceptLegacyRetirementFixture, defaultLegacyRetirementFileOps()); err != nil {
				t.Fatal(err)
			}
			assertLegacyRetirementComplete(t, root, host, record)
		})
	}
}

func TestLegacyRetirementFileResumesAfterSyncFailure(t *testing.T) {
	for failure := 1; failure <= 7; failure++ {
		root, host, record := fixtureLegacyFileRetirement(t)
		ops := defaultLegacyRetirementFileOps()
		calls := 0
		injected := errors.New("injected sync failure")
		ops.sync = func(file *os.File) error {
			calls++
			if calls == failure {
				return injected
			}
			return file.Sync()
		}
		if err := retireLegacyConfigurationFileUsing(host, record, acceptLegacyRetirementFixture, ops); !errors.Is(err, injected) {
			t.Fatalf("sync %d did not fail: %v", failure, err)
		}
		if err := retireLegacyConfigurationFileUsing(host, record, acceptLegacyRetirementFixture, defaultLegacyRetirementFileOps()); err != nil {
			t.Fatalf("sync %d cannot resume: %v", failure, err)
		}
		assertLegacyRetirementComplete(t, root, host, record)
	}
}

func TestLegacyRetirementFileRejectsGuardAndSourceDrift(t *testing.T) {
	for _, mutation := range []string{"denied", "modified", "symlink", "hardlink", "backup_directory", "intent", "final_guard"} {
		t.Run(mutation, func(t *testing.T) {
			root, host, record := fixtureLegacyFileRetirement(t)
			source := filepath.Join(root, record.Source.Path)
			backup := filepath.Join(root, legacyRetirementBackupDirectory(record))
			calls := 0
			guard := func(retired bool) error {
				calls++
				if mutation == "denied" {
					return errors.New("guard denied mutation")
				}
				if mutation == "final_guard" && retired {
					return os.WriteFile(source, []byte("administrator replacement\n"), 0600)
				}
				if calls != 2 {
					return nil
				}
				switch mutation {
				case "modified":
					return os.WriteFile(source, []byte("administrator replacement\n"), 0600)
				case "symlink":
					if err := os.Rename(source, source+".saved"); err != nil {
						return err
					}
					return os.Symlink(source+".saved", source)
				case "hardlink":
					return os.Link(source, source+".link")
				case "backup_directory":
					if err := os.Rename(backup, backup+".saved"); err != nil {
						return err
					}
					return os.Mkdir(backup, 0700)
				case "intent":
					return os.WriteFile(filepath.Join(backup, "intent.json"), []byte("{}"), 0600)
				}
				return nil
			}
			if err := retireLegacyConfigurationFileUsing(host, record, guard, defaultLegacyRetirementFileOps()); err == nil {
				t.Fatal("accepted state changed by the final guard")
			}
			if _, err := os.Lstat(source); err != nil {
				t.Fatal("active source was removed after refusal")
			}
			if mutation != "final_guard" {
				if _, err := os.Lstat(filepath.Join(backup, "original")); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("created a backup by removing refused source")
				}
			}
		})
	}
}

func TestLegacyRetirementFilePreservesConcurrentReplacementAtRename(t *testing.T) {
	for _, race := range []string{"source_before", "source_after", "backup_collision", "cross_device"} {
		t.Run(race, func(t *testing.T) {
			root, host, record := fixtureLegacyFileRetirement(t)
			source := filepath.Join(root, record.Source.Path)
			backup := filepath.Join(root, legacyRetirementBackupDirectory(record), "original")
			original, err := os.ReadFile(source) // #nosec G304 -- The path is constructed solely from this test's private temporary root and controlled fixture names.
			if err != nil {
				t.Fatal(err)
			}
			custom := []byte("administrator replacement\n")
			ops := defaultLegacyRetirementFileOps()
			triggered := false
			ops.rename = func(oldFD int, oldName string, newFD int, newName string, flags uint) error {
				if oldName != filepath.Base(source) || newName != "original" || triggered {
					return unix.Renameat2(oldFD, oldName, newFD, newName, flags)
				}
				triggered = true
				switch race {
				case "source_before":
					if err := os.Rename(source, source+".saved"); err != nil {
						return err
					}
					if err := os.WriteFile(source, custom, 0600); err != nil {
						return err
					}
				case "backup_collision":
					if err := os.WriteFile(backup, custom, 0600); err != nil {
						return err
					}
				case "cross_device":
					return unix.EXDEV
				}
				if err := unix.Renameat2(oldFD, oldName, newFD, newName, flags); err != nil {
					return err
				}
				if race == "source_after" {
					return os.WriteFile(source, custom, 0600)
				}
				return nil
			}
			if err := retireLegacyConfigurationFileUsing(host, record, acceptLegacyRetirementFixture, ops); err == nil || !triggered {
				t.Fatalf("race was not rejected: %v", err)
			}
			want := original
			if strings.HasPrefix(race, "source_") {
				want = custom
			}
			actual, err := os.ReadFile(source) // #nosec G304 -- The path is constructed solely from this test's private temporary root and controlled fixture names.
			if err != nil || !bytes.Equal(actual, want) {
				t.Fatal("active file was overwritten or lost")
			}
			switch race {
			case "source_before":
				actual, err = os.ReadFile(source + ".saved") // #nosec G304 -- The path is constructed solely from this test's private temporary root and controlled fixture names.
				if err != nil || !bytes.Equal(actual, original) {
					t.Fatal("original evidence was lost")
				}
			case "source_after":
				actual, err = os.ReadFile(backup) // #nosec G304 -- The path is constructed solely from this test's private temporary root and controlled fixture names.
				if err != nil || !bytes.Equal(actual, original) {
					t.Fatal("original backup was lost")
				}
			case "backup_collision":
				actual, err = os.ReadFile(backup) // #nosec G304 -- The path is constructed solely from this test's private temporary root and controlled fixture names.
				if err != nil || !bytes.Equal(actual, custom) {
					t.Fatal("preexisting backup was overwritten")
				}
			}
		})
	}
}

func TestLegacyRetirementFileRejectsUnjournaledBackupAndChangedRecords(t *testing.T) {
	for _, mutation := range []string{"unjournaled", "altered_backup", "linked_backup", "intent_extra", "intent_duplicate", "public_directory"} {
		t.Run(mutation, func(t *testing.T) {
			root, host, record := fixtureLegacyFileRetirement(t)
			backup := filepath.Join(root, legacyRetirementBackupDirectory(record))
			if mutation == "unjournaled" {
				if err := os.Rename(filepath.Join(root, record.Source.Path), filepath.Join(backup, "original")); err != nil {
					t.Fatal(err)
				}
			} else if mutation == "public_directory" {
				if err := os.Chmod(backup, 0755); err != nil { // #nosec G302 -- Deliberately varies synthetic metadata inside a private temporary root to test validation.
					t.Fatal(err)
				}
			} else {
				if err := retireLegacyConfigurationFileUsing(host, record, acceptLegacyRetirementFixture, defaultLegacyRetirementFileOps()); err != nil {
					t.Fatal(err)
				}
				switch mutation {
				case "altered_backup":
					if err := os.WriteFile(filepath.Join(backup, "original"), []byte("changed backup"), 0600); err != nil {
						t.Fatal(err)
					}
				case "linked_backup":
					if err := os.Link(filepath.Join(backup, "original"), filepath.Join(backup, "copy")); err != nil {
						t.Fatal(err)
					}
				default:
					content, err := os.ReadFile(filepath.Join(backup, "intent.json")) // #nosec G304 -- The path is constructed solely from this test's private temporary root and controlled fixture names.
					if err != nil {
						t.Fatal(err)
					}
					if mutation == "intent_extra" {
						content = append(content, '\n')
					} else {
						content = append([]byte(`{"schema":"duplicate",`), content[1:]...)
					}
					if err := os.WriteFile(filepath.Join(backup, "intent.json"), content, 0600); err != nil { // #nosec G703 -- The path is constructed solely from this test's private temporary root and controlled fixture names.
						t.Fatal(err)
					}
				}
			}
			if err := retireLegacyConfigurationFileUsing(host, record, acceptLegacyRetirementFixture, defaultLegacyRetirementFileOps()); err == nil {
				t.Fatal("accepted ambiguous or modified recovery evidence")
			}
		})
	}
}

func TestLegacyRetirementAbruptHelper(t *testing.T) {
	root := os.Getenv("SYSWARDEN_RETIREMENT_TEST_ROOT")
	if root == "" {
		return
	}
	content, err := os.ReadFile(filepath.Join(root, "request.json")) // #nosec G304 G703 -- Reads only the private temporary root passed by the parent test process.
	if err != nil {
		t.Fatal(err)
	}
	var record legacyRetirementFileRecord
	if err := json.Unmarshal(content, &record); err != nil {
		t.Fatal(err)
	}
	pinned, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pinned.Close() }()
	host := fixtureNFTPersistencePinnedRoot(t, pinned)
	ops := defaultLegacyRetirementFileOps()
	ops.checkpoint = func(phase string) error {
		if phase == os.Getenv("SYSWARDEN_RETIREMENT_TEST_PHASE") {
			os.Exit(73)
		}
		return nil
	}
	if err := retireLegacyConfigurationFileUsing(host, record, acceptLegacyRetirementFixture, ops); err != nil {
		t.Fatal(err)
	}
	t.Fatal("abrupt exit checkpoint was not reached")
}

func TestLegacyRetirementFileResumesAfterAbruptProcessExit(t *testing.T) {
	for _, phase := range []string{"intent-staged", "intent-published", "source-retired", "retirement-durable"} {
		t.Run(phase, func(t *testing.T) {
			root, host, record := fixtureLegacyFileRetirement(t)
			content, err := json.Marshal(record)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "request.json"), content, 0600); err != nil {
				t.Fatal(err)
			}
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			command := exec.Command(executable, "-test.run=^TestLegacyRetirementAbruptHelper$") // #nosec G204 -- Reexecutes only this test binary with a fixed helper selector and private fixture environment.
			command.Env = append(os.Environ(), "SYSWARDEN_RETIREMENT_TEST_ROOT="+root, "SYSWARDEN_RETIREMENT_TEST_PHASE="+phase)
			output, err := command.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 73 {
				t.Fatalf("helper did not exit abruptly: %v %s", err, output)
			}
			if err := retireLegacyConfigurationFileUsing(host, record, acceptLegacyRetirementFixture, defaultLegacyRetirementFileOps()); err != nil {
				t.Fatal(err)
			}
			assertLegacyRetirementComplete(t, root, host, record)
		})
	}
}
