//go:build linux

package firewall

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func fixtureLegacyFail2banJournal(t *testing.T) (string, nftPersistenceFilesystem, legacyFail2banRetirementPlan) {
	t.Helper()
	root, host := fixtureLegacyFail2banInventory(t)
	if err := os.MkdirAll(filepath.Join(root, "var/backups"), 0755); err != nil { // #nosec G301 -- Models system-directory permissions inside a private temporary root for ownership checks.
		t.Fatal(err)
	}
	paths := []string{legacyPlanTarget}
	for _, name := range []string{"syswarden-webhook", "syswarden-persistence"} {
		path := "/etc/fail2ban/action.d/" + name + ".conf"
		writeNFTPersistenceFixture(t, root, path, string(readLegacyFail2banFixture(t, name+".conf")))
		paths = append(paths, path)
	}
	plan, err := prepareLegacyFail2banRetirement(host, paths, fixtureLegacyFail2banPlanProbe(t))
	if err != nil {
		t.Fatal(err)
	}
	return root, host, plan
}

func acceptLegacyFail2banJournalFixture() error { return nil }

func assertLegacyFail2banJournalComplete(t *testing.T, host nftPersistenceFilesystem, plan legacyFail2banRetirementPlan) {
	t.Helper()
	record, err := readLegacyFail2banPlan(host, plan.sha256)
	if err != nil || !reflect.DeepEqual(record, plan.binding) {
		t.Fatal("durable plan changed", err)
	}
	state, err := inspectLegacyFail2banPlanState(host, record)
	if err != nil || len(state.retired) != len(plan.retiring) {
		t.Fatal("file plan is incomplete", err)
	}
	for _, file := range plan.records {
		intent, err := readLegacyRetirementFileRecord(host, legacyRetirementBackupDirectory(file))
		if err != nil || intent != file {
			t.Fatal("file intent is not bound to the whole plan", err)
		}
	}
	current := readLegacyFail2banInventoryFixture(t, host)
	if err := verifyLegacyFail2banInventoryRetirement(plan.baseline, current, plan.retiring); err != nil {
		t.Fatal("unrelated configuration changed", err)
	}
}

func TestLegacyFail2banJournalDurablyPublishesBeforeAnyFileMove(t *testing.T) {
	_, host, plan := fixtureLegacyFail2banJournal(t)
	guardCalls := 0
	guard := func() error { guardCalls++; return nil }
	if err := persistLegacyFail2banPlanUsing(host, plan, guard, defaultLegacyRetirementFileOps()); err != nil {
		t.Fatal(err)
	}
	if guardCalls < 2 {
		t.Fatal("required live guard was omitted")
	}
	if err := reattestLegacyFail2banPlanInventory(host, plan.baseline); err != nil {
		t.Fatal("publication changed active configuration", err)
	}
	path := legacyFail2banPlanPath(plan.sha256) + "/plan.json"
	before, err := host.snapshot(path)
	if err != nil {
		t.Fatal(err)
	}
	if before.identity.Mode().Perm() != 0600 {
		t.Fatal("journal is not private")
	}
	for _, record := range plan.records {
		directory, err := host.openDirectory(legacyRetirementBackupDirectory(record))
		if err != nil {
			t.Fatal(err)
		}
		info, err := directory.Stat(".")
		_ = directory.Close()
		if err != nil || info.Mode().Perm() != 0700 {
			t.Fatal("backup directory is not private", err)
		}
		if _, err := host.snapshot(legacyRetirementBackupDirectory(record) + "/intent.json"); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("file intent published before file execution")
		}
	}
	if err := persistLegacyFail2banPlanUsing(host, plan, guard, defaultLegacyRetirementFileOps()); err != nil {
		t.Fatal(err)
	}
	after, err := host.snapshot(path)
	if err != nil || !sameLegacyFail2banSource(before, after) {
		t.Fatal("idempotent publication replaced the reviewed journal", err)
	}
}

func TestLegacyFail2banJournalResumesAllFilesAndPreservesAdministratorConfiguration(t *testing.T) {
	_, host, plan := fixtureLegacyFail2banJournal(t)
	ops := defaultLegacyRetirementFileOps()
	if err := persistLegacyFail2banPlanUsing(host, plan, acceptLegacyFail2banJournalFixture, ops); err != nil {
		t.Fatal(err)
	}
	if err := resumeLegacyFail2banPlanUsing(host, plan.sha256, acceptLegacyFail2banJournalFixture, ops); err != nil {
		t.Fatal(err)
	}
	assertLegacyFail2banJournalComplete(t, host, plan)
	if err := resumeLegacyFail2banPlanUsing(host, plan.sha256, acceptLegacyFail2banJournalFixture, ops); err != nil {
		t.Fatal("completed plan cannot safely resume", err)
	}
	assertLegacyFail2banJournalComplete(t, host, plan)
}

func interruptLegacyFail2banPlanAfterFirstMove(t *testing.T, host nftPersistenceFilesystem, plan legacyFail2banRetirementPlan) {
	t.Helper()
	ops := defaultLegacyRetirementFileOps()
	if err := persistLegacyFail2banPlanUsing(host, plan, acceptLegacyFail2banJournalFixture, ops); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("synthetic interrupted plan")
	ops.checkpoint = func(phase string) error {
		if phase == "source-retired" {
			return injected
		}
		return nil
	}
	if err := resumeLegacyFail2banPlanUsing(host, plan.sha256, acceptLegacyFail2banJournalFixture, ops); !errors.Is(err, injected) {
		t.Fatal("interruption checkpoint was not reached", err)
	}
	state, err := inspectLegacyFail2banPlanState(host, plan.binding)
	if err != nil || len(state.retired) != 1 || !state.retired[legacyPlanTarget] {
		t.Fatal("jail was not retired first", err)
	}
}

func TestLegacyFail2banJournalRejectsChangesAcrossInterruption(t *testing.T) {
	for _, change := range []string{"new_file", "new_hidden_file", "modify_admin", "replace_admin", "remove_admin", "new_directory", "replace_directory", "replace_backup", "missing_backup", "both_source_and_backup", "changed_intent", "missing_intent", "missing_journal", "missing_backup_directory"} {
		t.Run(change, func(t *testing.T) {
			root, host, plan := fixtureLegacyFail2banJournal(t)
			interruptLegacyFail2banPlanAfterFirstMove(t, host, plan)
			admin := filepath.Join(root, "etc/fail2ban/jail.d/administrator.local")
			record := legacyFail2banPlanFileRecords(plan.binding, plan.sha256)[0]
			backupDir := filepath.Join(root, legacyRetirementBackupDirectory(record))
			var err error
			switch change {
			case "new_file":
				writeNFTPersistenceFixture(t, root, "/etc/fail2ban/jail.d/new.local", "[administrator-new]\nenabled = true\n")
			case "new_hidden_file":
				writeNFTPersistenceFixture(t, root, "/etc/fail2ban/jail.d/.new", "private copy\n")
			case "modify_admin":
				err = os.WriteFile(admin, []byte("[administrator-web]\nenabled = false\n"), 0600)
			case "replace_admin":
				data, readErr := os.ReadFile(admin) // #nosec G304 -- The path is constructed solely from this test's private temporary root and controlled fixture names.
				if readErr != nil {
					t.Fatal(readErr)
				}
				if err = os.Rename(admin, filepath.Join(root, "saved-admin")); err == nil {
					err = os.WriteFile(admin, data, 0600) // #nosec G703 -- The path is constructed solely from this test's private temporary root and controlled fixture names.
				}
			case "remove_admin":
				err = os.Rename(admin, filepath.Join(root, "saved-admin"))
			case "new_directory":
				err = os.Mkdir(filepath.Join(root, "etc/fail2ban/new.d"), 0700)
			case "replace_directory":
				path := filepath.Join(root, "etc/fail2ban/filter.d/custom.d")
				if err = os.Rename(path, filepath.Join(root, "saved-directory")); err == nil {
					err = os.Mkdir(path, 0700)
				}
			case "replace_backup":
				path := filepath.Join(backupDir, "original")
				data, readErr := os.ReadFile(path) // #nosec G304 -- The path is constructed solely from this test's private temporary root and controlled fixture names.
				if readErr != nil {
					t.Fatal(readErr)
				}
				if err = os.Rename(path, filepath.Join(root, "saved-original")); err == nil {
					err = os.WriteFile(path, data, 0600) // #nosec G703 -- The path is constructed solely from this test's private temporary root and controlled fixture names.
				}
			case "missing_backup":
				err = os.Rename(filepath.Join(backupDir, "original"), filepath.Join(root, "saved-original"))
			case "both_source_and_backup":
				err = os.WriteFile(filepath.Join(root, record.Source.Path), readLegacyFail2banFixture(t, "portscan-pre_v2.conf"), 0600)
			case "changed_intent":
				err = os.WriteFile(filepath.Join(backupDir, "intent.json"), []byte("{}"), 0600)
			case "missing_intent":
				err = os.Rename(filepath.Join(backupDir, "intent.json"), filepath.Join(root, "saved-intent"))
			case "missing_journal":
				err = os.Rename(filepath.Join(root, legacyFail2banPlanPath(plan.sha256), "plan.json"), filepath.Join(root, "saved-plan"))
			case "missing_backup_directory":
				next := legacyFail2banPlanFileRecords(plan.binding, plan.sha256)[1]
				err = os.Remove(filepath.Join(root, legacyRetirementBackupDirectory(next)))
			}
			if err != nil {
				t.Fatal(err)
			}
			called := false
			if err := resumeLegacyFail2banPlanUsing(host, plan.sha256, func() error { called = true; return nil }, defaultLegacyRetirementFileOps()); err == nil {
				t.Fatal("changed recovery state was accepted")
			}
			if called && change != "missing_backup_directory" {
				t.Fatal("live guard invoked before rejecting inconsistent evidence")
			}
			for _, next := range legacyFail2banPlanFileRecords(plan.binding, plan.sha256)[1:] {
				snapshot, err := host.snapshot(next.Source.Path)
				if err != nil || !matchesLegacyRetirementSource(next, snapshot) {
					t.Fatal("later source moved after failed recovery", err)
				}
			}
		})
	}
}

func TestLegacyFail2banJournalRejectsUnsafeOrNoncanonicalJournal(t *testing.T) {
	for _, kind := range []string{"newline", "unknown_field", "duplicate_field", "wrong_digest", "public_file", "public_directory", "symlink", "hardlink", "truncated"} {
		t.Run(kind, func(t *testing.T) {
			root, host, plan := fixtureLegacyFail2banJournal(t)
			if err := persistLegacyFail2banPlanUsing(host, plan, acceptLegacyFail2banJournalFixture, defaultLegacyRetirementFileOps()); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, legacyFail2banPlanPath(plan.sha256), "plan.json")
			data, err := os.ReadFile(path) // #nosec G304 -- The path is constructed solely from this test's private temporary root and controlled fixture names.
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "newline":
				err = os.WriteFile(path, append(data, '\n'), 0600) // #nosec G703 -- The path is constructed solely from this test's private temporary root and controlled fixture names.
			case "unknown_field":
				err = os.WriteFile(path, append([]byte("{\"extra\":true,"), data[1:]...), 0600) // #nosec G703 -- The path is constructed solely from this test's private temporary root and controlled fixture names.
			case "duplicate_field":
				err = os.WriteFile(path, append([]byte("{\"schema\":\""+legacyFail2banPlanSchema+"\","), data[1:]...), 0600) // #nosec G703 -- The path is constructed solely from this test's private temporary root and controlled fixture names.
			case "wrong_digest":
				err = os.WriteFile(path, bytes.Replace(data, []byte("views_sha256"), []byte("wrong_sha256"), 1), 0600) // #nosec G703 -- The path is constructed solely from this test's private temporary root and controlled fixture names.
			case "public_file":
				err = os.Chmod(path, 0644) // #nosec G302 -- Deliberately varies synthetic metadata inside a private temporary root to test validation.
			case "public_directory":
				err = os.Chmod(filepath.Dir(path), 0755) // #nosec G302 -- Deliberately varies synthetic metadata inside a private temporary root to test validation.
			case "symlink":
				if err = os.Rename(path, filepath.Join(root, "saved-plan")); err == nil {
					err = os.Symlink(filepath.Join(root, "saved-plan"), path)
				}
			case "hardlink":
				err = os.Link(path, filepath.Join(root, "saved-plan"))
			case "truncated":
				err = os.WriteFile(path, data[:len(data)/2], 0600) // #nosec G703 -- The path is constructed solely from this test's private temporary root and controlled fixture names.
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := readLegacyFail2banPlan(host, plan.sha256); err == nil {
				t.Fatal("unsafe or noncanonical journal accepted")
			}
			if err := resumeLegacyFail2banPlanUsing(host, plan.sha256, acceptLegacyFail2banJournalFixture, defaultLegacyRetirementFileOps()); err == nil {
				t.Fatal("invalid journal authorized recovery")
			}
			if err := reattestLegacyFail2banPlanInventory(host, plan.baseline); err != nil {
				t.Fatal("invalid journal changed active configuration", err)
			}
		})
	}
}

func TestLegacyFail2banJournalGuardChangesAreReattestedBeforeMoves(t *testing.T) {
	for _, explicitFailure := range []bool{false, true} {
		root, host, plan := fixtureLegacyFail2banJournal(t)
		if err := persistLegacyFail2banPlanUsing(host, plan, acceptLegacyFail2banJournalFixture, defaultLegacyRetirementFileOps()); err != nil {
			t.Fatal(err)
		}
		guard := func() error {
			if explicitFailure {
				return errors.New("synthetic live producer is not quiescent")
			}
			writeNFTPersistenceFixture(t, root, "/etc/fail2ban/jail.d/concurrent.local", "[administrator-web]\nenabled = false\n")
			return nil
		}
		if err := resumeLegacyFail2banPlanUsing(host, plan.sha256, guard, defaultLegacyRetirementFileOps()); err == nil {
			t.Fatal("unsafe guard boundary accepted")
		}
		for _, record := range plan.records {
			snapshot, err := host.snapshot(record.Source.Path)
			if err != nil || !matchesLegacyRetirementSource(record, snapshot) {
				t.Fatal("source moved after guard invalidation", err)
			}
		}
	}
}

func TestLegacyFail2banJournalBindsDirectoryDeviceRenumberingToUUID(t *testing.T) {
	_, _, plan := fixtureLegacyFail2banJournal(t)
	expected := plan.binding.Directories[0]
	expected.FilesystemUUID = "112233445566778899aabbccddeeff00"
	actual := expected
	actual.Device++
	if !sameLegacyFail2banPlanDirectory(actual, expected) {
		t.Fatal("same filesystem UUID did not allow device renumbering")
	}
	actual.FilesystemUUID = "ffeeddccbbaa99887766554433221100"
	if sameLegacyFail2banPlanDirectory(actual, expected) {
		t.Fatal("different filesystem UUID was accepted")
	}
	actual = expected
	actual.Inode++
	if sameLegacyFail2banPlanDirectory(actual, expected) {
		t.Fatal("different directory inode was accepted")
	}
	expected.FilesystemUUID = ""
	actual = expected
	actual.Device++
	if sameLegacyFail2banPlanDirectory(actual, expected) {
		t.Fatal("legacy directory allowed unbound device renumbering")
	}
}

func TestLegacyFail2banJournalRejectsReappearingSourceAtCompletion(t *testing.T) {
	root, host, plan := fixtureLegacyFail2banJournal(t)
	ops := defaultLegacyRetirementFileOps()
	if err := persistLegacyFail2banPlanUsing(host, plan, acceptLegacyFail2banJournalFixture, ops); err != nil {
		t.Fatal(err)
	}
	first := legacyFail2banPlanFileRecords(plan.binding, plan.sha256)[0]
	ops.checkpoint = func(phase string) error {
		if phase == "plan-complete" {
			return os.Rename(filepath.Join(root, legacyRetirementBackupDirectory(first), "original"), filepath.Join(root, first.Source.Path))
		}
		return nil
	}
	if err := resumeLegacyFail2banPlanUsing(host, plan.sha256, acceptLegacyFail2banJournalFixture, ops); err == nil || !strings.Contains(err.Error(), "reappear") {
		t.Fatal("reappearing active source was reported as complete retirement", err)
	}
}

func TestLegacyFail2banJournalRejectsReplacementDuringSync(t *testing.T) {
	root, host, plan := fixtureLegacyFail2banJournal(t)
	if err := persistLegacyFail2banPlanUsing(host, plan, acceptLegacyFail2banJournalFixture, defaultLegacyRetirementFileOps()); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, legacyFail2banPlanPath(plan.sha256), "plan.json")
	content, err := os.ReadFile(path) // #nosec G304 -- The path is constructed solely from this test's private temporary root and controlled fixture names.
	if err != nil {
		t.Fatal(err)
	}
	ops := defaultLegacyRetirementFileOps()
	changed := false
	ops.sync = func(file *os.File) error {
		if filepath.Base(file.Name()) == "plan.json" && !changed {
			changed = true
			if err := os.Rename(path, filepath.Join(root, "saved-original-plan")); err != nil {
				return err
			}
			if err := os.WriteFile(path, content, 0600); err != nil { // #nosec G703 -- The path is constructed solely from this test's private temporary root and controlled fixture names.
				return err
			}
		}
		return file.Sync()
	}
	if err := resumeLegacyFail2banPlanUsing(host, plan.sha256, acceptLegacyFail2banJournalFixture, ops); err == nil || !strings.Contains(err.Error(), "during synchronization") {
		t.Fatal("unsynced replacement journal was accepted", err)
	}
	if err := reattestLegacyFail2banPlanInventory(host, plan.baseline); err != nil {
		t.Fatal("source moved after journal replacement", err)
	}
}

func TestLegacyFail2banJournalDoesNotRecreateDeletedPublication(t *testing.T) {
	root, host, plan := fixtureLegacyFail2banJournal(t)
	ops := defaultLegacyRetirementFileOps()
	if err := persistLegacyFail2banPlanUsing(host, plan, acceptLegacyFail2banJournalFixture, ops); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, legacyFail2banPlanPath(plan.sha256), "plan.json")
	deleted := false
	guard := func() error {
		if !deleted {
			deleted = true
			return os.Rename(path, filepath.Join(root, "saved-plan"))
		}
		return nil
	}
	if err := resumeLegacyFail2banPlanUsing(host, plan.sha256, guard, ops); err == nil {
		t.Fatal("deleted publication was recreated")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("recovery replaced missing journal")
	}
	if err := reattestLegacyFail2banPlanInventory(host, plan.baseline); err != nil {
		t.Fatal("configuration changed after missing journal", err)
	}
}

func TestLegacyFail2banJournalPreservesUnsafeBackupPaths(t *testing.T) {
	for _, kind := range []string{"public_directory", "symlink", "regular_file"} {
		root, host, plan := fixtureLegacyFail2banJournal(t)
		path := filepath.Join(root, legacyRetirementBackupRoot)
		var err error
		switch kind {
		case "public_directory":
			err = os.Mkdir(path, 0755) // #nosec G301 -- Models system-directory permissions inside a private temporary root for ownership checks.
		case "symlink":
			err = os.Symlink(filepath.Join(root, "etc"), path)
		case "regular_file":
			err = os.WriteFile(path, []byte("administrator-owned file\n"), 0600)
		}
		if err != nil {
			t.Fatal(err)
		}
		before, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := persistLegacyFail2banPlanUsing(host, plan, acceptLegacyFail2banJournalFixture, defaultLegacyRetirementFileOps()); err == nil {
			t.Fatal("unsafe backup path was adopted", kind)
		}
		after, err := os.Lstat(path)
		if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
			t.Fatal("unsafe existing path was changed", err)
		}
		if err := reattestLegacyFail2banPlanInventory(host, plan.baseline); err != nil {
			t.Fatal("unsafe backup path changed active configuration", err)
		}
	}
}

func TestLegacyFail2banJournalAbruptExitChild(t *testing.T) {
	root := os.Getenv("SYSWARDEN_LEGACY_PLAN_CHILD_ROOT")
	if root == "" {
		t.Skip("private child-process fixture only")
	}
	data, err := os.ReadFile(filepath.Join(root, "fixture-plan.json")) // #nosec G304 G703 -- Reads only the private temporary root passed by the parent test process.
	if err != nil {
		t.Fatal(err)
	}
	var binding legacyFail2banPlanRecord
	if err := json.Unmarshal(data, &binding); err != nil {
		t.Fatal(err)
	}
	pinned, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer pinned.Close()
	host := fixtureNFTPersistencePinnedRoot(t, pinned)
	_, digest, err := encodeLegacyFail2banPlan(binding, host.expectedUID, host.expectedGID)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(os.Getenv("SYSWARDEN_LEGACY_PLAN_CHILD_PHASE"), ":")
	if len(parts) != 2 {
		t.Fatal("invalid test checkpoint")
	}
	wanted, err := strconv.Atoi(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	ops := defaultLegacyRetirementFileOps()
	ops.checkpoint = func(phase string) error {
		if phase == parts[0] {
			seen++
			if seen == wanted {
				os.Exit(79)
			}
		}
		return nil
	}
	plan := legacyFail2banRetirementPlan{sha256: digest, binding: binding}
	if err := persistLegacyFail2banPlanUsing(host, plan, acceptLegacyFail2banJournalFixture, ops); err != nil {
		t.Fatal(err)
	}
	if err := resumeLegacyFail2banPlanUsing(host, digest, acceptLegacyFail2banJournalFixture, ops); err != nil {
		t.Fatal(err)
	}
	t.Fatal("abrupt exit checkpoint was not reached")
}

func TestLegacyFail2banJournalResumesAbruptProcessExit(t *testing.T) {
	for _, phase := range []string{"backup-directory-durable:1", "plan-staged:1", "plan-published:1", "intent-published:1", "source-retired:1", "source-retired:2", "source-retired:3", "retirement-durable:2", "plan-complete:1"} {
		t.Run(phase, func(t *testing.T) {
			root, host, plan := fixtureLegacyFail2banJournal(t)
			content, err := json.Marshal(plan.binding)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "fixture-plan.json"), content, 0600); err != nil {
				t.Fatal(err)
			}
			command := exec.Command(os.Args[0], "-test.run=^TestLegacyFail2banJournalAbruptExitChild$") // #nosec G204 G702 -- Reexecutes only this test binary with a fixed helper selector and private fixture environment.
			command.Env = append(os.Environ(), "SYSWARDEN_LEGACY_PLAN_CHILD_ROOT="+root, "SYSWARDEN_LEGACY_PLAN_CHILD_PHASE="+phase)
			output, err := command.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 79 {
				t.Fatalf("child did not stop at %s: %v %s", phase, err, output)
			}
			if _, err := readLegacyFail2banPlan(host, plan.sha256); errors.Is(err, os.ErrNotExist) {
				if err := persistLegacyFail2banPlanUsing(host, plan, acceptLegacyFail2banJournalFixture, defaultLegacyRetirementFileOps()); err != nil {
					t.Fatal(err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if err := resumeLegacyFail2banPlanUsing(host, plan.sha256, acceptLegacyFail2banJournalFixture, defaultLegacyRetirementFileOps()); err != nil {
				t.Fatal(err)
			}
			assertLegacyFail2banJournalComplete(t, host, plan)
		})
	}
}

func TestLegacyFail2banJournalSyncFailuresRetainRecoverableEvidence(t *testing.T) {
	for _, point := range []string{"first_directory", "parent_directory", "plan_stage", "published_plan"} {
		t.Run(point, func(t *testing.T) {
			_, host, plan := fixtureLegacyFail2banJournal(t)
			ops := defaultLegacyRetirementFileOps()
			injected := errors.New("synthetic plan sync failure")
			calls := 0
			failed := false
			ops.sync = func(file *os.File) error {
				calls++
				if !failed && (point == "first_directory" && calls == 1 || point == "parent_directory" && calls == 2 || point == "plan_stage" && strings.Contains(file.Name(), ".plan-stage-") || point == "published_plan" && filepath.Base(file.Name()) == "plan.json") {
					failed = true
					return injected
				}
				return file.Sync()
			}
			if err := persistLegacyFail2banPlanUsing(host, plan, acceptLegacyFail2banJournalFixture, ops); !errors.Is(err, injected) || !failed {
				t.Fatal("sync failure not propagated", err)
			}
			if err := reattestLegacyFail2banPlanInventory(host, plan.baseline); err != nil {
				t.Fatal("failed publication changed active configuration", err)
			}
			if err := persistLegacyFail2banPlanUsing(host, plan, acceptLegacyFail2banJournalFixture, defaultLegacyRetirementFileOps()); err != nil {
				t.Fatal(err)
			}
			if err := resumeLegacyFail2banPlanUsing(host, plan.sha256, acceptLegacyFail2banJournalFixture, defaultLegacyRetirementFileOps()); err != nil {
				t.Fatal(err)
			}
			assertLegacyFail2banJournalComplete(t, host, plan)
		})
	}
}

func TestLegacyFail2banJournalRejectsMalformedPlanRecords(t *testing.T) {
	_, host, plan := fixtureLegacyFail2banJournal(t)
	for _, kind := range []string{"schema", "no_sources", "duplicate_source", "source_outside_tree", "source_plan", "source_size", "no_directory", "directory_owner", "directory_mode", "directory_uuid", "directory_parent", "target_missing", "target_duplicate", "views"} {
		t.Run(kind, func(t *testing.T) {
			content, _ := json.Marshal(plan.binding)
			var record legacyFail2banPlanRecord
			if err := json.Unmarshal(content, &record); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "schema":
				record.Schema = "other"
			case "no_sources":
				record.Sources = nil
			case "duplicate_source":
				record.Sources = append(record.Sources, record.Sources[0])
			case "source_outside_tree":
				record.Sources[0].Source.Path = "/etc/custom.conf"
			case "source_plan":
				record.Sources[0].PlanSHA256 = strings.Repeat("a", 64)
			case "source_size":
				record.Sources[0].Size = maximumLegacyFail2banTreeBytes + 1
			case "no_directory":
				record.Directories = nil
			case "directory_owner":
				record.Directories[0].UID++
			case "directory_mode":
				record.Directories[0].Mode |= 0020
			case "directory_uuid":
				record.Directories[0].FilesystemUUID = "invalid"
			case "directory_parent":
				record.Directories = record.Directories[1:]
			case "target_missing":
				record.Targets = []string{"/etc/fail2ban/absent.conf"}
			case "target_duplicate":
				record.Targets = append(record.Targets, record.Targets[0])
			case "views":
				clear(record.Views[:])
			}
			if _, _, err := encodeLegacyFail2banPlan(record, host.expectedUID, host.expectedGID); err == nil {
				t.Fatal("malformed record accepted", kind)
			}
		})
	}
	for _, guard := range []func() error{nil, func() error { return fmt.Errorf("synthetic guard refusal") }} {
		if err := persistLegacyFail2banPlanUsing(host, plan, guard, defaultLegacyRetirementFileOps()); err == nil {
			t.Fatal("missing or refusing guard was ignored")
		}
	}
}
