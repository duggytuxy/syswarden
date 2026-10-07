//go:build linux

package system

import (
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestHistoricalHostRemovalPreflightSeparatesExistingCleanupAndUnresolvedSources(t *testing.T) {
	absentCron := func() (string, bool, error) { return "", false, nil }
	for _, path := range append(append([]string(nil), historicalHostRemovalPaths...), historicalHostRemovalFinalPaths...) {
		t.Run(path, func(t *testing.T) {
			present := func(candidate string) (bool, error) { return candidate == path, nil }
			found, err := inspectHistoricalHostRemovalRemainders(true, present, absentCron)
			if err != nil || len(found) != 1 || found[0].path != path {
				t.Fatalf("candidate was not retained explicitly: %v %v", found, err)
			}
			finalErr := preflightHistoricalHostRemovalUsing(true, present, absentCron)
			if finalErr == nil || !strings.Contains(finalErr.Error(), path) {
				t.Fatal("complete removal accepted a retained candidate", finalErr)
			}
			for _, handled := range historicalHostRemovalFinalPaths {
				if path == handled && preflightHistoricalHostRemovalUsing(false, present, absentCron) != nil {
					t.Fatal("preflight prevented the existing exact cleanup phase")
				}
			}
		})
	}
	if err := preflightHistoricalHostRemovalUsing(true, func(string) (bool, error) { return false, nil }, absentCron); err != nil {
		t.Fatal("confirmed absence did not pass", err)
	}
}

func TestHistoricalHostRemovalCronEvidenceIsReadOnlyAndRedacted(t *testing.T) {
	content := "# syswarden reference in a comment\nMAILTO=operator@example.invalid\n" +
		"17 * * * * /opt/syswarden/bin/syswarden-cli update-feeds >/dev/null 2>&1\n" +
		"*/30 * * * * /opt/syswarden/bin/syswarden-cli ha-sync >/dev/null 2>&1\n" +
		"1 * * * * /usr/local/sbin/custom-backup --source=syswarden --token=private-fixture-value\n" +
		"2 * * * * /usr/local/sbin/unrelated-job\n"
	present := func(string) (bool, error) { return false, nil }
	reader := func() (string, bool, error) { return content, true, nil }
	found, err := inspectHistoricalHostRemovalRemainders(true, present, reader)
	want := []historicalHostRemovalRemainder{
		{"root crontab line 3", "exact historical generated schedule"},
		{"root crontab line 4", "exact historical generated schedule"},
		{"root crontab line 5", "unresolved scheduling dependency"},
	}
	if err != nil || !reflect.DeepEqual(found, want) {
		t.Fatalf("unexpected retained cron evidence: %v %v", found, err)
	}
	err = preflightHistoricalHostRemovalUsing(true, present, reader)
	if err == nil || strings.Contains(err.Error(), "private-fixture-value") || strings.Contains(err.Error(), "custom-backup") {
		t.Fatal("diagnostic leaked command contents or accepted retained scheduling", err)
	}
	if got, _, _ := reader(); got != content {
		t.Fatal("inspection changed root cron evidence")
	}
	for _, fixture := range []struct {
		content string
		exists  bool
	}{
		{"hidden", false}, {"unrelated\x00record", true}, {strings.Repeat("x", (1<<20)+1), true},
	} {
		if _, err := inspectHistoricalHostRemovalRemainders(false, present, func() (string, bool, error) { return fixture.content, fixture.exists, nil }); err == nil {
			t.Fatal("accepted inconsistent or unbounded cron evidence")
		}
	}
	sentinel := errors.New("synthetic observation failure")
	if _, err := inspectHistoricalHostRemovalRemainders(false, present, func() (string, bool, error) { return "", false, sentinel }); !errors.Is(err, sentinel) {
		t.Fatal("cron inspection failure was interpreted as absence", err)
	}
	if _, err := inspectHistoricalHostRemovalRemainders(false, func(string) (bool, error) { return false, sentinel }, reader); !errors.Is(err, sentinel) {
		t.Fatal("metadata inspection failure was interpreted as absence", err)
	}
}

func TestHistoricalHostRemovalMetadataInspectionPreservesFilesAndRefusesUnsafeParents(t *testing.T) {
	uid, gid := systemTestIdentity(t)
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	if err := root.MkdirAll("etc/aide/aide.conf.d", 0700); err != nil {
		t.Fatal(err)
	}
	path := "/etc/aide/aide.conf.d/99_syswarden_exclusions"
	inspect := func() (bool, error) { return historicalRemovalCandidatePresent(root, path, uid, gid, nil) }
	if found, err := inspect(); err != nil || found {
		t.Fatal("missing candidate", found, err)
	}
	if err := root.WriteFile(strings.TrimPrefix(path, "/"), []byte("private administrator content\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if found, err := inspect(); err != nil || !found {
		t.Fatal("regular candidate", found, err)
	}
	if got, err := root.ReadFile(strings.TrimPrefix(path, "/")); err != nil || string(got) != "private administrator content\n" {
		t.Fatal("file changed", err)
	}
	if err := root.Remove(strings.TrimPrefix(path, "/")); err != nil {
		t.Fatal(err)
	}
	if err := root.Symlink("absent-target", strings.TrimPrefix(path, "/")); err != nil {
		t.Fatal(err)
	}
	if found, err := inspect(); err != nil || !found {
		t.Fatal("dangling final symlink lost", found, err)
	}
	if err := root.Chmod("etc/aide", 0777); err != nil {
		t.Fatal(err)
	}
	if _, err := inspect(); err == nil {
		t.Fatal("writable ancestry accepted")
	}
	if err := root.Chmod("etc/aide", 0700); err != nil {
		t.Fatal(err)
	}
	if err := root.Rename("etc/aide", "etc/moved"); err != nil {
		t.Fatal(err)
	}
	if err := root.Symlink("moved", "etc/aide"); err != nil {
		t.Fatal(err)
	}
	if _, err := inspect(); err == nil {
		t.Fatal("symlink ancestry accepted")
	}
	for _, invalid := range []string{"", "/", "relative", "/etc/../etc/x", "/etc/x/", "/etc/\x00x"} {
		if _, err := historicalRemovalCandidatePresent(root, invalid, uid, gid, nil); err == nil {
			t.Fatal("invalid path accepted")
		}
	}
}

func TestHistoricalHostRemovalAbsenceCannotComeFromDetachedAncestry(t *testing.T) {
	uid, gid := systemTestIdentity(t)
	for _, change := range []string{"replace ancestor", "create target", "change mode"} {
		t.Run(change, func(t *testing.T) {
			root, err := os.OpenRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = root.Close() })
			if err := root.MkdirAll("etc/aide/aide.conf.d", 0700); err != nil {
				t.Fatal(err)
			}
			hook := func() {
				switch change {
				case "replace ancestor":
					if err := root.Rename("etc", "detached"); err != nil {
						t.Fatal(err)
					}
					if err := root.MkdirAll("etc/aide/aide.conf.d", 0700); err != nil {
						t.Fatal(err)
					}
				case "create target":
					if err := root.WriteFile("etc/aide/aide.conf.d/99_syswarden_exclusions", []byte("new administrator configuration"), 0600); err != nil {
						t.Fatal(err)
					}
				case "change mode":
					if err := root.Chmod("etc", 0777); err != nil {
						t.Fatal(err)
					}
				}
			}
			if _, err := historicalRemovalCandidatePresent(root, "/etc/aide/aide.conf.d/99_syswarden_exclusions", uid, gid, hook); err == nil {
				t.Fatal("concurrent ancestry or candidate change accepted as absence")
			}
		})
	}
}
