//go:build linux

package cronstate

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"syswarden-cli/pkg/platformpaths"
)

type testLegacyReader struct {
	mu      sync.Mutex
	content string
	present bool
	err     error
	reads   int
	onRead  func(int, *testLegacyReader)
}

func (reader *testLegacyReader) read() (string, bool, error) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	reader.reads++
	if reader.onRead != nil {
		reader.onRead(reader.reads, reader)
	}
	return reader.content, reader.present, reader.err
}

func (reader *testLegacyReader) set(content string, present bool) {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	reader.content = content
	reader.present = present
}

func testCronOptions(t *testing.T, reader *testLegacyReader) (Options, string) {
	t.Helper()
	rootPath := t.TempDir()
	if err := os.Chmod(rootPath, 0700); err != nil {
		t.Fatal(err)
	}
	cronPath := filepath.Join(rootPath, "etc", "cron.d")
	if err := os.MkdirAll(cronPath, 0755); err != nil {
		t.Fatal(err)
	}
	rootInfo, err := os.Stat(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("test filesystem lacks Unix identity")
	}
	options := DefaultOptions(reader.read)
	options.RootPath = rootPath
	options.DirectoryOwnerUID = int(stat.Uid)
	options.DirectoryOwnerGID = int(stat.Gid)
	options.FileOwnerUID = int(stat.Uid)
	options.FileOwnerGID = int(stat.Gid)
	options.AttestCronDProvider = func() error { return nil }
	return options, cronPath
}

func testCronOptionsAt(t *testing.T, rootPath string, reader *testLegacyReader) (Options, string) {
	t.Helper()
	cronPath := filepath.Join(rootPath, "etc", "cron.d")
	rootInfo, err := os.Stat(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := rootInfo.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("test filesystem lacks Unix identity")
	}
	options := DefaultOptions(reader.read)
	options.RootPath = rootPath
	options.DirectoryOwnerUID = int(stat.Uid)
	options.DirectoryOwnerGID = int(stat.Gid)
	options.FileOwnerUID = int(stat.Uid)
	options.FileOwnerGID = int(stat.Gid)
	options.AttestCronDProvider = func() error { return nil }
	return options, cronPath
}

func ownedPath(cronPath string) string {
	return filepath.Join(cronPath, DefaultFileName)
}

func pendingPath(cronPath string) string {
	return filepath.Join(cronPath, pendingFileName)
}

func readOwned(t *testing.T, cronPath string) string {
	t.Helper()
	content, err := os.ReadFile(ownedPath(cronPath))
	if err != nil {
		t.Fatal(err)
	}
	return string(content)
}

func replaceTestFile(t *testing.T, path string, content []byte, mode os.FileMode) {
	t.Helper()
	replacement := path + ".operator-replacement"
	if err := os.WriteFile(replacement, content, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
}

func legacyFeed(minute int) string {
	return ownedFeedLine(platformpaths.CLI, minute)[:strings.Index(ownedFeedLine(platformpaths.CLI, minute), " root ")] +
		" " + platformpaths.CLI + " update-feeds >/dev/null\n"
}

func legacyHA() string {
	return "*/30 * * * * " + platformpaths.CLI + " ha-sync >/dev/null 2>&1\n"
}

func TestFreshFeedPublicationIsCanonicalAndIdempotent(t *testing.T) {
	reader := &testLegacyReader{}
	options, cronPath := testCronOptions(t, reader)
	randomCalls := 0
	options.RandomMinute = func() (int, error) {
		randomCalls++
		return 23, nil
	}
	result, err := ReconcileFeed(options)
	if err != nil {
		t.Fatal(err)
	}
	if result != (FeedResult{Minute: 23}) || randomCalls != 1 {
		t.Fatalf("fresh feed result = %#v, random calls=%d", result, randomCalls)
	}
	want := ownedCronHeader + ownedFeedLine(platformpaths.CLI, 23) + "\n"
	if got := readOwned(t, cronPath); got != want {
		t.Fatalf("owned cron bytes = %q, want %q", got, want)
	}
	info, err := os.Lstat(ownedPath(cronPath))
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0644 {
		t.Fatalf("owned cron identity = %v, error=%v", info, err)
	}
	ownedStat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || ownedStat.Uid != uint32(options.FileOwnerUID) || ownedStat.Gid != uint32(options.FileOwnerGID) {
		t.Fatalf("owned cron account = %#v, want %d:%d", ownedStat, options.FileOwnerUID, options.FileOwnerGID)
	}

	before := readOwned(t, cronPath)
	options.RandomMinute = func() (int, error) {
		randomCalls++
		return 41, nil
	}
	result, err = ReconcileFeed(options)
	if err != nil {
		t.Fatal(err)
	}
	if result.Minute != 23 || randomCalls != 1 || readOwned(t, cronPath) != before {
		t.Fatalf("reload changed feed schedule: result=%#v random=%d", result, randomCalls)
	}
}

func TestHAReconciliationChangesOnlyOwnedHARecord(t *testing.T) {
	reader := &testLegacyReader{}
	options, cronPath := testCronOptions(t, reader)
	options.RandomMinute = func() (int, error) { return 37, nil }
	if _, err := ReconcileFeed(options); err != nil {
		t.Fatal(err)
	}
	feedLine := ownedFeedLine(platformpaths.CLI, 37) + "\n"
	if err := ReconcileHA(options, true); err != nil {
		t.Fatal(err)
	}
	withHA := readOwned(t, cronPath)
	if !strings.Contains(withHA, feedLine) || strings.Count(withHA, "ha-sync") != 1 {
		t.Fatalf("HA enable changed the owned feed record: %q", withHA)
	}
	if err := ReconcileHA(options, false); err != nil {
		t.Fatal(err)
	}
	withoutHA := readOwned(t, cronPath)
	if withoutHA != ownedCronHeader+feedLine {
		t.Fatalf("HA disable changed feed bytes: %q", withoutHA)
	}
}

func TestExactLegacyRecordsRemainReadOnlyCompatibilityEvidence(t *testing.T) {
	t.Run("legacy feed satisfies feed scheduling", func(t *testing.T) {
		operator := "MAILTO=operator@example.invalid\n15 2 * * * /usr/local/bin/backup\n"
		reader := &testLegacyReader{content: operator + legacyFeed(19), present: true}
		options, cronPath := testCronOptions(t, reader)
		options.RandomMinute = func() (int, error) {
			t.Fatal("random minute used for a legacy feed")
			return 0, nil
		}
		result, err := ReconcileFeed(options)
		if err != nil {
			t.Fatal(err)
		}
		if result != (FeedResult{Minute: 19, Legacy: true}) {
			t.Fatalf("legacy feed result = %#v", result)
		}
		if _, err := os.Lstat(ownedPath(cronPath)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("legacy feed created owned file: %v", err)
		}
		content, _, _ := reader.read()
		if content != operator+legacyFeed(19) {
			t.Fatal("operator root crontab bytes changed")
		}
	})

	t.Run("opposite legacy and owned jobs may coexist", func(t *testing.T) {
		reader := &testLegacyReader{content: legacyFeed(17), present: true}
		options, cronPath := testCronOptions(t, reader)
		if err := ReconcileHA(options, true); err != nil {
			t.Fatal(err)
		}
		if got := readOwned(t, cronPath); got != ownedCronHeader+ownedHALine(platformpaths.CLI)+"\n" {
			t.Fatalf("owned HA-only file = %q", got)
		}

		reader2 := &testLegacyReader{content: legacyHA(), present: true}
		options2, cronPath2 := testCronOptions(t, reader2)
		options2.RandomMinute = func() (int, error) { return 29, nil }
		if _, err := ReconcileFeed(options2); err != nil {
			t.Fatal(err)
		}
		if got := readOwned(t, cronPath2); got != ownedCronHeader+ownedFeedLine(platformpaths.CLI, 29)+"\n" {
			t.Fatalf("owned feed-only file = %q", got)
		}
	})
}

func TestLegacyAmbiguityAndSameJobCollisionsFailWithoutMutation(t *testing.T) {
	tests := []struct {
		name    string
		content string
		ha      *bool
	}{
		{name: "multiple feed records", content: legacyFeed(11) + legacyFeed(12)},
		{name: "multiple HA records", content: legacyHA() + legacyHA(), ha: func() *bool { value := true; return &value }()},
		{name: "disabled legacy HA", content: legacyHA(), ha: func() *bool { value := false; return &value }()},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			reader := &testLegacyReader{content: testCase.content, present: true}
			options, cronPath := testCronOptions(t, reader)
			options.RandomMinute = func() (int, error) { return 31, nil }
			var err error
			if testCase.ha == nil {
				_, err = ReconcileFeed(options)
			} else {
				err = ReconcileHA(options, *testCase.ha)
			}
			if err == nil {
				t.Fatal("ambiguous legacy state was accepted")
			}
			entries, readErr := os.ReadDir(cronPath)
			if readErr != nil || len(entries) != 0 {
				t.Fatalf("failure mutated cron directory: entries=%v error=%v", entries, readErr)
			}
		})
	}

	reader := &testLegacyReader{}
	options, cronPath := testCronOptions(t, reader)
	options.RandomMinute = func() (int, error) { return 43, nil }
	if _, err := ReconcileFeed(options); err != nil {
		t.Fatal(err)
	}
	before := readOwned(t, cronPath)
	reader.set(legacyFeed(43), true)
	if _, err := ReconcileFeed(options); err == nil {
		t.Fatal("same feed job in both stores was accepted")
	}
	if got := readOwned(t, cronPath); got != before {
		t.Fatal("same-job collision changed the owned cron file")
	}

	haReader := &testLegacyReader{}
	haOptions, haCronPath := testCronOptions(t, haReader)
	if err := ReconcileHA(haOptions, true); err != nil {
		t.Fatal(err)
	}
	haBefore := readOwned(t, haCronPath)
	haReader.set(legacyHA(), true)
	if err := ReconcileHA(haOptions, true); err == nil {
		t.Fatal("same HA job in both stores was accepted")
	}
	if got := readOwned(t, haCronPath); got != haBefore {
		t.Fatal("same HA collision changed the owned cron file")
	}
}

func TestLegacyLookalikesFailClosedWithoutBeingClaimedOrRewritten(t *testing.T) {
	operator := strings.Join([]string{
		"MAILTO=operator@example.invalid",
		"17  * * * * " + platformpaths.CLI + " update-feeds >/dev/null 2>&1",
		"17 * * * * " + platformpaths.CLI + " update-feeds --operator-option >/dev/null 2>&1",
		"*/30 * * * * " + platformpaths.CLI + " ha-sync --operator-option >/dev/null 2>&1",
		"19 * * * * " + platformpaths.CLI + " update-feeds; /usr/local/bin/operator-hook",
	}, "\n") + "\n"
	reader := &testLegacyReader{content: operator, present: true}
	options, cronPath := testCronOptions(t, reader)
	options.RandomMinute = func() (int, error) { return 47, nil }
	if _, err := ReconcileFeed(options); err == nil {
		t.Fatal("noncanonical legacy scheduling lookalikes were accepted")
	}
	content, _, _ := reader.read()
	if content != operator {
		t.Fatal("operator lookalike bytes changed")
	}
	entries, err := os.ReadDir(cronPath)
	if err != nil || len(entries) != 0 {
		t.Fatalf("lookalike rejection changed cron.d: entries=%v error=%v", entries, err)
	}
}

func TestUnsafeOwnedFileIdentitiesFailClosed(t *testing.T) {
	tests := []struct {
		name   string
		create func(string) error
		adjust func(*Options)
	}{
		{name: "symlink", create: func(path string) error { return os.Symlink("operator", path) }},
		{name: "FIFO", create: func(path string) error { return syscall.Mkfifo(path, 0644) }},
		{name: "wrong mode", create: func(path string) error { return os.WriteFile(path, []byte("operator\n"), 0600) }},
		{name: "unexpected content", create: func(path string) error { return os.WriteFile(path, []byte("operator\n"), 0644) }},
		{
			name: "hard link",
			create: func(path string) error {
				if err := os.WriteFile(path, []byte(ownedCronHeader+ownedHALine(platformpaths.CLI)+"\n"), 0644); err != nil {
					return err
				}
				return os.Link(path, filepath.Join(filepath.Dir(path), "operator-hardlink"))
			},
		},
		{
			name: "wrong owner contract",
			create: func(path string) error {
				return os.WriteFile(path, []byte(ownedCronHeader+ownedHALine(platformpaths.CLI)+"\n"), 0644)
			},
			adjust: func(options *Options) { options.FileOwnerUID++ },
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			reader := &testLegacyReader{}
			options, cronPath := testCronOptions(t, reader)
			if err := testCase.create(ownedPath(cronPath)); err != nil {
				t.Fatal(err)
			}
			if testCase.adjust != nil {
				testCase.adjust(&options)
			}
			if err := ReconcileHA(options, true); err == nil {
				t.Fatal("unsafe owned cron identity was accepted")
			}
			if _, err := os.Lstat(pendingPath(cronPath)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unsafe identity produced a staging file: %v", err)
			}
		})
	}
}

func TestSymlinkedOrSwappedCronParentsFailClosed(t *testing.T) {
	t.Run("symlinked cron directory", func(t *testing.T) {
		reader := &testLegacyReader{}
		options, cronPath := testCronOptions(t, reader)
		if err := os.Remove(cronPath); err != nil {
			t.Fatal(err)
		}
		operatorDirectory := filepath.Join(options.RootPath, "operator-cron.d")
		if err := os.Mkdir(operatorDirectory, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("../../operator-cron.d", cronPath); err != nil {
			t.Fatal(err)
		}
		options.RandomMinute = func() (int, error) { return 17, nil }
		if _, err := ReconcileFeed(options); err == nil {
			t.Fatal("symlinked cron directory was accepted")
		}
		entries, err := os.ReadDir(operatorDirectory)
		if err != nil || len(entries) != 0 {
			t.Fatalf("symlink target was modified: entries=%v error=%v", entries, err)
		}
	})

	t.Run("directory path swap before mutation", func(t *testing.T) {
		reader := &testLegacyReader{}
		options, cronPath := testCronOptions(t, reader)
		originalPath := cronPath + ".original"
		operatorDirectory := filepath.Join(options.RootPath, "operator-cron.d")
		if err := os.Mkdir(operatorDirectory, 0755); err != nil {
			t.Fatal(err)
		}
		options.beforeMutation = func() {
			if err := os.Rename(cronPath, originalPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("../../operator-cron.d", cronPath); err != nil {
				t.Fatal(err)
			}
		}
		options.RandomMinute = func() (int, error) { return 31, nil }
		if _, err := ReconcileFeed(options); err == nil {
			t.Fatal("cron directory swap was accepted")
		}
		for _, path := range []string{originalPath, operatorDirectory} {
			entries, err := os.ReadDir(path)
			if err != nil || len(entries) != 0 {
				t.Fatalf("directory swap caused SysWarden writes in %s: entries=%v error=%v", path, entries, err)
			}
		}
	})
}

func TestOperatorDriftBeforePublicationCausesZeroFilesystemWrites(t *testing.T) {
	operator := "MAILTO=operator@example.invalid\n"
	reader := &testLegacyReader{content: operator, present: true}
	reader.onRead = func(reads int, current *testLegacyReader) {
		if reads == 2 {
			current.content += "15 2 * * * /usr/local/bin/operator-backup\n"
		}
	}
	options, cronPath := testCronOptions(t, reader)
	options.RandomMinute = func() (int, error) { return 13, nil }
	if _, err := ReconcileFeed(options); err == nil {
		t.Fatal("operator drift was accepted")
	}
	entries, err := os.ReadDir(cronPath)
	if err != nil || len(entries) != 0 {
		t.Fatalf("operator drift caused filesystem writes: entries=%v error=%v", entries, err)
	}
}

func TestUnreadableOrContradictoryRootCrontabCausesZeroWrites(t *testing.T) {
	tests := []struct {
		name   string
		reader *testLegacyReader
	}{
		{name: "unreadable", reader: &testLegacyReader{err: errors.New("permission denied")}},
		{name: "absent with bytes", reader: &testLegacyReader{content: "unexpected\n", present: false}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			options, cronPath := testCronOptions(t, testCase.reader)
			options.RandomMinute = func() (int, error) { return 13, nil }
			if _, err := ReconcileFeed(options); err == nil {
				t.Fatal("invalid root crontab evidence was accepted")
			}
			entries, err := os.ReadDir(cronPath)
			if err != nil || len(entries) != 0 {
				t.Fatalf("invalid root evidence caused writes: entries=%v error=%v", entries, err)
			}
		})
	}
}

func TestCronDProviderAttestationFailsClosedBeforeOwnedPublication(t *testing.T) {
	t.Run("initial provider failure causes zero writes", func(t *testing.T) {
		reader := &testLegacyReader{}
		options, cronPath := testCronOptions(t, reader)
		options.RandomMinute = func() (int, error) { return 13, nil }
		options.AttestCronDProvider = func() error { return errors.New("provider inactive") }
		if _, err := ReconcileFeed(options); err == nil {
			t.Fatal("inactive cron.d provider was accepted")
		}
		entries, err := os.ReadDir(cronPath)
		if err != nil || len(entries) != 0 {
			t.Fatalf("provider failure caused writes: entries=%v error=%v", entries, err)
		}
	})

	t.Run("provider drift before replace preserves old state", func(t *testing.T) {
		reader := &testLegacyReader{}
		options, cronPath := testCronOptions(t, reader)
		options.RandomMinute = func() (int, error) { return 17, nil }
		if _, err := ReconcileFeed(options); err != nil {
			t.Fatal(err)
		}
		before := readOwned(t, cronPath)
		attestations := 0
		options.AttestCronDProvider = func() error {
			attestations++
			if attestations == 2 {
				return errors.New("provider drift")
			}
			return nil
		}
		if err := ReconcileHA(options, true); err == nil {
			t.Fatal("cron.d provider drift was accepted")
		}
		if got := readOwned(t, cronPath); got != before {
			t.Fatal("provider drift replaced the previous owned state")
		}
		if _, err := os.Lstat(pendingPath(cronPath)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("provider drift left staging residue: %v", err)
		}
	})

	t.Run("legacy-only scheduling requires cron.d provider", func(t *testing.T) {
		reader := &testLegacyReader{content: legacyFeed(19), present: true}
		options, cronPath := testCronOptions(t, reader)
		options.AttestCronDProvider = nil
		if _, err := ReconcileFeed(options); err == nil {
			t.Fatal("legacy-only scheduling bypassed provider attestation")
		}
		entries, readErr := os.ReadDir(cronPath)
		if readErr != nil || len(entries) != 0 {
			t.Fatalf("legacy-only scheduling created owned state: entries=%v error=%v", entries, readErr)
		}
		options.AttestCronDProvider = func() error { return nil }
		result, err := ReconcileFeed(options)
		if err != nil || !result.Legacy || result.Minute != 19 {
			t.Fatalf("attested legacy-only scheduling = %#v, error=%v", result, err)
		}
	})
}

func TestDestinationSwapBeforeReplaceIsDetected(t *testing.T) {
	reader := &testLegacyReader{}
	options, cronPath := testCronOptions(t, reader)
	options.RandomMinute = func() (int, error) { return 53, nil }
	if _, err := ReconcileFeed(options); err != nil {
		t.Fatal(err)
	}
	options.beforeReplace = func() {
		if err := os.WriteFile(ownedPath(cronPath), []byte("operator drift\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := ReconcileHA(options, true); err == nil {
		t.Fatal("destination swap was accepted")
	}
	if got := readOwned(t, cronPath); got != "operator drift\n" {
		t.Fatalf("destination drift was overwritten: %q", got)
	}
	if _, err := os.Lstat(pendingPath(cronPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("safe staging residue remains after rejected swap: %v", err)
	}
}

func TestInterruptedPublicationRecoveryAndUnsafeResidue(t *testing.T) {
	t.Run("safe partial staging is aborted and rebuilt", func(t *testing.T) {
		reader := &testLegacyReader{}
		options, cronPath := testCronOptions(t, reader)
		if err := os.WriteFile(pendingPath(cronPath), []byte(ownedCronHeader[:12]), 0600); err != nil {
			t.Fatal(err)
		}
		options.RandomMinute = func() (int, error) { return 7, nil }
		if _, err := ReconcileFeed(options); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(pendingPath(cronPath)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("recovered staging file remains: %v", err)
		}
		if got := readOwned(t, cronPath); !strings.Contains(got, ownedFeedLine(platformpaths.CLI, 7)) {
			t.Fatalf("recovered owned cron file = %q", got)
		}
	})

	t.Run("malformed regular staging is preserved", func(t *testing.T) {
		reader := &testLegacyReader{}
		options, cronPath := testCronOptions(t, reader)
		if err := os.WriteFile(pendingPath(cronPath), []byte("operator staging\n"), 0600); err != nil {
			t.Fatal(err)
		}
		options.RandomMinute = func() (int, error) { return 5, nil }
		if _, err := ReconcileFeed(options); err == nil {
			t.Fatal("malformed interrupted publication was accepted")
		}
		content, err := os.ReadFile(pendingPath(cronPath))
		if err != nil || string(content) != "operator staging\n" {
			t.Fatalf("malformed staging was mutated: %q error=%v", content, err)
		}
	})

	t.Run("unsafe staging identity fails closed", func(t *testing.T) {
		reader := &testLegacyReader{}
		options, cronPath := testCronOptions(t, reader)
		if err := os.Symlink("operator", pendingPath(cronPath)); err != nil {
			t.Fatal(err)
		}
		options.RandomMinute = func() (int, error) { return 5, nil }
		if _, err := ReconcileFeed(options); err == nil {
			t.Fatal("unsafe interrupted publication was accepted")
		}
		info, err := os.Lstat(pendingPath(cronPath))
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("unsafe staging identity was mutated: info=%v error=%v", info, err)
		}
	})
}

func TestRemoveForUninstallRemovesOnlyAttestedOwnedState(t *testing.T) {
	operator := "MAILTO=operator@example.invalid\n15 2 * * * /usr/local/bin/operator-backup\n"
	reader := &testLegacyReader{content: operator, present: true}
	options, cronPath := testCronOptions(t, reader)
	options.RandomMinute = func() (int, error) { return 23, nil }
	if _, err := ReconcileFeed(options); err != nil {
		t.Fatal(err)
	}
	if err := ReconcileHA(options, true); err != nil {
		t.Fatal(err)
	}
	if err := RemoveForUninstall(options); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(ownedPath(cronPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned cron file remains after uninstall removal: %v", err)
	}
	content, present, err := reader.read()
	if err != nil || !present || content != operator {
		t.Fatalf("uninstall changed root crontab evidence: %q present=%t error=%v", content, present, err)
	}
}

func TestRemoveForUninstallPreflightsAllStateBeforeMutation(t *testing.T) {
	t.Run("safe interrupted publication is removed", func(t *testing.T) {
		reader := &testLegacyReader{}
		options, cronPath := testCronOptions(t, reader)
		if err := os.WriteFile(pendingPath(cronPath), []byte(ownedCronHeader[:10]), 0600); err != nil {
			t.Fatal(err)
		}
		if err := RemoveForUninstall(options); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(pendingPath(cronPath)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("safe interrupted publication remains: %v", err)
		}
	})

	t.Run("malformed pending file is preserved", func(t *testing.T) {
		reader := &testLegacyReader{}
		options, cronPath := testCronOptions(t, reader)
		if err := os.WriteFile(pendingPath(cronPath), []byte("operator pending\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := RemoveForUninstall(options); err == nil {
			t.Fatal("malformed pending file was accepted")
		}
		content, err := os.ReadFile(pendingPath(cronPath))
		if err != nil || string(content) != "operator pending\n" {
			t.Fatalf("malformed pending file was mutated: %q error=%v", content, err)
		}
	})

	t.Run("malformed owned file preserves safe pending residue", func(t *testing.T) {
		reader := &testLegacyReader{}
		options, cronPath := testCronOptions(t, reader)
		if err := os.WriteFile(ownedPath(cronPath), []byte("operator owned\n"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(pendingPath(cronPath), []byte(ownedCronHeader[:8]), 0600); err != nil {
			t.Fatal(err)
		}
		if err := RemoveForUninstall(options); err == nil {
			t.Fatal("malformed owned file was accepted")
		}
		for path, want := range map[string]string{
			ownedPath(cronPath):   "operator owned\n",
			pendingPath(cronPath): ownedCronHeader[:8],
		} {
			content, err := os.ReadFile(path)
			if err != nil || string(content) != want {
				t.Fatalf("failed uninstall preflight mutated %s: %q error=%v", path, content, err)
			}
		}
	})

	t.Run("root crontab drift prevents owned removal", func(t *testing.T) {
		reader := &testLegacyReader{}
		options, cronPath := testCronOptions(t, reader)
		options.RandomMinute = func() (int, error) { return 41, nil }
		if _, err := ReconcileFeed(options); err != nil {
			t.Fatal(err)
		}
		before := readOwned(t, cronPath)
		reader.reads = 0
		reader.onRead = func(reads int, current *testLegacyReader) {
			if reads == 2 {
				current.content = "15 2 * * * /usr/local/bin/operator-backup\n"
				current.present = true
			}
		}
		if err := RemoveForUninstall(options); err == nil {
			t.Fatal("root crontab drift was accepted during uninstall removal")
		}
		if got := readOwned(t, cronPath); got != before {
			t.Fatal("root crontab drift caused owned removal")
		}
	})

	t.Run("legacy lookalike prevents removal", func(t *testing.T) {
		reader := &testLegacyReader{}
		options, cronPath := testCronOptions(t, reader)
		options.RandomMinute = func() (int, error) { return 43, nil }
		if _, err := ReconcileFeed(options); err != nil {
			t.Fatal(err)
		}
		before := readOwned(t, cronPath)
		reader.set("17  * * * * "+platformpaths.CLI+" update-feeds >/dev/null 2>&1\n", true)
		if err := RemoveForUninstall(options); err == nil {
			t.Fatal("legacy lookalike was accepted during uninstall removal")
		}
		if got := readOwned(t, cronPath); got != before {
			t.Fatal("legacy lookalike caused owned removal")
		}
	})
}

func TestFeedAndHAReconcilersSerializeDurably(t *testing.T) {
	reader := &testLegacyReader{}
	options, cronPath := testCronOptions(t, reader)
	options.RandomMinute = func() (int, error) { return 59, nil }
	start := make(chan struct{})
	errorsChannel := make(chan error, 2)
	go func() {
		<-start
		_, err := ReconcileFeed(options)
		errorsChannel <- err
	}()
	go func() {
		<-start
		errorsChannel <- ReconcileHA(options, true)
	}()
	close(start)
	for index := 0; index < 2; index++ {
		if err := <-errorsChannel; err != nil {
			t.Fatal(err)
		}
	}
	inspection, err := Inspect(options)
	if err != nil {
		t.Fatal(err)
	}
	if !inspection.OwnedFeed || !inspection.OwnedHA || inspection.FeedMinute != 59 {
		t.Fatalf("serialized cron state = %#v", inspection)
	}
	content := readOwned(t, cronPath)
	if strings.Count(content, "update-feeds") != 1 || strings.Count(content, "ha-sync") != 1 {
		t.Fatalf("serialized cron bytes contain duplicate jobs: %q", content)
	}
}

func TestCronTransactionSIGKILLHelper(t *testing.T) {
	if os.Getenv("SYSWARDEN_CRONSTATE_SIGKILL_HELPER") != "1" {
		return
	}
	rootPath := os.Getenv("SYSWARDEN_CRONSTATE_ROOT")
	fault := os.Getenv("SYSWARDEN_CRONSTATE_FAULT")
	action := os.Getenv("SYSWARDEN_CRONSTATE_ACTION")
	reader := &testLegacyReader{}
	options, _ := testCronOptionsAt(t, rootPath, reader)
	options.RandomMinute = func() (int, error) { return 23, nil }
	options.faultPoint = func(point string) {
		if point == fault {
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			os.Exit(97)
		}
	}
	var err error
	switch action {
	case "create":
		_, err = ReconcileFeed(options)
	case "update":
		err = ReconcileHA(options, true)
	case "delete":
		err = RemoveForUninstall(options)
	default:
		err = errors.New("unknown SIGKILL helper action")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Fatal("SIGKILL fault point was not reached")
}

func runCronSIGKILLHelper(t *testing.T, rootPath, action, fault string) {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestCronTransactionSIGKILLHelper$")
	command.Env = append(os.Environ(),
		"SYSWARDEN_CRONSTATE_SIGKILL_HELPER=1",
		"SYSWARDEN_CRONSTATE_ROOT="+rootPath,
		"SYSWARDEN_CRONSTATE_ACTION="+action,
		"SYSWARDEN_CRONSTATE_FAULT="+fault,
	)
	err := command.Run()
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) {
		t.Fatalf("SIGKILL helper error = %v", err)
	}
	status, ok := exitError.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("helper status = %v, want SIGKILL", exitError.ProcessState)
	}
}

func TestDurableCronTransactionRecoversRealSIGKILLBoundaries(t *testing.T) {
	t.Run("creation rollback and retry", func(t *testing.T) {
		reader := &testLegacyReader{}
		options, cronPath := testCronOptions(t, reader)
		options.RandomMinute = func() (int, error) { return 23, nil }
		runCronSIGKILLHelper(t, options.RootPath, "create", "cron-transaction-mutated:create")
		journalWire, err := os.ReadFile(filepath.Join(cronPath, transactionFileName))
		if err != nil {
			t.Fatal(err)
		}
		record, err := decodeTransactionBytes(journalWire, options)
		if err != nil || record.Operation != operationCreate || !record.New.Present || record.New.SHA256 == "" {
			t.Fatalf("creation journal = %#v, error=%v", record, err)
		}
		if _, err := ReconcileFeed(options); err != nil {
			t.Fatal(err)
		}
		if got := readOwned(t, cronPath); !strings.Contains(got, ownedFeedLine(platformpaths.CLI, 23)) {
			t.Fatalf("recovered creation = %q", got)
		}
	})

	t.Run("committed creation completes forward", func(t *testing.T) {
		reader := &testLegacyReader{}
		options, cronPath := testCronOptions(t, reader)
		options.RandomMinute = func() (int, error) { return 27, nil }
		runCronSIGKILLHelper(t, options.RootPath, "create", "cron-transaction-committed")
		if _, err := ReconcileFeed(options); err != nil {
			t.Fatal(err)
		}
		if got := readOwned(t, cronPath); strings.Count(got, "update-feeds") != 1 {
			t.Fatalf("forward-completed creation = %q", got)
		}
	})

	t.Run("update rollback and retry", func(t *testing.T) {
		reader := &testLegacyReader{}
		options, cronPath := testCronOptions(t, reader)
		options.RandomMinute = func() (int, error) { return 31, nil }
		if _, err := ReconcileFeed(options); err != nil {
			t.Fatal(err)
		}
		runCronSIGKILLHelper(t, options.RootPath, "update", "cron-transaction-mutated:update")
		if err := ReconcileHA(options, true); err != nil {
			t.Fatal(err)
		}
		if got := readOwned(t, cronPath); strings.Count(got, "update-feeds") != 1 || strings.Count(got, "ha-sync") != 1 {
			t.Fatalf("recovered update = %q", got)
		}
	})

	t.Run("committed update completes forward", func(t *testing.T) {
		reader := &testLegacyReader{}
		options, cronPath := testCronOptions(t, reader)
		options.RandomMinute = func() (int, error) { return 37, nil }
		if _, err := ReconcileFeed(options); err != nil {
			t.Fatal(err)
		}
		runCronSIGKILLHelper(t, options.RootPath, "update", "cron-transaction-committed")
		if err := ReconcileHA(options, true); err != nil {
			t.Fatal(err)
		}
		if got := readOwned(t, cronPath); strings.Count(got, "ha-sync") != 1 {
			t.Fatalf("forward-completed update = %q", got)
		}
	})

	t.Run("quarantined prior state completes forward", func(t *testing.T) {
		reader := &testLegacyReader{}
		options, cronPath := testCronOptions(t, reader)
		options.RandomMinute = func() (int, error) { return 39, nil }
		if _, err := ReconcileFeed(options); err != nil {
			t.Fatal(err)
		}
		runCronSIGKILLHelper(t, options.RootPath, "update", "cron-remove-quarantined:"+pendingFileName)
		if err := ReconcileHA(options, true); err != nil {
			t.Fatal(err)
		}
		if got := readOwned(t, cronPath); strings.Count(got, "ha-sync") != 1 {
			t.Fatalf("forward-completed quarantine = %q", got)
		}
	})

	t.Run("deletion rollback and retry", func(t *testing.T) {
		reader := &testLegacyReader{}
		options, cronPath := testCronOptions(t, reader)
		options.RandomMinute = func() (int, error) { return 41, nil }
		if _, err := ReconcileFeed(options); err != nil {
			t.Fatal(err)
		}
		runCronSIGKILLHelper(t, options.RootPath, "delete", "cron-transaction-mutated:delete")
		if err := RemoveForUninstall(options); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(ownedPath(cronPath)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("recovered deletion left owned state: %v", err)
		}
	})

	t.Run("committed deletion completes forward", func(t *testing.T) {
		reader := &testLegacyReader{}
		options, cronPath := testCronOptions(t, reader)
		options.RandomMinute = func() (int, error) { return 45, nil }
		if _, err := ReconcileFeed(options); err != nil {
			t.Fatal(err)
		}
		runCronSIGKILLHelper(t, options.RootPath, "delete", "cron-transaction-committed")
		if err := RemoveForUninstall(options); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(ownedPath(cronPath)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("forward-completed deletion left owned state: %v", err)
		}
	})
}

func TestCronTransactionRecoversDirectoryFsyncFailures(t *testing.T) {
	failure := errors.New("injected directory fsync failure")

	t.Run("prepared journal publication", func(t *testing.T) {
		reader := &testLegacyReader{}
		options, cronPath := testCronOptions(t, reader)
		options.RandomMinute = func() (int, error) { return 19, nil }
		realSync := options.syncDirectory
		syncCalls := 0
		options.syncDirectory = func(directory *os.File) error {
			syncCalls++
			if syncCalls == 2 {
				return failure
			}
			return realSync(directory)
		}
		if _, err := ReconcileFeed(options); !errors.Is(err, failure) {
			t.Fatalf("journal fsync failure = %v", err)
		}
		for _, name := range []string{pendingFileName, transactionFileName} {
			if _, err := os.Lstat(filepath.Join(cronPath, name)); err != nil {
				t.Fatalf("journal fsync failure lost %s: %v", name, err)
			}
		}
		options.syncDirectory = realSync
		if _, err := ReconcileFeed(options); err != nil {
			t.Fatal(err)
		}
		if got := readOwned(t, cronPath); !strings.Contains(got, ownedFeedLine(platformpaths.CLI, 19)) {
			t.Fatalf("journal fsync recovery = %q", got)
		}
	})

	t.Run("destination mutation", func(t *testing.T) {
		reader := &testLegacyReader{}
		options, cronPath := testCronOptions(t, reader)
		options.RandomMinute = func() (int, error) { return 21, nil }
		realSync := options.syncDirectory
		failNext := false
		options.faultPoint = func(point string) {
			if point == "cron-transaction-prepared" {
				failNext = true
			}
		}
		options.syncDirectory = func(directory *os.File) error {
			if failNext {
				failNext = false
				return failure
			}
			return realSync(directory)
		}
		if _, err := ReconcileFeed(options); !errors.Is(err, failure) {
			t.Fatalf("mutation fsync failure = %v", err)
		}
		if _, err := os.Lstat(ownedPath(cronPath)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed creation was not rolled back: %v", err)
		}
		options.faultPoint = func(string) {}
		options.syncDirectory = realSync
		if _, err := ReconcileFeed(options); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("committed marker publication", func(t *testing.T) {
		reader := &testLegacyReader{}
		options, cronPath := testCronOptions(t, reader)
		options.RandomMinute = func() (int, error) { return 25, nil }
		if _, err := ReconcileFeed(options); err != nil {
			t.Fatal(err)
		}
		realSync := options.syncDirectory
		failNext := false
		options.faultPoint = func(point string) {
			if point == "cron-transaction-mutated:update" {
				failNext = true
			}
		}
		options.syncDirectory = func(directory *os.File) error {
			if failNext {
				failNext = false
				return failure
			}
			return realSync(directory)
		}
		if err := ReconcileHA(options, true); !errors.Is(err, failure) {
			t.Fatalf("commit fsync failure = %v", err)
		}
		for _, name := range []string{transactionFileName, commitFileName} {
			if _, err := os.Lstat(filepath.Join(cronPath, name)); err != nil {
				t.Fatalf("commit fsync failure lost %s: %v", name, err)
			}
		}
		options.faultPoint = func(string) {}
		options.syncDirectory = realSync
		if err := ReconcileHA(options, true); err != nil {
			t.Fatal(err)
		}
		if got := readOwned(t, cronPath); strings.Count(got, "ha-sync") != 1 {
			t.Fatalf("commit fsync recovery = %q", got)
		}
	})

	t.Run("prior state retirement", func(t *testing.T) {
		reader := &testLegacyReader{}
		options, cronPath := testCronOptions(t, reader)
		options.RandomMinute = func() (int, error) { return 29, nil }
		if _, err := ReconcileFeed(options); err != nil {
			t.Fatal(err)
		}
		realSync := options.syncDirectory
		failNext := false
		options.faultPoint = func(point string) {
			if point == "cron-transaction-committed" {
				failNext = true
			}
		}
		options.syncDirectory = func(directory *os.File) error {
			if failNext {
				failNext = false
				return failure
			}
			return realSync(directory)
		}
		if err := ReconcileHA(options, true); !errors.Is(err, failure) {
			t.Fatalf("retirement fsync failure = %v", err)
		}
		if _, err := os.Lstat(filepath.Join(cronPath, retiredFileName)); err != nil {
			t.Fatalf("retirement fsync failure lost prior state: %v", err)
		}
		options.faultPoint = func(string) {}
		options.syncDirectory = realSync
		if err := ReconcileHA(options, true); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{pendingFileName, retiredFileName, transactionFileName, commitFileName} {
			if _, err := os.Lstat(filepath.Join(cronPath, name)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("retirement recovery left %s: %v", name, err)
			}
		}
	})
}

func TestCronRecoveryEvidenceDriftCausesZeroMutations(t *testing.T) {
	for _, drift := range []string{"root crontab", "provider"} {
		t.Run(drift, func(t *testing.T) {
			reader := &testLegacyReader{}
			options, cronPath := testCronOptions(t, reader)
			options.RandomMinute = func() (int, error) { return 33, nil }
			runCronSIGKILLHelper(t, options.RootPath, "create", "cron-transaction-mutated:create")

			snapshot := func() map[string]string {
				entries, err := os.ReadDir(cronPath)
				if err != nil {
					t.Fatal(err)
				}
				state := make(map[string]string, len(entries))
				for _, entry := range entries {
					content, err := os.ReadFile(filepath.Join(cronPath, entry.Name()))
					if err != nil {
						t.Fatal(err)
					}
					state[entry.Name()] = string(content)
				}
				return state
			}
			before := snapshot()
			renames := 0
			unlinks := 0
			originalRename := options.renameat2
			originalUnlink := options.unlinkat
			options.renameat2 = func(oldDirectory int, oldName string, newDirectory int, newName string, flags uint) error {
				renames++
				return originalRename(oldDirectory, oldName, newDirectory, newName, flags)
			}
			options.unlinkat = func(directory int, name string, flags int) error {
				unlinks++
				return originalUnlink(directory, name, flags)
			}
			if drift == "root crontab" {
				reader.onRead = func(reads int, current *testLegacyReader) {
					if reads == 2 {
						current.content = "MAILTO=operator@example.invalid\n"
						current.present = true
					}
				}
			} else {
				providerCalls := 0
				options.AttestCronDProvider = func() error {
					providerCalls++
					if providerCalls == 2 {
						return errors.New("provider changed")
					}
					return nil
				}
			}
			if _, err := ReconcileFeed(options); err == nil {
				t.Fatal("recovery evidence drift was accepted")
			}
			if renames != 0 || unlinks != 0 {
				t.Fatalf("recovery drift caused %d renames and %d unlinks", renames, unlinks)
			}
			after := snapshot()
			if len(after) != len(before) {
				t.Fatalf("recovery drift changed artifact count: before=%v after=%v", before, after)
			}
			for name, content := range before {
				if after[name] != content {
					t.Fatalf("recovery drift changed %s", name)
				}
			}
		})
	}
}

func TestCronCASMutationRestoresExternalDestinationSwap(t *testing.T) {
	reader := &testLegacyReader{}
	options, cronPath := testCronOptions(t, reader)
	options.RandomMinute = func() (int, error) { return 43, nil }
	if _, err := ReconcileFeed(options); err != nil {
		t.Fatal(err)
	}
	originalRename := options.renameat2
	injected := false
	options.renameat2 = func(oldDirectory int, oldName string, newDirectory int, newName string, flags uint) error {
		if !injected && oldName == pendingFileName && newName == DefaultFileName && flags == unix.RENAME_EXCHANGE {
			injected = true
			replaceTestFile(t, ownedPath(cronPath), []byte("operator destination\n"), 0644)
		}
		return originalRename(oldDirectory, oldName, newDirectory, newName, flags)
	}
	if err := ReconcileHA(options, true); err == nil {
		t.Fatal("external destination swap was accepted")
	}
	if got := readOwned(t, cronPath); got != "operator destination\n" {
		t.Fatalf("CAS restore changed external destination: %q", got)
	}
	for _, name := range []string{pendingFileName, retiredFileName, transactionFileName, commitFileName} {
		if _, err := os.Lstat(filepath.Join(cronPath, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("CAS restore left %s: %v", name, err)
		}
	}
}

func TestCronCASNeverUnlinksExternallyMutatedPendingState(t *testing.T) {
	reader := &testLegacyReader{}
	options, cronPath := testCronOptions(t, reader)
	options.RandomMinute = func() (int, error) { return 47, nil }
	unlinks := 0
	originalUnlink := options.unlinkat
	options.unlinkat = func(directory int, name string, flags int) error {
		unlinks++
		return originalUnlink(directory, name, flags)
	}
	options.beforeReplace = func() {
		replaceTestFile(t, pendingPath(cronPath), []byte("operator pending\n"), 0644)
	}
	if _, err := ReconcileFeed(options); err == nil {
		t.Fatal("externally mutated pending state was accepted")
	}
	content, err := os.ReadFile(pendingPath(cronPath))
	if err != nil || string(content) != "operator pending\n" {
		t.Fatalf("external pending state = %q, error=%v", content, err)
	}
	if unlinks != 0 {
		t.Fatalf("external pending drift triggered %d unlink operations", unlinks)
	}
	if _, err := os.Lstat(filepath.Join(cronPath, transactionFileName)); err != nil {
		t.Fatalf("pending drift lost durable journal: %v", err)
	}
}

func TestCronCASDeletionRestoresExternallyMutatedSource(t *testing.T) {
	reader := &testLegacyReader{}
	options, cronPath := testCronOptions(t, reader)
	options.RandomMinute = func() (int, error) { return 49, nil }
	if _, err := ReconcileFeed(options); err != nil {
		t.Fatal(err)
	}
	originalRename := options.renameat2
	injected := false
	options.renameat2 = func(oldDirectory int, oldName string, newDirectory int, newName string, flags uint) error {
		if !injected && oldName == DefaultFileName && newName == pendingFileName && flags == unix.RENAME_NOREPLACE {
			injected = true
			replaceTestFile(t, ownedPath(cronPath), []byte("operator deletion source\n"), 0644)
		}
		return originalRename(oldDirectory, oldName, newDirectory, newName, flags)
	}
	if err := RemoveForUninstall(options); err == nil {
		t.Fatal("externally mutated deletion source was accepted")
	}
	if got := readOwned(t, cronPath); got != "operator deletion source\n" {
		t.Fatalf("deletion CAS failed to restore external source: %q", got)
	}
	for _, name := range []string{pendingFileName, transactionFileName, commitFileName} {
		if _, err := os.Lstat(filepath.Join(cronPath, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("deletion CAS left %s: %v", name, err)
		}
	}
}

func TestCronPinnedRemovalNeverTouchesSwappedCanonicalDirectory(t *testing.T) {
	reader := &testLegacyReader{}
	options, cronPath := testCronOptions(t, reader)
	options.RandomMinute = func() (int, error) { return 50, nil }
	if _, err := ReconcileFeed(options); err != nil {
		t.Fatal(err)
	}
	detachedPath := cronPath + ".detached"
	operatorContent := []byte("operator canonical path\n")
	originalUnlink := options.unlinkat
	swapped := false
	options.unlinkat = func(directory int, name string, flags int) error {
		if !swapped {
			swapped = true
			if err := os.Rename(cronPath, detachedPath); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(cronPath, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(ownedPath(cronPath), operatorContent, 0644); err != nil {
				t.Fatal(err)
			}
		}
		return originalUnlink(directory, name, flags)
	}
	if err := RemoveForUninstall(options); err == nil {
		t.Fatal("canonical cron directory swap was accepted during removal")
	}
	content, err := os.ReadFile(ownedPath(cronPath))
	if err != nil || string(content) != string(operatorContent) {
		t.Fatalf("pinned removal touched the swapped canonical directory: %q error=%v", content, err)
	}
}

func TestCronRemovalRereadsRootEvidenceBeforeEveryNamespaceMutation(t *testing.T) {
	reader := &testLegacyReader{}
	options, cronPath := testCronOptions(t, reader)
	options.RandomMinute = func() (int, error) { return 52, nil }
	if _, err := ReconcileFeed(options); err != nil {
		t.Fatal(err)
	}
	unlinks := 0
	originalUnlink := options.unlinkat
	options.unlinkat = func(directory int, name string, flags int) error {
		unlinks++
		return originalUnlink(directory, name, flags)
	}
	options.faultPoint = func(point string) {
		if point == "cron-remove-quarantined:"+pendingFileName {
			reader.set("MAILTO=operator@example.invalid\n", true)
		}
	}
	if err := RemoveForUninstall(options); err == nil {
		t.Fatal("root evidence drift before unlink was accepted")
	}
	if unlinks != 0 {
		t.Fatalf("root evidence drift triggered %d unlink operations", unlinks)
	}
	for _, name := range []string{retiredFileName, transactionFileName, commitFileName} {
		if _, err := os.Lstat(filepath.Join(cronPath, name)); err != nil {
			t.Fatalf("root evidence drift lost recovery artifact %s: %v", name, err)
		}
	}
}

func TestCronCommittedCleanupPreservesExternalQuarantineCollision(t *testing.T) {
	reader := &testLegacyReader{}
	options, cronPath := testCronOptions(t, reader)
	options.RandomMinute = func() (int, error) { return 51, nil }
	if _, err := ReconcileFeed(options); err != nil {
		t.Fatal(err)
	}
	originalRename := options.renameat2
	injected := false
	options.renameat2 = func(oldDirectory int, oldName string, newDirectory int, newName string, flags uint) error {
		if !injected && oldName == pendingFileName && newName == retiredFileName && flags == unix.RENAME_NOREPLACE {
			injected = true
			if err := os.WriteFile(filepath.Join(cronPath, retiredFileName), []byte("operator retirement\n"), 0644); err != nil {
				t.Fatal(err)
			}
		}
		return originalRename(oldDirectory, oldName, newDirectory, newName, flags)
	}
	if err := ReconcileHA(options, true); err == nil {
		t.Fatal("external quarantine collision was accepted")
	}
	retired, err := os.ReadFile(filepath.Join(cronPath, retiredFileName))
	if err != nil || string(retired) != "operator retirement\n" {
		t.Fatalf("external quarantine collision = %q, error=%v", retired, err)
	}
	if got := readOwned(t, cronPath); strings.Count(got, "ha-sync") != 1 {
		t.Fatalf("durably committed target was not preserved: %q", got)
	}
	for _, name := range []string{pendingFileName, transactionFileName, commitFileName} {
		if _, err := os.Lstat(filepath.Join(cronPath, name)); err != nil {
			t.Fatalf("collision lost recovery evidence %s: %v", name, err)
		}
	}
}

func TestCronTransactionRollsBackProviderAndRootEvidenceDrift(t *testing.T) {
	for _, testCase := range []string{"provider", "root"} {
		t.Run(testCase, func(t *testing.T) {
			reader := &testLegacyReader{}
			options, cronPath := testCronOptions(t, reader)
			options.RandomMinute = func() (int, error) { return 53, nil }
			if _, err := ReconcileFeed(options); err != nil {
				t.Fatal(err)
			}
			before := readOwned(t, cronPath)
			drifted := false
			options.faultPoint = func(point string) {
				if point == "cron-transaction-mutated:update" {
					drifted = true
					if testCase == "root" {
						reader.set("MAILTO=operator@example.invalid\n", true)
					}
				}
			}
			options.AttestCronDProvider = func() error {
				if drifted && testCase == "provider" {
					return errors.New("provider drift")
				}
				return nil
			}
			if err := ReconcileHA(options, true); err == nil {
				t.Fatal("post-mutation evidence drift was accepted")
			}
			if got := readOwned(t, cronPath); got != before {
				t.Fatalf("evidence drift failed to restore prior state: %q", got)
			}
			for _, name := range []string{pendingFileName, retiredFileName, transactionFileName, commitFileName} {
				if _, err := os.Lstat(filepath.Join(cronPath, name)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("evidence drift left %s: %v", name, err)
				}
			}
		})
	}
}

func TestPreflightIsReadOnlyAndRequiresProviderForLegacyState(t *testing.T) {
	reader := &testLegacyReader{content: legacyFeed(17), present: true}
	options, cronPath := testCronOptions(t, reader)
	providerCalls := 0
	options.AttestCronDProvider = func() error {
		providerCalls++
		return nil
	}
	inspection, err := Preflight(options, false)
	if err != nil || inspection.LegacyFeedCount != 1 || providerCalls < 2 {
		t.Fatalf("preflight = %#v provider-calls=%d error=%v", inspection, providerCalls, err)
	}
	entries, err := os.ReadDir(cronPath)
	if err != nil || len(entries) != 0 {
		t.Fatalf("read-only preflight mutated cron.d: entries=%v error=%v", entries, err)
	}
	reader.set(legacyHA(), true)
	if _, err := Preflight(options, false); err == nil {
		t.Fatal("preflight accepted legacy HA while HA is disabled")
	}
	options.AttestCronDProvider = nil
	if _, err := Preflight(options, true); err == nil {
		t.Fatal("preflight accepted missing provider attestation")
	}
}
