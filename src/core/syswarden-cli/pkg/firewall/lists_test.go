package firewall

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func TestIsValidIPCompatibility(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input  string
		valid  bool
		isIPv4 bool
	}{
		{input: "192.0.2.1", valid: true, isIPv4: true},
		{input: "2001:db8::1", valid: true},
		{input: "192.0.2.0/24", valid: true, isIPv4: true},
		{input: "2001:db8::/64", valid: true},
		{input: "2001:db8::/32"},
		{input: "192.0.2.10:443"},
		{input: "[2001:db8::10]:443"},
		{input: "192.0.2.10 # operator comment"},
		{input: "192.0.2.1/33"},
		{input: "999.0.2.1"},
		{input: "example.com"},
		{input: " 192.0.2.1"},
		{input: "192.0.2.1 "},
		{input: "\t2001:db8::1"},
		{input: ""},
	}

	for _, test := range tests {
		test := test
		t.Run(test.input, func(t *testing.T) {
			t.Parallel()
			valid, isIPv4 := IsValidIP(test.input)
			if valid != test.valid || isIPv4 != test.isIPv4 {
				t.Fatalf("IsValidIP(%q) = (%t, %t), want (%t, %t)", test.input, valid, isIPv4, test.valid, test.isIPv4)
			}
		})
	}
}

func TestListEntryIPHandlesIPv4AndIPv6Ports(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		entry string
		want  string
	}{
		{entry: "192.0.2.10", want: "192.0.2.10"},
		{entry: "192.0.2.10:22", want: "192.0.2.10"},
		{entry: "2001:db8::10", want: "2001:db8::10"},
		{entry: "[2001:db8::10]:22", want: "2001:db8::10"},
	} {
		if got := listEntryIP(test.entry); got != test.want {
			t.Fatalf("listEntryIP(%q) = %q, want %q", test.entry, got, test.want)
		}
	}
}

func TestWhitelistAndSSHRemovalRecognizeProducedIPv6PortEntries(t *testing.T) {
	t.Parallel()
	const ip = "2001:db8::10"
	entry := formatListEntry(ip, "2222")
	if entry != "[2001:db8::10]:2222" {
		t.Fatalf("formatListEntry() = %q", entry)
	}
	for _, operation := range []string{"RemoveFromWhitelist", "RevokeSSH"} {
		t.Run(operation, func(t *testing.T) {
			content, found, changed := removeListEntriesForIP([]byte(entry+"\n2001:db8::20\n"), ip)
			if !found || !changed {
				t.Fatalf("%s removal logic did not recognize produced entry %q", operation, entry)
			}
			if string(content) != "2001:db8::20\n" {
				t.Fatalf("%s removal output = %q", operation, content)
			}
		})
	}
}

func TestAppendListFileDoesNotLoseConcurrentEntries(t *testing.T) {
	directory := t.TempDir()
	target := approvedListFile{directory: directory, name: "list"}
	if err := writeListFileAt(target, nil); err != nil {
		t.Fatal(err)
	}
	const writers = 32
	var wait sync.WaitGroup
	errorsByWriter := make(chan error, writers)
	for index := range writers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsByWriter <- appendListFileAt(target, []byte(fmt.Sprintf("192.0.2.%d\n", index)))
		}()
	}
	wait.Wait()
	close(errorsByWriter)
	for err := range errorsByWriter {
		if err != nil {
			t.Fatal(err)
		}
	}
	content, err := readListFileAt(target)
	if err != nil {
		t.Fatal(err)
	}
	for index := range writers {
		entry := fmt.Sprintf("192.0.2.%d\n", index)
		if strings.Count(string(content), entry) != 1 {
			t.Fatalf("concurrent entry %q count = %d", entry, strings.Count(string(content), entry))
		}
	}
}

func TestListAtomicRewriteSerializesConcurrentAppend(t *testing.T) {
	directory := t.TempDir()
	target := approvedListFile{directory: directory, name: "list"}
	if err := writeListFileAt(target, []byte("old\n")); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	appendDone := make(chan error, 1)
	if err := writeListFileAtBeforeRename(target, []byte("replacement\n"), func() error {
		go func() {
			close(started)
			appendDone <- appendListFileAt(target, []byte("appended\n"))
		}()
		<-started
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := <-appendDone; err != nil {
		t.Fatal(err)
	}
	content, err := readListFileAt(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "replacement\nappended\n" {
		t.Fatalf("rewrite/append output = %q", content)
	}
}

func TestRemoveFromFileCanonicalizationContract_SW_LIST_001(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "list")
	target := approvedListFile{directory: directory, name: "list"}
	content := "# operator comment\n 192.0.2.10 \n\n198.51.100.1\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil { // #nosec G302 -- the contract intentionally models an existing operator-created world-readable list
		t.Fatal(err)
	}
	if err := removeFromListFileAt(target, "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path) // #nosec G304 -- path is rooted in t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	want := "# operator comment\n198.51.100.1\n"
	if string(got) != want {
		t.Fatalf("removeFromFile() output = %q, want %q", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("removeFromFile() mode = %#o, want hardened mode 0600", info.Mode().Perm())
	}
	if strings.Contains(string(got), "192.0.2.10") {
		t.Fatal("removed address remains in the list")
	}
}

func TestAddToListFileRejectsUnsafeNewPolicy_SW_SEC_M1(t *testing.T) {
	target := approvedListFile{directory: t.TempDir(), name: "list"}
	for _, value := range []string{"0.0.0.0/0", "::/0", "8.8.0.0/16", "2606:4700::/48"} {
		if err := addToListFileAt(target, value); err == nil {
			t.Fatalf("addToListFileAt() accepted unsafe new policy %q", value)
		}
	}
	if _, err := readListFileAt(target); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("rejected additions created list state: %v", err)
	}
}

func TestRemoveFromListFileRecoversLegacyUnsafePolicy_SW_SEC_M1(t *testing.T) {
	directory := t.TempDir()
	target := approvedListFile{directory: directory, name: "list"}
	content := []byte("# legacy recovery fixture\n0.0.0.0/0\n::/0\n8.8.8.8\n")
	if err := writeListFileAt(target, content); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"0.0.0.0/0", "::/0"} {
		if err := removeFromListFileAt(target, value); err != nil {
			t.Fatalf("removeFromListFileAt(%q) error = %v", value, err)
		}
	}
	got, err := readListFileAt(target)
	if err != nil {
		t.Fatal(err)
	}
	want := "# legacy recovery fixture\n8.8.8.8\n"
	if string(got) != want {
		t.Fatalf("legacy recovery output = %q, want %q", got, want)
	}
}

func TestLegacyOperatorRecoverySanitizesEveryConfiguredListBeforeReload_SW2_M1(t *testing.T) {
	directory := t.TempDir()
	targets := []approvedListFile{
		{directory: directory, name: "whitelist.ipv4"},
		{directory: directory, name: "blocklist.ipv6"},
		{directory: directory, name: "ssh-bypass"},
	}
	fixtures := [][]byte{
		[]byte("0.0.0.0/0\n8.8.8.8\n"),
		[]byte("::/0\n2606:4700:4700::1111\n"),
		[]byte("malformed legacy entry\n1.1.1.1\n"),
	}
	for index, target := range targets {
		if err := writeListFileAt(target, fixtures[index]); err != nil {
			t.Fatal(err)
		}
	}
	changed, err := sanitizeLegacyListTargets(targets)
	if err != nil || !changed {
		t.Fatalf("global legacy list cleanup = (%t, %v), want (true, nil)", changed, err)
	}
	want := []string{"8.8.8.8\n", "2606:4700:4700::1111\n", "1.1.1.1\n"}
	for index, target := range targets {
		content, err := readListFileAt(target)
		if err != nil {
			t.Fatal(err)
		}
		if string(content) != want[index] {
			t.Fatalf("sanitized %s = %q, want %q", target.name, content, want[index])
		}
	}
}

func TestApprovedListFileAllowlistRejectsTraversalAndUnknownPaths(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		"/etc/syswarden/lists/../shadow",
		"/etc/syswarden/lists/syswarden_whitelist.ipv4/child",
		"/tmp/syswarden_whitelist.ipv4",
		"syswarden_whitelist.ipv4",
	} {
		if _, err := approvedListFileForPath(path); err == nil {
			t.Fatalf("approvedListFileForPath(%q) unexpectedly succeeded", path)
		}
	}
}

func TestListFileTargetRejectsUnsafeBasenames(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	for _, name := range []string{"", ".", "..", "../escape", "sub/list", `sub\\list`} {
		target := approvedListFile{directory: directory, name: name}
		if err := writeListFileAt(target, []byte("192.0.2.1\n")); err == nil {
			t.Fatalf("writeListFileAt(%q) unexpectedly succeeded", name)
		}
	}
}

func TestListFileRejectsSymlinkAndNonRegularTargets(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteFile("outside", []byte("do-not-touch\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := root.Symlink("outside", "list-link"); err != nil {
		t.Fatal(err)
	}
	if err := root.Mkdir("list-dir", 0700); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"list-link", "list-dir"} {
		target := approvedListFile{directory: directory, name: name}
		if _, err := readListFileAt(target); err == nil {
			t.Fatalf("readListFileAt(%q) unexpectedly succeeded", name)
		}
		if err := writeListFileAt(target, []byte("192.0.2.1\n")); err == nil {
			t.Fatalf("writeListFileAt(%q) unexpectedly succeeded", name)
		}
	}

	outside, err := root.ReadFile("outside")
	if err != nil {
		t.Fatal(err)
	}
	if string(outside) != "do-not-touch\n" {
		t.Fatalf("symlink target changed: %q", outside)
	}
}

func TestListFileRejectsSymlinkDirectoryComponent(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := root.Mkdir("real", 0700); err != nil {
		t.Fatal(err)
	}
	if err := root.Symlink("real", "linked"); err != nil {
		t.Fatal(err)
	}
	target := approvedListFile{directory: filepath.Join(base, "linked"), name: "list"}
	if err := writeListFileAt(target, []byte("192.0.2.1\n")); err == nil {
		t.Fatal("write through a symlink directory unexpectedly succeeded")
	}
	if _, err := root.Lstat("real/list"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("write escaped through symlink directory: %v", err)
	}
}

func TestListFileSecureRewriteCreatesOwnerOnlyRegularFile(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	target := approvedListFile{directory: directory, name: "list"}
	if err := writeListFileAt(target, []byte("192.0.2.1\n")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(filepath.Join(directory, "list"))
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatalf("created target mode = %v, want regular 0600", info.Mode())
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "list" {
		t.Fatalf("staging residue remains: %#v", entries)
	}
}

func TestListFileAtomicRewriteFailurePreservesOldContentAndRemovesStagingFile(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	target := approvedListFile{directory: directory, name: "list"}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteFile(target.name, []byte("old-content\n"), 0640); err != nil {
		t.Fatal(err)
	}
	before, err := root.Lstat(target.name)
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected failure before rename")
	err = writeListFileAtBeforeRename(target, []byte("new-content\n"), func() error { return injected })
	if !errors.Is(err, injected) {
		t.Fatalf("rewrite error = %v, want injected failure", err)
	}
	after, err := root.Lstat(target.name)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || after.Mode().Perm() != 0640 {
		t.Fatalf("failed rewrite changed destination metadata: before=%v after=%v", before.Mode(), after.Mode())
	}
	content, err := root.ReadFile(target.name)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "old-content\n" {
		t.Fatalf("failed rewrite changed old content: %q", content)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != target.name {
		t.Fatalf("failed rewrite left staging residue: %#v", entries)
	}
}

func TestListFileAtomicRewriteRejectsConcurrentSameInodeUpdate(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	target := approvedListFile{directory: directory, name: "list"}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteFile(target.name, []byte("old-content\n"), 0600); err != nil {
		t.Fatal(err)
	}
	err = writeListFileAtBeforeRename(target, []byte("replacement\n"), func() error {
		file, err := root.OpenFile(target.name, os.O_WRONLY|os.O_TRUNC, 0)
		if err != nil {
			return err
		}
		if _, err := file.WriteString("peer-update\n"); err != nil {
			_ = file.Close()
			return err
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return err
		}
		return file.Close()
	})
	if err == nil || !strings.Contains(err.Error(), "changed before publication") {
		t.Fatalf("rewrite error = %v, want concurrent-update rejection", err)
	}
	content, err := root.ReadFile(target.name)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "peer-update\n" {
		t.Fatalf("rewrite overwrote concurrent update: %q", content)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != target.name {
		t.Fatalf("concurrent-update rejection left staging residue: %#v", entries)
	}
}

func TestListRewriteRejectsChangeAfterSourceRead(t *testing.T) {
	directory := t.TempDir()
	target := approvedListFile{directory: directory, name: "list"}
	if err := writeListFileAt(target, []byte("source\n")); err != nil {
		t.Fatal(err)
	}
	snapshot, err := readListFileAt(target)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteFile("list", []byte("operator-update\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeListFileInDirectoryFromSnapshot(root, target, []byte("replacement\n"), snapshot); err == nil || !strings.Contains(err.Error(), "changed after it was read") {
		t.Fatalf("stale list rewrite error = %v", err)
	}
	content, err := root.ReadFile("list")
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "operator-update\n" {
		t.Fatalf("stale rewrite replaced newer list content: %q", content)
	}
}

func TestListFileAtomicRewritePreservesOwnerAndHardensMode(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	target := approvedListFile{directory: directory, name: "list"}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteFile(target.name, []byte("old\n"), 0640); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(filepath.Join(directory, target.name))
	if err != nil {
		t.Fatal(err)
	}
	if err := writeListFileAt(target, []byte("replacement\n")); err != nil {
		t.Fatal(err)
	}
	after, err := os.Lstat(filepath.Join(directory, target.name))
	if err != nil {
		t.Fatal(err)
	}
	beforeStat, beforeOK := before.Sys().(*syscall.Stat_t)
	afterStat, afterOK := after.Sys().(*syscall.Stat_t)
	if beforeOK && afterOK && (beforeStat.Uid != afterStat.Uid || beforeStat.Gid != afterStat.Gid) {
		t.Fatalf("owner changed: before=%d:%d after=%d:%d", beforeStat.Uid, beforeStat.Gid, afterStat.Uid, afterStat.Gid)
	}
	if after.Mode().Perm() != 0600 {
		t.Fatalf("rewritten list mode = %04o, want 0600", after.Mode().Perm())
	}
}

func TestPersistentBlocklistPairInitializationCoversFreshAndSingleFamilyStates_SW_GRC_025(t *testing.T) {
	t.Parallel()
	for _, fixture := range []struct {
		name    string
		initial map[string]string
	}{
		{name: "fresh install", initial: map[string]string{}},
		{name: "IPv4 only", initial: map[string]string{"syswarden_blacklist.ipv4": "192.0.2.10\n"}},
		{name: "IPv6 only", initial: map[string]string{"syswarden_blacklist.ipv6": "2001:db8::10\n"}},
	} {
		fixture := fixture
		t.Run(fixture.name, func(t *testing.T) {
			t.Parallel()
			directory := t.TempDir()
			targets := persistentBlocklistTargetsForTest(directory)
			initialIdentity := make(map[string]os.FileInfo, len(fixture.initial))
			for name, content := range fixture.initial {
				path := filepath.Join(directory, name)
				if err := os.WriteFile(path, []byte(content), 0600); err != nil {
					t.Fatal(err)
				}
				info, err := os.Lstat(path)
				if err != nil {
					t.Fatal(err)
				}
				initialIdentity[name] = info
			}

			if err := ensurePersistentBlocklistPairAt(targets, nil); err != nil {
				t.Fatal(err)
			}
			for _, target := range targets {
				content, err := os.ReadFile(filepath.Join(directory, target.name)) // #nosec G304 -- directory is created by t.TempDir and target names are fixed product constants
				if err != nil {
					t.Fatal(err)
				}
				if want := fixture.initial[target.name]; string(content) != want {
					t.Fatalf("%s content = %q, want %q", target.name, content, want)
				}
				info, err := os.Lstat(filepath.Join(directory, target.name))
				if err != nil {
					t.Fatal(err)
				}
				stat, ok := info.Sys().(*syscall.Stat_t)
				if !ok || !info.Mode().IsRegular() || info.Mode() != 0600 || stat.Nlink != 1 ||
					int64(stat.Uid) != int64(os.Geteuid()) || int64(stat.Gid) != int64(os.Getegid()) {
					t.Fatalf("%s identity is unsafe: mode=%v stat=%#v", target.name, info.Mode(), stat)
				}
				if before := initialIdentity[target.name]; before != nil && !os.SameFile(before, info) {
					t.Fatalf("existing %s was replaced during pair initialization", target.name)
				}
			}
			markerPath := filepath.Join(directory, persistentBlocklistPairMarkerName)
			marker, err := os.ReadFile(markerPath) // #nosec G304 -- markerPath is a fixed product filename beneath t.TempDir
			if err != nil || string(marker) != persistentBlocklistPairMarkerBytes {
				t.Fatalf("pair marker = %q, err=%v", marker, err)
			}
			markerInfo, err := os.Lstat(markerPath)
			if err != nil || !markerInfo.Mode().IsRegular() || markerInfo.Mode() != 0600 {
				t.Fatalf("pair marker identity is unsafe: info=%#v err=%v", markerInfo, err)
			}
		})
	}
}

func TestPersistentBlocklistPairInitializationSerializesConcurrentInstallers_SW_GRC_026(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	targets := persistentBlocklistTargetsForTest(directory)
	const workers = 16
	errorsSeen := make(chan error, workers)
	var group sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			errorsSeen <- ensurePersistentBlocklistPairAt(targets, nil)
		}()
	}
	group.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("concurrent initialization failed: %v", err)
		}
	}
	for _, target := range targets {
		content, err := os.ReadFile(filepath.Join(directory, target.name)) // #nosec G304 -- directory is created by t.TempDir and target names are fixed product constants
		if err != nil || len(content) != 0 {
			t.Fatalf("%s after concurrent initialization: content=%q err=%v", target.name, content, err)
		}
	}
	marker, err := os.ReadFile(filepath.Join(directory, persistentBlocklistPairMarkerName)) // #nosec G304 -- the marker is a fixed product filename beneath t.TempDir
	if err != nil || string(marker) != persistentBlocklistPairMarkerBytes {
		t.Fatalf("pair marker after concurrent initialization = %q, err=%v", marker, err)
	}
}

func TestPersistentBlocklistPairInitializationRejectsUnsafeIdentityAndCreateRace_SW_GRC_027(t *testing.T) {
	t.Parallel()
	t.Run("unsafe existing mode", func(t *testing.T) {
		directory := t.TempDir()
		targets := persistentBlocklistTargetsForTest(directory)
		path := filepath.Join(directory, targets[0].name)
		if err := os.WriteFile(path, []byte("192.0.2.10\n"), 0644); err != nil { // #nosec G306 -- this adversarial fixture deliberately uses an unsafe mode
			t.Fatal(err)
		}
		if err := ensurePersistentBlocklistPairAt(targets, nil); err == nil || !strings.Contains(err.Error(), "regular 0600 file") {
			t.Fatalf("unsafe existing mode error = %v", err)
		}
		content, err := os.ReadFile(path) // #nosec G304 -- path is a fixed product filename beneath t.TempDir
		if err != nil || string(content) != "192.0.2.10\n" {
			t.Fatalf("unsafe existing file was changed: content=%q err=%v", content, err)
		}
	})

	t.Run("target appears before exclusive create", func(t *testing.T) {
		directory := t.TempDir()
		targets := persistentBlocklistTargetsForTest(directory)
		collidingPath := filepath.Join(directory, targets[0].name)
		hookCalls := 0
		err := ensurePersistentBlocklistPairAt(targets, func(target approvedListFile) error {
			hookCalls++
			if hookCalls == 1 {
				return os.WriteFile(collidingPath, []byte("operator-race\n"), 0600)
			}
			return nil
		})
		if err == nil || (!strings.Contains(err.Error(), "create persistent blocklist file") &&
			!strings.Contains(err.Error(), "appeared during initialization")) {
			t.Fatalf("create race error = %v", err)
		}
		content, readErr := os.ReadFile(collidingPath) // #nosec G304 -- collidingPath is a fixed product filename beneath t.TempDir
		if readErr != nil || string(content) != "operator-race\n" {
			t.Fatalf("create race target was overwritten: content=%q err=%v", content, readErr)
		}
	})

	t.Run("unsafe directory mode", func(t *testing.T) {
		directory := t.TempDir()
		if err := os.Chmod(directory, 0770); err != nil { // #nosec G302 -- this adversarial fixture deliberately creates a group-writable directory
			t.Fatal(err)
		}
		if err := ensurePersistentBlocklistPairAt(persistentBlocklistTargetsForTest(directory), nil); err == nil ||
			!strings.Contains(err.Error(), "without group or world write access") {
			t.Fatalf("unsafe directory mode error = %v", err)
		}
	})

	t.Run("oversized evidence", func(t *testing.T) {
		directory := t.TempDir()
		path := filepath.Join(directory, persistentBlocklistIPv4Name)
		if err := os.WriteFile(path, nil, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Truncate(path, maximumPersistentBlocklistEvidenceBytes+1); err != nil {
			t.Fatal(err)
		}
		if err := ensurePersistentBlocklistPairAt(persistentBlocklistTargetsForTest(directory), nil); err == nil {
			t.Fatal("oversized persistent blocklist evidence was accepted")
		}
	})

	t.Run("post-initialization absence remains visible", func(t *testing.T) {
		directory := t.TempDir()
		targets := persistentBlocklistTargetsForTest(directory)
		if err := ensurePersistentBlocklistPairAt(targets, nil); err != nil {
			t.Fatal(err)
		}
		missingPath := filepath.Join(directory, persistentBlocklistIPv6Name)
		if err := os.Remove(missingPath); err != nil {
			t.Fatal(err)
		}
		err := ensurePersistentBlocklistPairAt(targets, nil)
		if err == nil || !strings.Contains(err.Error(), "unexpectedly missing after pair initialization") {
			t.Fatalf("unexpected post-initialization absence error = %v", err)
		}
		if _, err := os.Lstat(missingPath); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("unexpected absence was masked: %v", err)
		}
	})

	t.Run("invalid pair marker remains visible", func(t *testing.T) {
		directory := t.TempDir()
		targets := persistentBlocklistTargetsForTest(directory)
		if err := ensurePersistentBlocklistPairAt(targets, nil); err != nil {
			t.Fatal(err)
		}
		markerPath := filepath.Join(directory, persistentBlocklistPairMarkerName)
		if err := os.WriteFile(markerPath, []byte("invalid\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := ensurePersistentBlocklistPairAt(targets, nil); err == nil ||
			!strings.Contains(err.Error(), "marker content is invalid") {
			t.Fatalf("invalid pair marker error = %v", err)
		}
		marker, err := os.ReadFile(markerPath) // #nosec G304 -- markerPath is a fixed product filename beneath t.TempDir
		if err != nil || string(marker) != "invalid\n" {
			t.Fatalf("invalid marker was masked: marker=%q err=%v", marker, err)
		}
	})

	for _, fixture := range []struct {
		name    string
		prepare func(*testing.T, string, string)
	}{
		{
			name: "symbolic link",
			prepare: func(t *testing.T, directory, path string) {
				target := filepath.Join(directory, "operator-target")
				if err := os.WriteFile(target, []byte("operator\n"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "hard link",
			prepare: func(t *testing.T, directory, path string) {
				target := filepath.Join(directory, "operator-target")
				if err := os.WriteFile(target, []byte("operator\n"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(target, path); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		fixture := fixture
		t.Run(fixture.name, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, persistentBlocklistIPv4Name)
			fixture.prepare(t, directory, path)
			if err := ensurePersistentBlocklistPairAt(persistentBlocklistTargetsForTest(directory), nil); err == nil {
				t.Fatal("unsafe persistent blocklist identity was accepted")
			}
		})
	}
}

func persistentBlocklistTargetsForTest(directory string) []approvedListFile {
	return []approvedListFile{
		{directory: directory, name: persistentBlocklistIPv4Name},
		{directory: directory, name: persistentBlocklistIPv6Name},
	}
}
