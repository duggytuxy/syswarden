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
		{input: "2001:db8::/32", valid: true},
		{input: "192.0.2.10:443"},
		{input: "[2001:db8::10]:443"},
		{input: "192.0.2.10 # operator comment"},
		{input: "192.0.2.1/33"},
		{input: "999.0.2.1"},
		{input: "example.com"},
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
			content, found := removeListEntriesForIP([]byte(entry+"\n2001:db8::20\n"), ip)
			if !found {
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
