package network

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestApprovedFeedFileRejectsTraversalAndUnconfinedDestinations(t *testing.T) {
	t.Parallel()
	tests := []struct {
		path   string
		suffix string
	}{
		{path: "/etc/syswarden/lists/../shadow.ipv4", suffix: ".ipv4"},
		{path: "/tmp/feed.ipv4", suffix: ".ipv4"},
		{path: "/etc/syswarden/lists/sub/feed.ipv4", suffix: ".ipv4"},
		{path: "/etc/syswarden/lists/feed.ipv6", suffix: ".ipv4"},
		{path: "feed.ipv4", suffix: ".ipv4"},
	}
	for _, test := range tests {
		if _, err := approvedFeedFileForPath(test.path, test.suffix); err == nil {
			t.Fatalf("approvedFeedFileForPath(%q, %q) unexpectedly succeeded", test.path, test.suffix)
		}
	}
}

func TestOSINTAndASNWritersRejectUnconfinedPathsBeforeNetworkAccess(t *testing.T) {
	t.Parallel()
	if err := DownloadOSINT(t.Context(), "/tmp/syswarden-threatintel"); err == nil {
		t.Fatal("DownloadOSINT accepted an unconfined destination")
	}
	if err := FetchASNWhois("AS64500", "/tmp/AS64500"); err == nil {
		t.Fatal("FetchASNWhois accepted an unconfined destination")
	}
	if err := FetchASNWhois("AS/../../tmp/escape", "/etc/syswarden/lists/AS64500"); err == nil {
		t.Fatal("FetchASNWhois accepted a path-like ASN")
	}
}

func TestFeedFileTargetRejectsUnsafeBasenames(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	for _, name := range []string{"", ".", "..", "../escape.ipv4", "sub/list.ipv4", `sub\\list.ipv4`, "list.ipv6"} {
		target := feedFileTarget{directory: directory, name: name}
		if err := writeFeedFileAt(target, ".ipv4", []byte("192.0.2.1\n")); err == nil {
			t.Fatalf("writeFeedFileAt(%q) unexpectedly succeeded", name)
		}
	}
}

func TestCleanCIDRListAtRoutesFamiliesAtomicallyWithOwnerOnlyModes(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	v4Target := feedFileTarget{directory: directory, name: "feed.ipv4"}
	v6Target := feedFileTarget{directory: directory, name: "feed.ipv6"}
	if err := writeFeedFileAt(v4Target, ".ipv4", []byte("192.0.2.1\n2001:db8::1\ninvalid\n192.0.2.1\n")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	fixture, err := root.Open("feed.ipv4")
	if err != nil {
		t.Fatal(err)
	}
	if err := fixture.Chmod(0644); err != nil {
		_ = fixture.Close()
		t.Fatal(err)
	}
	if err := fixture.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cleanCIDRListAt(v4Target); err != nil {
		t.Fatal(err)
	}
	v4, err := readFeedFileAt(v4Target, ".ipv4")
	if err != nil {
		t.Fatal(err)
	}
	v6, err := readFeedFileAt(v6Target, ".ipv6")
	if err != nil {
		t.Fatal(err)
	}
	if string(v4) != "192.0.2.1/32\n" {
		t.Fatalf("IPv4 output = %q", v4)
	}
	if string(v6) != "2001:db8::1/128\n" {
		t.Fatalf("IPv6 output = %q", v6)
	}
	for _, name := range []string{"feed.ipv4", "feed.ipv6"} {
		info, err := root.Lstat(name)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatalf("%s mode = %v, want regular 0600", name, info.Mode())
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".syswarden-") {
			t.Fatalf("staging residue remains: %s", entry.Name())
		}
	}
}

func TestFeedFileRejectsSymlinkAndNonRegularTargets(t *testing.T) {
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
	if err := root.Symlink("outside", "linked.ipv4"); err != nil {
		t.Fatal(err)
	}
	if err := root.Mkdir("directory.ipv4", 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"linked.ipv4", "directory.ipv4"} {
		target := feedFileTarget{directory: directory, name: name}
		if _, err := readFeedFileAt(target, ".ipv4"); err == nil {
			t.Fatalf("readFeedFileAt(%q) unexpectedly succeeded", name)
		}
		if err := writeFeedFileAt(target, ".ipv4", []byte("192.0.2.1\n")); err == nil {
			t.Fatalf("writeFeedFileAt(%q) unexpectedly succeeded", name)
		}
	}
	out, err := root.ReadFile("outside")
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "do-not-touch\n" {
		t.Fatalf("symlink target changed: %q", out)
	}
}

func TestFeedFileRejectsSymlinkDirectoryComponent(t *testing.T) {
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
	target := feedFileTarget{directory: filepath.Join(base, "linked"), name: "feed.ipv4"}
	if err := writeFeedFileAt(target, ".ipv4", []byte("192.0.2.1\n")); err == nil {
		t.Fatal("write through a symlink directory unexpectedly succeeded")
	}
	if _, err := root.Lstat("real/feed.ipv4"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("write escaped through symlink directory: %v", err)
	}
}

func TestCleanCIDRListAtPropagatesSiblingSymlinkError(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	target := feedFileTarget{directory: directory, name: "feed.ipv4"}
	if err := writeFeedFileAt(target, ".ipv4", []byte("192.0.2.1\n2001:db8::1\n")); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile("outside", []byte("do-not-touch\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := root.Symlink("outside", "feed.ipv6"); err != nil {
		t.Fatal(err)
	}
	if err := cleanCIDRListAt(target); err == nil {
		t.Fatal("cleanCIDRListAt unexpectedly ignored the sibling symlink")
	}
	out, err := root.ReadFile("outside")
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "do-not-touch\n" {
		t.Fatalf("sibling symlink target changed: %q", out)
	}
}

func TestFeedFileAtomicRewriteFailurePreservesOldContentAndRemovesStagingFile(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	target := feedFileTarget{directory: directory, name: "feed.ipv4"}
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
	err = writeFeedFileAtBeforeRename(target, ".ipv4", []byte("new-content\n"), func() error { return injected })
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

func TestFeedFileAtomicRewriteRejectsConcurrentSameInodeUpdate(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	target := feedFileTarget{directory: directory, name: "feed.ipv4"}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteFile(target.name, []byte("old-content\n"), 0600); err != nil {
		t.Fatal(err)
	}
	err = writeFeedFileAtBeforeRename(target, ".ipv4", []byte("replacement\n"), func() error {
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

func TestFeedRewriteRejectsChangeAfterSourceRead(t *testing.T) {
	directory := t.TempDir()
	target := feedFileTarget{directory: directory, name: "feed.ipv4"}
	if err := writeFeedFileAt(target, ".ipv4", []byte("192.0.2.1\n")); err != nil {
		t.Fatal(err)
	}
	snapshot, err := readFeedFileAt(target, ".ipv4")
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteFile("feed.ipv4", []byte("198.51.100.1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeFeedFileInDirectoryFromSnapshot(root, target, []byte("203.0.113.1\n"), snapshot); err == nil || !strings.Contains(err.Error(), "changed after it was read") {
		t.Fatalf("stale feed rewrite error = %v", err)
	}
	content, err := root.ReadFile("feed.ipv4")
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "198.51.100.1\n" {
		t.Fatalf("stale rewrite replaced newer feed content: %q", content)
	}
}

func TestFeedAtomicRewriteSerializesConcurrentAppend(t *testing.T) {
	directory := t.TempDir()
	target := feedFileTarget{directory: directory, name: "feed.ipv4"}
	if err := writeFeedFileAt(target, ".ipv4", []byte("old\n")); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	appendDone := make(chan error, 1)
	if err := writeFeedFileAtBeforeRename(target, ".ipv4", []byte("replacement\n"), func() error {
		go func() {
			close(started)
			appendDone <- appendFeedFileAt(target, ".ipv4", []byte("appended\n"))
		}()
		<-started
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := <-appendDone; err != nil {
		t.Fatal(err)
	}
	content, err := readFeedFileAt(target, ".ipv4")
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "replacement\nappended\n" {
		t.Fatalf("rewrite/append output = %q", content)
	}
}

func TestFeedFileAtomicRewritePreservesOwnerAndHardensMode(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	target := feedFileTarget{directory: directory, name: "feed.ipv4"}
	path := filepath.Join(directory, target.name)
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteFile(target.name, []byte("old\n"), 0640); err != nil {
		t.Fatal(err)
	}
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFeedFileAt(target, ".ipv4", []byte("replacement\n")); err != nil {
		t.Fatal(err)
	}
	after, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	beforeStat, beforeOK := before.Sys().(*syscall.Stat_t)
	afterStat, afterOK := after.Sys().(*syscall.Stat_t)
	if beforeOK && afterOK && (beforeStat.Uid != afterStat.Uid || beforeStat.Gid != afterStat.Gid) {
		t.Fatalf("owner changed: before=%d:%d after=%d:%d", beforeStat.Uid, beforeStat.Gid, afterStat.Uid, afterStat.Gid)
	}
	if after.Mode().Perm() != 0600 {
		t.Fatalf("rewritten feed mode = %04o, want 0600", after.Mode().Perm())
	}
}
