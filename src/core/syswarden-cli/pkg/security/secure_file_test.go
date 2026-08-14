package security

import (
	"crypto/sha256"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestSecurityFileTargetAllowlistRejectsTraversal(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		"/etc/ssh/../shadow",
		"/etc/newsyslog.conf/child",
		"/tmp/sshd_config",
		"etc/ssh/sshd_config",
	} {
		if _, err := securityFileTargetForPath(path); err == nil {
			t.Fatalf("securityFileTargetForPath(%q) unexpectedly succeeded", path)
		}
	}
}

func TestRewriteSecurityFileRejectsSymlinkAndPreservesOwner(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteFile("victim", []byte("preserve\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := root.Symlink("victim", "config"); err != nil {
		t.Fatal(err)
	}
	target := securityFileTarget{directory: directory, name: "config"}
	if err := rewriteSecurityTarget(target, []byte("replacement\n")); err == nil {
		t.Fatal("rewrite accepted a symlink target")
	}
	got, err := root.ReadFile("victim")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "preserve\n" {
		t.Fatalf("symlink target changed: %q", got)
	}
	if err := root.Remove("config"); err != nil {
		t.Fatal(err)
	}
	file, err := root.OpenFile("config", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0640)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("old\n"); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := root.Lstat("config")
	if err != nil {
		t.Fatal(err)
	}
	if err := rewriteSecurityTarget(target, []byte("replacement\n")); err != nil {
		t.Fatal(err)
	}
	after, err := root.Lstat("config")
	if err != nil {
		t.Fatal(err)
	}
	beforeStat, beforeOK := before.Sys().(*syscall.Stat_t)
	afterStat, afterOK := after.Sys().(*syscall.Stat_t)
	if beforeOK && afterOK && (beforeStat.Uid != afterStat.Uid || beforeStat.Gid != afterStat.Gid) {
		t.Fatalf("security file owner changed: before=%d:%d after=%d:%d", beforeStat.Uid, beforeStat.Gid, afterStat.Uid, afterStat.Gid)
	}
	if after.Mode().Perm() != 0600 {
		t.Fatalf("security file mode = %04o, want 0600", after.Mode().Perm())
	}
	content, err := root.ReadFile("config")
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "replacement\n" {
		t.Fatalf("security file content = %q", content)
	}
}

func TestRewriteSecurityFileFailurePreservesOldContentAndRemovesStagingFile(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteFile("config", []byte("old-content\n"), 0640); err != nil {
		t.Fatal(err)
	}
	target := securityFileTarget{directory: directory, name: "config"}
	before, err := root.Lstat(target.name)
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected failure before rename")
	err = rewriteSecurityTargetBeforeRename(target, []byte("new-content\n"), func() error { return injected })
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

func TestRewriteSecurityFileRejectsConcurrentSameInodeUpdate(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	target := securityFileTarget{directory: directory, name: "config"}
	if err := root.WriteFile(target.name, []byte("old-content\n"), 0600); err != nil {
		t.Fatal(err)
	}
	err = rewriteSecurityTargetBeforeRename(target, []byte("replacement\n"), func() error {
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

func TestRewriteSecurityFileRejectsChangeAfterSourceRead(t *testing.T) {
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteFile("config", []byte("source\n"), 0600); err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256([]byte("source\n"))
	if err := root.WriteFile("config", []byte("operator-update\n"), 0600); err != nil {
		t.Fatal(err)
	}
	target := securityFileTarget{directory: directory, name: "config"}
	if err := rewriteSecurityTargetExpected(target, []byte("replacement\n"), &expected, nil); err == nil || !strings.Contains(err.Error(), "changed after it was read") {
		t.Fatalf("stale security rewrite error = %v", err)
	}
	content, err := root.ReadFile("config")
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "operator-update\n" {
		t.Fatalf("stale rewrite replaced newer security content: %q", content)
	}
}
