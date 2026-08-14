package integration

import (
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestWriteWazuhConfigRejectsDestinationSymlink(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.WriteFile("operator-owned.conf", []byte("preserve\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := root.Symlink("operator-owned.conf", wazuhConfigName); err != nil {
		t.Fatal(err)
	}
	if err := writeWazuhConfig(root, []byte("replacement\n")); err == nil {
		t.Fatal("writeWazuhConfig accepted a symbolic link")
	}
	victim, err := root.ReadFile("operator-owned.conf")
	if err != nil {
		t.Fatal(err)
	}
	if string(victim) != "preserve\n" {
		t.Fatalf("destination symlink was followed: %q", victim)
	}
}

func TestWriteWazuhConfigPreservesExistingFileMetadata(t *testing.T) {
	t.Parallel()

	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.WriteFile(wazuhConfigName, []byte("old\n"), 0640); err != nil {
		t.Fatal(err)
	}
	before, err := root.Lstat(wazuhConfigName)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeWazuhConfig(root, []byte("replacement\n")); err != nil {
		t.Fatal(err)
	}
	after, err := root.Lstat(wazuhConfigName)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode().Perm() != 0640 {
		t.Fatalf("wazuh config metadata changed: before=%v after=%v", before.Mode(), after.Mode())
	}
	beforeStat, beforeOK := before.Sys().(*syscall.Stat_t)
	afterStat, afterOK := after.Sys().(*syscall.Stat_t)
	if beforeOK && afterOK && (beforeStat.Uid != afterStat.Uid || beforeStat.Gid != afterStat.Gid) {
		t.Fatalf("wazuh config owner changed: before=%d:%d after=%d:%d", beforeStat.Uid, beforeStat.Gid, afterStat.Uid, afterStat.Gid)
	}
	config, err := root.ReadFile(wazuhConfigName)
	if err != nil {
		t.Fatal(err)
	}
	if string(config) != "replacement\n" {
		t.Fatalf("wazuh config = %q", config)
	}
}

func TestWriteWazuhConfigFailurePreservesOldContentAndRemovesStagingFile(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteFile(wazuhConfigName, []byte("old-content\n"), 0640); err != nil {
		t.Fatal(err)
	}
	before, err := root.Lstat(wazuhConfigName)
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected failure before rename")
	err = writeWazuhConfigBeforeRename(root, []byte("new-content\n"), func() error { return injected })
	if !errors.Is(err, injected) {
		t.Fatalf("rewrite error = %v, want injected failure", err)
	}
	after, err := root.Lstat(wazuhConfigName)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || after.Mode().Perm() != 0640 {
		t.Fatalf("failed rewrite changed destination metadata: before=%v after=%v", before.Mode(), after.Mode())
	}
	content, err := root.ReadFile(wazuhConfigName)
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
	if len(entries) != 1 || entries[0].Name() != wazuhConfigName {
		t.Fatalf("failed rewrite left staging residue: %#v", entries)
	}
}

func TestWriteWazuhConfigRejectsConcurrentSameInodeUpdate(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteFile(wazuhConfigName, []byte("old-content\n"), 0640); err != nil {
		t.Fatal(err)
	}
	err = writeWazuhConfigBeforeRename(root, []byte("replacement\n"), func() error {
		file, err := root.OpenFile(wazuhConfigName, os.O_WRONLY|os.O_TRUNC, 0)
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
	content, err := root.ReadFile(wazuhConfigName)
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
	if len(entries) != 1 || entries[0].Name() != wazuhConfigName {
		t.Fatalf("concurrent-update rejection left staging residue: %#v", entries)
	}
}

func TestWriteWazuhConfigRejectsChangeAfterSourceRead(t *testing.T) {
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	if err := root.WriteFile(wazuhConfigName, []byte("source\n"), 0640); err != nil {
		t.Fatal(err)
	}
	snapshot, err := root.ReadFile(wazuhConfigName)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile(wazuhConfigName, []byte("operator-update\n"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := writeWazuhConfigFromSnapshot(root, []byte("replacement\n"), snapshot); err == nil || !strings.Contains(err.Error(), "changed after it was read") {
		t.Fatalf("stale wazuh rewrite error = %v", err)
	}
	content, err := root.ReadFile(wazuhConfigName)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "operator-update\n" {
		t.Fatalf("stale rewrite replaced newer wazuh content: %q", content)
	}
}
