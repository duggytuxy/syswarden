//go:build linux

package config

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestTrustedProducerMetadataRejectsPrivilegeAndLinkChanges(t *testing.T) {
	producer := uint32(999)
	access := TrustedLogAccess{AuthorityUID: 0, ProducerUID: &producer}
	base := unix.Stat_t{Mode: unix.S_IFREG | 0640, Uid: producer, Nlink: 1}
	if err := access.ValidateFile(base, false); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*unix.Stat_t){func(s *unix.Stat_t) { s.Uid = 998 }, func(s *unix.Stat_t) { s.Mode |= 0020 }, func(s *unix.Stat_t) { s.Mode |= 0002 }, func(s *unix.Stat_t) { s.Mode |= unix.S_ISUID }, func(s *unix.Stat_t) { s.Mode = unix.S_IFIFO | 0600 }, func(s *unix.Stat_t) { s.Nlink = 2 }, func(s *unix.Stat_t) { s.Nlink = 0 }} {
		changed := base
		change(&changed)
		if err := access.ValidateFile(changed, false); err == nil {
			t.Fatalf("accepted changed inode: %+v", changed)
		}
	}
	base.Nlink = 0
	if err := access.ValidateFile(base, true); err != nil {
		t.Fatalf("held unlinked rotation inode: %v", err)
	}
	base.Nlink = 2
	if err := access.ValidateFile(base, true); err == nil {
		t.Fatal("held hardlink accepted")
	}
}

func TestTrustedProducerFileAccessPinsAuthorizedParentsAndLeaf(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.Mkdir("logs", 0700); err != nil {
		t.Fatal(err)
	}
	if err := root.WriteFile("logs/access.log", []byte("trusted\n"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := root.Open("logs/access.log")
	if err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	producer := stat.Uid
	// Synthetic authority makes the fixture owner a distinct producer without
	// requiring root or a chown. Native UID-map acceptance remains separate.
	access := TrustedLogAccess{AuthorityUID: int64(producer) + 1, ProducerUID: &producer}
	path := filepath.Join(root.Name(), "logs", "access.log")
	parent, name, err := access.OpenParent(path)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(parent)
	fd, _, err := access.OpenFile(parent, name)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatal(err)
	}
	if _, _, err := (TrustedLogAccess{AuthorityUID: int64(producer) + 1}).OpenFile(parent, name); err == nil {
		t.Fatal("missing grant accepted")
	}
	if err := root.Link("logs/access.log", "logs/second.log"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := access.OpenFile(parent, name); err == nil {
		t.Fatal("hardlink accepted")
	}
	if err := root.Remove("logs/second.log"); err != nil {
		t.Fatal(err)
	}
	if err := root.Symlink("logs", "alias"); err != nil {
		t.Fatal(err)
	}
	if fd, _, err := access.OpenParent(filepath.Join(root.Name(), "alias", "access.log")); err == nil {
		_ = unix.Close(fd)
		t.Fatal("linked parent accepted")
	}
	if err := root.Chmod("logs", 0777); err != nil {
		t.Fatal(err)
	}
	if fd, _, err := access.OpenParent(path); err == nil {
		_ = unix.Close(fd)
		t.Fatal("writable producer parent accepted")
	}
	if err := root.Chmod("logs", 0700); err != nil {
		t.Fatal(err)
	}
	if err := root.Remove("logs/access.log"); err != nil {
		t.Fatal(err)
	}
	if err := root.Symlink("outside", "logs/access.log"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := access.OpenFile(parent, name); err == nil {
		t.Fatal("linked leaf accepted")
	}
}
