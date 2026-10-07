//go:build linux

package fileorigin

import (
	"golang.org/x/sys/unix"
	"os"
	"testing"
)

func TestLogOriginNeverAdoptsExistingOrCopiedFiles(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	create := func(name string) *os.File {
		t.Helper()
		f, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		return f
	}
	original := create("original")
	if present, err := HasLogOrigin(original, CoreLog); err != nil || present {
		t.Fatal("unmarked file was adopted", present, err)
	}
	if err := MarkCreatedLog(original, CoreLog); err != nil {
		t.Fatal(err)
	}
	if present, err := HasLogOrigin(original, CoreLog); err != nil || !present {
		t.Fatal("created origin was not recognized", present, err)
	}
	if err := root.Rename("original", "retained"); err != nil {
		t.Fatal(err)
	}
	if present, err := HasLogOrigin(original, CoreLog); err != nil || !present {
		t.Fatal("rename lost the inode origin", present, err)
	}
	if present, err := HasLogOrigin(original, TelemetryLog); err == nil || present {
		t.Fatal("wrong log kind was accepted")
	}
	var data [256]byte
	n, err := unix.Fgetxattr(int(original.Fd()), LogAttribute, data[:])
	if err != nil {
		t.Fatal(err)
	}
	copied := create("copied")
	if err := unix.Fsetxattr(int(copied.Fd()), LogAttribute, data[:n], unix.XATTR_CREATE); err != nil {
		t.Fatal(err)
	}
	if present, err := HasLogOrigin(copied, CoreLog); err == nil || present {
		t.Fatal("copied marker was accepted on another inode")
	}
	if err := root.Link("retained", "second-link"); err != nil {
		t.Fatal(err)
	}
	if present, err := HasLogOrigin(original, CoreLog); err == nil || present {
		t.Fatal("shared inode acquired exclusive removal authority")
	}
}
