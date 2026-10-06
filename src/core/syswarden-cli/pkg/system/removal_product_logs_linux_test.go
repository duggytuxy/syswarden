//go:build linux

package system

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func markProductLogFixture(t *testing.T, root *os.Root, path, kind string) {
	t.Helper()
	file, err := root.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	var birth unix.Statx_t
	if err := unix.Statx(int(file.Fd()), "", unix.AT_EMPTY_PATH, unix.STATX_INO|unix.STATX_BTIME, &birth); err != nil {
		t.Fatal(err)
	}
	if birth.Mask&unix.STATX_BTIME == 0 {
		t.Fatal("fixture filesystem lacks creation timestamps")
	}
	record := fmt.Sprintf("SYSWARDEN_LOG_ORIGIN_V1\nkind=%s\ninode=%d\nbirth_sec=%d\nbirth_nsec=%d\n", kind, birth.Ino, birth.Btime.Sec, birth.Btime.Nsec)
	if err := unix.Fsetxattr(int(file.Fd()), productLogOriginAttribute, []byte(record), unix.XATTR_CREATE); err != nil {
		t.Fatal(err)
	}
}

func TestProductLogRetirementKeepsOwnedBytesAndRefusesUnknownData(t *testing.T) {
	for _, kind := range []string{"owned", "unmarked", "additional-file", "changed-before-move", "wrong-kind", "copied-marker", "hardlink", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			root, err := os.OpenRoot(base)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			for _, name := range []string{"logs", "backups"} {
				if err := root.Mkdir(name, 0700); err != nil {
					t.Fatal(err)
				}
			}
			for _, name := range []string{"core.log", "waf.json", "waf.json.1"} {
				path := "logs/" + name
				if err := root.WriteFile(path, []byte("Private product log bytes.\n"), 0600); err != nil {
					t.Fatal(err)
				}
				if kind == "unmarked" && name == "core.log" {
					continue
				}
				role := "telemetry"
				if name == "core.log" {
					role = "core"
				}
				if kind == "wrong-kind" && name == "core.log" {
					role = "telemetry"
				}
				markProductLogFixture(t, root, path, role)
			}
			switch kind {
			case "additional-file":
				if err := root.WriteFile("logs/administrator.conf", []byte("private operator data"), 0600); err != nil {
					t.Fatal(err)
				}
			case "copied-marker":
				file, err := root.Open("logs/core.log")
				if err != nil {
					t.Fatal(err)
				}
				var b [256]byte
				n, err := unix.Fgetxattr(int(file.Fd()), productLogOriginAttribute, b[:])
				_ = file.Close()
				if err != nil {
					t.Fatal(err)
				}
				if err := root.Rename("logs/core.log", "original"); err != nil {
					t.Fatal(err)
				}
				if err := root.WriteFile("logs/core.log", []byte("Administrator replacement.\n"), 0600); err != nil {
					t.Fatal(err)
				}
				file, err = root.Open("logs/core.log")
				if err != nil {
					t.Fatal(err)
				}
				err = unix.Fsetxattr(int(file.Fd()), productLogOriginAttribute, b[:n], unix.XATTR_CREATE)
				_ = file.Close()
				if err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := root.Link("logs/core.log", "operator-link"); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := root.Rename("logs/core.log", "original"); err != nil {
					t.Fatal(err)
				}
				if err := root.Symlink("../original", "logs/core.log"); err != nil {
					t.Fatal(err)
				}
			}
			checks := 0
			guard := func() error {
				checks++
				if kind == "changed-before-move" && checks == 2 {
					return root.WriteFile("logs/administrator.conf", []byte("Concurrent operator data"), 0600)
				}
				return nil
			}
			backup, err := retireAttestedDirectory(base, "logs", filepath.Join(base, "backups"), "product-logs", guard, inspectProductLogDirectory, unix.Renameat2)
			if kind != "owned" {
				if err == nil {
					t.Fatal("unproven or shared log inventory was retired")
				}
				if _, err := root.Lstat("logs"); err != nil {
					t.Fatal("unproven log directory was moved", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := root.Lstat("logs"); !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("owned logs remain active", err)
			}
			relative, err := filepath.Rel(base, backup)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"core.log", "waf.json", "waf.json.1"} {
				saved, err := root.ReadFile(filepath.Join(relative, name))
				if err != nil || string(saved) != "Private product log bytes.\n" {
					t.Fatal("private original log was lost", name, err)
				}
			}
		})
	}
}
