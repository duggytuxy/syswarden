//go:build linux

package system

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func snapshotRetirementFixture(t *testing.T) (string, *os.Root, map[string][]byte) {
	t.Helper()
	base := t.TempDir()
	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	for _, name := range []string{"ui", "backups"} {
		if err := root.Mkdir(name, 0700); err != nil {
			t.Fatal(err)
		}
	}
	content := map[string][]byte{"data.json": []byte(`{"sequence":3}`), "metrics_24h.json": []byte(`[{"count":2}]`)}
	for name, wire := range content {
		file, err := root.OpenFile("ui/"+name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(wire); err != nil {
			t.Fatal(err)
		}
		var birth unix.Statx_t
		if err := unix.Statx(int(file.Fd()), "", unix.AT_EMPTY_PATH, unix.STATX_INO|unix.STATX_BTIME, &birth); err != nil || birth.Mask&unix.STATX_BTIME == 0 {
			t.Fatal("fixture creation identity unavailable", err)
		}
		kind := "dashboard"
		if name == "metrics_24h.json" {
			kind = "metrics"
		}
		marker := fmt.Sprintf("SYSWARDEN_SNAPSHOT_ORIGIN_V1\nkind=%s\ninode=%d\nbirth_sec=%d\nbirth_nsec=%d\nsha256=%x\n", kind, birth.Ino, birth.Btime.Sec, birth.Btime.Nsec, sha256.Sum256(wire))
		if err := unix.Fsetxattr(int(file.Fd()), productSnapshotOriginAttribute, []byte(marker), unix.XATTR_CREATE); err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return base, root, content
}

func TestUISnapshotRetirementPreservesOriginalDirectoryAndContent(t *testing.T) {
	base, root, content := snapshotRetirementFixture(t)
	before, err := root.Stat("ui")
	if err != nil {
		t.Fatal(err)
	}
	backup, err := retireAttestedDirectory(base, "ui", filepath.Join(base, "backups"), "ui-snapshots", func() error { return nil }, inspectProductSnapshotDirectory, unix.Renameat2)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(backup)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("original snapshot directory was not retained", err)
	}
	retained, err := os.OpenRoot(backup)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = retained.Close() }()
	for name, wire := range content {
		got, err := retained.ReadFile(name)
		if err != nil || !bytes.Equal(got, wire) {
			t.Fatal("private snapshot content changed", name, err)
		}
	}
	if _, err := root.Lstat("ui"); !os.IsNotExist(err) {
		t.Fatal("active snapshots remained", err)
	}
}

func TestUISnapshotRetirementRefusesUnprovenSharedOrChangedFiles(t *testing.T) {
	for _, scenario := range []string{"unmarked", "modified", "copied-marker", "extra", "hardlink", "symlink", "mode", "changed-before-move"} {
		t.Run(scenario, func(t *testing.T) {
			base, root, content := snapshotRetirementFixture(t)
			name := "ui/data.json"
			file, err := root.Open(name)
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "unmarked":
				err = unix.Fremovexattr(int(file.Fd()), productSnapshotOriginAttribute)
			case "modified":
				content["data.json"] = []byte(`{"operator":true}`)
				err = root.WriteFile(name, content["data.json"], 0600)
			case "copied-marker":
				var marker [512]byte
				var size int
				size, err = unix.Fgetxattr(int(file.Fd()), productSnapshotOriginAttribute, marker[:])
				if err == nil {
					err = root.Rename(name, "original")
				}
				if err == nil {
					err = root.WriteFile(name, content["data.json"], 0600)
				}
				if err == nil {
					var replacement *os.File
					replacement, err = root.Open(name)
					if err == nil {
						err = unix.Fsetxattr(int(replacement.Fd()), productSnapshotOriginAttribute, marker[:size], unix.XATTR_CREATE)
						_ = replacement.Close()
					}
				}
			case "extra":
				err = root.WriteFile("ui/operator.conf", []byte("keep"), 0600)
			case "hardlink":
				err = root.Link(name, "operator-link")
			case "symlink":
				err = root.Rename(name, "original")
				if err == nil {
					err = root.Symlink("../original", name)
				}
			case "mode":
				err = root.Chmod(name, 0644)
			}
			_ = file.Close()
			if err != nil {
				t.Fatal(err)
			}
			checks := 0
			guard := func() error {
				checks++
				if scenario == "changed-before-move" && checks == 2 {
					return root.WriteFile("ui/operator.conf", []byte("keep"), 0600)
				}
				return nil
			}
			if _, err := retireAttestedDirectory(base, "ui", filepath.Join(base, "backups"), "ui-snapshots", guard, inspectProductSnapshotDirectory, unix.Renameat2); err == nil {
				t.Fatal("unproven snapshot inventory was retired")
			}
			if _, err := root.Lstat("ui"); err != nil {
				t.Fatal("active directory changed on refusal", err)
			}
			got, err := root.ReadFile(name)
			if err != nil || !bytes.Equal(got, content["data.json"]) {
				t.Fatal("snapshot data changed on refusal", err)
			}
		})
	}
}
