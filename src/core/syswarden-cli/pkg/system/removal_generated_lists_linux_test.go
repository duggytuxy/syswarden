//go:build linux

package system

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func generatedListRetirementFixture(t *testing.T) (string, string, map[string][]byte) {
	t.Helper()
	base := t.TempDir()
	parent, backups := filepath.Join(base, "configuration"), filepath.Join(base, "backups")
	for _, path := range []string{parent, backups, filepath.Join(parent, "lists")} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(filepath.Join(parent, "lists"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	content := map[string][]byte{
		".syswarden_blacklist_pair_v1": []byte("SYSWARDEN_PERSISTENT_BLOCKLIST_PAIR_V1\n"),
		".syswarden_whitelist_pair_v1": []byte("SYSWARDEN_PERSISTENT_WHITELIST_PAIR_V1\n"),
		"syswarden_blacklist.ipv4":     {}, "syswarden_blacklist.ipv6": {},
		"syswarden_whitelist.ipv4": []byte("192.0.2.1\n"), "syswarden_whitelist.ipv6": {},
	}
	for name, wire := range content {
		file, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(wire); err != nil {
			t.Fatal(err)
		}
		if isGeneratedListName(name) {
			if err := MarkCreatedGeneratedList(file, name, wire); err != nil {
				t.Fatal(err)
			}
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return parent, backups, content
}

func TestGeneratedListRetirementKeepsOriginalInodesAndBytes(t *testing.T) {
	parent, backups, content := generatedListRetirementFixture(t)
	before, err := os.Stat(filepath.Join(parent, "lists"))
	if err != nil {
		t.Fatal(err)
	}
	backup, err := retireAttestedDirectory(parent, "lists", backups, "generated-lists", func() error { return nil }, inspectGeneratedListDirectory, unix.Renameat2)
	if err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(backup)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("original directory was not retained", err)
	}
	root, err := os.OpenRoot(backup)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	for name, expected := range content {
		got, err := root.ReadFile(name)
		if err != nil || !bytes.Equal(got, expected) {
			t.Fatal("retained list bytes changed", name, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(parent, "lists")); !os.IsNotExist(err) {
		t.Fatal("active lists remained", err)
	}
}

func TestGeneratedListRetirementRefusesUnprovenOrChangedFiles(t *testing.T) {
	for _, kind := range []string{"unmarked", "modified", "copied", "marker", "extra", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			parent, backups, content := generatedListRetirementFixture(t)
			root, err := os.OpenRoot(filepath.Join(parent, "lists"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			name := "syswarden_whitelist.ipv4"
			file, err := root.Open(name)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "unmarked":
				err = unix.Fremovexattr(int(file.Fd()), generatedListOriginAttribute)
			case "modified":
				content[name] = []byte("192.0.2.99\n")
				err = root.WriteFile(name, content[name], 0600)
			case "copied":
				var marker [512]byte
				var size int
				size, err = unix.Fgetxattr(int(file.Fd()), generatedListOriginAttribute, marker[:])
				if err == nil {
					err = root.Remove(name)
				}
				if err == nil {
					err = root.WriteFile(name, content[name], 0600)
				}
				if err == nil {
					var replacement *os.File
					replacement, err = root.Open(name)
					if err == nil {
						err = unix.Fsetxattr(int(replacement.Fd()), generatedListOriginAttribute, marker[:size], unix.XATTR_CREATE)
						_ = replacement.Close()
					}
				}
			case "marker":
				err = root.WriteFile(".syswarden_whitelist_pair_v1", []byte("modified\n"), 0600)
			case "extra":
				err = root.WriteFile("administrator.txt", []byte("keep\n"), 0600)
			case "hardlink":
				err = os.Link(filepath.Join(parent, "lists", name), filepath.Join(parent, "shared"))
			}
			_ = file.Close()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := retireAttestedDirectory(parent, "lists", backups, "generated-lists", func() error { return nil }, inspectGeneratedListDirectory, unix.Renameat2); err == nil {
				t.Fatal("unproven list inventory was retired")
			}
			got, err := root.ReadFile(name)
			if err != nil || !bytes.Equal(got, content[name]) {
				t.Fatal("list input changed on refusal", err)
			}
			if _, err := os.Lstat(filepath.Join(parent, "lists")); err != nil {
				t.Fatal("active directory changed on refusal", err)
			}
		})
	}
}
