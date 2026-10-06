//go:build linux

package system

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestProductDirectoryFinalizationPreservesEveryUnretiredEntry(t *testing.T) {
	for _, kind := range []string{"regular", "hidden", "nested", "symlink", "hardlink", "empty"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			directory := filepath.Join(base, "product")
			if err := os.Mkdir(directory, 0700); err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(base, "administrator")
			content := []byte("private administrator sentinel\n")
			if err := os.WriteFile(outside, content, 0600); err != nil {
				t.Fatal(err)
			}
			entry := filepath.Join(directory, "keep.conf")
			switch kind {
			case "regular":
				if err := os.WriteFile(entry, content, 0600); err != nil {
					t.Fatal(err)
				}
			case "hidden":
				entry = filepath.Join(directory, ".keep")
				if err := os.WriteFile(entry, content, 0600); err != nil {
					t.Fatal(err)
				}
			case "nested":
				if err := os.Mkdir(filepath.Join(directory, "custom"), 0700); err != nil {
					t.Fatal(err)
				}
				entry = filepath.Join(directory, "custom", "keep.conf")
				if err := os.WriteFile(entry, content, 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(outside, entry); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(outside, entry); err != nil {
					t.Fatal(err)
				}
			}
			root, err := os.OpenRoot(base)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			err = removeEmptyProductDirectory(root, "product", directory)
			if kind == "empty" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("empty root remained", err)
				}
			} else {
				if err == nil {
					t.Fatal("nonempty directory accepted as a finalization target")
				}
				relative, err := filepath.Rel(base, entry)
				if err != nil {
					t.Fatal(err)
				}
				if kind == "symlink" {
					target, err := root.Readlink(relative)
					if err != nil || target != outside {
						t.Fatal("retained symlink changed", err)
					}
					relative = "administrator"
				}
				got, err := root.ReadFile(relative)
				if err != nil || !bytes.Equal(got, content) {
					t.Fatal("unretired entry changed", err)
				}
			}
			got, err := root.ReadFile("administrator")
			if err != nil || !bytes.Equal(got, content) {
				t.Fatal("external administrator file changed", err)
			}
		})
	}
}

func TestProductDirectoryFinalizationRefusesReplacedFileOrSymlink(t *testing.T) {
	for _, link := range []bool{false, true} {
		t.Run(map[bool]string{false: "file", true: "symlink"}[link], func(t *testing.T) {
			base := t.TempDir()
			target := filepath.Join(base, "product")
			other := filepath.Join(base, "administrator")
			if err := os.WriteFile(other, []byte("retained"), 0600); err != nil {
				t.Fatal(err)
			}
			if link {
				if err := os.Symlink(other, target); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(target, []byte("retained"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			root, err := os.OpenRoot(base)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = root.Close() }()
			if err := removeEmptyProductDirectory(root, "product", target); err == nil {
				t.Fatal("non-directory finalization succeeded")
			}
			for _, path := range []string{target, other} {
				name := filepath.Base(path)
				if link && path == target {
					value, err := root.Readlink(name)
					if err != nil || value != other {
						t.Fatal("replacement symlink changed", err)
					}
					name = "administrator"
				}
				content, err := root.ReadFile(name)
				if err != nil || string(content) != "retained" {
					t.Fatal("replacement changed", err)
				}
			}
		})
	}
}

func TestRemovalStateFinalizationPreservesUnprovenContentsAndBarrier(t *testing.T) {
	root := t.TempDir()
	reader, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	marker := filepath.Join(root, removalTombstoneName)
	if err := os.WriteFile(marker, []byte(RemovalTombstoneRecord), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "administrator.conf")
	if err := os.WriteFile(path, []byte("retain exact bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	err = removeRemovalStateContentsAtUsingMountInfo(root, systemTestUID(t), systemTestGID(t), refuseUnprovenRemovalEntry, func() ([]byte, error) { return []byte{}, nil })
	if err == nil {
		t.Fatal("unproven state was accepted for finalization")
	}
	for path, wanted := range map[string]string{marker: RemovalTombstoneRecord, path: "retain exact bytes"} {
		content, err := reader.ReadFile(filepath.Base(path))
		if err != nil || string(content) != wanted {
			t.Fatal("state or barrier changed", err)
		}
	}
}

func TestRHELRuntimeFinalizationCannotAdoptDirectoryContents(t *testing.T) {
	root := t.TempDir()
	reader, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	file := filepath.Join(root, "custom.conf")
	if err := os.WriteFile(file, []byte("administrator settings"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := cleanRHELPackageOwnedDirectory(root, nil, systemTestUID(t), systemTestGID(t)); err == nil {
		t.Fatal("runtime content adopted from its directory")
	}
	content, err := reader.ReadFile("custom.conf")
	if err != nil || string(content) != "administrator settings" {
		t.Fatal("administrator content changed", err)
	}
}
