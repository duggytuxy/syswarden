//go:build linux

package fileorigin

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func snapshotFixtureRoot(t *testing.T) (string, *os.Root) {
	t.Helper()
	path := t.TempDir()
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return path, root
}

func TestSnapshotPublicationPreservesOriginWithoutAdoptingLegacyOrChangedFiles(t *testing.T) {
	for _, scenario := range []string{"new", "legacy", "manual-edit"} {
		t.Run(scenario, func(t *testing.T) {
			directory, root := snapshotFixtureRoot(t)
			path := filepath.Join(directory, "data.json")
			if scenario == "manual-edit" {
				if err := PublishSnapshot(path, DashboardSnapshot, []byte(`{"initial":true}`)); err != nil {
					t.Fatal(err)
				}
			}
			if scenario != "new" {
				if err := root.WriteFile("data.json", []byte(`{"legacy":true}`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			for _, content := range []string{`{"sequence":1}`, `{"sequence":2}`} {
				if err := PublishSnapshot(path, DashboardSnapshot, []byte(content)); err != nil {
					t.Fatal(err)
				}
				got, err := ReadSnapshotFile(path, DashboardSnapshot)
				if err != nil || string(got) != content {
					t.Fatal("snapshot publication bytes differ", err)
				}
				file, err := root.Open("data.json")
				if err != nil {
					t.Fatal(err)
				}
				owned, originErr := HasSnapshotOrigin(file, DashboardSnapshot, sha256.Sum256(got))
				_ = file.Close()
				if originErr != nil || owned != (scenario == "new") {
					t.Fatal("publication adopted an unproven prior file", owned, originErr)
				}
			}
			entries, err := os.ReadDir(directory)
			if err != nil || len(entries) != 1 || entries[0].Name() != "data.json" {
				t.Fatal("completed publication left staging artifacts", entries, err)
			}
		})
	}
}

func TestSnapshotPublicationRefusesConcurrentInputAndStagingReplacement(t *testing.T) {
	for _, scenario := range []string{"content", "destination", "staging"} {
		t.Run(scenario, func(t *testing.T) {
			directory, root := snapshotFixtureRoot(t)
			path := filepath.Join(directory, "data.json")
			initial := []byte(`{"initial":true}`)
			if err := PublishSnapshot(path, DashboardSnapshot, initial); err != nil {
				t.Fatal(err)
			}
			keep := []byte(`{"administrator":true}`)
			stagingName := ""
			hook := func() {
				name := "data.json"
				if scenario == "staging" {
					entries, err := os.ReadDir(directory)
					if err != nil {
						t.Fatal(err)
					}
					for _, entry := range entries {
						if strings.HasPrefix(entry.Name(), ".syswarden-snapshot-") {
							name, stagingName = entry.Name(), entry.Name()
						}
					}
					if stagingName == "" {
						t.Fatal("staging hook found no exclusive output")
					}
				}
				if scenario != "content" {
					if err := root.Rename(name, "retained-original"); err != nil {
						t.Fatal(err)
					}
				}
				if err := root.WriteFile(name, keep, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := publishSnapshot(path, DashboardSnapshot, []byte(`{"new":true}`), hook); err == nil {
				t.Fatal("concurrent replacement was accepted")
			}
			name, expected := "data.json", keep
			if scenario == "staging" {
				name, expected = stagingName, keep
				got, err := root.ReadFile("data.json")
				if err != nil || !bytes.Equal(got, initial) {
					t.Fatal("staging replacement changed the previous publication", err)
				}
			}
			got, err := root.ReadFile(name)
			if err != nil || !bytes.Equal(got, expected) {
				t.Fatal("refusal discarded concurrent content", err)
			}
		})
	}
}

func TestSnapshotPublicationRejectsLinksAndOversizedContent(t *testing.T) {
	directory, root := snapshotFixtureRoot(t)
	path := filepath.Join(directory, "data.json")
	if err := root.WriteFile("administrator", []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := root.Symlink("administrator", "data.json"); err != nil {
		t.Fatal(err)
	}
	if err := PublishSnapshot(path, DashboardSnapshot, []byte(`{}`)); err == nil {
		t.Fatal("symlink output was overwritten")
	}
	if err := root.Remove("data.json"); err != nil {
		t.Fatal(err)
	}
	if err := PublishSnapshot(path, DashboardSnapshot, make([]byte, maximumSnapshotBytes+1)); err == nil {
		t.Fatal("oversized snapshot accepted")
	}
	got, err := root.ReadFile("administrator")
	if err != nil || string(got) != "keep" {
		t.Fatal("external file changed", err)
	}
	if _, err := root.Lstat("data.json"); !os.IsNotExist(err) {
		t.Fatal("refused publication created a target", err)
	}
}

func TestSnapshotPublicationRejectsUnsafeDirectoriesAndPaths(t *testing.T) {
	t.Run("group-writable-directory", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "shared")
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0770); err != nil {
			t.Fatal(err)
		}

		err := PublishSnapshot(filepath.Join(directory, "data.json"), DashboardSnapshot, []byte(`{}`))
		if err == nil {
			t.Fatal("group-writable snapshot directory was accepted")
		}
	})

	t.Run("world-writable-directory", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "shared")
		if err := os.Mkdir(directory, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0757); err != nil {
			t.Fatal(err)
		}

		err := PublishSnapshot(filepath.Join(directory, "data.json"), DashboardSnapshot, []byte(`{}`))
		if err == nil {
			t.Fatal("world-writable snapshot directory was accepted")
		}
	})

	t.Run("symlinked-parent-directory", func(t *testing.T) {
		base := t.TempDir()
		realDirectory := filepath.Join(base, "real")
		linkDirectory := filepath.Join(base, "linked")

		if err := os.Mkdir(realDirectory, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(realDirectory, linkDirectory); err != nil {
			t.Fatal(err)
		}

		err := PublishSnapshot(filepath.Join(linkDirectory, "data.json"), DashboardSnapshot, []byte(`{}`))
		if err == nil {
			t.Fatal("symlinked parent directory was accepted")
		}

		if _, err := os.Lstat(filepath.Join(realDirectory, "data.json")); !os.IsNotExist(err) {
			t.Fatal("publication created a file through the symlink", err)
		}
	})

	t.Run("relative-path", func(t *testing.T) {
		t.Chdir(t.TempDir())
		err := PublishSnapshot("data.json", DashboardSnapshot, []byte(`{}`))
		if err == nil || err.Error() != "snapshot destination is not a canonical product output" {
			t.Fatalf("unexpected relative destination result: %v", err)
		}
		if _, err := os.Lstat("data.json"); !os.IsNotExist(err) {
			t.Fatalf("relative snapshot destination was touched: %v", err)
		}
	})
}
