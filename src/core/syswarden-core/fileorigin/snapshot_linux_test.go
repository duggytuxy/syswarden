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
