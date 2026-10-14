//go:build linux

package system

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func feedOriginTestRoot(t *testing.T, path string) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root
}

func addGeneratedFeedFixture(t *testing.T, directory string, marked bool) map[string][]byte {
	t.Helper()
	root := feedOriginTestRoot(t, directory)
	content := []byte("192.0.2.10/32\n")
	files := map[string][]byte{
		"syswarden_threatintel.ipv4":                 content,
		"syswarden_threatintel.ipv4.provenance.json": []byte("private synthetic provenance\n"),
		fmt.Sprintf(".syswarden_threatintel.ipv4.syswarden-snapshot-%x", sha256.Sum256(content)): content,
	}
	for name, content := range files {
		file, err := root.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write(content); err != nil {
			t.Fatal(err)
		}
		if marked {
			if err := MarkCreatedFeedArtifact(file, name, content); err != nil {
				t.Fatal(err)
			}
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return files
}

func TestGeneratedListsRetirePublishedFeedArtifacts(t *testing.T) {
	parent, backups, original := generatedListRetirementFixture(t)
	for name, content := range addGeneratedFeedFixture(t, filepath.Join(parent, "lists"), true) {
		original[name] = content
	}
	backup, err := retireAttestedDirectory(parent, "lists", backups, "generated-lists", func() error { return nil }, inspectGeneratedListDirectory, unix.Renameat2)
	if err != nil {
		t.Fatal(err)
	}
	retained := feedOriginTestRoot(t, backup)
	for name, content := range original {
		got, err := retained.ReadFile(name)
		if err != nil || !bytes.Equal(content, got) {
			t.Fatal("private recovery copy changed", name, err)
		}
	}
}

func TestGeneratedFeedOriginRejectsModifiedOrCopiedArtifacts(t *testing.T) {
	for _, change := range []string{"unmarked", "bytes", "copied", "renamed", "hardlink", "symlink"} {
		t.Run(change, func(t *testing.T) {
			parent, backups, _ := generatedListRetirementFixture(t)
			directory := filepath.Join(parent, "lists")
			addGeneratedFeedFixture(t, directory, change != "unmarked")
			root := feedOriginTestRoot(t, parent)
			name := "lists/syswarden_threatintel.ipv4"
			path := filepath.Join(parent, name)
			var err error
			switch change {
			case "bytes":
				err = root.WriteFile(name, []byte("192.0.2.99/32\n"), 0600)
			case "copied":
				var marker [512]byte
				size, e := unix.Getxattr(path, generatedFeedOriginAttribute, marker[:])
				if e != nil {
					t.Fatal(e)
				}
				content, e := root.ReadFile(name)
				if e != nil {
					t.Fatal(e)
				}
				if err = root.Rename(name, name+".old"); err == nil {
					err = root.WriteFile(name, content, 0600)
				}
				if err == nil {
					err = unix.Setxattr(path, generatedFeedOriginAttribute, marker[:size], 0)
				}
				if err == nil {
					err = root.Remove(name + ".old")
				}
			case "renamed":
				err = root.Rename(name, "lists/syswarden_threatintel.ipv6")
			case "hardlink":
				err = root.Link(name, "shared")
			case "symlink":
				if err = root.Rename(name, "external"); err == nil {
					err = root.Symlink("../external", name)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := retireAttestedDirectory(parent, "lists", backups, "generated-lists", func() error { return nil }, inspectGeneratedListDirectory, unix.Renameat2); err == nil {
				t.Fatal("unproven feed was automatically retired")
			}
			if _, err := os.Stat(directory); err != nil {
				t.Fatal("refusal moved the active directory", err)
			}
		})
	}
}

func TestLegacyFeedRetentionRequiresExactOperatorReview(t *testing.T) {
	parent, backups, profile := legacyDataFixture(t, "lists")
	files := addGeneratedFeedFixture(t, filepath.Join(parent, "lists"), false)
	directory, err := openExistingPinnedServiceDirectory(filepath.Join(parent, "lists"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, plan, err := inspectLegacyDataDirectory(directory, false, profile)
	directory.close()
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range plan.Files {
		if IsGeneratedFeedArtifactName(filepath.Base(file.Path)) && file.CreationProvenance {
			t.Fatal("old feed was assigned ownership")
		}
	}
	if _, _, err := applyLegacyRetention(parent, backups, strings.Repeat("0", 64), func() error { return nil }, unix.Renameat2, profile); err == nil {
		t.Fatal("unreviewed feed retention accepted")
	}
	_, backup, err := applyLegacyRetention(parent, backups, snapshot.digest, func() error { return nil }, unix.Renameat2, profile)
	if err != nil {
		t.Fatal(err)
	}
	retained := feedOriginTestRoot(t, backup)
	for name, content := range files {
		got, err := retained.ReadFile(name)
		if err != nil || !bytes.Equal(content, got) {
			t.Fatal("legacy feed original was lost", err)
		}
	}
	if _, again, err := applyLegacyRetention(parent, backups, snapshot.digest, func() error { return nil }, unix.Renameat2, profile); err != nil || again != backup {
		t.Fatal("completed feed retention did not resume", err)
	}
}

func TestGeneratedFeedNamesAreBoundedWithoutConferringOwnership(t *testing.T) {
	for _, name := range []string{"administrator.ipv4", "syswarden_threatintel.ipv4.old", "../syswarden_threatintel.ipv4", ".syswarden_threatintel.ipv4.syswarden-snapshot-" + strings.Repeat("A", 64), ".syswarden_threatintel.ipv6.syswarden-snapshot-abc"} {
		if IsGeneratedFeedArtifactName(name) {
			t.Fatal("unbounded feed name accepted", name)
		}
	}
}

func TestFeedRetentionUsesPublicationSizeAndInventoryBounds(t *testing.T) {
	parent, _, profile := legacyDataFixture(t, "lists")
	directoryPath := filepath.Join(parent, "lists")
	root := feedOriginTestRoot(t, directoryPath)
	file, err := root.OpenFile("syswarden_threatintel.ipv6", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := file.Truncate(MaximumGeneratedFeedBytes); err != nil {
		t.Fatal(err)
	}
	directory, err := openExistingPinnedServiceDirectory(directoryPath)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.close()
	if _, _, err := inspectLegacyDataDirectory(directory, false, profile); err != nil {
		t.Fatal("publisher-sized legacy feed cannot be retained intact", err)
	}
	if err := file.Truncate(MaximumGeneratedFeedBytes + 1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := inspectLegacyDataDirectory(directory, false, profile); err == nil {
		t.Fatal("oversized feed retention accepted")
	}
	if err := file.Truncate(0); err != nil {
		t.Fatal(err)
	}
	for index := 0; index <= MaximumGeneratedFeedSnapshots; index++ {
		name := fmt.Sprintf(".syswarden_threatintel.ipv4.syswarden-snapshot-%064x", index)
		if err := root.WriteFile(name, nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := inspectLegacyDataDirectory(directory, false, profile); err == nil || !strings.Contains(err.Error(), "snapshot inventory") {
		t.Fatal("per-family generation limit was not enforced", err)
	}
}

func TestLegacyFeedRetentionCannotOverrideModifiedCreationOrigin(t *testing.T) {
	parent, _, profile := legacyDataFixture(t, "lists")
	directoryPath := filepath.Join(parent, "lists")
	addGeneratedFeedFixture(t, directoryPath, true)
	root := feedOriginTestRoot(t, directoryPath)
	name := "syswarden_threatintel.ipv4"
	if err := root.WriteFile(name, []byte("192.0.2.42/32\n"), 0600); err != nil {
		t.Fatal(err)
	}
	directory, err := openExistingPinnedServiceDirectory(directoryPath)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.close()
	if _, _, err := inspectLegacyDataDirectory(directory, false, profile); err == nil || !strings.Contains(err.Error(), "modified creation marker") {
		t.Fatal("explicit retention bypassed invalid creation evidence", err)
	}
}
