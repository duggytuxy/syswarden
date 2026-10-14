//go:build linux

package network

import (
	"crypto/sha256"
	"fmt"
	"os"
	"syswarden-cli/pkg/system"
	"testing"
)

func TestFeedPublicationBindsEveryCreatedArtifactAcrossRefreshes(t *testing.T) {
	target := feedFileTarget{directory: t.TempDir(), name: "syswarden_threatintel.ipv4"}
	directory, err := os.OpenRoot(target.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	for _, address := range []string{"8.8.8.8/32", "1.1.1.1/32", "9.9.9.9/32"} {
		candidate := canonicalFeedFromPrefixes(mustParseFeedPrefixes(t, address))
		if err := publishCanonicalFeedWithProvenanceAt(target, ".ipv4", candidate, testIPv4FeedPolicy(1), feedPublicationPolicy{verified: true}, []string{"https://feeds.example.test/list"}, ""); err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(target.directory)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if !system.IsGeneratedFeedArtifactName(name) {
				t.Fatal("unexpected publisher artifact", name)
			}
			content, err := directory.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			file, err := directory.Open(name)
			if err != nil {
				t.Fatal(err)
			}
			owned, err := system.HasGeneratedFeedArtifactOrigin(file, name, sha256.Sum256(content))
			_ = file.Close()
			if err != nil || !owned {
				t.Fatal("published artifact lacks exact writer provenance", name, err)
			}
		}
		if len(entries) > 4 {
			t.Fatal("obsolete owned generations accumulated")
		}
	}
}

func TestFeedRefreshDoesNotAdoptExistingUnmarkedInput(t *testing.T) {
	target := feedFileTarget{directory: t.TempDir(), name: "syswarden_threatintel.ipv4"}
	directory, err := os.OpenRoot(target.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if err := directory.WriteFile(target.name, []byte("8.8.8.8/32\n"), 0600); err != nil {
		t.Fatal(err)
	}
	content := []byte("1.1.1.1/32\n")
	if err := writeFeedFileAt(target, ".ipv4", content); err != nil {
		t.Fatal(err)
	}
	file, err := directory.Open(target.name)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	owned, err := system.HasGeneratedFeedArtifactOrigin(file, target.name, sha256.Sum256(content))
	if err != nil || owned {
		t.Fatal("refresh adopted existing unmarked input", err)
	}
}

func TestFeedRefreshRejectsModifiedOriginAndPreservesUnmarkedSnapshot(t *testing.T) {
	target := feedFileTarget{directory: t.TempDir(), name: "syswarden_threatintel.ipv4"}
	directory, err := os.OpenRoot(target.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if err := writeFeedFileAt(target, ".ipv4", []byte("8.8.8.8/32\n")); err != nil {
		t.Fatal(err)
	}
	manual := []byte("1.1.1.1/32\n")
	if err := directory.WriteFile(target.name, manual, 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeFeedFileAt(target, ".ipv4", []byte("9.9.9.9/32\n")); err == nil {
		t.Fatal("changed creation origin was overwritten")
	}
	got, err := directory.ReadFile(target.name)
	if err != nil || string(got) != string(manual) {
		t.Fatal("manual feed edit changed", err)
	}
	snapshot, err := feedSnapshotTarget(target, fmt.Sprintf("%x", sha256.Sum256(manual)))
	if err != nil {
		t.Fatal(err)
	}
	if err := directory.WriteFile(snapshot.name, manual, 0600); err != nil {
		t.Fatal(err)
	}
	if err := cleanupFeedSnapshotsInDirectory(directory, target); err != nil {
		t.Fatal(err)
	}
	if _, err := directory.Stat(snapshot.name); err != nil {
		t.Fatal("snapshot name alone authorized deletion", err)
	}
}
