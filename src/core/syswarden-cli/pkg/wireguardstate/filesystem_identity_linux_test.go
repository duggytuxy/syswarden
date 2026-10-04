//go:build linux

package wireguardstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFilesystemBindingRejectsSubstitutionAndLegacyRebinding(t *testing.T) {
	actual := Artifact{Path: ServerConfigurationPath, SHA256: strings.Repeat("1", 64),
		Mode: 0600, UID: 0, GID: 0, NLink: 1, Device: 2064, Inode: 42,
		FilesystemUUID: "1234567890abcdef1234567890abcdef"}
	for _, test := range []struct {
		name   string
		change func(*Artifact)
		accept bool
	}{
		{"same-filesystem-renumbered", func(a *Artifact) { a.Device = 2048 }, true},
		{"different-filesystem", func(a *Artifact) { a.FilesystemUUID = strings.Repeat("b", 32) }, false},
		{"zero-filesystem-uuid", func(a *Artifact) { a.FilesystemUUID = strings.Repeat("0", 32) }, false},
		{"malformed-filesystem-uuid", func(a *Artifact) { a.FilesystemUUID = "unknown" }, false},
		{"replacement-inode", func(a *Artifact) { a.Inode++ }, false},
		{"changed-content", func(a *Artifact) { a.SHA256 = strings.Repeat("2", 64) }, false},
		{"changed-path", func(a *Artifact) { a.Path = ClientConfigurationPath }, false},
		{"changed-permissions", func(a *Artifact) { a.Mode = 0644 }, false},
		{"changed-owner", func(a *Artifact) { a.UID = 1000 }, false},
		{"additional-hard-link", func(a *Artifact) { a.NLink = 2 }, false},
		{"legacy-same-device", func(a *Artifact) { a.FilesystemUUID = "" }, true},
		{"legacy-renumbered-device", func(a *Artifact) { a.FilesystemUUID = ""; a.Device = 2048 }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			expected := actual
			test.change(&expected)
			if got := sameArtifact(actual, expected); got != test.accept {
				t.Fatalf("record verification = %v, want %v", got, test.accept)
			}
		})
	}
	expected := actual
	actual.FilesystemUUID = ""
	if sameArtifact(actual, expected) {
		t.Fatal("lost kernel UUID support silently downgraded an existing binding")
	}
}

func TestManifestReadAndRemovalSurviveDeviceRenumbering(t *testing.T) {
	root, uid, gid := prepareStateRoot(t)
	manifest := publishTestStateWithOwnedOpenRCLink(t, root, uid, gid)
	if manifest.Artifacts[0].FilesystemUUID == "" {
		t.Skip("kernel filesystem UUID unavailable; strict legacy matching remains covered")
	}
	for index := range manifest.Artifacts {
		if manifest.Artifacts[index].FilesystemUUID == "" {
			t.Fatal("generated files have inconsistent persistent filesystem evidence")
		}
		manifest.Artifacts[index].Device ^= 16
	}
	if manifest.OpenRCServiceLink.FilesystemUUID == "" {
		t.Fatal("owned service link lacks its pinned parent filesystem identity")
	}
	manifest.OpenRCServiceLink.Device ^= 16
	wire, err := canonicalManifestBytes(manifest, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, strings.TrimPrefix(ManifestPath, "/"))
	if err := os.WriteFile(path, wire, 0600); err != nil {
		t.Fatal(err)
	}
	before, err := legacyTestFiles(t, root).ReadFile(strings.TrimPrefix(ClientConfigurationPath, "/"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAndVerify(root, uid, gid); err != nil {
		t.Fatalf("stable filesystem rejected after device renumbering: %v", err)
	}
	after, err := ReadVerifiedArtifact(root, manifest, ClientConfigurationPath, uid, gid)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("client bytes changed during persistent verification: %v", err)
	}
	if err := RemoveOwnedArtifacts(root, uid, gid); err != nil {
		t.Fatalf("exact cleanup failed after device renumbering: %v", err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("completed removal retained its manifest: %v", err)
	}
}

func TestFilesystemUUIDReadRejectsInvalidDescriptor(t *testing.T) {
	if _, err := readFilesystemUUID(-1); err == nil {
		t.Fatal("invalid descriptor was treated as unsupported filesystem evidence")
	}
}

func TestLegacyMigrationResumesAfterFilesystemDeviceRenumbering(t *testing.T) {
	for _, point := range []string{"journal", "backup:0", "backup:1", "backup:2", "stage", "exchange", "original-archive", "manifest", "receipt"} {
		t.Run(point, func(t *testing.T) {
			root, uid, gid := migrationFixture(t)
			initial, err := InspectLegacyMigration(root, uid, gid)
			if err != nil {
				t.Fatal(err)
			}
			if initial.Live[0].FilesystemUUID == "" {
				t.Skip("filesystem UUID unavailable")
			}
			previous := legacyMigrationFault
			t.Cleanup(func() { legacyMigrationFault = previous })
			sentinel := errors.New("interrupted before reboot")
			legacyMigrationFault = func(got string) error {
				if got == point {
					return sentinel
				}
				return nil
			}
			err = BeginLegacyMigration(root, initial, exactTestServerConfiguration(), uid, gid)
			if err == nil {
				current, inspectErr := InspectLegacyMigration(root, uid, gid)
				if inspectErr != nil {
					t.Fatal(inspectErr)
				}
				err = ContinueLegacyMigration(root, current, exactTestServerConfiguration(), uid, gid)
			}
			if !errors.Is(err, sentinel) {
				t.Fatalf("boundary %s not reached: %v", point, err)
			}
			legacyMigrationFault = previous
			journalPath := LegacyMigrationPath
			if point == "receipt" {
				journalPath = LegacyMigrationReceiptPath
			}
			path := filepath.Join(root, journalPath)
			wire, err := legacyTestFiles(t, root).ReadFile(strings.TrimPrefix(journalPath, "/"))
			if err != nil {
				t.Fatal(err)
			}
			journal, err := decodeLegacyMigration(wire, uid, gid)
			if err != nil {
				t.Fatal(err)
			}
			for i := range journal.Original {
				journal.Original[i].Device ^= 16
			}
			wire, err = json.Marshal(journal)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, wire, 0600); err != nil {
				t.Fatal(err)
			}
			current, err := InspectLegacyMigration(root, uid, gid)
			if err != nil {
				t.Fatal("inspection after renumbering", err)
			}
			if err := ContinueLegacyMigration(root, current, exactTestServerConfiguration(), uid, gid); err != nil {
				t.Fatal("continuation after renumbering", err)
			}
			final, err := InspectLegacyMigration(root, uid, gid)
			if err != nil || !final.Completed() {
				t.Fatal("incomplete migration", err)
			}
			if _, err := ReadAndVerify(root, uid, gid); err != nil {
				t.Fatal(err)
			}
			for logical, original := range testOwnedContents() {
				backup, err := legacyTestFiles(t, root).ReadFile(strings.TrimPrefix(LegacyMigrationBackupPath(logical), "/"))
				if err != nil || !bytes.Equal(backup, original) {
					t.Fatal("original backup changed", err)
				}
			}
		})
	}
}

func TestFilesystemUUIDUnsupportedDescriptorKeepsStrictDeviceBinding(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = read.Close(); _ = write.Close() }()
	uuid, err := CaptureFilesystemUUID(read)
	if err != nil || uuid != "" {
		t.Fatalf("unsupported descriptor: uuid=%q err=%v", uuid, err)
	}
	if sameFilesystemIdentity(2064, uuid, 2048, "") {
		t.Fatal("unsupported filesystem accepted changed device")
	}
	if sameFilesystemIdentity(2048, uuid, 2048, "1234567890abcdef1234567890abcdef") {
		t.Fatal("unsupported filesystem downgraded recorded UUID")
	}
}
