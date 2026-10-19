package journal

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	contracts "syswarden-core/contracts/v5"
	"syswarden-core/fleetregistry"
)

// Reuse the mandatory real cross-UID adversary, including its positive canary,
// dropped capabilities and identity checks. Only disposable test files exist.
func testFleetRegistryBoundary(t *testing.T, work, canary string) {
	t.Helper()
	golden, err := hex.DecodeString(string(bytes.TrimSpace(readFile(t, "../fleetregistry/testdata/registry-v1.hex"))))
	if err != nil {
		t.Fatal(err)
	}
	generation, err := contracts.DecodeNodeRegistryGeneration(readFile(t, "../contracts/v5/testdata/node-registry-generation.json"))
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, err := contracts.DecodeNodeRegistryCheckpoint(readFile(t, "../contracts/v5/testdata/node-registry-checkpoint.json"))
	if err != nil {
		t.Fatal(err)
	}
	gr, err := generation.Reference()
	if err != nil {
		t.Fatal(err)
	}
	cr, err := checkpoint.Reference()
	if err != nil {
		t.Fatal(err)
	}
	expected := contracts.NodeRegistryContinuityContext{AuthorityID: generation.AuthorityID, LineageID: generation.LineageID, Generation: gr, Checkpoint: cr}
	path := filepath.Join(work, "fleet-registry")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(path, fleetregistry.SnapshotFileName)
	if err := os.WriteFile(name, golden, 0600); err != nil {
		t.Fatal(err)
	}
	directory, err := openFixtureDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = directory.Close() }()
	store, err := fleetregistry.OpenSnapshotStore(directory, expected)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close() }()
	dirs := []string{path}
	before := adversarialSnapshot(t, dirs)
	for _, attack := range []string{"read", "overwrite", "append", "truncate", "unlink", "rename", "hardlink", "chmod", "chown", "create", "symlink", "replace-directory"} {
		t.Run(attack, func(t *testing.T) {
			target := name
			if attack == "create" || attack == "symlink" || attack == "replace-directory" {
				target = path
			}
			runAdversary(t, canary, attack, target, nil)
			requireAdversarialSnapshot(t, before, dirs)
		})
	}
	t.Run("verified-read-after-attacks", func(t *testing.T) {
		snapshot, err := store.Read(expected)
		if err != nil || snapshot.Generation != generation || snapshot.Checkpoint != checkpoint {
			t.Fatal("protected registry became unavailable after denied attacks", err)
		}
		encoded, err := fleetregistry.EncodeSnapshot(snapshot, expected)
		if err != nil || !bytes.Equal(encoded, golden) {
			t.Fatal("protected snapshot changed", err)
		}
		requireAdversarialSnapshot(t, before, dirs)
	})
}
