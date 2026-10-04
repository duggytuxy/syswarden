//go:build linux

package network

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syswarden-cli/pkg/wireguardstate"
	"testing"
)

func readFilesystemFixture(t *testing.T, path string) ([]byte, error) {
	t.Helper()
	relative, err := filepath.Rel(wireGuardFilesystemRoot, path)
	if err != nil {
		return nil, err
	}
	return legacyTestFiles(t, wireGuardFilesystemRoot).ReadFile(relative)
}

func writeFilesystemFixture(t *testing.T, path string, wire []byte, mode os.FileMode) error {
	t.Helper()
	relative, err := filepath.Rel(wireGuardFilesystemRoot, path)
	if err != nil {
		return err
	}
	return legacyTestFiles(t, wireGuardFilesystemRoot).WriteFile(relative, wire, mode)
}

func writeFilesystemTestManifest(t *testing.T, path string, manifest wireguardstate.Manifest) []byte {
	t.Helper()
	wire, err := canonicalWireGuardManifestBytes(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFilesystemFixture(t, path, wire, 0600); err != nil {
		t.Fatal(err)
	}
	return wire
}

func removeFilesystemBindingsForTest(t *testing.T) wireguardstate.Manifest {
	t.Helper()
	manifest, _ := currentWireGuardForwardingState(t)
	if manifest.Artifacts[0].FilesystemUUID == "" {
		t.Skip("filesystem UUID unavailable on this kernel; strict fallback is tested separately")
	}
	for i := range manifest.Artifacts {
		manifest.Artifacts[i].FilesystemUUID = ""
	}
	if manifest.OpenRCServiceLink != nil {
		manifest.OpenRCServiceLink.FilesystemUUID = ""
	}
	writeFilesystemTestManifest(t, filepath.Join(wireGuardFilesystemRoot, wireguardstate.ManifestPath), manifest)
	return manifest
}

// Alter only durable device evidence to model a reboot that renumbers the
// underlying block device. Actual files, UUIDs and inodes remain unchanged.
func renumberBindingJournalForTest(t *testing.T, root string) {
	t.Helper()
	path := filepath.Join(root, wireGuardFilesystemBindingPath)
	wire, err := readFilesystemFixture(t, path)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := decodeWireGuardFilesystemBinding(wire)
	if err != nil {
		t.Fatal(err)
	}
	oldWire, targetWire := journal.OldContent, journal.TargetContent
	shift := func(content string) string {
		manifest, err := decodeWireGuardManifestBytes([]byte(content))
		if err != nil {
			t.Fatal(err)
		}
		for i := range manifest.Artifacts {
			manifest.Artifacts[i].Device ^= 16
		}
		if manifest.OpenRCServiceLink != nil {
			manifest.OpenRCServiceLink.Device ^= 16
		}
		wire, err := canonicalWireGuardManifestBytes(manifest)
		if err != nil {
			t.Fatal(err)
		}
		return string(wire)
	}
	journal.OldContent, journal.TargetContent = shift(oldWire), shift(targetWire)
	journal.OldManifest.Device ^= 16
	digest := sha256.Sum256([]byte(journal.OldContent))
	journal.OldManifest.SHA256 = hex.EncodeToString(digest[:])
	journal.OldManifest.Size = int64(len(journal.OldContent))
	for _, name := range []string{wireguardstate.ManifestPath, "/etc/wireguard/" + wireGuardFilesystemBindingStage} {
		p := filepath.Join(root, name)
		content, err := readFilesystemFixture(t, p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		var replacement string
		switch string(content) {
		case oldWire:
			replacement = journal.OldContent
		case targetWire:
			replacement = journal.TargetContent
		default:
			t.Fatal("unexpected manifest content in reboot fixture")
		}
		if err := writeFilesystemFixture(t, p, []byte(replacement), 0600); err != nil {
			t.Fatal(err)
		}
	}
	wire, err = canonicalWireGuardFilesystemBinding(journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFilesystemFixture(t, path, wire, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestFilesystemBindingResumesEveryBoundaryAfterDeviceRenumbering(t *testing.T) {
	for _, alpine := range []bool{false, true} {
		for _, point := range []string{"journal-published", "manifest-staged", "manifest-exchanged", "prior-removed"} {
			t.Run(fmtFilesystemTestName(alpine, point), func(t *testing.T) {
				harness, _ := prepareEnabledWireGuardForDisable(t, alpine)
				before, _ := currentWireGuardForwardingState(t)
				removeFilesystemBindingsForTest(t)
				previous := wireGuardFilesystemBindingFault
				t.Cleanup(func() { wireGuardFilesystemBindingFault = previous })
				sentinel := errors.New("binding interrupted")
				wireGuardFilesystemBindingFault = func(got string) error {
					if got == point {
						return sentinel
					}
					return nil
				}
				if err := bindVerifiedWireGuardFilesystems(); !errors.Is(err, sentinel) {
					t.Fatalf("boundary %s not reached: %v", point, err)
				}
				if _, _, err := inspectWireGuardStateForPreflight(); err == nil {
					t.Fatal("read-only preflight ignored pending binding")
				}
				renumberBindingJournalForTest(t, harness.root)
				wireGuardFilesystemBindingFault = func(string) error { return nil }
				if err := RecoverPendingWireGuardForwardingState(); err != nil {
					t.Fatalf("reboot recovery failed: %v", err)
				}
				after, _ := currentWireGuardForwardingState(t)
				for i, original := range before.Artifacts {
					if !wireguardstate.MatchesRecordedArtifact(original, after.Artifacts[i]) || after.Artifacts[i].FilesystemUUID == "" {
						t.Fatal("binding changed generated bytes, inode or metadata")
					}
				}
				for _, path := range []string{wireGuardFilesystemBindingPath, "/etc/wireguard/" + wireGuardFilesystemBindingStage} {
					if _, err := os.Lstat(filepath.Join(harness.root, path)); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("binding residue: %s: %v", path, err)
					}
				}
				if err := bindVerifiedWireGuardFilesystems(); err != nil {
					t.Fatalf("idempotent binding: %v", err)
				}
			})
		}
	}
}

func fmtFilesystemTestName(alpine bool, point string) string {
	if alpine {
		return "openrc/" + point
	}
	return "systemd/" + point
}

func TestFilesystemBindingRefusesUnprovenLegacyDeviceChange(t *testing.T) {
	harness, _ := prepareEnabledWireGuardForDisable(t, false)
	manifest := removeFilesystemBindingsForTest(t)
	manifest.Artifacts[0].Device ^= 16
	path := filepath.Join(harness.root, wireguardstate.ManifestPath)
	before := writeFilesystemTestManifest(t, path, manifest)
	if err := bindVerifiedWireGuardFilesystems(); err == nil {
		t.Fatal("legacy device mismatch was silently rebound")
	}
	after, err := readFilesystemFixture(t, path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("refusal changed legacy evidence", err)
	}
	if present, err := wireGuardPrivatePathPresent(wireGuardFilesystemBindingPath); err != nil || present {
		t.Fatal("refusal published mutation intent", err)
	}
}

func TestFilesystemBindingRefusesChangedEvidenceOnResume(t *testing.T) {
	for _, kind := range []string{"client", "manifest", "stage", "journal", "uuid", "inode"} {
		t.Run(kind, func(t *testing.T) {
			harness, _ := prepareEnabledWireGuardForDisable(t, false)
			removeFilesystemBindingsForTest(t)
			previous := wireGuardFilesystemBindingFault
			t.Cleanup(func() { wireGuardFilesystemBindingFault = previous })
			sentinel := errors.New("stop before exchange")
			wireGuardFilesystemBindingFault = func(point string) error {
				if point == "manifest-staged" {
					return sentinel
				}
				return nil
			}
			if err := bindVerifiedWireGuardFilesystems(); !errors.Is(err, sentinel) {
				t.Fatal(err)
			}
			wireGuardFilesystemBindingFault = func(string) error { return nil }
			path := filepath.Join(harness.root, wireguardstate.ClientConfigurationPath)
			switch kind {
			case "manifest":
				path = filepath.Join(harness.root, wireguardstate.ManifestPath)
			case "stage":
				path = filepath.Join(harness.root, "/etc/wireguard/"+wireGuardFilesystemBindingStage)
			case "journal", "uuid", "inode":
				path = filepath.Join(harness.root, wireGuardFilesystemBindingPath)
			}
			wire, err := readFilesystemFixture(t, path)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "uuid" || kind == "inode" {
				journal, err := decodeWireGuardFilesystemBinding(wire)
				if err != nil {
					t.Fatal(err)
				}
				target, err := decodeWireGuardManifestBytes([]byte(journal.TargetContent))
				if err != nil {
					t.Fatal(err)
				}
				if kind == "uuid" {
					target.Artifacts[0].FilesystemUUID = strings.Repeat("b", 32)
				} else {
					target.Artifacts[0].Inode++
				}
				updated, err := canonicalWireGuardManifestBytes(target)
				if err != nil {
					t.Fatal(err)
				}
				journal.TargetContent = string(updated)
				// This adversarial journal must also pass the byte-level canonical check.
				wire, err = json.MarshalIndent(journal, "", "  ")
				if err != nil {
					t.Fatal(err)
				}
				wire = append(wire, '\n')
			} else {
				wire = append(wire, []byte("changed\n")...)
			}
			if err := writeFilesystemFixture(t, path, wire, 0600); err != nil {
				t.Fatal(err)
			}
			before, err := readFilesystemFixture(t, path)
			if err != nil {
				t.Fatal(err)
			}
			if err := RecoverPendingWireGuardForwardingState(); err == nil {
				t.Fatal("changed evidence accepted")
			}
			after, err := readFilesystemFixture(t, path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("changed evidence was not preserved", err)
			}
		})
	}
}

func TestForwardingRecoverySurvivesDeviceRenumbering(t *testing.T) {
	for _, point := range []string{"journal-published", "forwarding-staged", "manifest-staged", "forwarding-exchanged", "manifest-exchanged"} {
		t.Run(point, func(t *testing.T) {
			harness, _ := prepareEnabledWireGuardForDisable(t, false)
			manifest, _ := currentWireGuardForwardingState(t)
			if manifest.Artifacts[0].FilesystemUUID == "" {
				t.Skip("filesystem UUID unavailable")
			}
			target, err := canonicalWireGuardForwardingContent(exactWireGuardNFTIdentity(), false, true, "0")
			if err != nil {
				t.Fatal(err)
			}
			previous := wireGuardForwardingTransitionFault
			t.Cleanup(func() { wireGuardForwardingTransitionFault = previous })
			crashMarker := &struct{}{}
			crashed := false
			func() {
				defer func() {
					if value := recover(); value != nil {
						if value != crashMarker {
							panic(value)
						}
						crashed = true
					}
				}()
				wireGuardForwardingTransitionFault = func(got string) error {
					if got == point {
						panic(crashMarker)
					}
					return nil
				}
				if err := transitionWireGuardForwardingPersistenceGuarded(exactWireGuardNFTIdentity(), target); err != nil {
					t.Fatal(err)
				}
			}()
			if !crashed {
				t.Fatal("interruption was not reached")
			}
			wireGuardForwardingTransitionFault = previous
			journal, _, present, err := readWireGuardForwardingTransitionJournal()
			if err != nil || !present {
				t.Fatal("missing interrupted journal", err)
			}
			for _, name := range []string{filepath.Base(wireguardstate.ManifestPath), journal.ManifestStageName} {
				path := filepath.Join(harness.root, "etc/wireguard", name)
				wire, err := readFilesystemFixture(t, path)
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				value, err := decodeWireGuardManifestBytes(wire)
				if err != nil {
					t.Fatal(err)
				}
				for i := range value.Artifacts {
					value.Artifacts[i].Device ^= 16
				}
				updated := writeFilesystemTestManifest(t, path, value)
				if string(wire) == journal.OldManifestContent {
					journal.OldManifestContent = string(updated)
				}
			}
			journal.OldForwarding.Device ^= 16
			journal.OldManifest.Device ^= 16
			digest := sha256.Sum256([]byte(journal.OldManifestContent))
			journal.OldManifest.SHA256 = hex.EncodeToString(digest[:])
			journal.OldManifest.Size = int64(len(journal.OldManifestContent))
			wire, err := canonicalWireGuardForwardingJournal(journal)
			if err != nil {
				t.Fatal(err)
			}
			if err := writeFilesystemFixture(t, filepath.Join(harness.root, wireGuardForwardingTransitionPath), wire, 0600); err != nil {
				t.Fatal(err)
			}
			if err := RecoverPendingWireGuardForwardingState(); err != nil {
				t.Fatal("forwarding recovery after reboot", err)
			}
			_, state := currentWireGuardForwardingState(t)
			if state.BootEnabled != (point != "manifest-exchanged") {
				t.Fatal("recovery chose the wrong side of commit")
			}
			if err := transitionWireGuardForwardingPersistenceGuarded(exactWireGuardNFTIdentity(), target); err != nil {
				t.Fatal("forwarding retry", err)
			}
			if pending, err := wireGuardForwardingTransitionPending(); err != nil || pending {
				t.Fatal("forwarding journal remains", err)
			}
		})
	}
}
