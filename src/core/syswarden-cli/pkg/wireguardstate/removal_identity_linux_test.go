//go:build linux

package wireguardstate

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func removalIdentityFixture(t *testing.T, withOpenRC, renumber bool) (string, uint32, uint32, transactionJournal) {
	t.Helper()
	root, uid, gid, manifest, _ := ownedPolicyFixture(t, withOpenRC)
	for index := range manifest.Artifacts {
		if manifest.Artifacts[index].FilesystemUUID == "" {
			t.Skip("kernel filesystem UUID unavailable; strict legacy refusal is tested separately")
		}
		manifest.Artifacts[index].FilesystemUUID = ""
	}
	if withOpenRC {
		if manifest.OpenRCServiceLink.FilesystemUUID == "" {
			t.Skip("owned service link has no persistent filesystem evidence")
		}
		manifest.OpenRCServiceLink.FilesystemUUID = ""
	}
	files := legacyTestFiles(t, root)
	wire, err := canonicalManifestBytes(manifest, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	if err := files.WriteFile(strings.TrimPrefix(ManifestPath, "/"), wire, 0600); err != nil {
		t.Fatal(err)
	}
	committed := adversarialPolicyTransitionPause(t, root, uid, gid, "receipt")
	if err := FinalizePolicyTransition(root, committed, uid, gid); err != nil {
		t.Fatal(err)
	}
	_, receiptWire, err := captureLogical(root, PolicyTransitionReceiptPath, uid, gid, maximumOwnedArtifactBytes)
	if err != nil {
		t.Fatal(err)
	}
	var record policyTransitionRecord
	if err := policyDecode(receiptWire, &record); err != nil {
		t.Fatal(err)
	}
	if renumber {
		// Construct a historical fixture whose recorded device number predates
		// the current mount. All UUIDs and physical objects remain unchanged.
		// These synthetic records are frozen before any recovery assertion.
		for index := range record.Intent.Manifest.Artifacts {
			record.Intent.Manifest.Artifacts[index].Device ^= 16
			record.Intent.OriginalArtifacts[index].Device ^= 16
		}
		if withOpenRC {
			record.Intent.Manifest.OpenRCServiceLink.Device ^= 16
			record.Intent.OriginalServiceLink.Device ^= 16
		}
		record.Server.Device ^= 16
		wire, err := canonicalManifestBytes(record.Intent.Manifest, uid, gid)
		if err != nil {
			t.Fatal(err)
		}
		record.Intent.ManifestContent = string(wire)
		if err := files.WriteFile(strings.TrimPrefix(PolicyTransitionManifestArchivePath, "/"), wire, 0600); err != nil {
			t.Fatal(err)
		}
		archive, _, err := captureLogical(root, PolicyTransitionManifestArchivePath, uid, gid, maximumOwnedArtifactBytes)
		if err != nil {
			t.Fatal(err)
		}
		record.Intent.ManifestArtifact = policyArtifactAt(archive, ManifestPath)
		_, targetWire, err := policyTargetManifest(record.Intent, record.Server, uid, gid)
		if err != nil {
			t.Fatal(err)
		}
		if err := files.WriteFile(strings.TrimPrefix(ManifestPath, "/"), targetWire, 0600); err != nil {
			t.Fatal(err)
		}
		record.Manifest, _, err = captureLogical(root, ManifestPath, uid, gid, maximumOwnershipManifestSize)
		if err != nil {
			t.Fatal(err)
		}
		intentWire, err := policyCanonical(record.Intent)
		if err != nil {
			t.Fatal(err)
		}
		record.IntentArtifact.SHA256 = plannedArtifact(PolicyTransitionPath, intentWire, uid, gid).SHA256
		receiptWire, err = policyCanonical(record)
		if err != nil {
			t.Fatal(err)
		}
		if err := files.WriteFile(strings.TrimPrefix(PolicyTransitionReceiptPath, "/"), receiptWire, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := RefusePendingPolicyTransition(root); err != nil {
		t.Fatal("synthetic finalized lineage is invalid", err)
	}
	target, _, err := policyTargetManifest(record.Intent, record.Server, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	manifestRecord, _, err := captureLogical(root, ManifestPath, uid, gid, maximumOwnershipManifestSize)
	if err != nil {
		t.Fatal(err)
	}
	journal := transactionJournal{Schema: transactionSchema, Operation: string(TransactionOperationRemovePendingReload),
		Manifest: &journalArtifact{Artifact: manifestRecord, QuarantineName: removalIdentityQuarantine(ManifestPath)}}
	for _, artifact := range target.Artifacts {
		journal.Artifacts = append(journal.Artifacts, journalArtifact{Artifact: artifact, QuarantineName: removalIdentityQuarantine(artifact.Path)})
	}
	if target.OpenRCServiceLink != nil {
		journal.OpenRCServiceLink = &journalSymlink{Artifact: *target.OpenRCServiceLink, QuarantineName: removalIdentityQuarantine(OpenRCServiceLinkPath)}
	}
	return root, uid, gid, journal
}

func removalIdentityQuarantine(path string) string {
	return "." + filepath.Base(path) + ".syswarden-quarantine-" + strings.Repeat("a", 32)
}

func publishRemovalIdentityFixture(t *testing.T, root string, uid, gid uint32, journal transactionJournal) []byte {
	t.Helper()
	wire, err := canonicalJournalBytes(journal, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publishTransactionJournal(root, journal, uid, gid); err != nil {
		t.Fatal(err)
	}
	return wire
}

func TestRemovalIdentityNewJournalCapturesUUIDWithoutRewritingManifest(t *testing.T) {
	root, uid, gid, _ := removalIdentityFixture(t, true, false)
	files := legacyTestFiles(t, root)
	original, err := files.ReadFile(strings.TrimPrefix(ManifestPath, "/"))
	if err != nil {
		t.Fatal(err)
	}
	before := observeOwnedPolicyFiles(t, root)
	checked := false
	previous := wireGuardStateFaultPoint
	t.Cleanup(func() { wireGuardStateFaultPoint = previous })
	wireGuardStateFaultPoint = func(point string) {
		if point != "remove-before-rename:"+OpenRCServiceLinkPath {
			return
		}
		checked = true
		journal, _, err := readTransactionJournal(root, uid, gid)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range journal.Artifacts {
			if entry.Artifact.FilesystemUUID == "" {
				t.Fatal("new removal journal discarded captured filesystem identity")
			}
		}
		if journal.OpenRCServiceLink == nil || journal.OpenRCServiceLink.Artifact.FilesystemUUID == "" {
			t.Fatal("new removal journal discarded owned service-link filesystem identity")
		}
		current, err := files.ReadFile(strings.TrimPrefix(ManifestPath, "/"))
		if err != nil || !bytes.Equal(current, original) {
			t.Fatal("new removal rewrote the historical manifest before deletion", err)
		}
	}
	if ready, err := PrepareRemoval(root, uid, gid); err != nil || !ready || !checked {
		t.Fatal("new removal did not reach its exact identity check", err)
	}
	for _, logical := range []string{PolicyTransitionReceiptPath, PolicyTransitionServerArchivePath, PolicyTransitionManifestArchivePath} {
		path := strings.TrimPrefix(logical, "/")
		if !reflect.DeepEqual(before[path], observeOwnedPolicyFiles(t, root)[path]) {
			t.Fatal("new removal changed immutable successor evidence")
		}
	}
}

func TestRemovalIdentityLegacyJournalRecoversRenumberedFinalAndQuarantinePairs(t *testing.T) {
	for _, phase := range []string{"all-live", "link-quarantined", "server-removed-client-quarantined", "companions-removed-manifest-quarantined", "all-removed"} {
		t.Run(phase, func(t *testing.T) {
			root, uid, gid, journal := removalIdentityFixture(t, true, true)
			files := legacyTestFiles(t, root)
			wire := publishRemovalIdentityFixture(t, root, uid, gid, journal)
			remove := func(logical string) {
				t.Helper()
				if err := files.Remove(strings.TrimPrefix(logical, "/")); err != nil {
					t.Fatal(err)
				}
			}
			quarantine := func(logical, name string) {
				t.Helper()
				if err := files.Rename(strings.TrimPrefix(logical, "/"), strings.TrimPrefix(filepath.Join(filepath.Dir(logical), name), "/")); err != nil {
					t.Fatal(err)
				}
			}
			switch phase {
			case "link-quarantined":
				quarantine(OpenRCServiceLinkPath, journal.OpenRCServiceLink.QuarantineName)
			case "server-removed-client-quarantined":
				remove(OpenRCServiceLinkPath)
				remove(ServerConfigurationPath)
				quarantine(ClientConfigurationPath, journal.Artifacts[1].QuarantineName)
			case "companions-removed-manifest-quarantined", "all-removed":
				remove(OpenRCServiceLinkPath)
				for _, logical := range canonicalArtifactPaths {
					remove(logical)
				}
				if phase == "all-removed" {
					remove(ManifestPath)
				} else {
					quarantine(ManifestPath, journal.Manifest.QuarantineName)
				}
			}
			before := observeOwnedPolicyFiles(t, root)
			if recovered, err := RecoverRemoval(root, uid, gid); err != nil || !recovered {
				t.Fatal("sealed UUID proof did not recover legacy removal", err)
			}
			current, err := files.ReadFile(strings.TrimPrefix(TransactionPath, "/"))
			if err != nil || !bytes.Equal(current, wire) {
				t.Fatal("recovery rewrote the immutable old removal journal", err)
			}
			journalPath := strings.TrimPrefix(TransactionPath, "/")
			after := observeOwnedPolicyFiles(t, root)
			if !reflect.DeepEqual(before[journalPath], after[journalPath]) {
				t.Fatal("recovery replaced or modified the old journal inode or metadata")
			}
			if finalized, err := FinalizeRemoval(root, uid, gid); err != nil || !finalized {
				t.Fatal("completed removal could not explicitly consume reload debt", err)
			}
			if retained, err := InspectPolicyTransition(root, uid, gid); err != nil || retained.State != "retained" {
				t.Fatal("recovered removal damaged retained successor lineage", err)
			}
			after = observeOwnedPolicyFiles(t, root)
			for _, logical := range []string{PolicyTransitionReceiptPath, PolicyTransitionServerArchivePath, PolicyTransitionManifestArchivePath} {
				path := strings.TrimPrefix(logical, "/")
				if !reflect.DeepEqual(before[path], after[path]) {
					t.Fatal("recovery changed immutable receipt or original archive")
				}
			}
		})
	}
}

func TestRemovalIdentityRefusesContradictionBeforeAnyOwnedDeletion(t *testing.T) {
	for _, kind := range []string{"client-uuid", "client-inode", "client-digest", "server-generation", "link-uuid", "link-ownership", "forwarding-uuid", "manifest-uuid", "missing-lineage", "changed-receipt", "duplicate-client", "hardlinked-client"} {
		t.Run(kind, func(t *testing.T) {
			root, uid, gid, journal := removalIdentityFixture(t, true, true)
			files := legacyTestFiles(t, root)
			switch kind {
			case "client-uuid":
				journal.Artifacts[1].Artifact.FilesystemUUID = strings.Repeat("b", 32)
			case "client-inode":
				journal.Artifacts[1].Artifact.Inode++
			case "client-digest":
				journal.Artifacts[1].Artifact.SHA256 = strings.Repeat("b", 64)
			case "server-generation":
				journal.Artifacts[0].Artifact.Inode++
			case "link-uuid":
				journal.OpenRCServiceLink.Artifact.FilesystemUUID = strings.Repeat("b", 32)
			case "link-ownership":
				journal.OpenRCServiceLink = nil
			case "forwarding-uuid":
				journal.Artifacts[2].Artifact.FilesystemUUID = strings.Repeat("b", 32)
			case "manifest-uuid":
				journal.Manifest.Artifact.FilesystemUUID = strings.Repeat("b", 32)
			case "missing-lineage":
				for _, logical := range []string{PolicyTransitionReceiptPath, PolicyTransitionServerArchivePath, PolicyTransitionManifestArchivePath} {
					if err := files.Remove(strings.TrimPrefix(logical, "/")); err != nil {
						t.Fatal(err)
					}
				}
			case "changed-receipt":
				if err := files.WriteFile(strings.TrimPrefix(PolicyTransitionReceiptPath, "/"), []byte("{}\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "duplicate-client":
				wire, err := files.ReadFile(strings.TrimPrefix(ClientConfigurationPath, "/"))
				if err != nil {
					t.Fatal(err)
				}
				path := strings.TrimPrefix(filepath.Join(filepath.Dir(ClientConfigurationPath), journal.Artifacts[1].QuarantineName), "/")
				if err := files.WriteFile(path, wire, 0600); err != nil {
					t.Fatal(err)
				}
			case "hardlinked-client":
				if err := files.Link(strings.TrimPrefix(ClientConfigurationPath, "/"), "retained-client-hardlink"); err != nil {
					t.Fatal(err)
				}
			}
			publishRemovalIdentityFixture(t, root, uid, gid, journal)
			before := observeOwnedPolicyFiles(t, root)
			if _, err := RecoverRemoval(root, uid, gid); err == nil {
				t.Fatal("contradictory removal proof was accepted")
			}
			if !reflect.DeepEqual(before, observeOwnedPolicyFiles(t, root)) {
				t.Fatal("refused recovery changed surviving files or durable evidence")
			}
		})
	}
}

func TestRemovalIdentityRecoveryNeverAdoptsAnUnownedOpenRCLink(t *testing.T) {
	root, uid, gid, journal := removalIdentityFixture(t, false, true)
	files := legacyTestFiles(t, root)
	if err := files.Mkdir("etc/init.d", 0755); err != nil { // #nosec G301 -- protected administrator OpenRC fixture
		t.Fatal(err)
	}
	path := strings.TrimPrefix(OpenRCServiceLinkPath, "/")
	if err := files.Symlink(OpenRCServiceLinkTarget, path); err != nil {
		t.Fatal(err)
	}
	before := observeOwnedPolicyFiles(t, root)[path]
	publishRemovalIdentityFixture(t, root, uid, gid, journal)
	if _, err := RecoverRemoval(root, uid, gid); err != nil {
		t.Fatal(err)
	}
	if _, err := FinalizeRemoval(root, uid, gid); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, observeOwnedPolicyFiles(t, root)[path]) {
		t.Fatal("legacy recovery adopted or removed the administrator service link")
	}
}

func TestRemovalIdentityWithoutPersistentProofKeepsStrictDeviceMatching(t *testing.T) {
	root, uid, gid := prepareStateRoot(t)
	publishTestState(t, root, uid, gid)
	manifest, record, err := readManifestWithRecord(root, uid, gid)
	if err != nil {
		t.Fatal(err)
	}
	journal := transactionJournal{Schema: transactionSchema, Operation: string(TransactionOperationRemovePendingReload),
		Manifest: &journalArtifact{Artifact: record, QuarantineName: removalIdentityQuarantine(ManifestPath)}}
	for _, artifact := range manifest.Artifacts {
		artifact.FilesystemUUID = ""
		artifact.Device ^= 16
		journal.Artifacts = append(journal.Artifacts, journalArtifact{Artifact: artifact, QuarantineName: removalIdentityQuarantine(artifact.Path)})
	}
	publishRemovalIdentityFixture(t, root, uid, gid, journal)
	before := observeOwnedPolicyFiles(t, root)
	if _, err := RecoverRemoval(root, uid, gid); err == nil {
		t.Fatal("UUID-free removal inferred new device ownership from current files")
	}
	if !reflect.DeepEqual(before, observeOwnedPolicyFiles(t, root)) {
		t.Fatal("unsupported recovery changed retained artifacts")
	}
	if _, err := os.Lstat(filepath.Join(root, ServerConfigurationPath)); errors.Is(err, os.ErrNotExist) {
		t.Fatal("unsupported recovery removed an original artifact")
	}
}
