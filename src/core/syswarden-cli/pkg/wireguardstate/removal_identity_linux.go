//go:build linux

package wireguardstate

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
)

// captureRemovalIdentities preserves every verified ownership field and adds
// only the persistent filesystem evidence returned by the pinned live object.
// The original manifest is never rewritten or modified through its slices.
func captureRemovalIdentities(root string, manifest Manifest, uid, gid uint32) (Manifest, error) {
	bound := manifest
	bound.Artifacts = append([]Artifact(nil), manifest.Artifacts...)
	for index, expected := range manifest.Artifacts {
		actual, _, err := captureLogical(root, expected.Path, uid, gid, maximumOwnedArtifactBytes)
		if err != nil || !sameArtifact(actual, expected) {
			return Manifest{}, errors.Join(fmt.Errorf("owned artifact changed before removal identity capture"), err)
		}
		bound.Artifacts[index] = actual
	}
	if manifest.OpenRCServiceLink != nil {
		actual, present, err := InspectOpenRCServiceLink(root, uid, gid)
		if err != nil || !present || !sameSymlinkArtifact(actual, *manifest.OpenRCServiceLink) {
			return Manifest{}, errors.Join(fmt.Errorf("owned service link changed before removal identity capture"), err)
		}
		bound.OpenRCServiceLink = &actual
	}
	return bound, nil
}

// removalIdentityProofs never updates durable journal bytes. An old UUID-free
// entry can use a stronger original identity only when the immutable successor
// independently binds that exact historical record to the captured original.
// A present UUID is never discarded, replaced, or inferred from a live file.
func removalIdentityProofs(root string, journal transactionJournal, uid, gid uint32) (transactionJournal, error) {
	if err := validateJournal(&journal, uid, gid); err != nil {
		return transactionJournal{}, err
	}
	if !isRemovalOperation(journal.Operation) || journal.Manifest == nil || journal.Manifest.Artifact.Inode == 0 {
		return transactionJournal{}, fmt.Errorf("removal requires exact journaled ownership identities")
	}
	for _, entry := range journal.Artifacts {
		if entry.Artifact.Inode == 0 {
			return transactionJournal{}, fmt.Errorf("removal cannot use planned-only artifact ownership")
		}
	}
	if journal.OpenRCServiceLink != nil && journal.OpenRCServiceLink.Artifact.Inode == 0 {
		return transactionJournal{}, fmt.Errorf("removal cannot use planned-only service-link ownership")
	}
	proofs := journal
	proofs.Artifacts = append([]journalArtifact(nil), journal.Artifacts...)
	if journal.OpenRCServiceLink != nil {
		link := *journal.OpenRCServiceLink
		proofs.OpenRCServiceLink = &link
	}
	present, err := inventoryLogicalExists(root, PolicyTransitionReceiptPath)
	if err != nil || !present {
		return proofs, err
	}
	lineage, err := inspectPolicyTransition(root, uid, gid, true)
	if err != nil {
		return transactionJournal{}, err
	}
	if !lineage.Complete || lineage.State != "lineage" || !sameArtifact(journal.Artifacts[0].Artifact, lineage.record.Server) {
		return transactionJournal{}, fmt.Errorf("removal journal does not bind the finalized policy successor")
	}
	intent := lineage.record.Intent
	client := journal.Artifacts[1].Artifact
	if client != intent.Manifest.Artifacts[1] && !sameArtifact(client, intent.OriginalArtifacts[1]) {
		return transactionJournal{}, fmt.Errorf("removal client differs from sealed successor lineage")
	}
	for index := 1; index < len(proofs.Artifacts); index++ {
		recorded := journal.Artifacts[index].Artifact
		if recorded.FilesystemUUID == "" && recorded == intent.Manifest.Artifacts[index] && intent.OriginalArtifacts[index].FilesystemUUID != "" {
			proofs.Artifacts[index].Artifact = intent.OriginalArtifacts[index]
		}
	}
	if (journal.OpenRCServiceLink == nil) != (intent.OriginalServiceLink == nil) {
		return transactionJournal{}, fmt.Errorf("removal service-link ownership differs from sealed successor lineage")
	}
	if journal.OpenRCServiceLink != nil {
		recorded := journal.OpenRCServiceLink.Artifact
		if recorded != *intent.Manifest.OpenRCServiceLink && !sameSymlinkArtifact(recorded, *intent.OriginalServiceLink) {
			return transactionJournal{}, fmt.Errorf("removal service link differs from sealed successor lineage")
		}
		if recorded.FilesystemUUID == "" && recorded == *intent.Manifest.OpenRCServiceLink && intent.OriginalServiceLink.FilesystemUUID != "" {
			proofs.OpenRCServiceLink.Artifact = *intent.OriginalServiceLink
		}
	}
	return proofs, nil
}

func preflightRemovalArtifact(root string, entry journalArtifact, uid, gid uint32) (resultErr error) {
	directory, err := openPinnedDirectory(root, filepath.Dir(entry.Artifact.Path), uid, gid)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, directory.file.Close()) }()
	limit := int64(maximumOwnedArtifactBytes)
	if entry.Artifact.Path == ManifestPath {
		limit = maximumOwnershipManifestSize
	}
	present := 0
	for _, name := range []string{filepath.Base(entry.Artifact.Path), entry.QuarantineName} {
		actual, _, err := captureAt(directory, name, entry.Artifact.Path, uid, gid, limit)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil || !sameArtifact(actual, entry.Artifact) {
			return errors.Join(fmt.Errorf("remaining removal artifact does not match its exact proof: %s", entry.Artifact.Path), err)
		}
		present++
	}
	if present > 1 {
		return fmt.Errorf("both final and quarantine removal artifacts remain: %s", entry.Artifact.Path)
	}
	return nil
}

func preflightRemovalServiceLink(root string, entry journalSymlink, uid, gid uint32) (resultErr error) {
	directory, err := openPinnedDirectory(root, filepath.Dir(OpenRCServiceLinkPath), uid, gid)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, directory.file.Close()) }()
	present := 0
	for _, name := range []string{filepath.Base(OpenRCServiceLinkPath), entry.QuarantineName} {
		actual, err := captureSymlinkAt(directory, name, uid, gid)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil || !sameSymlinkArtifact(actual, entry.Artifact) {
			return errors.Join(fmt.Errorf("remaining removal service link does not match its exact proof"), err)
		}
		present++
	}
	if present > 1 {
		return fmt.Errorf("both final and quarantine removal service links remain")
	}
	return nil
}

// Inspect every surviving final/quarantine before the first deletion. Missing
// pairs are valid partial removal; conflicting pairs and changed evidence stop
// the entire continuation. Each removal still reattests its own pinned object.
func preflightRemovalIdentities(root string, journal transactionJournal, uid, gid uint32) error {
	for _, entry := range journal.Artifacts {
		if err := preflightRemovalArtifact(root, entry, uid, gid); err != nil {
			return err
		}
	}
	if err := preflightRemovalArtifact(root, *journal.Manifest, uid, gid); err != nil {
		return err
	}
	if journal.OpenRCServiceLink != nil {
		return preflightRemovalServiceLink(root, *journal.OpenRCServiceLink, uid, gid)
	}
	return nil
}
