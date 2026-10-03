//go:build linux

package network

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"syswarden-cli/pkg/wireguardstate"
)

const wireGuardFilesystemBindingPath = "/etc/wireguard/.syswarden-filesystem-binding-v1.json"
const wireGuardFilesystemBindingStage = ".syswarden-ownership-v1.json.filesystem-stage"
const wireGuardFilesystemBindingSchema = "syswarden-wireguard-filesystem-binding-v1"

var wireGuardFilesystemBindingFault = func(string) error { return nil }

// A binding transition changes only optional filesystem UUID fields. Its old
// manifest identity and both byte strings are durable before any exchange.
// Recovery can therefore finish after a reboot without trusting a new device
// number for a legacy record that never had persistent filesystem evidence.
type wireGuardFilesystemBindingJournal struct {
	Schema        string             `json:"schema"`
	OldManifest   wireGuardExactFile `json:"old_manifest"`
	OldContent    string             `json:"old_content"`
	TargetContent string             `json:"target_content"`
}

func canonicalWireGuardFilesystemBinding(j wireGuardFilesystemBindingJournal) ([]byte, error) {
	if j.Schema != wireGuardFilesystemBindingSchema || !validWireGuardExactFile(j.OldManifest, 32<<10) ||
		int64(len(j.OldContent)) != j.OldManifest.Size {
		return nil, fmt.Errorf("invalid WireGuard filesystem binding journal")
	}
	digest := sha256.Sum256([]byte(j.OldContent))
	if hex.EncodeToString(digest[:]) != j.OldManifest.SHA256 {
		return nil, fmt.Errorf("filesystem binding prior manifest digest mismatch")
	}
	prior, err := decodeWireGuardManifestBytes([]byte(j.OldContent))
	if err != nil {
		return nil, err
	}
	target, err := decodeWireGuardManifestBytes([]byte(j.TargetContent))
	if err != nil || !filesystemBindingOnlyAddsUUIDs(prior, target) {
		return nil, fmt.Errorf("filesystem binding changes fields beyond verified UUID evidence")
	}
	wire, err := json.MarshalIndent(j, "", "  ")
	return append(wire, '\n'), err
}

func filesystemBindingOnlyAddsUUIDs(prior, target wireguardstate.Manifest) bool {
	if prior.Schema != target.Schema || len(prior.Artifacts) != len(target.Artifacts) ||
		(prior.OpenRCServiceLink == nil) != (target.OpenRCServiceLink == nil) {
		return false
	}
	changed := false
	for i, old := range prior.Artifacts {
		current := target.Artifacts[i]
		if !wireguardstate.ValidFilesystemUUID(current.FilesystemUUID) ||
			(old.FilesystemUUID != "" && old.FilesystemUUID != current.FilesystemUUID) {
			return false
		}
		changed = changed || old.FilesystemUUID != current.FilesystemUUID
		current.FilesystemUUID = old.FilesystemUUID
		if current != old {
			return false
		}
	}
	if prior.OpenRCServiceLink != nil {
		old, current := *prior.OpenRCServiceLink, *target.OpenRCServiceLink
		if !wireguardstate.ValidFilesystemUUID(current.FilesystemUUID) ||
			(old.FilesystemUUID != "" && old.FilesystemUUID != current.FilesystemUUID) {
			return false
		}
		changed = changed || old.FilesystemUUID != current.FilesystemUUID
		current.FilesystemUUID = old.FilesystemUUID
		if current != old {
			return false
		}
	}
	return changed
}

func decodeWireGuardFilesystemBinding(wire []byte) (wireGuardFilesystemBindingJournal, error) {
	var journal wireGuardFilesystemBindingJournal
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&journal); err != nil {
		return journal, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return journal, fmt.Errorf("filesystem binding journal has trailing data")
	}
	canonical, err := canonicalWireGuardFilesystemBinding(journal)
	if err != nil {
		return journal, err
	}
	if !bytes.Equal(canonical, wire) {
		return journal, fmt.Errorf("filesystem binding journal is not canonical")
	}
	return journal, nil
}

func recoverWireGuardFilesystemBinding() error {
	journalPresent, err := wireGuardPrivatePathPresent(wireGuardFilesystemBindingPath)
	if err != nil {
		return err
	}
	stageExists, err := wireGuardPrivatePathPresent("/etc/wireguard/" + wireGuardFilesystemBindingStage)
	if err != nil || (!journalPresent && !stageExists) {
		return err
	}
	directory, err := openAttestedWireGuardDirectory("etc/wireguard", 0700)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	journalIdentity, wire, present, err := readWireGuardExactFileAt(directory,
		filepath.Base(wireGuardFilesystemBindingPath), maximumForwardingTransitionBytes)
	if err != nil {
		return err
	}
	stage, stageWire, stagePresent, err := readWireGuardExactFileAt(directory, wireGuardFilesystemBindingStage, 32<<10)
	if err != nil {
		return err
	}
	if !present {
		if stagePresent {
			return fmt.Errorf("orphaned filesystem binding stage has no durable ownership evidence")
		}
		return nil
	}
	journal, err := decodeWireGuardFilesystemBinding(wire)
	if err != nil {
		return err
	}
	target, err := decodeWireGuardManifestBytes([]byte(journal.TargetContent))
	if err != nil {
		return err
	}
	if err := wireguardstate.VerifyManifest(wireGuardFilesystemRoot, target,
		wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID); err != nil {
		return fmt.Errorf("reattest filesystem-bound artifacts before recovery: %w", err)
	}
	active, activeWire, activePresent, err := readWireGuardExactFileAt(directory, filepath.Base(wireguardstate.ManifestPath), 32<<10)
	if err != nil || !activePresent {
		return errors.Join(fmt.Errorf("filesystem binding active manifest is unavailable"), err)
	}
	activeOld := bytes.Equal(activeWire, []byte(journal.OldContent)) && sameWireGuardExactFile(active, journal.OldManifest)
	activeNew := bytes.Equal(activeWire, []byte(journal.TargetContent))
	if !activeOld && !activeNew {
		return fmt.Errorf("filesystem binding active manifest was replaced or changed")
	}
	if activeOld {
		if stagePresent && !bytes.Equal(stageWire, []byte(journal.TargetContent)) {
			return fmt.Errorf("filesystem binding stage contains unrecognized content")
		}
		if !stagePresent {
			stage, err = createWireGuardExactFileAt(directory, wireGuardFilesystemBindingStage, []byte(journal.TargetContent))
			if err != nil {
				return err
			}
		}
		if err := wireGuardFilesystemBindingFault("manifest-staged"); err != nil {
			return err
		}
		current, currentWire, currentPresent, err := readWireGuardExactFileAt(directory, filepath.Base(wireguardstate.ManifestPath), 32<<10)
		if err != nil || !currentPresent || !sameWireGuardExactFile(current, active) || !bytes.Equal(currentWire, activeWire) {
			return errors.Join(fmt.Errorf("filesystem binding active manifest changed before exchange"), err)
		}
		expectedStage := stage
		if err := exchangeWireGuardFiles(directory, filepath.Base(wireguardstate.ManifestPath), wireGuardFilesystemBindingStage); err != nil {
			return err
		}
		current, currentWire, currentPresent, err = readWireGuardExactFileAt(directory, filepath.Base(wireguardstate.ManifestPath), 32<<10)
		if err != nil || !currentPresent || !sameWireGuardExactFile(current, expectedStage) || !bytes.Equal(currentWire, []byte(journal.TargetContent)) {
			restoreErr := exchangeWireGuardFiles(directory, filepath.Base(wireguardstate.ManifestPath), wireGuardFilesystemBindingStage)
			return errors.Join(fmt.Errorf("filesystem binding target changed during exchange"), err, restoreErr)
		}
		stage, stageWire, stagePresent, err = readWireGuardExactFileAt(directory, wireGuardFilesystemBindingStage, 32<<10)
		if err != nil || !stagePresent || !sameWireGuardExactFile(stage, journal.OldManifest) || !bytes.Equal(stageWire, []byte(journal.OldContent)) {
			restoreErr := exchangeWireGuardFiles(directory, filepath.Base(wireguardstate.ManifestPath), wireGuardFilesystemBindingStage)
			return errors.Join(fmt.Errorf("filesystem binding prior manifest changed during exchange"), err, restoreErr)
		}
		if err := wireGuardFilesystemBindingFault("manifest-exchanged"); err != nil {
			return err
		}
	}
	if stagePresent {
		if !sameWireGuardExactFile(stage, journal.OldManifest) || !bytes.Equal(stageWire, []byte(journal.OldContent)) {
			return fmt.Errorf("filesystem binding prior manifest stage no longer matches its journal")
		}
		if err := removeExactWireGuardFileAt(directory, wireGuardFilesystemBindingStage, stage, 32<<10); err != nil {
			return err
		}
	}
	if err := wireGuardFilesystemBindingFault("prior-removed"); err != nil {
		return err
	}
	if _, err := wireguardstate.ReadAndVerify(wireGuardFilesystemRoot, wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID); err != nil {
		return err
	}
	return removeExactWireGuardFileAt(directory, filepath.Base(wireGuardFilesystemBindingPath), journalIdentity, maximumForwardingTransitionBytes)
}

// Called only under the activation guard in the mutation phase. UUID-free
// records must first match their original device, inode, metadata and digest.
func bindVerifiedWireGuardFilesystems() error {
	if err := recoverWireGuardFilesystemBinding(); err != nil {
		return err
	}
	prior, err := wireguardstate.ReadAndVerify(wireGuardFilesystemRoot, wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID)
	if err != nil {
		return err
	}
	actual, err := wireguardstate.CaptureManifest(wireGuardFilesystemRoot, wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID)
	if err != nil {
		return err
	}
	target := prior
	target.Artifacts = append([]wireguardstate.Artifact(nil), prior.Artifacts...)
	for i, old := range prior.Artifacts {
		if !wireguardstate.MatchesRecordedArtifact(actual.Artifacts[i], old) {
			return fmt.Errorf("artifact changed before filesystem binding")
		}
		target.Artifacts[i].FilesystemUUID = actual.Artifacts[i].FilesystemUUID
	}
	if prior.OpenRCServiceLink != nil {
		link, present, err := wireguardstate.InspectOpenRCServiceLink(wireGuardFilesystemRoot, wireGuardExpectedOwnerUID, wireGuardExpectedOwnerGID)
		if err != nil || !present || !wireguardstate.MatchesRecordedServiceLink(link, *prior.OpenRCServiceLink) {
			return errors.Join(fmt.Errorf("service link changed before filesystem binding"), err)
		}
		targetLink := *prior.OpenRCServiceLink
		targetLink.FilesystemUUID = link.FilesystemUUID
		target.OpenRCServiceLink = &targetLink
	}
	oldWire, err := canonicalWireGuardManifestBytes(prior)
	if err != nil {
		return err
	}
	targetWire, err := canonicalWireGuardManifestBytes(target)
	if err != nil || bytes.Equal(oldWire, targetWire) {
		return err
	}
	directory, err := openAttestedWireGuardDirectory("etc/wireguard", 0700)
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	oldIdentity, currentWire, present, err := readWireGuardExactFileAt(directory, filepath.Base(wireguardstate.ManifestPath), 32<<10)
	if err != nil || !present || !bytes.Equal(currentWire, oldWire) {
		return errors.Join(fmt.Errorf("manifest changed before filesystem binding"), err)
	}
	journal := wireGuardFilesystemBindingJournal{Schema: wireGuardFilesystemBindingSchema,
		OldManifest: oldIdentity, OldContent: string(oldWire), TargetContent: string(targetWire)}
	wire, err := canonicalWireGuardFilesystemBinding(journal)
	if err != nil {
		return err
	}
	if _, err := createWireGuardExactFileAt(directory, filepath.Base(wireGuardFilesystemBindingPath), wire); err != nil {
		return err
	}
	if err := wireGuardFilesystemBindingFault("journal-published"); err != nil {
		return err
	}
	return recoverWireGuardFilesystemBinding()
}
