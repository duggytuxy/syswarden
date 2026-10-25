//go:build linux

package wireguardstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"reflect"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	PolicyTransitionPath                = "/etc/wireguard/.syswarden-policy-transition-v1.json"
	PolicyTransitionReceiptPath         = "/etc/wireguard/.syswarden-policy-transition-v1.complete.json"
	policyTransitionPreparedPath        = "/etc/wireguard/.syswarden-policy-transition-v1.prepared.json"
	policyTransitionFinalizingPath      = "/etc/wireguard/.syswarden-policy-transition-v1.finalizing.json"
	policyTransitionServerStage         = "/etc/wireguard/.wg-syswarden.conf.syswarden-policy-stage-v1"
	policyTransitionManifestStage       = "/etc/wireguard/.syswarden-ownership-v1.json.policy-stage-v1"
	PolicyTransitionServerArchivePath   = "/etc/wireguard/.wg-syswarden.conf.syswarden-policy-source-v1"
	PolicyTransitionManifestArchivePath = "/etc/wireguard/.syswarden-ownership-v1.json.policy-source-v1"
	policyTransitionIntentSchema        = "syswarden-owned-wireguard-policy-intent-v1"
	policyTransitionRecordSchema        = "syswarden-owned-wireguard-policy-successor-v1"
)

var policyTransitionFault = func(string) error { return nil }

var policyTransitionPendingPaths = [...]string{
	PolicyTransitionPath, policyTransitionFinalizingPath, policyTransitionPreparedPath,
	policyTransitionServerStage, policyTransitionManifestStage,
}

// RefusePendingPolicyTransition is a bounded no-follow presence guard. Unsafe
// entries and orphaned stages block ordinary operations without being opened or
// removed. Completed lineage is verified independently of current live files,
// allowing exact ordinary forwarding and removal transactions to recover.
func RefusePendingPolicyTransition(root string) error {
	for _, path := range policyTransitionPendingPaths {
		present, err := inventoryLogicalExists(root, path)
		if err != nil || present {
			return errors.Join(fmt.Errorf("owned WireGuard policy transition requires explicit recovery; preserve %s", path), err)
		}
	}
	var present []bool
	for _, path := range []string{PolicyTransitionReceiptPath, PolicyTransitionServerArchivePath, PolicyTransitionManifestArchivePath} {
		exists, err := inventoryLogicalExists(root, path)
		if err != nil {
			return err
		}
		present = append(present, exists)
	}
	if !present[0] && !present[1] && !present[2] {
		return nil
	}
	if !present[0] || !present[1] || !present[2] {
		return fmt.Errorf("incomplete owned WireGuard policy lineage must be preserved")
	}
	// Inventory directories derive their owner from the protected root. Never
	// trust a receipt's own claimed uid/gid to authorize its contents.
	directory, err := openPinnedInventoryDirectory(root, filepath.Dir(PolicyTransitionReceiptPath))
	if err != nil {
		return err
	}
	info, statErr := directory.file.Stat()
	closeErr := directory.file.Close()
	if err := errors.Join(statErr, closeErr); err != nil {
		return err
	}
	owner, err := statIdentity(info)
	if err != nil {
		return err
	}
	lineage, err := inspectPolicyTransition(root, owner.Uid, owner.Gid, true)
	if err != nil {
		return err
	}
	if !lineage.Complete || lineage.State != "lineage" {
		return fmt.Errorf("policy transition appeared during lineage inspection")
	}
	return nil
}

type policyTransitionIntent struct {
	Schema              string                      `json:"schema"`
	Manifest            Manifest                    `json:"source_manifest"`
	ManifestArtifact    Artifact                    `json:"source_manifest_artifact"`
	OriginalArtifacts   []Artifact                  `json:"original_artifacts"`
	OriginalServiceLink *SymlinkArtifact            `json:"original_service_link,omitempty"`
	ManifestContent     string                      `json:"source_manifest_bytes"`
	Source              ServerConfigurationIdentity `json:"source"`
	Target              ServerConfigurationIdentity `json:"target"`
	TargetSHA256        string                      `json:"target_server_sha256"`
	Predecessor         []Artifact                  `json:"predecessor"`
}

// The prepared record is immutable. Its rename to the receipt records file
// commitment only. It neither records nor implies service or runtime acceptance.
type policyTransitionRecord struct {
	Schema         string                 `json:"schema"`
	Intent         policyTransitionIntent `json:"intent"`
	IntentArtifact Artifact               `json:"intent_artifact"`
	Server         Artifact               `json:"target_server"`
	Manifest       Artifact               `json:"target_manifest"`
}

// PolicyTransitionSnapshot contains no server/client configuration bytes.
// FilesCommitted means that the target pair and private original archives are
// durable. Complete means explicit Finalize removed the pending file debt; it
// does not establish runtime health or qualify the missing host-start fence.
type PolicyTransitionSnapshot struct {
	State           string                      `json:"state"`
	FilesCommitted  bool                        `json:"files_committed"`
	Complete        bool                        `json:"complete"`
	Journal         *Artifact                   `json:"journal,omitempty"`
	Prepared        *Artifact                   `json:"prepared,omitempty"`
	Receipt         *Artifact                   `json:"receipt,omitempty"`
	Source          ServerConfigurationIdentity `json:"source"`
	Target          ServerConfigurationIdentity `json:"target"`
	ServerArchive   *Artifact                   `json:"server_archive,omitempty"`
	ManifestArchive *Artifact                   `json:"manifest_archive,omitempty"`
	intent          policyTransitionIntent
	record          policyTransitionRecord
	serverStage     *Artifact
	manifestStage   *Artifact
	serverLive      Artifact
	manifestLive    Artifact
	serverBytes     []byte
	targetBytes     []byte
	finalizing      bool
}

func policyArtifactAt(record Artifact, path string) Artifact {
	record.Path = path
	return record
}

func policySameAt(actual *Artifact, expected Artifact) bool {
	return actual != nil && sameArtifact(*actual, policyArtifactAt(expected, actual.Path))
}

func policyCanonical(value any) ([]byte, error) {
	wire, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return wire, nil
}

func policyDecode(wire []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("invalid owned policy transition record")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return fmt.Errorf("owned policy transition record has trailing data")
	}
	canonical, err := policyCanonical(value)
	if err != nil || !bytes.Equal(canonical, wire) {
		return fmt.Errorf("noncanonical owned policy transition record")
	}
	return nil
}

func validatePolicyIntent(intent policyTransitionIntent, uid, gid uint32) error {
	manifestWire, err := canonicalManifestBytes(intent.Manifest, uid, gid)
	if err != nil || intent.Schema != policyTransitionIntentSchema || string(manifestWire) != intent.ManifestContent ||
		!validPlannedOrExactArtifact(intent.ManifestArtifact, ManifestPath, uid, gid) || intent.ManifestArtifact.Inode == 0 ||
		plannedArtifact(ManifestPath, manifestWire, uid, gid).SHA256 != intent.ManifestArtifact.SHA256 ||
		intent.Source.PolicyVersion != 0 || intent.Target.PolicyVersion != 2 ||
		!wireGuardOwnershipTokenPattern.MatchString(intent.TargetSHA256) {
		return fmt.Errorf("invalid owned policy transition intent")
	}
	if len(intent.OriginalArtifacts) != len(intent.Manifest.Artifacts) {
		return fmt.Errorf("incomplete bound policy source")
	}
	for index, actual := range intent.OriginalArtifacts {
		if !sameArtifact(actual, intent.Manifest.Artifacts[index]) {
			return fmt.Errorf("bound policy source differs from original manifest")
		}
	}
	if !policySameLink(intent.OriginalServiceLink, intent.Manifest.OpenRCServiceLink) {
		return fmt.Errorf("bound policy service link differs from original manifest")
	}
	if len(intent.Predecessor) != 0 && len(intent.Predecessor) != 5 {
		return fmt.Errorf("incomplete owned policy predecessor inventory")
	}
	for index, artifact := range intent.Predecessor {
		paths := []string{LegacyMigrationReceiptPath, LegacyMigrationBackupPath(ServerConfigurationPath),
			LegacyMigrationBackupPath(ClientConfigurationPath), LegacyMigrationBackupPath(ForwardingConfigurationPath), legacyMigrationOriginal}
		if !validPlannedOrExactArtifact(artifact, paths[index], uid, gid) || artifact.Inode == 0 {
			return fmt.Errorf("invalid owned policy predecessor identity")
		}
	}
	return nil
}

func policyTargetManifest(intent policyTransitionIntent, server Artifact, uid, gid uint32) (Manifest, []byte, error) {
	target := intent.Manifest
	target.Artifacts = append([]Artifact(nil), intent.Manifest.Artifacts...)
	target.Artifacts[0] = policyArtifactAt(server, ServerConfigurationPath)
	wire, err := canonicalManifestBytes(target, uid, gid)
	return target, wire, err
}

func validatePolicyRecord(record policyTransitionRecord, intent policyTransitionIntent, uid, gid uint32) error {
	if record.Schema != policyTransitionRecordSchema || !reflect.DeepEqual(record.Intent, intent) {
		return fmt.Errorf("policy successor does not bind its exact intent")
	}
	wire, err := policyCanonical(intent)
	if err != nil || !validPlannedOrExactArtifact(record.IntentArtifact, PolicyTransitionPath, uid, gid) || record.IntentArtifact.Inode == 0 ||
		record.IntentArtifact.SHA256 != plannedArtifact(PolicyTransitionPath, wire, uid, gid).SHA256 {
		return fmt.Errorf("policy successor does not bind its intent file")
	}
	for _, item := range []struct {
		record Artifact
		path   string
	}{{record.Server, ServerConfigurationPath}, {record.Manifest, ManifestPath}} {
		if !validPlannedOrExactArtifact(item.record, item.path, uid, gid) || item.record.Inode == 0 {
			return fmt.Errorf("invalid prepared policy identity")
		}
	}
	_, targetWire, err := policyTargetManifest(intent, record.Server, uid, gid)
	if err != nil || record.Server.SHA256 != intent.TargetSHA256 || record.Manifest.SHA256 != plannedArtifact(ManifestPath, targetWire, uid, gid).SHA256 {
		return fmt.Errorf("prepared policy target differs from the exact successor")
	}
	return nil
}

func policyOtherTransactionsAbsent(root string) error {
	for _, path := range []string{LegacyMigrationPath, ForwardingTransitionPath,
		"/etc/wireguard/.syswarden-filesystem-binding-v1.json", "/etc/wireguard/.syswarden-ownership-v1.json.filesystem-stage"} {
		if exists, err := inventoryLogicalExists(root, path); err != nil || exists {
			return errors.Join(fmt.Errorf("another WireGuard transition blocks owned policy replacement"), err)
		}
	}
	for _, location := range []struct{ directory, prefix string }{
		{"/etc/wireguard", ".syswarden-ownership-v1.json.stage-"},
		{"/etc/sysctl.d", ".99-syswarden-wireguard.conf.stage-"},
	} {
		directory, err := openPinnedInventoryDirectory(root, location.directory)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return err
		}
		scanErr := func() error {
			for total := 0; ; {
				names, readErr := directory.file.Readdirnames(128)
				total += len(names)
				if total > 4096 {
					return fmt.Errorf("WireGuard transition directory inventory exceeds its bound")
				}
				for _, name := range names {
					if strings.HasPrefix(name, location.prefix) {
						return fmt.Errorf("orphaned forwarding publication stage blocks policy replacement")
					}
				}
				if errors.Is(readErr, io.EOF) {
					return nil
				}
				if readErr != nil {
					return readErr
				}
			}
		}()
		if err := errors.Join(scanErr, directory.file.Close()); err != nil {
			return err
		}
	}
	inventory, err := inspectInventory(root)
	if err != nil || inventory.Transaction {
		return errors.Join(fmt.Errorf("another WireGuard ownership transaction blocks policy replacement"), err)
	}
	return nil
}

func policyVerifyCompanions(root string, intent policyTransitionIntent, uid, gid uint32) error {
	for _, artifact := range intent.OriginalArtifacts[1:] {
		actual, _, err := captureLogical(root, artifact.Path, uid, gid, maximumOwnedArtifactBytes)
		if err != nil || !sameArtifact(actual, artifact) {
			return errors.Join(fmt.Errorf("owned policy companion changed"), err)
		}
	}
	if intent.OriginalServiceLink != nil {
		actual, present, err := InspectOpenRCServiceLink(root, uid, gid)
		if err != nil || !present || !sameSymlinkArtifact(actual, *intent.OriginalServiceLink) {
			return errors.Join(fmt.Errorf("owned OpenRC link changed during policy transition"), err)
		}
	}
	return nil
}

// InspectPolicyTransition classifies only exact, ordered publication states.
// It is read-only even for corrupt, interrupted or orphaned transition files.
func InspectPolicyTransition(root string, uid, gid uint32) (PolicyTransitionSnapshot, error) {
	return inspectPolicyTransition(root, uid, gid, false)
}

// lineageOnly proves sealed originals without inspecting mutable live paths.
// It is used by ordinary recovery, which may have already removed an exact file.
func inspectPolicyTransition(root string, uid, gid uint32, lineageOnly bool) (PolicyTransitionSnapshot, error) {
	var snapshot PolicyTransitionSnapshot
	if !lineageOnly {
		if err := policyOtherTransactionsAbsent(root); err != nil {
			return snapshot, err
		}
	}
	journal, journalWire, err := captureMigrationOptional(root, PolicyTransitionPath, uid, gid)
	if err != nil {
		return snapshot, err
	}
	finalizing, finalizingWire, err := captureMigrationOptional(root, policyTransitionFinalizingPath, uid, gid)
	if err != nil || (journal != nil && finalizing != nil) {
		return snapshot, errors.Join(fmt.Errorf("ambiguous owned policy finalization"), err)
	}
	if finalizing != nil {
		journal, journalWire, snapshot.finalizing = finalizing, finalizingWire, true
	}
	prepared, preparedWire, err := captureMigrationOptional(root, policyTransitionPreparedPath, uid, gid)
	if err != nil {
		return snapshot, err
	}
	receipt, receiptWire, err := captureMigrationOptional(root, PolicyTransitionReceiptPath, uid, gid)
	if err != nil || (prepared != nil && receipt != nil) {
		return snapshot, errors.Join(fmt.Errorf("ambiguous owned policy successor records"), err)
	}
	serverStage, _, err := captureMigrationOptional(root, policyTransitionServerStage, uid, gid)
	if err != nil {
		return snapshot, err
	}
	manifestStage, manifestStageWire, err := captureMigrationOptional(root, policyTransitionManifestStage, uid, gid)
	if err != nil {
		return snapshot, err
	}
	serverArchive, archiveServerWire, err := captureMigrationOptional(root, PolicyTransitionServerArchivePath, uid, gid)
	if err != nil {
		return snapshot, err
	}
	manifestArchive, archiveManifestWire, err := captureMigrationOptional(root, PolicyTransitionManifestArchivePath, uid, gid)
	if err != nil {
		return snapshot, err
	}
	if journal == nil && receipt == nil {
		if prepared != nil || serverStage != nil || manifestStage != nil || serverArchive != nil || manifestArchive != nil {
			return snapshot, fmt.Errorf("orphaned policy transition evidence must be preserved")
		}
		return snapshot, nil
	}
	if journal != nil {
		if err := policyDecode(journalWire, &snapshot.intent); err != nil {
			return snapshot, err
		}
	} else {
		if err := policyDecode(receiptWire, &snapshot.record); err != nil {
			return snapshot, err
		}
		snapshot.intent = snapshot.record.Intent
	}
	intent := snapshot.intent
	if err := validatePolicyIntent(intent, uid, gid); err != nil {
		return snapshot, err
	}
	snapshot.Journal, snapshot.Prepared, snapshot.Receipt = journal, prepared, receipt
	snapshot.Source, snapshot.Target = intent.Source, intent.Target
	snapshot.ServerArchive, snapshot.ManifestArchive = serverArchive, manifestArchive
	snapshot.serverStage, snapshot.manifestStage = serverStage, manifestStage
	if prepared != nil || receipt != nil {
		wire := preparedWire
		if receipt != nil {
			wire = receiptWire
		}
		if err := policyDecode(wire, &snapshot.record); err != nil {
			return snapshot, err
		}
		if err := validatePolicyRecord(snapshot.record, intent, uid, gid); err != nil {
			return snapshot, err
		}
		if journal != nil && !policySameAt(journal, snapshot.record.IntentArtifact) {
			return snapshot, fmt.Errorf("owned policy intent file changed after preparation")
		}
	}
	if err := verifyPolicyPredecessor(root, intent, uid, gid); err != nil {
		return snapshot, err
	}
	var liveServer, liveManifest *Artifact
	var liveServerWire, liveManifestWire []byte
	if !lineageOnly {
		liveServer, liveServerWire, err = captureMigrationOptional(root, ServerConfigurationPath, uid, gid)
		if err != nil {
			return snapshot, err
		}
		liveManifest, liveManifestWire, err = captureMigrationOptional(root, ManifestPath, uid, gid)
		if err != nil {
			return snapshot, err
		}
	}
	oldServer, oldManifest := intent.OriginalArtifacts[0], intent.ManifestArtifact
	oldServerLive := policySameAt(liveServer, oldServer)
	oldManifestLive := policySameAt(liveManifest, oldManifest) && string(liveManifestWire) == intent.ManifestContent
	oldServerStage := policySameAt(serverStage, oldServer)
	oldManifestStage := policySameAt(manifestStage, oldManifest) && string(manifestStageWire) == intent.ManifestContent
	oldServerArchive := policySameAt(serverArchive, oldServer)
	oldManifestArchive := policySameAt(manifestArchive, oldManifest) && string(archiveManifestWire) == intent.ManifestContent
	if (serverArchive != nil && !oldServerArchive) || (manifestArchive != nil && !oldManifestArchive) {
		return snapshot, fmt.Errorf("owned policy original archive changed")
	}
	if (oldServerStage && oldServerArchive) || (oldManifestStage && oldManifestArchive) {
		return snapshot, fmt.Errorf("duplicate owned policy originals")
	}
	var sourceWire []byte
	switch {
	case oldServerLive:
		sourceWire = liveServerWire
	case oldServerStage:
		_, sourceWire, err = captureLogical(root, policyTransitionServerStage, uid, gid, maximumOwnedArtifactBytes)
	case oldServerArchive:
		sourceWire = archiveServerWire
	default:
		return snapshot, fmt.Errorf("owned policy original server is missing")
	}
	if err != nil {
		return snapshot, err
	}
	source, err := ParseServerConfiguration(sourceWire)
	if err != nil || source != intent.Source {
		return snapshot, fmt.Errorf("owned policy original server identity changed")
	}
	targetWire, err := ScopedServerConfiguration(sourceWire)
	if err != nil {
		return snapshot, err
	}
	target, err := ParseServerConfiguration(targetWire)
	if err != nil || target != intent.Target || plannedArtifact(ServerConfigurationPath, targetWire, uid, gid).SHA256 != intent.TargetSHA256 {
		return snapshot, fmt.Errorf("owned policy successor changed")
	}
	snapshot.serverBytes, snapshot.targetBytes = sourceWire, targetWire
	if liveServer != nil {
		snapshot.serverLive = *liveServer
	}
	if liveManifest != nil {
		snapshot.manifestLive = *liveManifest
	}
	if journal == nil {
		if serverStage != nil || manifestStage != nil || prepared != nil || !oldServerArchive || !oldManifestArchive {
			return snapshot, fmt.Errorf("incomplete finalized policy lineage")
		}
		if lineageOnly {
			snapshot.State, snapshot.FilesCommitted, snapshot.Complete = "lineage", true, true
			return snapshot, nil
		}
		if liveServer == nil && liveManifest == nil {
			for _, path := range canonicalArtifactPaths {
				if present, err := inventoryLogicalExists(root, path); err != nil || present {
					return snapshot, errors.Join(fmt.Errorf("partial owned removal is not retained policy lineage"), err)
				}
			}
			if intent.OriginalServiceLink != nil {
				if present, err := inventoryLogicalExists(root, OpenRCServiceLinkPath); err != nil || present {
					return snapshot, errors.Join(fmt.Errorf("owned service link remains after policy removal"), err)
				}
			}
			// Removal leaves these private archives as inert historical evidence.
			snapshot.State, snapshot.FilesCommitted, snapshot.Complete = "retained", true, true
			return snapshot, nil
		}
		if !policySameAt(liveServer, snapshot.record.Server) {
			return snapshot, fmt.Errorf("live policy differs from finalized successor")
		}
		manifest, _, err := readManifestWithRecord(root, uid, gid)
		if err != nil {
			return snapshot, err
		}
		if err := VerifyManifest(root, manifest, uid, gid); err != nil {
			return snapshot, err
		}
		if err := verifyPolicyManifestSuccessor(root, manifest, snapshot.record, uid, gid); err != nil {
			return snapshot, err
		}
		snapshot.State, snapshot.FilesCommitted, snapshot.Complete = "complete", true, true
		return snapshot, nil
	}
	if err := policyVerifyCompanions(root, intent, uid, gid); err != nil {
		return snapshot, err
	}
	if prepared == nil && receipt == nil {
		if !oldServerLive || !oldManifestLive || serverArchive != nil || manifestArchive != nil || snapshot.finalizing {
			return snapshot, fmt.Errorf("policy publication began without sealed target identities")
		}
		if manifestStage != nil && serverStage == nil {
			return snapshot, fmt.Errorf("policy manifest stage has no server stage")
		}
		if serverStage != nil {
			if serverStage.SHA256 != intent.TargetSHA256 {
				return snapshot, fmt.Errorf("policy server stage changed")
			}
			_, targetManifestWire, err := policyTargetManifest(intent, *serverStage, uid, gid)
			if err != nil || (manifestStage != nil && !bytes.Equal(manifestStageWire, targetManifestWire)) {
				return snapshot, fmt.Errorf("policy manifest stage changed")
			}
		}
		snapshot.State = "intent"
		return snapshot, nil
	}
	newServerLive := policySameAt(liveServer, snapshot.record.Server)
	newManifestLive := policySameAt(liveManifest, snapshot.record.Manifest)
	newServerStage := policySameAt(serverStage, snapshot.record.Server)
	newManifestStage := policySameAt(manifestStage, snapshot.record.Manifest)
	switch {
	case oldServerLive && oldManifestLive && newServerStage && newManifestStage && serverArchive == nil && manifestArchive == nil && receipt == nil:
		snapshot.State = "prepared"
	case newServerLive && oldManifestLive && oldServerStage && newManifestStage && serverArchive == nil && manifestArchive == nil && receipt == nil:
		snapshot.State = "server-published"
	case newServerLive && newManifestLive && (oldServerStage || oldServerArchive) && (oldManifestStage || oldManifestArchive):
		if (serverStage != nil && !oldServerStage) || (manifestStage != nil && !oldManifestStage) || (oldManifestArchive && !oldServerArchive) {
			return snapshot, fmt.Errorf("policy original archival order is invalid")
		}
		snapshot.State = "pair-published"
		if oldServerArchive && oldManifestArchive {
			snapshot.State = "originals-archived"
			if receipt != nil {
				snapshot.State, snapshot.FilesCommitted = "files-committed", true
			}
		} else if receipt != nil {
			return snapshot, fmt.Errorf("policy receipt precedes complete original archival")
		}
	default:
		return snapshot, fmt.Errorf("unrecognized mixed owned policy publication state")
	}
	if snapshot.finalizing && !snapshot.FilesCommitted {
		return snapshot, fmt.Errorf("policy finalization precedes file commitment")
	}
	return snapshot, nil
}

// The untouched historical records may lack UUIDs. Accept those exact records
// or a later binding to the independently captured original. Callers must first
// VerifyManifest so this comparison cannot adopt an unverified manifest.
func verifyPolicyManifestSuccessor(root string, manifest Manifest, record policyTransitionRecord, uid, gid uint32) error {
	intent := record.Intent
	clientUnchanged := reflect.DeepEqual(manifest.Artifacts[1], intent.Manifest.Artifacts[1])
	linkUnchanged := reflect.DeepEqual(manifest.OpenRCServiceLink, intent.Manifest.OpenRCServiceLink)
	if !sameArtifact(manifest.Artifacts[0], record.Server) ||
		(!clientUnchanged && !sameArtifact(manifest.Artifacts[1], intent.OriginalArtifacts[1])) ||
		(!linkUnchanged && !policySameLink(manifest.OpenRCServiceLink, intent.OriginalServiceLink)) {
		return fmt.Errorf("finalized successor ownership lineage changed")
	}
	// An unchanged UUID-free envelope is preserved, but must not downgrade the
	// stronger filesystem evidence captured independently before replacement.
	client, _, err := captureLogical(root, ClientConfigurationPath, uid, gid, maximumOwnedArtifactBytes)
	if err != nil || !sameArtifact(client, intent.OriginalArtifacts[1]) {
		return errors.Join(fmt.Errorf("live client differs from bound policy source"), err)
	}
	if intent.OriginalServiceLink != nil {
		link, present, err := InspectOpenRCServiceLink(root, uid, gid)
		if err != nil || !present || !sameSymlinkArtifact(link, *intent.OriginalServiceLink) {
			return errors.Join(fmt.Errorf("live service link differs from bound policy source"), err)
		}
	}
	return nil
}

// Current envelope checks must allow a valid filesystem-binding journal: its
// recovery verifies the new manifest before consuming that separate journal.
// Immutable-only inspection also lets removal recovery finish partial pairs.
func verifyFinalizedPolicyManifest(root string, manifest Manifest, uid, gid uint32) error {
	present, err := inventoryLogicalExists(root, PolicyTransitionReceiptPath)
	if err != nil || !present {
		return err
	}
	lineage, err := inspectPolicyTransition(root, uid, gid, true)
	if err != nil {
		return err
	}
	if !lineage.Complete || lineage.State != "lineage" {
		return fmt.Errorf("policy lineage is not finalized")
	}
	return verifyPolicyManifestSuccessor(root, manifest, lineage.record, uid, gid)
}

func policySameLink(actual, expected *SymlinkArtifact) bool {
	if actual == nil || expected == nil {
		return actual == nil && expected == nil
	}
	return sameSymlinkArtifact(*actual, *expected)
}

// BeginPolicyTransition records file-only intent before creating any stages.
// The caller must separately hold the activation guard and a qualified durable
// service-start fence. There is intentionally no production caller yet.
func BeginPolicyTransition(root string, expected OwnedPolicySnapshot, uid, gid uint32) error {
	if err := RefusePendingPolicyTransition(root); err != nil {
		return err
	}
	if err := policyOtherTransactionsAbsent(root); err != nil {
		return err
	}
	for _, path := range []string{PolicyTransitionReceiptPath, PolicyTransitionServerArchivePath, PolicyTransitionManifestArchivePath} {
		if present, err := inventoryLogicalExists(root, path); err != nil || present {
			return errors.Join(fmt.Errorf("existing policy lineage must be preserved; new transition refused"), err)
		}
	}
	current, err := InspectOwnedPolicy(root, uid, gid)
	if err != nil || !reflect.DeepEqual(current, expected) || current.Source.PolicyVersion != 0 {
		return errors.Join(fmt.Errorf("owned policy source changed or is not v1"), err)
	}
	_, manifestWire, err := captureLogical(root, ManifestPath, uid, gid, maximumOwnershipManifestSize)
	if err != nil {
		return err
	}
	intent := policyTransitionIntent{Schema: policyTransitionIntentSchema, Manifest: current.Manifest,
		ManifestArtifact: current.ManifestArtifact, ManifestContent: string(manifestWire), Source: current.Source,
		Target: current.Target, TargetSHA256: current.TargetServerSHA256, Predecessor: []Artifact{}}
	for _, expected := range current.Manifest.Artifacts {
		actual, _, err := captureLogical(root, expected.Path, uid, gid, maximumOwnedArtifactBytes)
		if err != nil || !sameArtifact(actual, expected) {
			return errors.Join(fmt.Errorf("policy source changed before filesystem binding"), err)
		}
		intent.OriginalArtifacts = append(intent.OriginalArtifacts, actual)
	}
	if current.Manifest.OpenRCServiceLink != nil {
		actual, present, err := InspectOpenRCServiceLink(root, uid, gid)
		if err != nil || !present || !sameSymlinkArtifact(actual, *current.Manifest.OpenRCServiceLink) {
			return errors.Join(fmt.Errorf("owned service link changed before policy binding"), err)
		}
		intent.OriginalServiceLink = &actual
	}
	if current.PredecessorReceipt != nil {
		previous, err := InspectLegacyMigration(root, uid, gid)
		if err != nil || !previous.Completed() || previous.OriginalArchive == nil || len(previous.Backups) != 3 {
			return errors.Join(fmt.Errorf("policy predecessor cannot be preserved exactly"), err)
		}
		intent.Predecessor = append(intent.Predecessor, *previous.Receipt)
		intent.Predecessor = append(intent.Predecessor, previous.Backups...)
		intent.Predecessor = append(intent.Predecessor, *previous.OriginalArchive)
	}
	if err := validatePolicyIntent(intent, uid, gid); err != nil {
		return err
	}
	if err := verifyPolicyPredecessor(root, intent, uid, gid); err != nil {
		return err
	}
	again, err := InspectOwnedPolicy(root, uid, gid)
	if err != nil || !reflect.DeepEqual(current, again) {
		return errors.Join(fmt.Errorf("owned policy changed before durable intent"), err)
	}
	wire, err := policyCanonical(intent)
	if err != nil {
		return err
	}
	if err := writeLegacyMigrationFile(root, PolicyTransitionPath, wire, uid, gid); err != nil {
		return err
	}
	return policyTransitionFault("intent")
}

// ContinuePolicyTransition rolls forward only the exact recorded file operation.
// It never changes services, runtime, companions or original evidence. Even a
// successful call retains pending intent until explicit host confirmation.
func ContinuePolicyTransition(root string, expected PolicyTransitionSnapshot, uid, gid uint32) error {
	current, err := InspectPolicyTransition(root, uid, gid)
	if err != nil || !reflect.DeepEqual(current, expected) {
		return errors.Join(fmt.Errorf("owned policy transition changed before continuation"), err)
	}
	if current.Complete {
		return nil
	}
	if current.Journal == nil || current.finalizing {
		return fmt.Errorf("owned policy transition has no continuable intent")
	}
	for steps := 0; steps < 8; steps++ {
		current, err = InspectPolicyTransition(root, uid, gid)
		if err != nil {
			return err
		}
		var point string
		switch current.State {
		case "intent":
			if current.serverStage == nil {
				err = writeLegacyMigrationFile(root, policyTransitionServerStage, current.targetBytes, uid, gid)
				point = "server-stage"
			} else if current.manifestStage == nil {
				_, wire, encodeErr := policyTargetManifest(current.intent, *current.serverStage, uid, gid)
				if encodeErr != nil {
					return encodeErr
				}
				err = writeLegacyMigrationFile(root, policyTransitionManifestStage, wire, uid, gid)
				point = "manifest-stage"
			} else {
				record := policyTransitionRecord{Schema: policyTransitionRecordSchema, Intent: current.intent,
					IntentArtifact: *current.Journal, Server: policyArtifactAt(*current.serverStage, ServerConfigurationPath), Manifest: policyArtifactAt(*current.manifestStage, ManifestPath)}
				if err := validatePolicyRecord(record, current.intent, uid, gid); err != nil {
					return err
				}
				wire, encodeErr := policyCanonical(record)
				if encodeErr != nil {
					return encodeErr
				}
				err = writeLegacyMigrationFile(root, policyTransitionPreparedPath, wire, uid, gid)
				point = "prepared"
			}
		case "prepared":
			err = renameLegacyMigrationFile(root, *current.serverStage, ServerConfigurationPath, &current.serverLive, uid, gid)
			point = "server-exchange"
		case "server-published":
			err = renameLegacyMigrationFile(root, *current.manifestStage, ManifestPath, &current.manifestLive, uid, gid)
			point = "manifest-exchange"
		case "pair-published":
			if current.ServerArchive == nil {
				err = renameLegacyMigrationFile(root, *current.serverStage, PolicyTransitionServerArchivePath, nil, uid, gid)
				point = "server-archive"
			} else {
				err = renameLegacyMigrationFile(root, *current.manifestStage, PolicyTransitionManifestArchivePath, nil, uid, gid)
				point = "manifest-archive"
			}
		case "originals-archived":
			err = renameLegacyMigrationFile(root, *current.Prepared, PolicyTransitionReceiptPath, nil, uid, gid)
			point = "receipt"
		case "files-committed":
			return nil
		default:
			return fmt.Errorf("owned policy transition cannot continue state %q", current.State)
		}
		if err != nil {
			return err
		}
		if err := policyTransitionFault(point); err != nil {
			return err
		}
	}
	final, err := InspectPolicyTransition(root, uid, gid)
	if err != nil || !final.FilesCommitted {
		return errors.Join(fmt.Errorf("owned policy file commitment did not converge"), err)
	}
	return nil
}

// FinalizePolicyTransition acknowledges file debt only after the caller has
// separately established host acceptance and exact fence restoration. This API
// establishes neither condition itself and has no production caller. A receipt
// or hash is never host authorization. Interrupted finalization remains blocked.
func FinalizePolicyTransition(root string, expected PolicyTransitionSnapshot, uid, gid uint32) error {
	current, err := InspectPolicyTransition(root, uid, gid)
	if err != nil || !reflect.DeepEqual(current, expected) {
		return errors.Join(fmt.Errorf("owned policy transition changed before explicit finalization"), err)
	}
	if current.Complete {
		return nil
	}
	if !current.FilesCommitted || current.Journal == nil {
		return fmt.Errorf("owned policy files are not committed")
	}
	record := policyArtifactAt(*current.Journal, PolicyTransitionPath)
	if err := removeExactLogical(root, record, filepath.Base(policyTransitionFinalizingPath), uid, gid); err != nil {
		return err
	}
	if err := policyTransitionFault("finalized"); err != nil {
		return err
	}
	final, err := InspectPolicyTransition(root, uid, gid)
	if err != nil || !final.Complete {
		return errors.Join(fmt.Errorf("owned policy finalization did not converge"), err)
	}
	return nil
}
