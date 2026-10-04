//go:build linux

package wireguardstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"

	"golang.org/x/sys/unix"
)

const (
	LegacyMigrationPath        = "/etc/wireguard/.syswarden-legacy-migration-v1.json"
	LegacyMigrationReceiptPath = "/etc/wireguard/.syswarden-legacy-migration-v1.complete.json"
	legacyMigrationStage       = "/etc/wireguard/.wg-syswarden.conf.syswarden-migration-v1"
	legacyMigrationOriginal    = "/etc/wireguard/.wg-syswarden.conf.syswarden-migration-original-v1"
	legacyMigrationSchema      = "syswarden-wireguard-legacy-migration-v1"
)

var legacyMigrationFault = func(string) error { return nil }

type legacyMigrationJournal struct {
	Schema       string     `json:"schema"`
	Original     []Artifact `json:"original"`
	Token        string     `json:"ownership_token"`
	ServerSHA256 string     `json:"target_server_sha256"`
}

// LegacyMigrationSnapshot contains no serializable configuration or key bytes.
// Callers must validate the exact historical templates before beginning, and
// must hold the activation guard throughout all runtime and disk mutations.
type LegacyMigrationSnapshot struct {
	Journal          *Artifact         `json:"journal,omitempty"`
	Receipt          *Artifact         `json:"receipt,omitempty"`
	Live             []Artifact        `json:"live"`
	Backups          []Artifact        `json:"backups"`
	Stage            *Artifact         `json:"stage,omitempty"`
	OriginalArchive  *Artifact         `json:"original_archive,omitempty"`
	Manifest         *Artifact         `json:"manifest,omitempty"`
	OriginalContents map[string][]byte `json:"-"`
	journal          legacyMigrationJournal
}

func LegacyMigrationBackupPath(path string) string {
	for _, allowed := range canonicalArtifactPaths {
		if path == allowed {
			return filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".syswarden-legacy-v1")
		}
	}
	return ""
}

func (snapshot LegacyMigrationSnapshot) OwnershipToken() string { return snapshot.journal.Token }
func (snapshot LegacyMigrationSnapshot) Completed() bool        { return snapshot.Receipt != nil }

func (snapshot LegacyMigrationSnapshot) OriginalArtifacts() []Artifact {
	if snapshot.Journal == nil && snapshot.Receipt == nil {
		return append([]Artifact(nil), snapshot.Live...)
	}
	return append([]Artifact(nil), snapshot.journal.Original...)
}

func captureMigrationOptional(root, path string, uid, gid uint32) (*Artifact, []byte, error) {
	present, err := inventoryLogicalExists(root, path)
	if err != nil || !present {
		return nil, nil, err
	}
	record, content, err := captureLogical(root, path, uid, gid, maximumOwnedArtifactBytes)
	if err != nil {
		return nil, nil, err
	}
	return &record, content, nil
}

func decodeLegacyMigration(content []byte, uid, gid uint32) (legacyMigrationJournal, error) {
	var journal legacyMigrationJournal
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&journal); err != nil {
		return journal, fmt.Errorf("invalid legacy migration journal")
	}
	canonical, err := json.Marshal(journal)
	if err != nil || !bytes.Equal(canonical, content) || journal.Schema != legacyMigrationSchema ||
		!wireGuardOwnershipTokenPattern.MatchString(journal.Token) ||
		!wireGuardOwnershipTokenPattern.MatchString(journal.ServerSHA256) || len(journal.Original) != len(canonicalArtifactPaths) {
		return journal, fmt.Errorf("noncanonical legacy migration journal")
	}
	for index, path := range canonicalArtifactPaths {
		if !validPlannedOrExactArtifact(journal.Original[index], path, uid, gid) || journal.Original[index].Inode == 0 {
			return journal, fmt.Errorf("invalid original legacy migration identity")
		}
	}
	return journal, nil
}

// InspectLegacyMigration is read-only, including when a previous apply stopped
// between publication phases. Backups remain permanently outside active paths.
func InspectLegacyMigration(root string, uid, gid uint32) (LegacyMigrationSnapshot, error) {
	snapshot := LegacyMigrationSnapshot{OriginalContents: make(map[string][]byte)}
	journal, journalBytes, err := captureMigrationOptional(root, LegacyMigrationPath, uid, gid)
	if err != nil {
		return snapshot, err
	}
	receipt, receiptBytes, err := captureMigrationOptional(root, LegacyMigrationReceiptPath, uid, gid)
	if err != nil {
		return snapshot, err
	}
	if journal != nil && receipt != nil {
		return snapshot, fmt.Errorf("legacy migration journal and completion receipt coexist")
	}
	snapshot.Journal, snapshot.Receipt = journal, receipt
	if receipt != nil {
		journalBytes = receiptBytes
	}
	if journal != nil || receipt != nil {
		snapshot.journal, err = decodeLegacyMigration(journalBytes, uid, gid)
		if err != nil {
			return snapshot, err
		}
	}
	inventory, err := inspectInventory(root)
	if err != nil {
		return snapshot, err
	}
	if inventory.Transaction {
		return snapshot, fmt.Errorf("another WireGuard ownership transaction is pending")
	}
	if journal == nil && receipt == nil && inventory.Manifest {
		return snapshot, fmt.Errorf("current WireGuard state already has an ownership manifest")
	}
	snapshot.Stage, _, err = captureMigrationOptional(root, legacyMigrationStage, uid, gid)
	if err != nil {
		return snapshot, err
	}
	snapshot.OriginalArchive, _, err = captureMigrationOptional(root, legacyMigrationOriginal, uid, gid)
	if err != nil {
		return snapshot, err
	}
	if journal == nil && receipt == nil && (snapshot.Stage != nil || snapshot.OriginalArchive != nil) {
		return snapshot, fmt.Errorf("unjournaled legacy migration files exist; preserve them for inspection")
	}
	for index, path := range canonicalArtifactPaths {
		live, content, err := captureLogical(root, path, uid, gid, maximumOwnedArtifactBytes)
		if err != nil {
			return snapshot, err
		}
		snapshot.Live = append(snapshot.Live, live)
		backupPath := LegacyMigrationBackupPath(path)
		backup, backupContent, err := captureMigrationOptional(root, backupPath, uid, gid)
		if err != nil {
			return snapshot, err
		}
		if journal == nil && receipt == nil {
			if backup != nil {
				return snapshot, fmt.Errorf("legacy migration backup already exists without a journal; refusing overwrite")
			}
			snapshot.OriginalContents[path] = content
			continue
		}
		original := snapshot.journal.Original[index]
		if backup != nil {
			planned := original
			planned.Path = backupPath
			planned.Device, planned.Inode = 0, 0
			if !artifactMatchesPlan(*backup, planned) {
				return snapshot, fmt.Errorf("legacy migration backup does not match its journal")
			}
			snapshot.Backups = append(snapshot.Backups, *backup)
			snapshot.OriginalContents[path] = backupContent
		} else if sameArtifact(live, original) {
			snapshot.OriginalContents[path] = content
		} else {
			return snapshot, fmt.Errorf("legacy migration original evidence is missing")
		}
		if index == 0 {
			if !sameArtifact(live, original) && live.SHA256 != snapshot.journal.ServerSHA256 {
				return snapshot, fmt.Errorf("legacy migration server changed outside its journal")
			}
		} else if receipt == nil && !sameArtifact(live, original) {
			return snapshot, fmt.Errorf("legacy migration companion artifact changed")
		}
	}
	if journal != nil || receipt != nil {
		original := snapshot.journal.Original[0]
		if snapshot.Stage != nil {
			stageOriginal := original
			stageOriginal.Path = legacyMigrationStage
			if !sameArtifact(*snapshot.Stage, stageOriginal) && snapshot.Stage.SHA256 != snapshot.journal.ServerSHA256 {
				return snapshot, fmt.Errorf("legacy migration stage changed")
			}
		}
		if snapshot.OriginalArchive != nil {
			original.Path = legacyMigrationOriginal
			if !sameArtifact(*snapshot.OriginalArchive, original) {
				return snapshot, fmt.Errorf("legacy migration original archive changed")
			}
		}
		serverReplaced := snapshot.Live[0].SHA256 == snapshot.journal.ServerSHA256
		if serverReplaced && len(snapshot.Backups) != len(canonicalArtifactPaths) {
			return snapshot, fmt.Errorf("legacy migration replacement lacks complete backups")
		}
		if snapshot.Stage != nil && snapshot.OriginalArchive != nil {
			return snapshot, fmt.Errorf("legacy migration stage and original archive coexist")
		}
		if snapshot.OriginalArchive != nil && !serverReplaced {
			return snapshot, fmt.Errorf("legacy migration archive exists before replacement")
		}
		if inventory.Manifest {
			manifest, err := ReadAndVerify(root, uid, gid)
			if err != nil {
				return snapshot, err
			}
			if !serverReplaced || manifest.Artifacts[1].SHA256 != snapshot.journal.Original[1].SHA256 {
				return snapshot, fmt.Errorf("legacy migration manifest does not preserve the historical client")
			}
			snapshot.Manifest, _, err = captureMigrationOptional(root, ManifestPath, uid, gid)
			if err != nil {
				return snapshot, err
			}
		}
		if receipt != nil && (snapshot.Manifest == nil || snapshot.Stage != nil || snapshot.OriginalArchive == nil) {
			return snapshot, fmt.Errorf("legacy migration completion is incomplete")
		}
	}
	return snapshot, nil
}

func writeLegacyMigrationFile(root, path string, content []byte, uid, gid uint32) error {
	directory, err := openPinnedDirectory(root, filepath.Dir(path), uid, gid)
	if err != nil {
		return err
	}
	defer func() { _ = directory.file.Close() }()
	_, err = writePrivateNamed(directory, filepath.Base(path), path, content, uid, gid, maximumOwnedArtifactBytes)
	return err
}

// BeginLegacyMigration publishes intent before backups or active configuration
// change. It refuses preexisting archives and never overwrites a private file.
func BeginLegacyMigration(root string, expected LegacyMigrationSnapshot, server []byte, uid, gid uint32) error {
	current, err := InspectLegacyMigration(root, uid, gid)
	if err != nil || !reflect.DeepEqual(current, expected) {
		return errors.Join(fmt.Errorf("legacy migration state changed before journal publication"), err)
	}
	if current.Journal != nil || current.Receipt != nil {
		return fmt.Errorf("legacy migration already has durable intent")
	}
	identity, err := ParseServerConfiguration(server)
	if err != nil {
		return err
	}
	planned := plannedArtifact(ServerConfigurationPath, server, uid, gid)
	journal := legacyMigrationJournal{Schema: legacyMigrationSchema, Original: current.Live, Token: identity.OwnershipToken, ServerSHA256: planned.SHA256}
	wire, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	if err := writeLegacyMigrationFile(root, LegacyMigrationPath, wire, uid, gid); err != nil {
		return err
	}
	return legacyMigrationFault("journal")
}

func renameLegacyMigrationFile(root string, expected Artifact, destination string, exchangeWith *Artifact, uid, gid uint32) error {
	if filepath.Dir(expected.Path) != filepath.Dir(destination) {
		return fmt.Errorf("legacy migration rename must stay in one directory")
	}
	directory, err := openPinnedDirectory(root, filepath.Dir(expected.Path), uid, gid)
	if err != nil {
		return err
	}
	defer func() { _ = directory.file.Close() }()
	sourceName, destinationName := filepath.Base(expected.Path), filepath.Base(destination)
	actual, _, err := captureAt(directory, sourceName, expected.Path, uid, gid, maximumOwnedArtifactBytes)
	if err != nil || !sameArtifact(actual, expected) {
		return errors.Join(fmt.Errorf("legacy migration rename source changed"), err)
	}
	flags := uint(unix.RENAME_NOREPLACE)
	if exchangeWith != nil {
		actual, _, err := captureAt(directory, destinationName, destination, uid, gid, maximumOwnedArtifactBytes)
		if err != nil || !sameArtifact(actual, *exchangeWith) {
			return errors.Join(fmt.Errorf("legacy migration exchange target changed"), err)
		}
		flags = unix.RENAME_EXCHANGE
	}
	if err := unix.Renameat2(int(directory.file.Fd()), sourceName, int(directory.file.Fd()), destinationName, flags); err != nil {
		return err
	}
	if err := directory.file.Sync(); err != nil {
		return err
	}
	actual, _, err = captureAt(directory, destinationName, destination, uid, gid, maximumOwnedArtifactBytes)
	expected.Path = destination
	if err != nil || !sameArtifact(actual, expected) {
		return errors.Join(fmt.Errorf("legacy migration renamed file failed attestation; evidence retained"), err)
	}
	if exchangeWith != nil {
		expectedSource := *exchangeWith
		expectedSource.Path = filepath.Join(filepath.Dir(destination), sourceName)
		actual, _, err = captureAt(directory, sourceName, expectedSource.Path, uid, gid, maximumOwnedArtifactBytes)
		if err != nil || !sameArtifact(actual, expectedSource) {
			return errors.Join(fmt.Errorf("legacy migration exchanged original failed attestation; evidence retained"), err)
		}
	}
	return nil
}

// ContinueLegacyMigration preserves all three original files in private backups,
// replaces only the server hooks, and publishes ownership as the final active
// artifact. Interrupted calls resume from exact journal and inode evidence.
// No file is deleted and no service or kernel state is changed by this API.
func ContinueLegacyMigration(root string, expected LegacyMigrationSnapshot, server []byte, uid, gid uint32) error {
	current, err := InspectLegacyMigration(root, uid, gid)
	if err != nil || !reflect.DeepEqual(current, expected) {
		return errors.Join(fmt.Errorf("legacy migration state changed before continuation"), err)
	}
	if current.Completed() {
		return nil
	}
	if current.Journal == nil {
		return fmt.Errorf("legacy migration has no durable intent")
	}
	identity, err := ParseServerConfiguration(server)
	if err != nil || identity.OwnershipToken != current.journal.Token || plannedArtifact(ServerConfigurationPath, server, uid, gid).SHA256 != current.journal.ServerSHA256 {
		return fmt.Errorf("legacy migration target does not match its journal")
	}
	for index, path := range canonicalArtifactPaths {
		backup := LegacyMigrationBackupPath(path)
		present, err := inventoryLogicalExists(root, backup)
		if err != nil {
			return err
		}
		if !present {
			if err := writeLegacyMigrationFile(root, backup, current.OriginalContents[path], uid, gid); err != nil {
				return err
			}
			if err := legacyMigrationFault(fmt.Sprintf("backup:%d", index)); err != nil {
				return err
			}
		}
	}
	current, err = InspectLegacyMigration(root, uid, gid)
	if err != nil {
		return err
	}
	if current.Live[0].SHA256 != current.journal.ServerSHA256 {
		if current.Stage == nil {
			if err := writeLegacyMigrationFile(root, legacyMigrationStage, server, uid, gid); err != nil {
				return err
			}
			if err := legacyMigrationFault("stage"); err != nil {
				return err
			}
		}
		current, err = InspectLegacyMigration(root, uid, gid)
		if err != nil {
			return err
		}
		if current.Stage == nil || current.Stage.SHA256 != current.journal.ServerSHA256 {
			return fmt.Errorf("legacy migration target stage missing")
		}
		if err := renameLegacyMigrationFile(root, *current.Stage, ServerConfigurationPath, &current.Live[0], uid, gid); err != nil {
			return err
		}
		if err := legacyMigrationFault("exchange"); err != nil {
			return err
		}
	}
	current, err = InspectLegacyMigration(root, uid, gid)
	if err != nil {
		return err
	}
	if current.Stage != nil {
		original := current.journal.Original[0]
		original.Path = legacyMigrationStage
		if !sameArtifact(*current.Stage, original) {
			return fmt.Errorf("legacy migration exchange did not retain the original server")
		}
		if err := renameLegacyMigrationFile(root, original, legacyMigrationOriginal, nil, uid, gid); err != nil {
			return err
		}
		if err := legacyMigrationFault("original-archive"); err != nil {
			return err
		}
	}
	current, err = InspectLegacyMigration(root, uid, gid)
	if err != nil {
		return err
	}
	if current.Manifest == nil {
		manifest, err := CaptureManifest(root, uid, gid)
		if err != nil {
			return err
		}
		wire, err := canonicalManifestBytes(manifest, uid, gid)
		if err != nil {
			return err
		}
		if err := writeLegacyMigrationFile(root, ManifestPath, wire, uid, gid); err != nil {
			return err
		}
		if err := legacyMigrationFault("manifest"); err != nil {
			return err
		}
	}
	current, err = InspectLegacyMigration(root, uid, gid)
	if err != nil {
		return err
	}
	if current.Manifest == nil || current.OriginalArchive == nil || current.Stage != nil {
		return fmt.Errorf("legacy migration is not ready for completion")
	}
	if err := renameLegacyMigrationFile(root, *current.Journal, LegacyMigrationReceiptPath, nil, uid, gid); err != nil {
		return err
	}
	if err := legacyMigrationFault("receipt"); err != nil {
		return err
	}
	final, err := InspectLegacyMigration(root, uid, gid)
	if err != nil || !final.Completed() {
		return errors.Join(fmt.Errorf("legacy migration completion verification failed"), err)
	}
	return nil
}

func preflightLegacyMigration(root string) error {
	present, err := inventoryLogicalExists(root, LegacyMigrationPath)
	if err != nil {
		return err
	}
	if present {
		return fmt.Errorf("historical WireGuard migration is pending; resume the exact reviewed migration before installation or removal")
	}
	return nil
}
