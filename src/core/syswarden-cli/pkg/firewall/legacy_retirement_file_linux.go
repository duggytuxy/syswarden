//go:build linux

package firewall

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"syswarden-cli/pkg/wireguardstate"

	"golang.org/x/sys/unix"
)

const legacyRetirementSchema = "syswarden-legacy-file-retirement-v1"

type legacyRetirementFileRecord struct {
	Schema     string                  `json:"schema"`
	PlanSHA256 string                  `json:"plan_sha256"`
	Source     wireguardstate.Artifact `json:"source"`
	Size       int64                   `json:"size"`
	ModifiedNS int64                   `json:"modified_ns"`
}

type legacyRetirementFileOps struct {
	rename     func(int, string, int, string, uint) error
	sync       func(*os.File) error
	checkpoint func(string) error
}

func defaultLegacyRetirementFileOps() legacyRetirementFileOps {
	return legacyRetirementFileOps{
		rename:     unix.Renameat2,
		sync:       (*os.File).Sync,
		checkpoint: func(string) error { return nil },
	}
}

func validLegacyRetirementDigest(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}

func legacyRetirementBackupDirectory(record legacyRetirementFileRecord) string {
	return "/var/backups/syswarden-retired-v1/" + record.PlanSHA256 + "/" + fmt.Sprintf("%x", sha256.Sum256([]byte(record.Source.Path)))
}

func makeLegacyRetirementFileRecord(path, plan string, snapshot nftPersistenceRead) (legacyRetirementFileRecord, error) {
	if snapshot.identity == nil {
		return legacyRetirementFileRecord{}, fmt.Errorf("legacy retirement source has no pinned identity")
	}
	stat, ok := snapshot.identity.Sys().(*syscall.Stat_t)
	if !ok || !snapshot.identity.Mode().IsRegular() || snapshot.identity.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 ||
		int64(len(snapshot.content)) != snapshot.identity.Size() {
		return legacyRetirementFileRecord{}, fmt.Errorf("legacy retirement source has an invalid file identity")
	}
	record := legacyRetirementFileRecord{
		Schema: legacyRetirementSchema, PlanSHA256: plan, Size: snapshot.identity.Size(), ModifiedNS: snapshot.identity.ModTime().UnixNano(),
		Source: wireguardstate.Artifact{
			Path: path, SHA256: fmt.Sprintf("%x", sha256.Sum256(snapshot.content)), Mode: uint32(snapshot.identity.Mode().Perm()),
			UID: stat.Uid, GID: stat.Gid, NLink: uint64(stat.Nlink), Device: uint64(stat.Dev), Inode: stat.Ino,
			FilesystemUUID: snapshot.filesystemUUID,
		},
	}
	return record, validateLegacyRetirementFileRecord(record, stat.Uid, stat.Gid)
}

func validateLegacyRetirementFileRecord(record legacyRetirementFileRecord, uid, gid uint32) error {
	a := record.Source
	if record.Schema != legacyRetirementSchema || !validLegacyRetirementDigest(record.PlanSHA256) ||
		!canonicalNFTPersistencePath(a.Path, false) || !strings.HasPrefix(a.Path, "/etc/") ||
		!validLegacyRetirementDigest(a.SHA256) || a.UID != uid || a.GID != gid || a.NLink != 1 || a.Inode == 0 ||
		a.Mode > 0777 || a.Mode&0022 != 0 || record.Size < 0 || record.Size > maximumNFTPersistenceBytes ||
		!wireguardstate.ValidFilesystemUUID(a.FilesystemUUID) {
		return fmt.Errorf("invalid legacy retirement file record")
	}
	return nil
}

func matchesLegacyRetirementSource(record legacyRetirementFileRecord, snapshot nftPersistenceRead) bool {
	actual, err := makeLegacyRetirementFileRecord(record.Source.Path, record.PlanSHA256, snapshot)
	return err == nil && actual.Size == record.Size && actual.ModifiedNS == record.ModifiedNS &&
		wireguardstate.MatchesRecordedArtifact(actual.Source, record.Source)
}

func readLegacyRetirementFileRecord(host nftPersistenceFilesystem, directory string) (legacyRetirementFileRecord, error) {
	snapshot, err := host.snapshot(directory + "/intent.json")
	if err != nil {
		return legacyRetirementFileRecord{}, err
	}
	if snapshot.identity.Mode().Perm() != 0600 || len(snapshot.content) > 16384 {
		return legacyRetirementFileRecord{}, fmt.Errorf("legacy retirement intent is not a bounded private record")
	}
	var record legacyRetirementFileRecord
	decoder := json.NewDecoder(bytes.NewReader(snapshot.content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return record, fmt.Errorf("invalid legacy retirement intent encoding")
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(snapshot.content, canonical) || legacyRetirementBackupDirectory(record) != directory {
		return record, fmt.Errorf("legacy retirement intent is not canonical or path-bound")
	}
	return record, validateLegacyRetirementFileRecord(record, host.expectedUID, host.expectedGID)
}

func legacyRetirementSourceState(host nftPersistenceFilesystem, record legacyRetirementFileRecord) (bool, error) {
	source, sourceErr := host.snapshot(record.Source.Path)
	backup, backupErr := host.snapshot(legacyRetirementBackupDirectory(record) + "/original")
	sourceMissing, backupMissing := errors.Is(sourceErr, fs.ErrNotExist), errors.Is(backupErr, fs.ErrNotExist)
	if sourceErr != nil && !sourceMissing || backupErr != nil && !backupMissing {
		return false, errors.Join(fmt.Errorf("legacy retirement source or backup cannot be attested"), sourceErr, backupErr)
	}
	if sourceMissing && backupMissing || !sourceMissing && !backupMissing {
		return false, fmt.Errorf("legacy retirement source and backup have an ambiguous presence state")
	}
	if sourceMissing {
		if !matchesLegacyRetirementSource(record, backup) {
			return false, fmt.Errorf("legacy retirement backup does not match its original identity")
		}
		return true, nil
	}
	if !matchesLegacyRetirementSource(record, source) {
		return false, fmt.Errorf("legacy retirement source changed after inspection")
	}
	return false, nil
}

func attestLegacyRetirementDirectory(host nftPersistenceFilesystem, path string, expected os.FileInfo) error {
	current, err := host.openDirectory(path)
	if err != nil {
		return err
	}
	defer func() { _ = current.Close() }()
	actual, err := current.Stat(".")
	if err != nil || !os.SameFile(expected, actual) || expected.Mode() != actual.Mode() {
		return fmt.Errorf("legacy retirement directory identity changed")
	}
	before, beforeOK := expected.Sys().(*syscall.Stat_t)
	after, afterOK := actual.Sys().(*syscall.Stat_t)
	if !beforeOK || !afterOK || before.Uid != after.Uid || before.Gid != after.Gid {
		return fmt.Errorf("legacy retirement directory ownership changed")
	}
	return nil
}

// publishLegacyRetirementIntent never replaces an existing journal. An
// interrupted private staging file is left inactive for inspection; it is
// never accepted as intent and is never deleted based only on its name.
func publishLegacyRetirementIntent(directory *os.Root, descriptor *os.File, record legacyRetirementFileRecord, ops legacyRetirementFileOps) error {
	content, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return publishLegacyRetirementJSON(directory, descriptor, "intent", content, ops)
}

func publishLegacyRetirementJSON(directory *os.Root, descriptor *os.File, kind string, content []byte, ops legacyRetirementFileOps) error {
	limit := 2 << 20
	if kind == "kernel" || kind == "historical-source" {
		limit = maximumNFTPersistenceBytes
	}
	if kind == "unused-runtime" {
		limit = 512
	}
	unusedResume := strings.HasPrefix(kind, legacyUnusedResumePrefix) && validLegacyRetirementDigest(strings.TrimPrefix(kind, legacyUnusedResumePrefix))
	if unusedResume {
		limit = 64 << 10
	}
	if kind != "intent" && kind != "plan" && kind != "kernel" && kind != "edit" && kind != "unused-runtime" && kind != "historical-source" && kind != "kernel-retirement" && kind != nftRemovalProgressKind && !unusedResume || len(content) == 0 || len(content) > limit {
		return fmt.Errorf("invalid legacy retirement journal kind or size")
	}
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return err
	}
	name := "." + kind + "-stage-" + hex.EncodeToString(token[:])
	file, err := directory.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return fmt.Errorf("create private legacy retirement intent stage: %w", err)
	}
	defer func() { _ = file.Close() }()
	if err := file.Chmod(0600); err != nil {
		return fmt.Errorf("set private legacy retirement intent permissions: %w", err)
	}
	if written, err := file.Write(content); err != nil || written != len(content) {
		return errors.Join(fmt.Errorf("legacy retirement intent stage is incomplete and retained"), err, io.ErrShortWrite)
	}
	if err := ops.sync(file); err != nil {
		return fmt.Errorf("sync legacy retirement intent stage: %w", err)
	}
	if err := ops.checkpoint(kind + "-staged"); err != nil {
		return err
	}
	if err := ops.rename(int(descriptor.Fd()), name, int(descriptor.Fd()), kind+".json", unix.RENAME_NOREPLACE); err != nil {
		return fmt.Errorf("publish legacy retirement intent without replacement: %w", err)
	}
	if err := ops.sync(descriptor); err != nil {
		return fmt.Errorf("sync published legacy retirement intent: %w", err)
	}
	return nil
}

// retireLegacyConfigurationFileUsing moves one previously attested file to a
// precreated private backup directory on the same filesystem. Moving the inode
// retains content, permissions, labels and extended attributes. Cross-device
// moves are refused before the active path changes. This does not establish
// ownership, create backup directories, edit shared files or stop a service.
//
// The mandatory guard must reattest ownership, dependencies and the removal
// barrier under the caller's locks. Its argument distinguishes a prepared
// source from an already retired source during an interrupted-operation retry.
// All original bytes are retained permanently outside the active path. No
// completed outcome is returned without durable intent and an exact backup.
func retireLegacyConfigurationFileUsing(host nftPersistenceFilesystem, record legacyRetirementFileRecord, guard func(bool) error, ops legacyRetirementFileOps) error {
	if guard == nil || ops.rename == nil || ops.sync == nil || ops.checkpoint == nil {
		return fmt.Errorf("legacy retirement requires complete guards and filesystem operations")
	}
	if err := validateLegacyRetirementFileRecord(record, host.expectedUID, host.expectedGID); err != nil {
		return err
	}
	backupPath := legacyRetirementBackupDirectory(record)
	backup, err := host.openDirectory(backupPath)
	if err != nil {
		return err
	}
	defer func() { _ = backup.Close() }()
	info, err := backup.Stat(".")
	if err != nil || info.Mode().Perm() != 0700 {
		return fmt.Errorf("legacy retirement backup directory is not private")
	}
	backupFD, err := backup.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = backupFD.Close() }()
	parent, err := host.openDirectory(filepath.Dir(record.Source.Path))
	if err != nil {
		return err
	}
	defer func() { _ = parent.Close() }()
	parentFD, err := parent.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = parentFD.Close() }()
	parentInfo, err := parentFD.Stat()
	if err != nil || parentInfo.Sys().(*syscall.Stat_t).Dev != info.Sys().(*syscall.Stat_t).Dev {
		return fmt.Errorf("legacy retirement requires a private backup on the source filesystem")
	}
	attestDirectories := func() error {
		return errors.Join(
			attestLegacyRetirementDirectory(host, filepath.Dir(record.Source.Path), parentInfo),
			attestLegacyRetirementDirectory(host, backupPath, info),
		)
	}
	intent, err := readLegacyRetirementFileRecord(host, backupPath)
	if errors.Is(err, fs.ErrNotExist) {
		retired, stateErr := legacyRetirementSourceState(host, record)
		if stateErr != nil || retired {
			return errors.Join(fmt.Errorf("legacy retirement lacks intent for the inspected state"), stateErr)
		}
		if err := guard(false); err != nil {
			return err
		}
		if err := attestDirectories(); err != nil {
			return err
		}
		if err := publishLegacyRetirementIntent(backup, backupFD, record, ops); err != nil {
			return err
		}
		if err := ops.checkpoint("intent-published"); err != nil {
			return err
		}
		intent, err = readLegacyRetirementFileRecord(host, backupPath)
	}
	if err != nil || intent != record {
		return errors.Join(fmt.Errorf("legacy retirement intent differs from the reviewed record"), err)
	}
	// A previous call may have published intent but failed its directory sync.
	// Make both the current record and its directory durable before any move.
	intentFile, err := backup.OpenFile("intent.json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	intentSyncErr := ops.sync(intentFile)
	intentCloseErr := intentFile.Close()
	if err := errors.Join(intentSyncErr, intentCloseErr, ops.sync(backupFD)); err != nil {
		return fmt.Errorf("legacy retirement intent is not durably prepared: %w", err)
	}
	retired, err := legacyRetirementSourceState(host, record)
	if err != nil {
		return err
	}
	if err := guard(retired); err != nil {
		return err
	}
	if err := attestDirectories(); err != nil {
		return err
	}
	intent, err = readLegacyRetirementFileRecord(host, backupPath)
	if err != nil || intent != record {
		return errors.Join(fmt.Errorf("legacy retirement intent changed at the mutation boundary"), err)
	}
	// Reattest after the caller's potentially lengthy runtime checks.
	confirmed, err := legacyRetirementSourceState(host, record)
	if err != nil || confirmed != retired {
		return errors.Join(fmt.Errorf("legacy retirement state changed at the mutation boundary"), err)
	}
	if !retired {
		name := filepath.Base(record.Source.Path)
		file, err := parent.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		// Durably retain original data before publishing its new location.
		syncErr := ops.sync(file)
		closeErr := file.Close()
		if syncErr != nil || closeErr != nil {
			return errors.Join(syncErr, closeErr)
		}
		if err := ops.rename(int(parentFD.Fd()), name, int(backupFD.Fd()), "original", unix.RENAME_NOREPLACE); err != nil {
			return fmt.Errorf("retire legacy configuration without overwriting a backup: %w", err)
		}
		if err := ops.checkpoint("source-retired"); err != nil {
			return err
		}
		retired, err = legacyRetirementSourceState(host, record)
		if err != nil || !retired {
			// A file swapped immediately before rename belongs back at its
			// active path. Never overwrite anything created there meanwhile.
			restoreErr := ops.rename(int(backupFD.Fd()), "original", int(parentFD.Fd()), name, unix.RENAME_NOREPLACE)
			return errors.Join(fmt.Errorf("legacy retirement moved an unexpected state; retained intent requires inspection"), err, restoreErr, ops.sync(parentFD), ops.sync(backupFD))
		}
	}
	if err := errors.Join(ops.sync(parentFD), ops.sync(backupFD)); err != nil {
		return fmt.Errorf("legacy retirement directory sync is incomplete; intent and original are retained: %w", err)
	}
	if err := ops.checkpoint("retirement-durable"); err != nil {
		return err
	}
	if err := guard(true); err != nil {
		return err
	}
	if err := attestDirectories(); err != nil {
		return err
	}
	intent, err = readLegacyRetirementFileRecord(host, backupPath)
	if err != nil || intent != record {
		return errors.Join(fmt.Errorf("legacy retirement intent changed before completion"), err)
	}
	retired, err = legacyRetirementSourceState(host, record)
	if err != nil || !retired {
		return errors.Join(fmt.Errorf("legacy retirement is not exactly complete"), err)
	}
	return nil
}
