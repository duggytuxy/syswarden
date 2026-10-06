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
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"syscall"
)

const nftPersistenceSharedSchema = "syswarden-nftables-shared-edit-v1"

type nftPersistenceEditPlanner func([]byte) (nftPersistenceEdit, error)

type nftPersistenceSharedRecord struct {
	Schema      string                     `json:"schema"`
	Original    legacyRetirementFileRecord `json:"original"`
	Replacement legacyRetirementFileRecord `json:"replacement"`
	Stage       string                     `json:"stage"`
	Xattrs      string                     `json:"xattrs_sha256"`
}

func nftPersistenceSharedDirectory(record nftPersistenceSharedRecord) string {
	return legacyFail2banPlanPath(record.Original.PlanSHA256) + "/nft-persistence/" + fmt.Sprintf("%x", sha256.Sum256([]byte(record.Original.Source.Path)))
}

func encodeNFTPersistenceSharedRecord(record nftPersistenceSharedRecord, host nftPersistenceFilesystem) ([]byte, error) {
	old, next := record.Original, record.Replacement
	stage, err := hex.DecodeString(record.Stage)
	if record.Schema != nftPersistenceSharedSchema || err != nil || len(stage) != 16 || hex.EncodeToString(stage) != record.Stage ||
		validateLegacyRetirementFileRecord(old, host.expectedUID, host.expectedGID) != nil ||
		validateLegacyRetirementFileRecord(next, host.expectedUID, host.expectedGID) != nil ||
		old.PlanSHA256 != next.PlanSHA256 || old.Source.Path != next.Source.Path || old.Source.SHA256 == next.Source.SHA256 ||
		old.Source.Inode == next.Source.Inode || old.Source.Device != next.Source.Device || old.Source.FilesystemUUID != next.Source.FilesystemUUID ||
		old.Source.Mode != next.Source.Mode || !validLegacyRetirementDigest(record.Xattrs) {
		return nil, fmt.Errorf("invalid bounded shared nftables edit evidence")
	}
	content, err := json.Marshal(record)
	if err != nil || len(content) > 16384 {
		return nil, fmt.Errorf("shared nftables edit evidence exceeds its bound")
	}
	return content, nil
}

func snapshotNFTPersistenceMetadata(host nftPersistenceFilesystem, path string) (nftPersistenceRead, []nftPersistenceXattr, error) {
	var empty nftPersistenceRead
	snapshot, err := host.snapshot(path)
	if err != nil {
		return empty, nil, err
	}
	parent, err := host.openDirectory(filepath.Dir(path))
	if err != nil {
		return empty, nil, err
	}
	defer func() { _ = parent.Close() }()
	file, err := parent.OpenFile(filepath.Base(path), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return empty, nil, err
	}
	defer func() { _ = file.Close() }()
	identity, err := file.Stat()
	if err != nil || !sameNFTPersistenceIdentity(identity, snapshot.identity) {
		return empty, nil, fmt.Errorf("shared nftables file changed before metadata inspection")
	}
	attrs, err := readNFTPersistenceXattrs(file)
	if err != nil {
		return empty, nil, err
	}
	confirmed, err := host.snapshot(path)
	if err != nil || !sameLegacyFail2banSource(snapshot, confirmed) {
		return empty, nil, fmt.Errorf("shared nftables file changed during metadata inspection")
	}
	return snapshot, attrs, nil
}

func readNFTPersistenceSharedRecord(host nftPersistenceFilesystem, path, review string) (nftPersistenceSharedRecord, error) {
	var empty nftPersistenceSharedRecord
	if !canonicalNFTPersistencePath(path, false) || !validLegacyRetirementDigest(review) {
		return empty, fmt.Errorf("shared nftables recovery requires an exact path and reviewed digest")
	}
	locator := nftPersistenceSharedRecord{Original: legacyRetirementFileRecord{PlanSHA256: review}}
	locator.Original.Source.Path = path
	directory := nftPersistenceSharedDirectory(locator)
	root, err := host.openDirectory(directory)
	if err != nil {
		return empty, err
	}
	info, statErr := root.Stat(".")
	_ = root.Close()
	if statErr != nil || info.Mode().Perm() != 0700 {
		return empty, fmt.Errorf("shared nftables recovery directory is not private")
	}
	intent, err := host.snapshot(directory + "/edit.json")
	if err != nil {
		return empty, err
	}
	var record nftPersistenceSharedRecord
	if len(intent.content) > 16384 || intent.identity.Mode().Perm() != 0600 || json.Unmarshal(intent.content, &record) != nil {
		return empty, fmt.Errorf("shared nftables edit evidence is not bounded and private")
	}
	content, err := encodeNFTPersistenceSharedRecord(record, host)
	if err != nil || !bytes.Equal(content, intent.content) || record.Original.Source.Path != path || record.Original.PlanSHA256 != review {
		return empty, fmt.Errorf("shared nftables edit evidence is noncanonical or differs from review")
	}
	return record, nil
}

// Preparation writes only private staging and evidence. The caller's guard
// must independently attest source ownership, include-graph coverage, service
// entry points, locks and removal state. A marker or pathname alone is never
// sufficient authority to detach a persistent source.
func prepareNFTPersistenceSharedEdit(host nftPersistenceFilesystem, path, review string, guard func() error, ops legacyRetirementFileOps) (nftPersistenceSharedRecord, error) {
	return prepareNFTPersistenceSharedEditUsing(host, path, review, guard, ops, planLegacyNFTIncludeRetirement)
}

func prepareNFTPersistenceSharedEditUsing(host nftPersistenceFilesystem, path, review string, guard func() error, ops legacyRetirementFileOps, planner nftPersistenceEditPlanner) (nftPersistenceSharedRecord, error) {
	var empty nftPersistenceSharedRecord
	if !validLegacyRetirementOperations(guard, ops) || !validLegacyRetirementDigest(review) || planner == nil {
		return empty, fmt.Errorf("shared nftables editing requires complete reviewed guards")
	}
	if err := guard(); err != nil {
		return empty, err
	}
	if existing, err := readNFTPersistenceSharedRecord(host, path, review); err == nil {
		return existing, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return empty, err
	}
	original, attrs, err := snapshotNFTPersistenceMetadata(host, path)
	if err != nil {
		return empty, err
	}
	edit, err := planner(original.content)
	if err != nil || len(edit.removed) == 0 {
		return empty, fmt.Errorf("shared nftables file has no exact reviewed entries eligible for retirement")
	}
	old, err := makeLegacyRetirementFileRecord(path, review, original)
	if err != nil {
		return empty, err
	}
	record := nftPersistenceSharedRecord{Schema: nftPersistenceSharedSchema, Original: old, Xattrs: nftPersistenceXattrDigest(attrs)}
	directory := nftPersistenceSharedDirectory(record)
	if err := ensureLegacyRetirementPrivateDirectory(host, directory, ops); err != nil {
		return empty, err
	}
	root, err := host.openDirectory(directory)
	if err != nil {
		return empty, err
	}
	defer func() { _ = root.Close() }()
	descriptor, err := root.Open(".")
	if err != nil {
		return empty, err
	}
	defer func() { _ = descriptor.Close() }()
	info, err := descriptor.Stat()
	if err != nil || info.Sys().(*syscall.Stat_t).Dev != original.identity.Sys().(*syscall.Stat_t).Dev {
		return empty, fmt.Errorf("shared nftables editing requires staging on the source filesystem")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return empty, err
	}
	record.Stage = hex.EncodeToString(nonce[:])
	stage, err := root.OpenFile(record.Stage, os.O_CREATE|os.O_EXCL|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return empty, err
	}
	defer func() { _ = stage.Close() }()
	if host.expectedUID > math.MaxInt32 || host.expectedGID > math.MaxInt32 {
		return empty, fmt.Errorf("shared nftables metadata ownership exceeds supported IDs")
	}
	if err := stage.Chown(int(host.expectedUID), int(host.expectedGID)); err != nil {
		return empty, err
	}
	if n, err := stage.Write(edit.content); err != nil || n != len(edit.content) {
		return empty, fmt.Errorf("shared nftables private candidate was not completely written")
	}
	if err := stage.Chmod(original.identity.Mode().Perm()); err != nil {
		return empty, err
	}
	if err := copyNFTPersistenceXattrs(stage, attrs); err != nil {
		return empty, err
	}
	if err := errors.Join(ops.sync(stage), ops.sync(descriptor)); err != nil {
		return empty, err
	}
	replacement, replacementAttrs, err := snapshotNFTPersistenceMetadata(host, directory+"/"+record.Stage)
	if err != nil || nftPersistenceXattrDigest(replacementAttrs) != record.Xattrs || !bytes.Equal(replacement.content, edit.content) {
		return empty, fmt.Errorf("shared nftables candidate differs from its exact content or metadata")
	}
	record.Replacement, err = makeLegacyRetirementFileRecord(path, review, replacement)
	if err != nil {
		return empty, err
	}
	content, err := encodeNFTPersistenceSharedRecord(record, host)
	if err != nil {
		return empty, err
	}
	if err := guard(); err != nil {
		return empty, err
	}
	current, currentAttrs, err := snapshotNFTPersistenceMetadata(host, path)
	if err != nil || !sameLegacyFail2banSource(current, original) || nftPersistenceXattrDigest(currentAttrs) != record.Xattrs {
		return empty, fmt.Errorf("shared nftables original changed before private intent publication")
	}
	if err := attestLegacyRetirementDirectory(host, directory, info); err != nil {
		return empty, err
	}
	if err := publishLegacyRetirementJSON(root, descriptor, "edit", content, ops); err != nil {
		return empty, err
	}
	if err := ops.checkpoint("shared-edit-intent-durable"); err != nil {
		return empty, err
	}
	confirmed, err := readNFTPersistenceSharedRecord(host, path, review)
	if err != nil || confirmed != record {
		return empty, fmt.Errorf("shared nftables edit evidence changed after publication")
	}
	return record, guard()
}
