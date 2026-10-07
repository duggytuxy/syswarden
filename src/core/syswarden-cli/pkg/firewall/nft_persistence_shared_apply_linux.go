//go:build linux

package firewall

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

type nftPersistenceSharedState struct {
	phase       int
	original    nftPersistenceRead
	replacement nftPersistenceRead
}

// The only accepted states are before exchange, after exchange and after the
// original inode was retained privately. Neither active-path absence nor a
// duplicate original is a successful or automatically repairable state.
func inspectNFTPersistenceSharedState(host nftPersistenceFilesystem, record nftPersistenceSharedRecord) (nftPersistenceSharedState, error) {
	return inspectNFTPersistenceSharedStateUsing(host, record, planLegacyNFTIncludeRetirement)
}

func inspectNFTPersistenceSharedStateUsing(host nftPersistenceFilesystem, record nftPersistenceSharedRecord, planner nftPersistenceEditPlanner) (nftPersistenceSharedState, error) {
	var empty nftPersistenceSharedState
	if planner == nil {
		return empty, fmt.Errorf("shared nftables state requires its exact reviewed planner")
	}
	if _, err := encodeNFTPersistenceSharedRecord(record, host); err != nil {
		return empty, err
	}
	directory := nftPersistenceSharedDirectory(record)
	paths := []string{record.Original.Source.Path, directory + "/" + record.Stage, directory + "/original"}
	values := make([]nftPersistenceRead, 3)
	present := make([]bool, 3)
	for index, path := range paths {
		value, attrs, err := snapshotNFTPersistenceMetadata(host, path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil || nftPersistenceXattrDigest(attrs) != record.Xattrs {
			return empty, fmt.Errorf("shared nftables edit has changed or unavailable file metadata")
		}
		values[index], present[index] = value, true
	}
	if !present[0] {
		return empty, fmt.Errorf("shared nftables active source is absent")
	}
	oldAt := func(index int) bool {
		return present[index] && matchesLegacyRetirementSource(record.Original, values[index])
	}
	newAt := func(index int) bool {
		return present[index] && matchesLegacyRetirementSource(record.Replacement, values[index])
	}
	var state nftPersistenceSharedState
	switch {
	case oldAt(0) && newAt(1) && !present[2]:
		state = nftPersistenceSharedState{0, values[0], values[1]}
	case newAt(0) && oldAt(1) && !present[2]:
		state = nftPersistenceSharedState{1, values[1], values[0]}
	case newAt(0) && !present[1] && oldAt(2):
		state = nftPersistenceSharedState{2, values[2], values[0]}
	default:
		return empty, fmt.Errorf("shared nftables edit has ambiguous or changed source and backup identities")
	}
	edit, err := planner(state.original.content)
	if err != nil || len(edit.removed) == 0 || !bytes.Equal(edit.content, state.replacement.content) {
		return empty, fmt.Errorf("shared nftables replacement is not the exact bounded reviewed edit")
	}
	return state, nil
}

func restoreNFTPersistenceExchange(host nftPersistenceFilesystem, record nftPersistenceSharedRecord, parent, backup *os.File, ops legacyRetirementFileOps) error {
	current, attrs, err := snapshotNFTPersistenceMetadata(host, record.Original.Source.Path)
	if err != nil || !matchesLegacyRetirementSource(record.Replacement, current) || nftPersistenceXattrDigest(attrs) != record.Xattrs {
		return fmt.Errorf("shared nftables active file changed during exchange; all private evidence is retained")
	}
	if err := ops.rename(int(parent.Fd()), filepath.Base(record.Original.Source.Path), int(backup.Fd()), record.Stage, unix.RENAME_EXCHANGE); err != nil {
		return fmt.Errorf("shared nftables source restoration is unconfirmed; preserve all evidence: %w", err)
	}
	return errors.Join(ops.sync(parent), ops.sync(backup))
}

// Exchange keeps the shared active path present throughout the operation.
// The original inode remains in a private backup, including its exact xattrs.
// The guard distinguishes original and edited include graphs and must verify
// every retained dependency and external runtime producer under removal locks.
func applyNFTPersistenceSharedEdit(host nftPersistenceFilesystem, record nftPersistenceSharedRecord, guard func(bool) error, ops legacyRetirementFileOps) error {
	return applyNFTPersistenceSharedEditUsing(host, record, guard, ops, planLegacyNFTIncludeRetirement)
}

func applyNFTPersistenceSharedEditUsing(host nftPersistenceFilesystem, record nftPersistenceSharedRecord, guard func(bool) error, ops legacyRetirementFileOps, planner nftPersistenceEditPlanner) error {
	if guard == nil || planner == nil || !validLegacyRetirementOperations(func() error { return guard(false) }, ops) {
		return fmt.Errorf("shared nftables editing requires complete mutation guards")
	}
	if _, err := encodeNFTPersistenceSharedRecord(record, host); err != nil {
		return err
	}
	directory := nftPersistenceSharedDirectory(record)
	backup, err := host.openDirectory(directory)
	if err != nil {
		return err
	}
	defer func() { _ = backup.Close() }()
	backupFD, err := backup.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = backupFD.Close() }()
	backupInfo, err := backupFD.Stat()
	if err != nil || backupInfo.Mode().Perm() != 0700 {
		return fmt.Errorf("shared nftables backup directory is not private")
	}
	parentPath, name := filepath.Dir(record.Original.Source.Path), filepath.Base(record.Original.Source.Path)
	parent, err := host.openDirectory(parentPath)
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
	if err != nil || parentInfo.Sys().(*syscall.Stat_t).Dev != backupInfo.Sys().(*syscall.Stat_t).Dev {
		return fmt.Errorf("shared nftables exchange requires the original filesystem")
	}
	check := func() (nftPersistenceSharedState, error) {
		var empty nftPersistenceSharedState
		if err := errors.Join(attestLegacyRetirementDirectory(host, parentPath, parentInfo), attestLegacyRetirementDirectory(host, directory, backupInfo)); err != nil {
			return empty, err
		}
		intent, err := readNFTPersistenceSharedRecord(host, record.Original.Source.Path, record.Original.PlanSHA256)
		if err != nil || intent != record {
			return empty, fmt.Errorf("shared nftables intent changed at the mutation boundary")
		}
		return inspectNFTPersistenceSharedStateUsing(host, record, planner)
	}
	state, err := check()
	if err != nil {
		return err
	}
	if err := guard(state.phase != 0); err != nil {
		return err
	}
	intent, err := backup.OpenFile("edit.json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	syncErr := ops.sync(intent)
	closeErr := intent.Close()
	if err := errors.Join(syncErr, closeErr, ops.sync(backupFD)); err != nil {
		return err
	}
	state, err = check()
	if err != nil {
		return err
	}
	if state.phase == 0 {
		original, err := parent.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		syncErr := ops.sync(original)
		closeErr := original.Close()
		if err := errors.Join(syncErr, closeErr); err != nil {
			return err
		}
		if err := guard(false); err != nil {
			return err
		}
		confirmed, err := check()
		if err != nil || confirmed.phase != 0 {
			return fmt.Errorf("shared nftables state changed immediately before exchange")
		}
		if err := ops.rename(int(parentFD.Fd()), name, int(backupFD.Fd()), record.Stage, unix.RENAME_EXCHANGE); err != nil {
			return err
		}
		state, err = check()
		if err != nil || state.phase != 1 {
			restoreErr := restoreNFTPersistenceExchange(host, record, parentFD, backupFD, ops)
			return errors.Join(fmt.Errorf("shared nftables exchange encountered an unexpected original; retain the reviewed evidence"), err, restoreErr)
		}
		if err := ops.checkpoint("shared-edit-exchanged"); err != nil {
			return err
		}
	}
	if state.phase == 1 {
		if err := guard(true); err != nil {
			return err
		}
		confirmed, err := check()
		if err != nil || confirmed.phase != 1 {
			return fmt.Errorf("shared nftables state changed before original retention")
		}
		if err := ops.rename(int(backupFD.Fd()), record.Stage, int(backupFD.Fd()), "original", unix.RENAME_NOREPLACE); err != nil {
			return err
		}
		if err := ops.checkpoint("shared-edit-original-retained"); err != nil {
			return err
		}
	}
	if err := errors.Join(ops.sync(parentFD), ops.sync(backupFD)); err != nil {
		return err
	}
	if err := guard(true); err != nil {
		return err
	}
	state, err = check()
	if err != nil || state.phase != 2 {
		return fmt.Errorf("shared nftables edit is not exactly complete")
	}
	if err := ops.checkpoint("shared-edit-durable"); err != nil {
		return err
	}
	return guard(true)
}
