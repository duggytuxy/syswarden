//go:build linux

package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"golang.org/x/sys/unix"
)

const activationRetirementSchema = "syswarden-activation-retirement-v1"

type activationRetirementEntry struct {
	Name string                 `json:"name"`
	File activationFileIdentity `json:"file"`
}

type activationRetirementRecord struct {
	Schema    string                      `json:"schema"`
	Path      string                      `json:"path"`
	Parent    activationDirectoryIdentity `json:"parent"`
	Directory activationDirectoryIdentity `json:"directory"`
	Entries   []activationRetirementEntry `json:"entries"`
}

// ActivationStateRemoval holds exact custody of validated product activation
// records. Current TOML may differ or be absent. Unrecognized files are never
// adopted, and an interrupted retirement retains its exact parent-side intent.
type ActivationStateRemoval struct {
	store         activationApprovalStore
	record        *activationRetirementRecord
	journal       *secureFileIdentity
	unlock        func()
	journalUnlock func()
	closed        bool
	retired       bool
}

// InspectActivationStateForRemoval is used only inside the authorized removal
// lifecycle. Nil,nil means both the activation directory and retirement intent
// are absent. It takes bounded publication custody, not a runtime-wide lock.
func InspectActivationStateForRemoval() (*ActivationStateRemoval, error) {
	store, err := productionActivationStore()
	if err != nil {
		return nil, err
	}
	return inspectActivationStateRemovalAt(store)
}

func inspectActivationStateRemovalAt(store activationApprovalStore) (*ActivationStateRemoval, error) {
	parent, parentIdentity, err := openActivationDirectory(filepath.Dir(store.path), store.uid)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = parent.Close() }()
	if raw, file, err := readActivationFile(parent, activationRetirementName, store.uid, maximumActivationRecordBytes); err == nil {
		if file.Mode != 0600 {
			return nil, errors.New("activation retirement intent is not private")
		}
		record, err := decodeActivationRetirement(raw, store)
		if err != nil {
			return nil, err
		}
		if record.Parent != parentIdentity {
			return nil, errors.New("activation retirement parent changed")
		}
		identity, err := retirementIdentity(parent, activationRetirementName, store.uid, file)
		if err != nil {
			return nil, err
		}
		removal := &ActivationStateRemoval{store: store, record: record, journal: identity}
		unlock, err := lockActivationRetirement(parent, file, store.uid)
		if err != nil {
			return nil, err
		}
		removal.journalUnlock = unlock
		if err := removal.Revalidate(); err != nil {
			_ = removal.Close()
			return nil, err
		}
		return removal, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	state, err := readActivationStateUsing(store, nil)
	if err != nil {
		return nil, err
	}
	if state == nil {
		return nil, nil
	}
	// Empty or lock-only state can result from an explicitly approved write
	// failing before publication. Refuse it as unproven removal ownership.
	if state.record == nil {
		return nil, errors.New("activation directory has no verified product approval; explicit recovery is required")
	}
	unlock, err := lockActivationStore(store)
	if err != nil {
		return nil, err
	}
	removal := &ActivationStateRemoval{store: store, unlock: unlock}
	failed := true
	defer func() {
		if failed {
			_ = removal.Close()
		}
	}()
	state, err = readActivationStateUsing(store, nil)
	if err != nil {
		return nil, err
	}
	if state == nil || state.record == nil {
		return nil, errors.New("activation records disappeared during removal inspection")
	}
	directory, identity, err := openActivationDirectory(store.path, store.uid)
	if err != nil {
		return nil, err
	}
	defer func() { _ = directory.Close() }()
	record := &activationRetirementRecord{Schema: activationRetirementSchema, Path: store.path, Parent: parentIdentity, Directory: identity}
	for _, name := range []string{activationLockName, activationAppliedName, activationApprovedName} {
		_, file, err := readActivationFile(directory, name, store.uid, maximumActivationRecordBytes)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if file.Mode != 0600 {
			return nil, errors.New("activation removal artifact is not private")
		}
		record.Entries = append(record.Entries, activationRetirementEntry{Name: name, File: file})
	}
	sort.Slice(record.Entries, func(i, j int) bool { return record.Entries[i].Name < record.Entries[j].Name })
	removal.record = record
	if err := removal.Revalidate(); err != nil {
		return nil, err
	}
	failed = false
	return removal, nil
}

func decodeActivationRetirement(raw []byte, store activationApprovalStore) (*activationRetirementRecord, error) {
	var record activationRetirementRecord
	if err := decodeActivationCanonical(raw, &record); err != nil {
		return nil, err
	}
	if record.Schema != activationRetirementSchema || record.Path != store.path || len(record.Entries) < 2 || len(record.Entries) > 3 ||
		record.Directory.Mode != 0700 {
		return nil, errors.New("activation retirement contract is invalid")
	}
	if err := validateActivationDirectory(record.Parent, store.uid); err != nil {
		return nil, err
	}
	if err := validateActivationDirectory(record.Directory, store.uid); err != nil {
		return nil, err
	}
	previous := ""
	hasApproval, hasLock := false, false
	for _, entry := range record.Entries {
		if entry.Name <= previous || (entry.Name != activationApprovedName && entry.Name != activationAppliedName && entry.Name != activationLockName) ||
			entry.File.Mode != 0600 {
			return nil, errors.New("activation retirement inventory is invalid")
		}
		if err := validateActivationFile(entry.File, store.uid); err != nil {
			return nil, err
		}
		if entry.Name == activationLockName && entry.File.Size != 0 {
			return nil, errors.New("activation retirement lock is not empty")
		}
		previous = entry.Name
		hasApproval = hasApproval || entry.Name == activationApprovedName
		hasLock = hasLock || entry.Name == activationLockName
	}
	if !hasApproval || !hasLock {
		return nil, errors.New("activation retirement lacks exact approval ownership")
	}
	return &record, nil
}

func retirementIdentity(root *os.Root, name string, uid uint32, expected activationFileIdentity) (*secureFileIdentity, error) {
	raw, info, err := readSecureRegularFileSnapshotBounded(root, name, name, maximumActivationRecordBytes)
	if err != nil {
		return nil, err
	}
	actual, err := activationFileFrom(info, raw, uid, maximumActivationRecordBytes)
	if err != nil || actual != expected {
		return nil, errors.New("activation retirement artifact changed")
	}
	return newSecureFileIdentity(raw, info), nil
}

func lockActivationRetirement(parent *os.Root, expected activationFileIdentity, uid uint32) (func(), error) {
	file, err := parent.OpenFile(activationRetirementName, os.O_RDWR|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, errors.New("activation retirement is already in progress")
	}
	raw, actual, err := readActivationFile(parent, activationRetirementName, uid, maximumActivationRecordBytes)
	info, infoErr := file.Stat()
	opened, openedErr := activationFileFrom(info, raw, uid, maximumActivationRecordBytes)
	if err != nil || infoErr != nil || openedErr != nil || actual != expected || opened != expected {
		_ = file.Close()
		return nil, errors.New("activation retirement custody changed")
	}
	return func() { _ = file.Close() }, nil
}

func (removal *ActivationStateRemoval) Revalidate() error {
	if removal == nil || removal.closed || removal.record == nil {
		return errors.New("activation removal custody is unavailable")
	}
	if removal.retired {
		return nil
	}
	parent, identity, err := openActivationDirectory(filepath.Dir(removal.store.path), removal.store.uid)
	if err != nil {
		return err
	}
	defer func() { _ = parent.Close() }()
	if identity != removal.record.Parent {
		return errors.New("activation removal parent changed")
	}
	if removal.journal == nil {
		if _, err := parent.Lstat(activationRetirementName); !errors.Is(err, os.ErrNotExist) {
			return errors.New("activation retirement intent appeared")
		}
	} else {
		raw, info, err := readSecureRegularFileSnapshotBounded(parent, activationRetirementName, activationRetirementName, maximumActivationRecordBytes)
		if err != nil || !sameSecureFileMetadata(removal.journal.info, info) || !removal.journal.matches(raw, info) {
			return errors.New("activation retirement intent changed; preserve recovery evidence")
		}
	}
	directory, current, err := openActivationDirectory(removal.store.path, removal.store.uid)
	if errors.Is(err, os.ErrNotExist) && removal.journal != nil {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() { _ = directory.Close() }()
	if current != removal.record.Directory {
		return errors.New("activation removal directory identity changed")
	}
	file, err := directory.Open(".")
	if err != nil {
		return err
	}
	entries, readErr := file.ReadDir(4)
	_ = file.Close()
	if readErr != nil && readErr != io.EOF {
		return readErr
	}
	if len(entries) > len(removal.record.Entries) {
		return errors.New("activation removal found unrecognized entries")
	}
	expected := make(map[string]activationFileIdentity)
	for _, entry := range removal.record.Entries {
		expected[entry.Name] = entry.File
	}
	for _, entry := range entries {
		witness, found := expected[entry.Name()]
		if !found {
			return errors.New("activation removal found an unrecognized artifact")
		}
		_, actual, err := readActivationFile(directory, entry.Name(), removal.store.uid, maximumActivationRecordBytes)
		if err != nil || actual != witness {
			return errors.New("activation removal artifact changed; retained for explicit recovery")
		}
	}
	if removal.journal == nil && len(entries) != len(expected) {
		return errors.New("activation removal inventory changed before durable intent")
	}
	return nil
}

// Retire removes only the recorded files. The parent-side intent survives every
// partial deletion until directory removal is durable, making retry exact even
// after approved.json or the original lock file has already been removed.
func (removal *ActivationStateRemoval) Retire() error {
	if err := removal.Revalidate(); err != nil {
		return err
	}
	if removal.retired {
		return nil
	}
	parentPath := filepath.Dir(removal.store.path)
	parent, _, err := openActivationDirectory(parentPath, removal.store.uid)
	if err != nil {
		return err
	}
	defer func() { _ = parent.Close() }()
	if removal.journal == nil {
		raw, err := activationCanonical(removal.record)
		if err != nil {
			return err
		}
		if _, err := decodeActivationRetirement(raw, removal.store); err != nil {
			return err
		}
		if err := replaceSecureConfigFile(parentPath, activationRetirementName, raw, nil, removal.Revalidate, nil, nil); err != nil {
			return fmt.Errorf("activation retirement intent was not durably published: %w", err)
		}
		current, witness, err := readActivationFile(parent, activationRetirementName, removal.store.uid, maximumActivationRecordBytes)
		if err != nil || !bytes.Equal(raw, current) {
			return errors.New("activation retirement intent changed after publication")
		}
		journal, err := retirementIdentity(parent, activationRetirementName, removal.store.uid, witness)
		if err != nil {
			return err
		}
		removal.journal = journal
		unlock, err := lockActivationRetirement(parent, witness, removal.store.uid)
		if err != nil {
			return err
		}
		removal.journalUnlock = unlock
	}
	if err := removal.Revalidate(); err != nil {
		return err
	}
	directory, _, err := openActivationDirectory(removal.store.path, removal.store.uid)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil {
		defer func() { _ = directory.Close() }()
		for _, entry := range removal.record.Entries {
			if err := removal.Revalidate(); err != nil {
				return err
			}
			_, actual, err := readActivationFile(directory, entry.Name, removal.store.uid, maximumActivationRecordBytes)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil || actual != entry.File {
				return errors.New("activation retirement refuses changed file")
			}
			identity, err := retirementIdentity(directory, entry.Name, removal.store.uid, entry.File)
			if err != nil {
				return err
			}
			if err := removeConfigReplacementFile(directory, entry.Name, identity, defaultConfigReplacementOps()); err != nil {
				return err
			}
			if err := syncRootDirectory(directory); err != nil {
				return err
			}
		}
		if err := removal.Revalidate(); err != nil {
			return err
		}
		if err := parent.Remove(filepath.Base(removal.store.path)); err != nil {
			return err
		}
		if err := syncRootDirectory(parent); err != nil {
			return err
		}
	}
	if err := removal.Revalidate(); err != nil {
		return err
	}
	if err := removeConfigReplacementFile(parent, activationRetirementName, removal.journal, defaultConfigReplacementOps()); err != nil {
		return err
	}
	if err := syncRootDirectory(parent); err != nil {
		return err
	}
	removal.retired = true
	return nil
}

func (removal *ActivationStateRemoval) Close() error {
	if removal == nil || removal.closed {
		return nil
	}
	removal.closed = true
	if removal.journalUnlock != nil {
		removal.journalUnlock()
	}
	if removal.unlock != nil {
		removal.unlock()
	}
	return nil
}
