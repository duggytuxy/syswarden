//go:build linux

package sshpolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"reflect"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	sshRetiredPrefix           = ".ssh-policy-retired-"
	sshRetirementReceiptPrefix = ".ssh-policy-retirement-"
)

// This record authorizes only an explicitly reviewed move into private
// retention. It does not retrospectively claim product ownership, authorize
// deletion, or allow an orphan to become active transaction storage.
type sshStateRetirement struct {
	Schema          int                  `json:"schema"`
	Instance        string               `json:"instance"`
	InventorySHA256 string               `json:"inventory_sha256"`
	Parent          sshDirectoryIdentity `json:"parent"`
	Directory       sshDirectoryIdentity `json:"directory"`
	Modified        unix.Timespec        `json:"modified"`
	Changed         unix.Timespec        `json:"changed"`
	Marker          *sshRecoveryImage    `json:"marker"`
}

type sshRetirementInspection struct {
	record  sshStateRetirement
	receipt *sshFileImage
	retired bool
}

func validSSHRetirementReceiptName(name string) bool {
	return strings.HasPrefix(name, sshRetirementReceiptPrefix) && strings.HasSuffix(name, ".json") &&
		lowerDigest.MatchString(strings.TrimSuffix(strings.TrimPrefix(name, sshRetirementReceiptPrefix), ".json"))
}

func (record sshStateRetirement) receiptName() string {
	return sshRetirementReceiptPrefix + record.Instance + ".json"
}

func (record sshStateRetirement) digest() string {
	data, _ := json.Marshal(record) // The record has no custom marshalers or unsupported values.
	return digestBytes(append([]byte("SYSWARDEN-SSH-UNATTRIBUTED-RETIREMENT-V1\x00"), data...))
}

func (record sshStateRetirement) validate(uid int) error {
	if record.Schema != 1 || !lowerDigest.MatchString(record.Instance) || !lowerDigest.MatchString(record.InventorySHA256) ||
		record.Modified.Nsec < 0 || record.Modified.Nsec >= 1e9 || record.Changed.Nsec < 0 || record.Changed.Nsec >= 1e9 {
		return ErrInventoryUnsafe
	}
	if err := errors.Join(record.Parent.validate(uid, false), record.Directory.validate(uid, true)); err != nil {
		return err
	}
	if record.Parent.Device != record.Directory.Device || record.Parent.Inode == record.Directory.Inode {
		return ErrInventoryUnsafe
	}
	if record.Marker != nil {
		if err := record.Marker.validate(uid, 1); err != nil {
			return err
		}
		if record.Marker.Device != record.Directory.Device || record.Marker.Inode == record.Directory.Inode ||
			record.Marker.Inode == record.Parent.Inode || record.Marker.Mode&07777 != 0600 ||
			int64(record.Marker.GID) != int64(uid) || !bytes.Equal(record.Marker.Data, sshMarkerBytes(record.Instance)) {
			return ErrInventoryUnsafe
		}
	}
	return nil
}

func decodeSSHStateRetirement(data []byte, uid int) (sshStateRetirement, error) {
	if len(data) == 0 || len(data) > maxSSHOwnerBytes {
		return sshStateRetirement{}, ErrInventoryBounds
	}
	var record sshStateRetirement
	if err := json.Unmarshal(data, &record); err != nil {
		return sshStateRetirement{}, ErrInventoryUnsafe
	}
	encoded, err := json.Marshal(record)
	if err != nil || !bytes.Equal(encoded, data) {
		return sshStateRetirement{}, ErrInventoryUnsafe
	}
	if err := record.validate(uid); err != nil {
		return sshStateRetirement{}, err
	}
	return record, nil
}

// Observe only an empty directory or the exact private marker. Arbitrary
// children, unsafe metadata and symlink/hardlink aliases remain untouched.
func observeSSHOrphan(parent *os.File, name, instance string, uid int) (sshDirectoryIdentity, inventoryStamp, *sshRecoveryImage, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return sshDirectoryIdentity{}, inventoryStamp{}, nil, err
	}
	directory := os.NewFile(uintptr(fd), "ssh-unattributed-private-directory")
	defer directory.Close()
	var before, after, named unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return sshDirectoryIdentity{}, inventoryStamp{}, nil, err
	}
	identity, err := sshDirectoryImage(directory, uid)
	if err != nil {
		return sshDirectoryIdentity{}, inventoryStamp{}, nil, err
	}
	if err := identity.validate(uid, true); err != nil {
		return sshDirectoryIdentity{}, inventoryStamp{}, nil, err
	}
	names, err := directory.Readdirnames(2)
	if err != nil && !errors.Is(err, io.EOF) {
		return sshDirectoryIdentity{}, inventoryStamp{}, nil, err
	}
	if len(names) > 1 || (len(names) == 1 && names[0] != sshMarkerName) {
		return sshDirectoryIdentity{}, inventoryStamp{}, nil, ErrInventoryUnsafe
	}
	var marker *sshRecoveryImage
	if len(names) == 1 {
		image, err := readSSHPrivateChild(directory, sshMarkerName, uid, maxSSHOwnerBytes)
		if err != nil {
			return sshDirectoryIdentity{}, inventoryStamp{}, nil, err
		}
		if !bytes.Equal(image.data, sshMarkerBytes(instance)) {
			return sshDirectoryIdentity{}, inventoryStamp{}, nil, ErrInventoryUnsafe
		}
		value := recoveryImage(image)
		marker = &value
	}
	current, err := sshDirectoryImage(directory, uid)
	if err != nil || !reflect.DeepEqual(identity, current) {
		return sshDirectoryIdentity{}, inventoryStamp{}, nil, errors.Join(ErrInventoryChanged, err)
	}
	if err := errors.Join(unix.Fstat(fd, &after), unix.Fstatat(int(parent.Fd()), name, &named, unix.AT_SYMLINK_NOFOLLOW)); err != nil ||
		stamp(before) != stamp(after) || stamp(after) != stamp(named) {
		return sshDirectoryIdentity{}, inventoryStamp{}, nil, errors.Join(ErrInventoryChanged, err)
	}
	return identity, stamp(after), marker, nil
}

func attestSSHOrphan(parent *os.File, record sshStateRetirement, uid int, retired bool) error {
	name := sshStateStagePrefix + record.Instance
	if retired {
		name = sshRetiredPrefix + record.Instance
	}
	identity, metadata, marker, err := observeSSHOrphan(parent, name, record.Instance, uid)
	if err != nil || !reflect.DeepEqual(identity, record.Directory) || !reflect.DeepEqual(marker, record.Marker) ||
		metadata.modified != record.Modified || (!retired && metadata.changed != record.Changed) {
		return errors.Join(ErrInventoryChanged, err)
	}
	// Rename changes directory ctime, but never the inode, bytes, mtime, mode,
	// ownership, attributes or contained marker identity. Do not chmod/copy it.
	return nil
}

func sshChildAbsent(parent *os.File, name string) error {
	var state unix.Stat_t
	if err := unix.Fstatat(int(parent.Fd()), name, &state, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return err
	}
	return ErrInventoryChanged
}

func checkSSHRetirementSlots(parent *os.File, instance string) error {
	// Reopen "." to get an independent directory offset on every recheck.
	fd, err := unix.Openat(int(parent.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(fd), "ssh-retirement-parent-listing")
	defer directory.Close()
	names, err := directory.Readdirnames(MaxDirectoryEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if len(names) > MaxDirectoryEntries {
		return ErrInventoryBounds
	}
	for _, name := range names {
		if name == sshStateName || name == sshOwnerName ||
			(strings.HasPrefix(name, sshStateStagePrefix) && name != sshStateStagePrefix+instance) {
			return fmt.Errorf("SSH retirement conflicts with active or other unattributed state: %w", ErrInventoryUnsafe)
		}
	}
	return nil
}

func sshStateInventoryDigest(snapshot inventorySnapshot) string {
	return planDigest(migrationPlan{inventory: snapshot})
}

func collectSSHRetirement(root, parent *os.File, uid int, instance string) (sshRetirementInspection, error) {
	snapshot, err := collectSSHStateInventory(root, uid)
	if err != nil {
		return sshRetirementInspection{}, err
	}
	identity, err := sshDirectoryImage(parent, uid)
	if err != nil {
		return sshRetirementInspection{}, err
	}
	if err := identity.validate(uid, false); err != nil {
		return sshRetirementInspection{}, err
	}
	if err := checkSSHRetirementSlots(parent, instance); err != nil {
		return sshRetirementInspection{}, err
	}
	result := sshRetirementInspection{}
	receipt, err := readSSHPrivateChild(parent, sshRetirementReceiptPrefix+instance+".json", uid, maxSSHOwnerBytes)
	if err == nil {
		result.record, err = decodeSSHStateRetirement(receipt.data, uid)
		if err != nil {
			return sshRetirementInspection{}, err
		}
		result.receipt = &receipt
		if result.record.Instance != instance || !reflect.DeepEqual(result.record.Parent, identity) ||
			result.record.InventorySHA256 != sshStateInventoryDigest(snapshot) {
			return sshRetirementInspection{}, ErrInventoryChanged
		}
		result.retired = sshChildAbsent(parent, sshStateStagePrefix+instance) == nil
		absent := sshRetiredPrefix + instance
		if result.retired {
			absent = sshStateStagePrefix + instance
		}
		if err := errors.Join(sshChildAbsent(parent, absent), attestSSHOrphan(parent, result.record, uid, result.retired)); err != nil {
			return sshRetirementInspection{}, err
		}
	} else if errors.Is(err, unix.ENOENT) {
		if err := sshChildAbsent(parent, sshRetiredPrefix+instance); err != nil {
			return sshRetirementInspection{}, err
		}
		directory, metadata, marker, err := observeSSHOrphan(parent, sshStateStagePrefix+instance, instance, uid)
		if err != nil {
			return sshRetirementInspection{}, err
		}
		result.record = sshStateRetirement{1, instance, sshStateInventoryDigest(snapshot), identity, directory, metadata.modified, metadata.changed, marker}
	} else {
		return sshRetirementInspection{}, err
	}
	if err := result.record.validate(uid); err != nil {
		return sshRetirementInspection{}, err
	}
	if err := errors.Join(recheckSSHStateParent(root, parent, uid, identity),
		recheckSSHStateInventory(root, uid, snapshot), attestSSHOrphan(parent, result.record, uid, result.retired),
		checkSSHRetirementSlots(parent, instance)); err != nil {
		return sshRetirementInspection{}, err
	}
	if result.receipt != nil {
		current, err := readSSHPrivateChild(parent, result.record.receiptName(), uid, maxSSHOwnerBytes)
		if err != nil || !reflect.DeepEqual(current, *result.receipt) {
			return sshRetirementInspection{}, errors.Join(ErrInventoryChanged, err)
		}
	} else if err := sshChildAbsent(parent, result.record.receiptName()); err != nil {
		return sshRetirementInspection{}, err
	}
	return result, nil
}

func openSSHRetirementParent(root *os.File, uid int, instance string) (*os.File, error) {
	if root == nil || uid < 0 || uid > math.MaxUint32 || !lowerDigest.MatchString(instance) {
		return nil, ErrInventoryUnsafe
	}
	parent, err := openSSHStateParent(root, uid)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(parent.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, errors.Join(err, parent.Close())
	}
	return parent, nil
}

// Internal read-only inspection. The future root-only adapter must present the
// exact operation and digest for explicit approval. No approval is inferred
// from a filename, matching marker, prior installation or a dry run.
func inspectSSHStateRetirement(root *os.File, uid int, instance string) (sshRetirementInspection, error) {
	parent, err := openSSHRetirementParent(root, uid, instance)
	if err != nil {
		return sshRetirementInspection{}, err
	}
	defer parent.Close()
	return collectSSHRetirement(root, parent, uid, instance)
}

func retireSSHState(root *os.File, uid int, instance, approved string, ops sshProvisionOps) error {
	if !lowerDigest.MatchString(approved) || ops.sync == nil || ops.rename == nil {
		return ErrInventoryUnsafe
	}
	parent, err := openSSHRetirementParent(root, uid, instance)
	if err != nil {
		return err
	}
	defer parent.Close()
	inspection, err := collectSSHRetirement(root, parent, uid, instance)
	if err != nil {
		return err
	}
	record := inspection.record
	if approved != record.digest() {
		return ErrInventoryChanged
	}
	if inspection.receipt == nil {
		data, err := json.Marshal(record)
		if err != nil {
			return err
		}
		image, err := writeSSHPrivateChild(parent, record.receiptName(), data, uid, ops.sync)
		if err != nil {
			return err
		}
		inspection.receipt = &image
	}
	guard := func() error {
		current, err := collectSSHRetirement(root, parent, uid, instance)
		if err != nil || !reflect.DeepEqual(current.record, record) || !reflect.DeepEqual(current.receipt, inspection.receipt) {
			return errors.Join(ErrInventoryChanged, err)
		}
		return nil
	}
	// Reestablish receipt durability after a process interruption before moving
	// anything. No receipt or destination is ever overwritten.
	if err := ops.sync(parent); err != nil {
		return fmt.Errorf("SSH retirement receipt durability is uncertain; preserve evidence: %w", err)
	}
	if err := guard(); err != nil {
		return err
	}
	if !inspection.retired {
		if err := ops.rename(int(parent.Fd()), sshStateStagePrefix+instance, int(parent.Fd()), sshRetiredPrefix+instance, unix.RENAME_NOREPLACE); err != nil {
			return err
		}
	}
	if err := errors.Join(sshChildAbsent(parent, sshStateStagePrefix+instance), attestSSHOrphan(parent, record, uid, true)); err != nil {
		return err
	}
	if err := ops.sync(parent); err != nil {
		return fmt.Errorf("SSH private retirement durability is uncertain; preserve evidence: %w", err)
	}
	return guard()
}
