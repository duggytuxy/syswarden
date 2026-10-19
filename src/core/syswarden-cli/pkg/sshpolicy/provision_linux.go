//go:build linux

package sshpolicy

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
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
	sshStateParent      = "/var/lib/syswarden"
	sshStateName        = "ssh-policy-v1"
	sshOwnerName        = "ssh-policy-owner-v1.json"
	sshMarkerName       = "ownership.json"
	sshStateStagePrefix = ".ssh-policy-create-"
	maxSSHOwnerBytes    = 128 << 10
)

// The sibling receipt is independent of the directory it attributes. The
// immutable marker binds a random instance and an exact inode, not just bytes.
// This is custody against unrelated UIDs, not a defense against trusted root.
type sshStateOwner struct {
	Schema    int                  `json:"schema"`
	Instance  string               `json:"instance"`
	Parent    sshDirectoryIdentity `json:"parent"`
	Directory sshDirectoryIdentity `json:"directory"`
	Marker    sshRecoveryImage     `json:"marker"`
}

type sshDirectoryIdentity struct {
	Device     uint64            `json:"device"`
	Inode      uint64            `json:"inode"`
	Mode       uint32            `json:"mode"`
	UID        uint32            `json:"uid"`
	GID        uint32            `json:"gid"`
	Attributes map[string][]byte `json:"attributes"`
}

func sshDirectoryImage(file *os.File, uid int) (sshDirectoryIdentity, error) {
	if file == nil {
		return sshDirectoryIdentity{}, ErrInventoryUnsafe
	}
	var before, after unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &before); err != nil || !(&inventoryReader{uid: uid}).trusted(before, true) {
		return sshDirectoryIdentity{}, errors.Join(ErrInventoryUnsafe, err)
	}
	attrs, err := readSSHAttributes(int(file.Fd()))
	if err != nil {
		return sshDirectoryIdentity{}, err
	}
	if err := unix.Fstat(int(file.Fd()), &after); err != nil || stamp(before) != stamp(after) {
		return sshDirectoryIdentity{}, errors.Join(ErrInventoryChanged, err)
	}
	return sshDirectoryIdentity{uint64(after.Dev), after.Ino, after.Mode, after.Uid, after.Gid, attrs}, nil
}

func (identity sshDirectoryIdentity) validate(uid int, private bool) error {
	if identity.Inode == 0 || int64(identity.UID) != int64(uid) || identity.Mode&unix.S_IFMT != unix.S_IFDIR ||
		identity.Mode&07022 != 0 || identity.Mode&0100 == 0 || identity.Attributes == nil {
		return ErrInventoryUnsafe
	}
	if private && (identity.Mode&07777 != 0700 || int64(identity.GID) != int64(uid)) {
		return ErrInventoryUnsafe
	}
	return validateSSHAttributes(identity.Attributes, false)
}

func sshMarkerBytes(instance string) []byte {
	return []byte("SYSWARDEN-SSH-STATE-V1\n" + instance + "\n")
}

func (owner sshStateOwner) validate(uid int) error {
	if owner.Schema != 1 || !lowerDigest.MatchString(owner.Instance) {
		return ErrInventoryUnsafe
	}
	if err := errors.Join(owner.Parent.validate(uid, false), owner.Directory.validate(uid, true), owner.Marker.validate(uid, 1)); err != nil {
		return err
	}
	if owner.Parent.Device != owner.Directory.Device || owner.Marker.Device != owner.Directory.Device ||
		owner.Parent.Inode == owner.Directory.Inode || owner.Marker.Inode == owner.Directory.Inode ||
		owner.Marker.Inode == owner.Parent.Inode || owner.Marker.Mode&07777 != 0600 || int64(owner.Marker.GID) != int64(uid) ||
		!bytes.Equal(owner.Marker.Data, sshMarkerBytes(owner.Instance)) {
		return ErrInventoryUnsafe
	}
	return nil
}

func decodeSSHOwner(data []byte, uid int) (sshStateOwner, error) {
	if len(data) == 0 || len(data) > maxSSHOwnerBytes {
		return sshStateOwner{}, ErrInventoryBounds
	}
	var owner sshStateOwner
	if err := json.Unmarshal(data, &owner); err != nil {
		return sshStateOwner{}, ErrInventoryUnsafe
	}
	encoded, err := json.Marshal(owner)
	if err != nil || !bytes.Equal(encoded, data) {
		return sshStateOwner{}, ErrInventoryUnsafe
	}
	if err := owner.validate(uid); err != nil {
		return sshStateOwner{}, err
	}
	return owner, nil
}

// A caller keeps the descriptor open while inspecting a fixed child. The name
// is a private constant, never an operator-supplied path or Include expression.
func readSSHPrivateChild(directory *os.File, name string, uid, limit int) (sshFileImage, error) {
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOCTTY, 0)
	if err != nil {
		return sshFileImage{}, err
	}
	file := os.NewFile(uintptr(fd), "ssh-private-state-record")
	defer file.Close()
	image, err := readSSHImage(file, uid, 1, limit)
	if err != nil || image.state.mode&07777 != 0600 || int64(image.state.gid) != int64(uid) {
		return sshFileImage{}, errors.Join(ErrInventoryUnsafe, err)
	}
	var named unix.Stat_t
	if err := unix.Fstatat(int(directory.Fd()), name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil || stamp(named) != image.state {
		return sshFileImage{}, errors.Join(ErrInventoryChanged, err)
	}
	return image, nil
}

func readSSHOwner(parent *os.File, uid int) (sshStateOwner, sshFileImage, error) {
	image, err := readSSHPrivateChild(parent, sshOwnerName, uid, maxSSHOwnerBytes)
	if err != nil {
		return sshStateOwner{}, sshFileImage{}, err
	}
	owner, err := decodeSSHOwner(image.data, uid)
	return owner, image, err
}

func openSSHStateParent(root *os.File, uid int) (*os.File, error) {
	if root == nil {
		return nil, ErrInventoryUnsafe
	}
	reader := inventoryReader{root: root, uid: uid, state: inventorySnapshot{nodes: make(map[string]inventoryStamp)}}
	parent, err := reader.openDirectory(sshStateParent)
	if err != nil || parent == nil {
		return nil, errors.Join(ErrInventoryUnsafe, err)
	}
	return parent, nil
}

func recheckSSHStateParent(root, parent *os.File, uid int, identity sshDirectoryIdentity) error {
	current, err := openSSHStateParent(root, uid)
	if err != nil {
		return err
	}
	defer current.Close()
	held, err := sshDirectoryImage(parent, uid)
	if err != nil {
		return err
	}
	named, err := sshDirectoryImage(current, uid)
	if err != nil || !reflect.DeepEqual(held, identity) || !reflect.DeepEqual(named, identity) {
		return errors.Join(ErrInventoryChanged, err)
	}
	return nil
}

func attestSSHStateDirectory(parent *os.File, name string, owner sshStateOwner, uid int, staging bool) error {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(fd), "ssh-owned-state-directory")
	defer directory.Close()
	identity, err := sshDirectoryImage(directory, uid)
	if err != nil || !reflect.DeepEqual(identity, owner.Directory) {
		return errors.Join(ErrInventoryChanged, err)
	}
	marker, err := readSSHPrivateChild(directory, sshMarkerName, uid, maxSSHOwnerBytes)
	if err != nil || !reflect.DeepEqual(recoveryImage(marker), owner.Marker) {
		return errors.Join(ErrInventoryChanged, err)
	}
	if staging {
		names, err := directory.Readdirnames(2)
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		if len(names) != 1 || names[0] != sshMarkerName {
			return ErrInventoryUnsafe
		}
	}
	after, err := sshDirectoryImage(directory, uid)
	if err != nil || !reflect.DeepEqual(after, identity) {
		return errors.Join(ErrInventoryChanged, err)
	}
	var named unix.Stat_t
	if err := unix.Fstatat(int(parent.Fd()), name, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil || named.Dev != identity.Device || named.Ino != identity.Inode ||
		named.Mode != identity.Mode || named.Uid != identity.UID || named.Gid != identity.GID {
		return errors.Join(ErrInventoryChanged, err)
	}
	return nil
}

// verifySSHStateOwner does not repair storage. Every journal use rechecks the
// independently retained receipt, its parent, and the exact marker identity.
func verifySSHStateOwner(root *os.File, uid int) (sshFileImage, error) {
	parent, err := openSSHStateParent(root, uid)
	if err != nil {
		return sshFileImage{}, err
	}
	defer parent.Close()
	owner, image, err := readSSHOwner(parent, uid)
	if err != nil {
		return sshFileImage{}, err
	}
	if err := recheckSSHStateParent(root, parent, uid, owner.Parent); err != nil {
		return sshFileImage{}, err
	}
	if err := attestSSHStateDirectory(parent, sshStateName, owner, uid, false); err != nil {
		return sshFileImage{}, err
	}
	_, after, err := readSSHOwner(parent, uid)
	if err != nil || !reflect.DeepEqual(image, after) {
		return sshFileImage{}, errors.Join(ErrInventoryChanged, err)
	}
	if err := recheckSSHStateParent(root, parent, uid, owner.Parent); err != nil {
		return sshFileImage{}, err
	}
	return image, nil
}

type sshProvisionOps struct {
	sync   func(*os.File) error
	rename func(int, string, int, string, uint) error
}

func sshProvisionDefaults() sshProvisionOps { return sshProvisionOps{(*os.File).Sync, unix.Renameat2} }

// provisionSSHState remains internal. The shared product parent must already
// exist with trusted ownership. Only a new private directory is created here.
// Existing unreceipted names and pre-receipt crash debris are never adopted.
func provisionSSHState(root *os.File, uid int, ops sshProvisionOps) error {
	if uid < 0 || uid > math.MaxUint32 || ops.sync == nil || ops.rename == nil {
		return ErrInventoryUnsafe
	}
	parent, err := openSSHStateParent(root, uid)
	if err != nil {
		return err
	}
	defer parent.Close()
	if err := unix.Flock(int(parent.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fmt.Errorf("SSH state provisioning is busy: %w", err)
	}
	identity, err := sshDirectoryImage(parent, uid)
	if err != nil {
		return err
	}
	if err := identity.validate(uid, false); err != nil {
		return err
	}
	owner, _, err := readSSHOwner(parent, uid)
	if errors.Is(err, unix.ENOENT) {
		if err := checkSSHUnclaimedState(parent); err != nil {
			return err
		}
		owner, err = createSSHState(root, parent, uid, identity, ops)
	}
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(owner.Parent, identity) {
		return ErrInventoryChanged
	}
	return completeSSHState(root, parent, uid, owner, ops)
}

func checkSSHUnclaimedState(parent *os.File) error {
	// Bound the shared-directory listing. Do not infer ownership of leftovers
	// from a random-looking name, even when their bytes match the current code.
	names, err := parent.Readdirnames(MaxDirectoryEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if len(names) > MaxDirectoryEntries {
		return ErrInventoryBounds
	}
	for _, name := range names {
		if name == sshStateName || name == sshOwnerName || strings.HasPrefix(name, sshStateStagePrefix) {
			return fmt.Errorf("unattributed SSH state exists; preserve it for explicit recovery")
		}
	}
	return nil
}

func writeSSHPrivateChild(parent *os.File, name string, data []byte, uid int, syncDirectory func(*os.File) error) (sshFileImage, error) {
	if uid < 0 || uid > math.MaxUint32 || parent == nil || syncDirectory == nil ||
		(name != sshOwnerName && name != sshMarkerName) {
		return sshFileImage{}, ErrInventoryUnsafe
	}
	if len(data) == 0 || len(data) > maxSSHOwnerBytes {
		return sshFileImage{}, ErrInventoryBounds
	}
	file, err := openSSHAnonymous(parent, uid)
	if err != nil {
		return sshFileImage{}, err
	}
	attrs, err := readSSHAttributes(int(file.Fd()))
	if err != nil {
		return sshFileImage{}, errors.Join(err, file.Close())
	}
	wanted := make(map[string][]byte)
	if label, exists := attrs["security.selinux"]; exists {
		wanted["security.selinux"] = label
	}
	stage, err := finishSSHAnonymous(file, data, 0600, uint32(uid), wanted, uid)
	if err != nil {
		return sshFileImage{}, err
	}
	defer stage.Close()
	if err := unix.Linkat(unix.AT_FDCWD, fmt.Sprintf("/proc/self/fd/%d", stage.file.Fd()), int(parent.Fd()), name, unix.AT_SYMLINK_FOLLOW); err != nil {
		return sshFileImage{}, err
	}
	if err := syncDirectory(parent); err != nil {
		return sshFileImage{}, fmt.Errorf("SSH state durability is uncertain; preserve evidence: %w", err)
	}
	image, err := readSSHPrivateChild(parent, name, uid, maxSSHOwnerBytes)
	if err != nil {
		return sshFileImage{}, err
	}
	retained, err := readSSHImage(stage.file, uid, 1, maxSSHOwnerBytes)
	if err != nil || !reflect.DeepEqual(image, retained) || image.state.ino != stage.image.state.ino ||
		image.state.dev != stage.image.state.dev || !bytes.Equal(image.data, data) {
		return sshFileImage{}, errors.Join(ErrInventoryChanged, err)
	}
	return image, nil
}

func createSSHState(root, parent *os.File, uid int, parentIdentity sshDirectoryIdentity, ops sshProvisionOps) (sshStateOwner, error) {
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return sshStateOwner{}, err
	}
	instance := hex.EncodeToString(random[:])
	name := sshStateStagePrefix + instance
	if err := recheckSSHStateParent(root, parent, uid, parentIdentity); err != nil {
		return sshStateOwner{}, err
	}
	if err := unix.Mkdirat(int(parent.Fd()), name, 0700); err != nil {
		return sshStateOwner{}, err
	}
	// From this point, failures preserve the new directory. Before a durable
	// sibling receipt exists it cannot be claimed automatically after a crash.
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return sshStateOwner{}, err
	}
	directory := os.NewFile(uintptr(fd), "ssh-new-state-directory")
	defer directory.Close()
	if err := directory.Chown(uid, uid); err != nil {
		return sshStateOwner{}, err
	}
	if err := directory.Chmod(0700); err != nil {
		return sshStateOwner{}, err
	}
	attrs, err := readSSHAttributes(fd)
	if err != nil {
		return sshStateOwner{}, err
	}
	// Strip inherited discretionary ACLs only from our newly created inode.
	// Preserve its kernel-assigned SELinux label, never a parent label copy.
	wanted := make(map[string][]byte)
	if label, exists := attrs["security.selinux"]; exists {
		wanted["security.selinux"] = label
	}
	if _, exists := attrs["system.posix_acl_default"]; exists {
		if err := unix.Fremovexattr(fd, "system.posix_acl_default"); err != nil {
			return sshStateOwner{}, err
		}
	}
	if err := replaceSSHAttributes(fd, wanted); err != nil {
		return sshStateOwner{}, err
	}
	marker, err := writeSSHPrivateChild(directory, sshMarkerName, sshMarkerBytes(instance), uid, ops.sync)
	if err != nil {
		return sshStateOwner{}, err
	}
	identity, err := sshDirectoryImage(directory, uid)
	if err != nil {
		return sshStateOwner{}, err
	}
	owner := sshStateOwner{1, instance, parentIdentity, identity, recoveryImage(marker)}
	if err := owner.validate(uid); err != nil {
		return sshStateOwner{}, err
	}
	if err := attestSSHStateDirectory(parent, name, owner, uid, true); err != nil {
		return sshStateOwner{}, err
	}
	if err := recheckSSHStateParent(root, parent, uid, parentIdentity); err != nil {
		return sshStateOwner{}, err
	}
	if err := ops.sync(parent); err != nil {
		return sshStateOwner{}, err
	}
	data, err := json.Marshal(owner)
	if err != nil {
		return sshStateOwner{}, err
	}
	if _, err := writeSSHPrivateChild(parent, sshOwnerName, data, uid, ops.sync); err != nil {
		return sshStateOwner{}, err
	}
	return owner, nil
}

func completeSSHState(root, parent *os.File, uid int, owner sshStateOwner, ops sshProvisionOps) error {
	if err := recheckSSHStateParent(root, parent, uid, owner.Parent); err != nil {
		return err
	}
	stage := sshStateStagePrefix + owner.Instance
	var named unix.Stat_t
	err := unix.Fstatat(int(parent.Fd()), sshStateName, &named, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		if err := attestSSHStateDirectory(parent, stage, owner, uid, true); err != nil {
			return err
		}
		// Reestablish receipt durability on a reopened, interrupted attempt.
		if err := ops.sync(parent); err != nil {
			return err
		}
		current, _, err := readSSHOwner(parent, uid)
		if err != nil || !reflect.DeepEqual(current, owner) {
			return errors.Join(ErrInventoryChanged, err)
		}
		if err := recheckSSHStateParent(root, parent, uid, owner.Parent); err != nil {
			return err
		}
		if err := attestSSHStateDirectory(parent, stage, owner, uid, true); err != nil {
			return err
		}
		if err := ops.rename(int(parent.Fd()), stage, int(parent.Fd()), sshStateName, unix.RENAME_NOREPLACE); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if err := unix.Fstatat(int(parent.Fd()), stage, &named, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		return errors.Join(ErrInventoryChanged, err)
	}
	if err := attestSSHStateDirectory(parent, sshStateName, owner, uid, false); err != nil {
		return err
	}
	if err := ops.sync(parent); err != nil {
		return fmt.Errorf("SSH state publication durability is uncertain; preserve evidence: %w", err)
	}
	if err := recheckSSHStateParent(root, parent, uid, owner.Parent); err != nil {
		return err
	}
	image, err := verifySSHStateOwner(root, uid)
	if err != nil {
		return err
	}
	current, err := decodeSSHOwner(image.data, uid)
	if err != nil || !reflect.DeepEqual(current, owner) {
		return errors.Join(ErrInventoryChanged, err)
	}
	return nil
}
