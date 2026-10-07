//go:build linux

package fileorigin

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const SnapshotAttribute = "user.syswarden.snapshot-origin-v1"
const DashboardSnapshot = "dashboard"
const MetricsSnapshot = "metrics"
const maximumSnapshotBytes = 16 << 20

var errSnapshotOriginUnavailable = errors.New("snapshot creation identity is unavailable")

type snapshotIdentity struct {
	device, inode, links uint64
	mode, uid, gid       uint32
	size                 int64
	modified, changed    syscall.Timespec
}

type snapshotObservation struct {
	exists   bool
	identity snapshotIdentity
	digest   [sha256.Size]byte
	owned    bool
	content  []byte
}

func snapshotFileIdentity(info os.FileInfo) (snapshotIdentity, error) {
	if info == nil {
		return snapshotIdentity{}, fmt.Errorf("snapshot metadata is unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || stat.Nlink != 1 ||
		int64(stat.Uid) != int64(os.Geteuid()) || int64(stat.Gid) != int64(os.Getegid()) ||
		info.Size() < 0 || info.Size() > maximumSnapshotBytes {
		return snapshotIdentity{}, fmt.Errorf("snapshot must be a bounded exclusive private owned file")
	}
	return snapshotIdentity{stat.Dev, stat.Ino, uint64(stat.Nlink), stat.Mode, stat.Uid, stat.Gid, stat.Size, stat.Mtim, stat.Ctim}, nil
}

func validSnapshotKind(kind string) bool {
	return kind == DashboardSnapshot || kind == MetricsSnapshot
}

func snapshotOriginRecord(file *os.File, kind string, digest [sha256.Size]byte) ([]byte, error) {
	if file == nil || !validSnapshotKind(kind) {
		return nil, fmt.Errorf("snapshot origin request is invalid")
	}
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	identity, err := snapshotFileIdentity(info)
	if err != nil {
		return nil, err
	}
	var birth unix.Statx_t
	if err := unix.Statx(int(file.Fd()), "", unix.AT_EMPTY_PATH, unix.STATX_INO|unix.STATX_BTIME, &birth); err != nil {
		return nil, err
	}
	if birth.Mask&unix.STATX_BTIME == 0 || birth.Ino != identity.inode {
		return nil, errSnapshotOriginUnavailable
	}
	return []byte(fmt.Sprintf("SYSWARDEN_SNAPSHOT_ORIGIN_V1\nkind=%s\ninode=%d\nbirth_sec=%d\nbirth_nsec=%d\nsha256=%x\n", kind, identity.inode, birth.Btime.Sec, birth.Btime.Nsec, digest)), nil
}

// HasSnapshotOrigin never upgrades an old or manually changed snapshot into
// an owned file. The digest must come from a stable descriptor-rooted read.
func HasSnapshotOrigin(file *os.File, kind string, digest [sha256.Size]byte) (bool, error) {
	if file == nil || !validSnapshotKind(kind) {
		return false, fmt.Errorf("snapshot origin request is invalid")
	}
	var record [512]byte
	size, err := unix.Fgetxattr(int(file.Fd()), SnapshotAttribute, record[:])
	if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.ENOTSUP) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	expected, err := snapshotOriginRecord(file, kind, digest)
	return err == nil && string(record[:size]) == string(expected), err
}

func readSnapshot(root *os.Root, name, kind string) (snapshotObservation, error) {
	var observed snapshotObservation
	before, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return observed, nil
	}
	if err != nil {
		return observed, err
	}
	observed.identity, err = snapshotFileIdentity(before)
	if err != nil {
		return observed, err
	}
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return observed, err
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	identity, identityErr := snapshotFileIdentity(opened)
	if err != nil || identityErr != nil || identity != observed.identity {
		return observed, fmt.Errorf("snapshot changed while opening")
	}
	observed.content, err = io.ReadAll(io.LimitReader(file, maximumSnapshotBytes+1))
	if err != nil || int64(len(observed.content)) != identity.size {
		return observed, fmt.Errorf("snapshot changed during bounded read")
	}
	observed.digest = sha256.Sum256(observed.content)
	observed.owned, err = HasSnapshotOrigin(file, kind, observed.digest)
	if err != nil {
		return observed, err
	}
	after, err := root.Lstat(name)
	afterIdentity, identityErr := snapshotFileIdentity(after)
	if err != nil || identityErr != nil || afterIdentity != observed.identity {
		return observed, fmt.Errorf("snapshot changed during inspection")
	}
	observed.exists = true
	return observed, nil
}

func sameSnapshot(left, right snapshotObservation, moved bool) bool {
	if moved {
		left.identity.changed, right.identity.changed = syscall.Timespec{}, syscall.Timespec{}
	}
	return left.exists == right.exists && left.identity == right.identity && left.digest == right.digest && left.owned == right.owned
}

func openSnapshotDirectory(path, kind string) (*os.Root, string, error) {
	name := filepath.Base(path)
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !validSnapshotKind(kind) ||
		kind == DashboardSnapshot && name != "data.json" || kind == MetricsSnapshot && name != "metrics_24h.json" {
		return nil, "", fmt.Errorf("snapshot destination is not a canonical product output")
	}
	directory := filepath.Dir(path)
	before, err := os.Lstat(directory)
	if err != nil {
		return nil, "", err
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 || before.Mode().Perm()&0022 != 0 ||
		int64(stat.Uid) != int64(os.Geteuid()) || int64(stat.Gid) != int64(os.Getegid()) {
		return nil, "", fmt.Errorf("snapshot directory is not owner controlled")
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		return nil, "", err
	}
	for _, component := range strings.Split(strings.TrimPrefix(directory, "/"), "/") {
		if component == "" {
			continue
		}
		entry, statErr := root.Lstat(component)
		if statErr != nil || !entry.IsDir() || entry.Mode()&os.ModeSymlink != 0 {
			_ = root.Close()
			return nil, "", fmt.Errorf("snapshot ancestor is not a real directory")
		}
		next, openErr := root.OpenRoot(component)
		if openErr != nil {
			_ = root.Close()
			return nil, "", openErr
		}
		opened, statErr := next.Stat(".")
		if statErr != nil || !os.SameFile(entry, opened) {
			_ = next.Close()
			_ = root.Close()
			return nil, "", fmt.Errorf("snapshot ancestor changed while opening")
		}
		_ = root.Close()
		root = next
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(before, opened) || before.Mode() != opened.Mode() {
		_ = root.Close()
		return nil, "", fmt.Errorf("snapshot directory changed while opening")
	}
	return root, name, nil
}

func ReadSnapshotFile(path, kind string) ([]byte, error) {
	root, name, err := openSnapshotDirectory(path, kind)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	observed, err := readSnapshot(root, name, kind)
	if err != nil {
		return nil, err
	}
	if !observed.exists {
		return nil, os.ErrNotExist
	}
	return observed.content, nil
}

// PublishSnapshot stages an exclusive inode and keeps legacy snapshots
// unmarked. Exchange publication verifies the displaced inode before removing
// it, so a concurrent replacement is restored or retained for inspection.
func PublishSnapshot(path, kind string, content []byte) error {
	return publishSnapshot(path, kind, content, nil)
}

func publishSnapshot(path, kind string, content []byte, beforePublish func()) error {
	if len(content) > maximumSnapshotBytes {
		return fmt.Errorf("snapshot exceeds its publication bound")
	}
	root, name, err := openSnapshotDirectory(path, kind)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	parent, err := root.Open(".")
	if err != nil {
		return err
	}
	defer func() { _ = parent.Close() }()
	if err := unix.Flock(int(parent.Fd()), unix.LOCK_EX); err != nil {
		return err
	}
	defer func() { _ = unix.Flock(int(parent.Fd()), unix.LOCK_UN) }()
	before, err := readSnapshot(root, name, kind)
	if err != nil {
		return err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	temporary := ".syswarden-snapshot-" + kind + "-" + hex.EncodeToString(nonce[:])
	staged, err := root.OpenFile(temporary, os.O_RDWR|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			current, currentErr := root.Lstat(temporary)
			opened, openedErr := staged.Stat()
			if currentErr == nil && openedErr == nil && os.SameFile(current, opened) {
				_ = root.Remove(temporary)
			}
		}
		_ = staged.Close()
	}()
	if written, err := staged.Write(content); err != nil || written != len(content) {
		return errors.Join(fmt.Errorf("write complete snapshot staging content"), err)
	}
	if !before.exists || before.owned {
		record, err := snapshotOriginRecord(staged, kind, sha256.Sum256(content))
		if err != nil && !snapshotOriginUnavailable(err) {
			return err
		}
		if err == nil {
			if err := unix.Fsetxattr(int(staged.Fd()), SnapshotAttribute, record, unix.XATTR_CREATE); err != nil && !snapshotOriginUnavailable(err) {
				return err
			}
		}
	}
	if err := staged.Sync(); err != nil {
		return err
	}
	created, err := readSnapshot(root, temporary, kind)
	if err != nil {
		return err
	}
	if beforePublish != nil {
		beforePublish()
	}
	checkRoot, _, err := openSnapshotDirectory(path, kind)
	if err != nil {
		return err
	}
	namedParent, namedErr := checkRoot.Stat(".")
	pinnedParent, pinnedErr := root.Stat(".")
	_ = checkRoot.Close()
	if namedErr != nil || pinnedErr != nil || !os.SameFile(namedParent, pinnedParent) {
		return fmt.Errorf("snapshot parent changed before publication")
	}
	current, err := readSnapshot(root, name, kind)
	if err != nil || !sameSnapshot(before, current, false) {
		return fmt.Errorf("snapshot destination changed before publication")
	}
	currentStage, err := readSnapshot(root, temporary, kind)
	if err != nil || !sameSnapshot(created, currentStage, false) {
		return fmt.Errorf("snapshot staging entry changed before publication")
	}
	flags := uint(unix.RENAME_NOREPLACE)
	if before.exists {
		flags = unix.RENAME_EXCHANGE
	}
	if err := unix.Renameat2(int(parent.Fd()), temporary, int(parent.Fd()), name, flags); err != nil {
		return err
	}
	removeTemporary = false
	if err := parent.Sync(); err != nil {
		return err
	}
	published, publishErr := readSnapshot(root, name, kind)
	if publishErr != nil || !sameSnapshot(created, published, true) {
		return fmt.Errorf("published snapshot changed; preserve staging evidence")
	}
	if before.exists {
		displaced, err := readSnapshot(root, temporary, kind)
		if err != nil || !sameSnapshot(before, displaced, true) {
			current, currentErr := readSnapshot(root, name, kind)
			if currentErr != nil || !sameSnapshot(created, current, true) {
				return fmt.Errorf("snapshot changed again before restoration; preserve both paths")
			}
			if restoreErr := unix.Renameat2(int(parent.Fd()), temporary, int(parent.Fd()), name, unix.RENAME_EXCHANGE); restoreErr != nil {
				return fmt.Errorf("snapshot displacement changed and restoration failed; preserve both paths")
			}
			if err := parent.Sync(); err != nil {
				return fmt.Errorf("sync restored snapshot directory: %w", err)
			}
			return fmt.Errorf("snapshot displacement changed; concurrent content restored and staging retained")
		}
		if err := root.Remove(temporary); err != nil {
			return err
		}
	}
	return parent.Sync()
}

func snapshotOriginUnavailable(err error) bool {
	return errors.Is(err, errSnapshotOriginUnavailable) || errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.ENOSYS)
}
