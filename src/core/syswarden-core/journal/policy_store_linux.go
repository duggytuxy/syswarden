package journal

import (
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// LocalCustodyPolicy retains the current independently administered policy in a
// bounded protected ledger. Do not copy it. It owns its directory reference.
// The bootstrap pin and protected directory must be independently provisioned.
// Only trusted administration may call Install/Disable; neither is an IPC action.
// Signatures authenticate policy statements, not an operator's update request.
// This is not a service, root-rollback defense or key-rotation implementation.
type LocalCustodyPolicy struct {
	mu        sync.Mutex
	directory *os.File
	root      CustodyPolicyTrust
}
type policyLease struct {
	directory     *os.File
	file          segmentFile
	root          CustodyPolicyTrust
	stamp         unix.Stat_t
	tip           policyTip
	poisoned      bool
	syncDirectory func() error
}

func openPolicyLease(dir *os.File, root CustodyPolicyTrust, create bool) (*policyLease, error) {
	flags := unix.O_RDWR | unix.O_APPEND | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_NOCTTY
	if create {
		flags |= unix.O_CREAT | unix.O_EXCL
	} else {
		var st unix.Stat_t
		if err := unix.Fstatat(int(dir.Fd()), policyFileName, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil || !privateFile(st) || st.Size > maxPolicyFile {
			return nil, errors.Join(ErrUnsafeStorage, err, dir.Close())
		}
	}
	fd, err := unix.Openat(int(dir.Fd()), policyFileName, flags, 0600)
	if err != nil {
		return nil, errors.Join(err, dir.Close())
	}
	l := &policyLease{directory: dir, file: diskFile{os.NewFile(uintptr(fd), "custody-policy")}, root: root, syncDirectory: dir.Sync}
	l.stamp, err = attestEntry(dir, l.file, policyFileName)
	if err != nil || l.stamp.Size > maxPolicyFile || (create && l.stamp.Size != 0) {
		return nil, errors.Join(ErrUnsafeStorage, err, l.close())
	}
	return l, nil
}

// BootstrapLocalCustodyPolicy exclusively records an independently approved root
// pin and signed policy. No missing/current policy is inferred from journal data.
// Failure retains all bytes; no retry resets or repairs an existing object.
func BootstrapLocalCustodyPolicy(directory *os.File, initial CustodyPolicySnapshot, now time.Time) error {
	initial = clonePolicySnapshot(initial)
	trust := initial.Trust
	trust.Enabled = true
	if _, err := VerifyCustodyAccessPolicy(initial.Document, initial.Signature, trust, now); err != nil {
		return err
	}
	dir, err := openDirectory(directory)
	if err != nil {
		return err
	}
	l, err := openPolicyLease(dir, initial.Trust, true)
	if err != nil {
		return err
	}
	if err = errors.Join(l.append(initial, "bootstrap"), l.close()); err != nil {
		return errors.Join(ErrCommitUncertain, err)
	}
	return nil
}

// OpenLocalCustodyPolicy never bootstraps. The independently pinned original root
// verifies the complete protected transition history, including expired/disabled
// policies. Every acquisition resynchronizes and reads back that bounded history.
func OpenLocalCustodyPolicy(directory *os.File, root CustodyPolicyTrust) (*LocalCustodyPolicy, error) {
	if !validPolicyRoot(root) {
		return nil, ErrPolicyState
	}
	dir, err := openDirectory(directory)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(dir.Fd()), unix.LOCK_UN); err != nil {
		return nil, errors.Join(err, dir.Close())
	}
	b := &LocalCustodyPolicy{directory: dir, root: clonePolicyTrust(root)}
	l, err := b.acquire()
	if err != nil {
		return nil, errors.Join(err, b.Close())
	}
	if err = l.close(); err != nil {
		return nil, errors.Join(ErrCommitUncertain, err, b.Close())
	}
	return b, nil
}
func (b *LocalCustodyPolicy) acquire() (*policyLease, error) {
	if b == nil {
		return nil, ErrPolicyState
	}
	b.mu.Lock()
	if b.directory == nil {
		b.mu.Unlock()
		return nil, ErrClosed
	}
	dir, err := openDirectory(b.directory)
	root := b.root
	b.mu.Unlock()
	if err != nil {
		return nil, err
	}
	l, err := openPolicyLease(dir, root, false)
	if err != nil {
		return nil, err
	}
	l.tip, err = l.read()
	if err == nil {
		err = l.file.Sync()
	}
	if err == nil {
		err = l.syncDirectory()
	}
	if err == nil {
		err = l.refresh()
	}
	if err != nil {
		return nil, errors.Join(ErrCommitUncertain, err, l.close())
	}
	return l, nil
}

// Current returns owned administrative state even if policy is disabled/expired.
// Call the authorized coordinator entry points for operational admission.
func (b *LocalCustodyPolicy) Current() (CustodyPolicySnapshot, error) {
	l, err := b.acquire()
	if err != nil {
		return CustodyPolicySnapshot{}, err
	}
	result := clonePolicySnapshot(l.tip.snapshot)
	if err = l.close(); err != nil {
		return CustodyPolicySnapshot{}, errors.Join(ErrCommitUncertain, err)
	}
	return result, nil
}

// Install is a trusted administrative compare-and-install primitive. Expected
// and next MUST come from independently authorized administration, never an IPC
// requester. A signed document alone does not approve installation. Admission
// grants cannot call this method. Updates share the operation's exclusive lock.
// Only the exact next revision, same issuer and same custody enrollment are
// supported. Enabled installs reserve the last record for emergency Disable.
func (b *LocalCustodyPolicy) Install(expected CustodyPolicyTrust, next CustodyPolicySnapshot, now time.Time) (CustodyPolicySnapshot, error) {
	next = clonePolicySnapshot(next)
	trust := next.Trust
	trust.Enabled = true
	if _, err := VerifyCustodyAccessPolicy(next.Document, next.Signature, trust, now); err != nil {
		return CustodyPolicySnapshot{}, err
	}
	return b.change(expected, next, "install")
}

// Disable is separately authorized administration, not a client operation. It
// preserves the exact current signed bytes and revision, even after expiry. Only
// enabled-to-disabled is permitted; re-enabling requires a new signed revision.
// The final reserved record can disable without obtaining a new issuer signature.
func (b *LocalCustodyPolicy) Disable(expected CustodyPolicyTrust) (CustodyPolicySnapshot, error) {
	l, err := b.acquire()
	if err != nil {
		return CustodyPolicySnapshot{}, err
	}
	next := clonePolicySnapshot(l.tip.snapshot)
	next.Trust.Enabled = false
	return l.changeAndClose(expected, next, "disable")
}
func (b *LocalCustodyPolicy) change(expected CustodyPolicyTrust, next CustodyPolicySnapshot, op string) (CustodyPolicySnapshot, error) {
	l, err := b.acquire()
	if err != nil {
		return CustodyPolicySnapshot{}, err
	}
	return l.changeAndClose(expected, next, op)
}
func (l *policyLease) changeAndClose(expected CustodyPolicyTrust, next CustodyPolicySnapshot, op string) (result CustodyPolicySnapshot, err error) {
	defer func() {
		err = errors.Join(err, l.close())
		if err != nil {
			result = CustodyPolicySnapshot{}
		}
	}()
	if !samePolicyTrust(l.tip.snapshot.Trust, expected) || !policyTransition(l.tip.snapshot, next, op) {
		return result, ErrPolicyState
	}
	if l.tip.count >= MaxPolicyRecords || (l.tip.count == MaxPolicyRecords-1 && next.Trust.Enabled) {
		return result, ErrFull
	}
	if err = l.append(next, op); err != nil {
		return result, err
	}
	return clonePolicySnapshot(l.tip.snapshot), nil
}

// Close stops new acquisitions, without silently expiring an existing operation.
func (b *LocalCustodyPolicy) Close() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.directory == nil {
		return nil
	}
	err := b.directory.Close()
	b.directory = nil
	return err
}
func (l *policyLease) unchanged() error {
	if l.file == nil {
		return ErrClosed
	}
	if l.poisoned {
		return ErrCommitUncertain
	}
	st, err := attestEntry(l.directory, l.file, policyFileName)
	if err != nil || !sameStamp(st, l.stamp) {
		l.poisoned = true
		return errors.Join(ErrChanged, err)
	}
	return nil
}
func (l *policyLease) read() (policyTip, error) {
	if err := l.unchanged(); err != nil {
		return policyTip{}, err
	}
	if l.stamp.Size <= 0 || l.stamp.Size > maxPolicyFile {
		return policyTip{}, ErrPolicyState
	}
	data := make([]byte, int(l.stamp.Size))
	n, err := l.file.ReadAt(data, 0)
	if err != nil || n != len(data) {
		return policyTip{}, errors.Join(ErrPolicyState, err)
	}
	if err = l.unchanged(); err != nil {
		return policyTip{}, err
	}
	return scanPolicies(data, l.root)
}
func (l *policyLease) refresh() error {
	tip, err := l.read()
	if err != nil || !samePolicyTip(tip, l.tip) {
		l.poisoned = true
		return errors.Join(ErrChanged, err)
	}
	return nil
}
func (l *policyLease) append(next CustodyPolicySnapshot, op string) error {
	if l.tip.count >= MaxPolicyRecords {
		return ErrFull
	}
	if err := l.unchanged(); err != nil {
		return err
	}
	frame, err := policyFrame(next, l.tip.count+1, op, l.tip.hash)
	if err != nil {
		return err
	}
	n, err := l.file.Write(frame)
	if err == nil && n != len(frame) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = l.file.Sync()
	}
	if err == nil {
		err = l.syncDirectory()
	}
	if err != nil {
		l.poisoned = true
		return errors.Join(ErrCommitUncertain, err)
	}
	st, err := attestEntry(l.directory, l.file, policyFileName)
	if err != nil || st.Dev != l.stamp.Dev || st.Ino != l.stamp.Ino || st.Gid != l.stamp.Gid || st.Size != int64(l.tip.bytes+len(frame)) {
		l.poisoned = true
		return errors.Join(ErrCommitUncertain, err)
	}
	l.stamp = st
	tip, err := l.read()
	var sum [sha256.Size]byte
	copy(sum[:], frame[len(frame)-sha256.Size:])
	if err != nil || !samePolicySnapshot(tip.snapshot, next) || tip.hash != sum || tip.count != l.tip.count+1 || tip.bytes != l.tip.bytes+len(frame) {
		l.poisoned = true
		return errors.Join(ErrCommitUncertain, err)
	}
	l.tip = tip
	return nil
}
func (l *policyLease) close() error {
	if l.file == nil {
		return nil
	}
	err := errors.Join(l.file.Close(), l.directory.Close())
	l.file = nil
	l.directory = nil
	return err
}
