package journal

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"sync"

	"golang.org/x/sys/unix"
	contracts "syswarden-core/contracts/v5"
)

// CustodyEnrollment is explicit independent bootstrap authority. The caller must
// authenticate its origin and provision a separate protected directory. It is
// pinned for this backend; this component is not a key rotation/revocation service.
type CustodyEnrollment struct {
	Initial   contracts.JournalCheckpointAnchor
	Authority contracts.JournalCheckpointAuthority
}

// CustodyRecoveryRequest owns a scope-bound exact pending intent and plan digest.
// These values describe the requested decision; they do not authenticate anyone.
type CustodyRecoveryRequest struct {
	Intent     CustodyIntent
	PlanSHA256 string
}

// CustodyRecoveryAuthorizer must authenticate the principal, enforce current
// scope/policy, independently verify approval, and durably audit the decision.
// Its returned lowercase SHA-256 identifies that audit record, not a credential.
// It must be bounded, must not reenter the lease, and must return an error when
// the independent approval or audit is unavailable. Nil denies all recovery.
type CustodyRecoveryAuthorizer interface {
	AuthorizeCustodyRecovery(CustodyRecoveryRequest) (decisionSHA256 string, err error)
}

func custodyEnrollment(e CustodyEnrollment) (RestartState, error) {
	s := RestartState{Initial: e.Initial, Head: e.Initial, Authority: e.Authority}
	if validateRestartState(s) != nil || e.Initial.NextSequence < e.Authority.FirstSequence || e.Initial.NextSequence > e.Authority.LastSequence {
		return RestartState{}, ErrCustodyState
	}
	s.Authority.PublicKey = bytes.Clone(s.Authority.PublicKey)
	return s, nil
}

// LocalCustody is an inactive filesystem backend rooted in a caller-provisioned
// private directory. Do not copy it. It owns its directory descriptor; it never
// provisions users, changes permissions, discovers keys or ingests production data.
// Protection depends on the authority's OS isolation and protected ancestors.
// Checksums do not prevent same-UID/root rollback of the custody file itself.
type LocalCustody struct {
	mu         sync.Mutex
	directory  *os.File
	enrollment RestartState
	authorizer CustodyRecoveryAuthorizer
}

type fileCustodyLease struct {
	mu            sync.Mutex
	directory     *os.File
	file          segmentFile
	enrollment    RestartState
	authorizer    CustodyRecoveryAuthorizer
	stamp         unix.Stat_t
	tip           custodyTip
	poisoned      bool
	syncDirectory func() error
}

func openCustodyLease(dir *os.File, enrollment RestartState, authorizer CustodyRecoveryAuthorizer, create bool) (*fileCustodyLease, error) {
	flags := unix.O_RDWR | unix.O_APPEND | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_NOCTTY
	if create {
		flags |= unix.O_CREAT | unix.O_EXCL
	} else {
		var st unix.Stat_t
		if err := unix.Fstatat(int(dir.Fd()), custodyFileName, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil || !privateFile(st) || st.Size > maxCustodyFile {
			return nil, errors.Join(ErrUnsafeStorage, err, dir.Close())
		}
	}
	fd, err := unix.Openat(int(dir.Fd()), custodyFileName, flags, 0600)
	if err != nil {
		return nil, errors.Join(err, dir.Close())
	}
	l := &fileCustodyLease{directory: dir, file: diskFile{os.NewFile(uintptr(fd), "journal-custody")}, enrollment: enrollment, authorizer: authorizer, syncDirectory: dir.Sync}
	l.stamp, err = attestEntry(dir, l.file, custodyFileName)
	if err != nil || l.stamp.Size > maxCustodyFile || (create && l.stamp.Size != 0) {
		return nil, errors.Join(ErrUnsafeStorage, err, l.Close())
	}
	return l, nil
}

// BootstrapLocalCustody exclusively writes an authorized enrollment record.
// Existing objects are never adopted, overwritten or removed. Any uncertain
// write/sync/close outcome retains the file for separate inspection.
func BootstrapLocalCustody(directory *os.File, enrollment CustodyEnrollment) error {
	state, err := custodyEnrollment(enrollment)
	if err != nil {
		return err
	}
	dir, err := openDirectory(directory)
	if err != nil {
		return err
	}
	l, err := openCustodyLease(dir, state, nil, true)
	if err != nil {
		return err
	}
	err = errors.Join(l.append(state, "bootstrap", "", ""), l.Close())
	if err != nil {
		return errors.Join(ErrCommitUncertain, err)
	}
	return nil
}

// OpenLocalCustody verifies an existing protected ledger against explicit pinned
// enrollment. It never bootstraps a missing file. Each Acquire rereads and syncs
// the full bounded ledger under a fresh process lock; no cached head is returned.
// A complete valid protected transition after an interrupted call is authoritative
// here. Partial/corrupt records fail closed, with no accepted prefix or repair.
func OpenLocalCustody(directory *os.File, enrollment CustodyEnrollment, authorizer CustodyRecoveryAuthorizer) (*LocalCustody, error) {
	state, err := custodyEnrollment(enrollment)
	if err != nil {
		return nil, err
	}
	dir, err := openDirectory(directory)
	if err != nil {
		return nil, err
	}
	// Keep an owned reference without holding the lease lock between calls.
	if err = unix.Flock(int(dir.Fd()), unix.LOCK_UN); err != nil {
		return nil, errors.Join(err, dir.Close())
	}
	b := &LocalCustody{directory: dir, enrollment: state, authorizer: authorizer}
	lease, err := b.Acquire()
	if err != nil {
		return nil, errors.Join(err, b.Close())
	}
	if err = lease.Close(); err != nil {
		return nil, errors.Join(ErrCommitUncertain, err, b.Close())
	}
	return b, nil
}

func (b *LocalCustody) Acquire() (RestartLease, error) {
	b.mu.Lock()
	if b.directory == nil {
		b.mu.Unlock()
		return nil, ErrClosed
	}
	dir, err := openDirectory(b.directory)
	enrollment, authorizer := b.enrollment, b.authorizer
	b.mu.Unlock()
	if err != nil {
		return nil, err
	}
	l, err := openCustodyLease(dir, enrollment, authorizer, false)
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
		return nil, errors.Join(ErrCommitUncertain, err, l.Close())
	}
	return l, nil
}

// Close stops new acquisitions. Existing independent leases remain valid until
// their own Close, so closing a factory cannot silently revoke a live transaction.
func (b *LocalCustody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.directory == nil {
		return nil
	}
	err := b.directory.Close()
	b.directory = nil
	return err
}

func (l *fileCustodyLease) usable() error {
	if l.file == nil {
		return ErrClosed
	}
	if l.poisoned {
		return ErrCommitUncertain
	}
	return nil
}
func (l *fileCustodyLease) unchanged() error {
	st, err := attestEntry(l.directory, l.file, custodyFileName)
	if err != nil || !sameStamp(st, l.stamp) {
		l.poisoned = true
		return errors.Join(ErrChanged, err)
	}
	return nil
}
func (l *fileCustodyLease) read() (custodyTip, error) {
	if err := l.unchanged(); err != nil {
		return custodyTip{}, err
	}
	if l.stamp.Size <= 0 || l.stamp.Size > maxCustodyFile {
		return custodyTip{}, ErrCustodyFormat
	}
	data := make([]byte, int(l.stamp.Size))
	n, err := l.file.ReadAt(data, 0)
	if err != nil || n != len(data) {
		return custodyTip{}, errors.Join(ErrCustodyFormat, err)
	}
	if err = l.unchanged(); err != nil {
		return custodyTip{}, err
	}
	return scanCustody(data, l.enrollment)
}
func sameCustodyTip(a, b custodyTip) bool {
	return sameRestartState(a.state, b.state) && a.plan == b.plan && a.decision == b.decision && a.hash == b.hash && a.count == b.count && a.bytes == b.bytes
}
func (l *fileCustodyLease) refresh() error {
	if err := l.usable(); err != nil {
		return err
	}
	tip, err := l.read()
	if err != nil || !sameCustodyTip(tip, l.tip) {
		l.poisoned = true
		return errors.Join(ErrChanged, err)
	}
	return nil
}
func (l *fileCustodyLease) State() (RestartState, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.refresh(); err != nil {
		return RestartState{}, err
	}
	s := l.tip.state
	s.Authority.PublicKey = bytes.Clone(s.Authority.PublicKey)
	return s, nil
}

func (l *fileCustodyLease) append(state RestartState, operation, plan, decision string) error {
	if l.tip.count >= MaxCustodyRecords {
		return ErrFull
	}
	if err := l.unchanged(); err != nil {
		return err
	}
	frame, err := custodyFrame(state, l.tip.count+1, operation, plan, decision, l.tip.hash)
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
	st, err := attestEntry(l.directory, l.file, custodyFileName)
	if err != nil || st.Dev != l.stamp.Dev || st.Ino != l.stamp.Ino || st.Gid != l.stamp.Gid || st.Size != int64(l.tip.bytes+len(frame)) {
		l.poisoned = true
		return errors.Join(ErrCommitUncertain, err)
	}
	l.stamp = st
	tip, err := l.read()
	var expectedHash [sha256.Size]byte
	copy(expectedHash[:], frame[len(frame)-sha256.Size:])
	if err != nil || !sameRestartState(tip.state, state) || tip.hash != expectedHash || tip.count != l.tip.count+1 || tip.plan != plan || tip.decision != decision {
		l.poisoned = true
		return errors.Join(ErrCommitUncertain, err)
	}
	l.tip = tip
	return nil
}

func (l *fileCustodyLease) Prepare(intent CustodyIntent) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.refresh(); err != nil {
		return err
	}
	if l.tip.state.Pending != (CustodyIntent{}) || intent.Before != l.tip.state.Head {
		return ErrCustodyState
	}
	next := l.tip.state
	next.Pending = intent
	if intent == (CustodyIntent{}) || validateRestartState(next) != nil {
		return ErrCustodyState
	}
	// Keep one record available for Finish after preparing this intent.
	if l.tip.count > MaxCustodyRecords-2 {
		return ErrFull
	}
	return l.append(next, "prepare", "", "")
}
func (l *fileCustodyLease) Finish(intent CustodyIntent) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.refresh(); err != nil {
		return err
	}
	if intent == (CustodyIntent{}) || intent != l.tip.state.Pending {
		return ErrCustodyState
	}
	next := l.tip.state
	next.Head, next.Pending = intent.After, CustodyIntent{}
	return l.append(next, "finish", "", "")
}
func (l *fileCustodyLease) AuthorizeRecovery(planSHA256 string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.refresh(); err != nil {
		return err
	}
	if l.authorizer == nil || !validRecoveryApproval(planSHA256) || l.tip.state.Pending == (CustodyIntent{}) {
		return ErrRecoveryApproval
	}
	if l.tip.count >= MaxCustodyRecords || (l.tip.count == MaxCustodyRecords-1 && l.tip.plan != planSHA256) {
		return ErrFull
	}
	decision, err := l.authorizer.AuthorizeCustodyRecovery(CustodyRecoveryRequest{Intent: l.tip.state.Pending, PlanSHA256: planSHA256})
	if err != nil || !validRecoveryApproval(decision) {
		return errors.Join(ErrRecoveryApproval, err)
	}
	if err = l.refresh(); err != nil {
		return err
	}
	// Reuse only the exact already durable decision after fresh authorization.
	// A different decision needs a record while still reserving Finish capacity.
	if l.tip.plan == planSHA256 && l.tip.decision == decision {
		return nil
	}
	if l.tip.count > MaxCustodyRecords-2 {
		return ErrFull
	}
	return l.append(l.tip.state, "approve", planSHA256, decision)
}
func (l *fileCustodyLease) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := errors.Join(l.file.Close(), l.directory.Close())
	l.file = nil
	l.directory = nil
	return err
}
