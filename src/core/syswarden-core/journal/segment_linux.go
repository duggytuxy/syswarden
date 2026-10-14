// Package journal implements inactive, bounded Linux journal segment storage.
// It does not provision trust, establish independent restart state or ingest production events.
package journal

import (
	"errors"
	"io"
	"os"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
	contracts "syswarden-core/contracts/v5"
)

var (
	ErrInvalidOptions  = errors.New("invalid journal segment options")
	ErrUnsafeStorage   = errors.New("journal storage ownership or metadata is unsafe")
	ErrLocked          = errors.New("journal directory already has a cooperating writer or reader")
	ErrConflict        = errors.New("journal append cursor does not match committed state")
	ErrFull            = errors.New("journal segment capacity exhausted")
	ErrClosed          = errors.New("journal segment is closed")
	ErrSealed          = errors.New("authenticated journal segment is read-only")
	ErrChanged         = errors.New("journal storage changed outside this handle")
	ErrCommitUncertain = errors.New("journal commit uncertain; preserve bytes for verified recovery")
)

// Limits are mandatory per-segment ceilings, not measured retention budgets.
type Limits struct{ MaxBytes, MaxFrames int }

// Receipt describes this handle's verified prefix, not a signed checkpoint or
// persistently committed continuity anchor. Append additionally requires sync;
// a reopened historical receipt does not attest past storage synchronization.
// A failed append returns zero.
type Receipt struct {
	Start, End    contracts.JournalCursor
	Bytes, Frames int
}

// Snapshot owns its byte slice. Reading sensitive records requires separate
// caller authorization; this storage package does not redact or grant access.
type Snapshot struct {
	Receipt
	Data []byte
}

type segmentFile interface {
	Fd() uintptr
	Write([]byte) (int, error)
	ReadAt([]byte, int64) (int, error)
	Sync() error
	Close() error
}

type diskFile struct{ *os.File }

// Use one kernel write, without os.File.Write's internal short-write loop.
// An interrupted or partial result must reach the uncertain-commit boundary.
func (f diskFile) Write(data []byte) (int, error) {
	return unix.Write(int(f.Fd()), data)
}

// Segment serializes access within a process and holds an independent advisory
// directory lock. Do not copy it. The zero value is closed. Only newly created
// segments are writable; reopening authenticates and freezes the entire file.
type Segment struct {
	mu               sync.Mutex
	directory        *os.File
	file             segmentFile
	name             string
	limits           Limits
	receipt          Receipt
	stamp            unix.Stat_t
	sealed, poisoned bool
	created          bool
}

func validName(name string) bool {
	if len(name) != len("segment-")+32+len(".swj") || !strings.HasPrefix(name, "segment-") || !strings.HasSuffix(name, ".swj") {
		return false
	}
	for _, c := range name[8:40] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func validateOptions(name string, start contracts.JournalCursor, limits Limits) error {
	if !validName(name) {
		return ErrInvalidOptions
	}
	_, err := contracts.ScanEventJournal(nil, contracts.JournalReadContext{Start: start, MaxBytes: limits.MaxBytes, MaxFrames: limits.MaxFrames})
	if err != nil {
		return ErrInvalidOptions
	}
	return nil
}

func privateDirectory(st unix.Stat_t) bool {
	return st.Mode&(unix.S_IFMT|07777) == unix.S_IFDIR|0700 && int64(st.Uid) == int64(os.Geteuid()) && st.Nlink > 0
}

func privateFile(st unix.Stat_t) bool {
	return st.Mode&(unix.S_IFMT|07777) == unix.S_IFREG|0600 && int64(st.Uid) == int64(os.Geteuid()) && st.Nlink == 1 && st.Size >= 0
}

// openDirectory makes a fresh open file description: dup would share flock
// ownership with the caller and would not serialize independent handles.
func openDirectory(directory *os.File) (*os.File, error) {
	if directory == nil {
		return nil, ErrUnsafeStorage
	}
	raw, err := directory.SyscallConn()
	if err != nil {
		return nil, ErrUnsafeStorage
	}
	fd := -1
	var openErr error
	err = raw.Control(func(parent uintptr) {
		fd, openErr = unix.Openat(int(parent), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	})
	if err != nil || openErr != nil {
		return nil, errors.Join(ErrUnsafeStorage, err, openErr)
	}
	owned := os.NewFile(uintptr(fd), "journal-directory")
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil || !privateDirectory(st) {
		return nil, errors.Join(ErrUnsafeStorage, err, owned.Close())
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, errors.Join(ErrLocked, err, owned.Close())
	}
	return owned, nil
}

func (s *Segment) attest() (unix.Stat_t, error) {
	return attestEntry(s.directory, s.file, s.name)
}

func attestEntry(directory *os.File, file segmentFile, name string) (unix.Stat_t, error) {
	var dir, fd, entry unix.Stat_t
	if err := unix.Fstat(int(directory.Fd()), &dir); err != nil || !privateDirectory(dir) {
		return fd, errors.Join(ErrUnsafeStorage, err)
	}
	if err := unix.Fstat(int(file.Fd()), &fd); err != nil || !privateFile(fd) {
		return fd, errors.Join(ErrUnsafeStorage, err)
	}
	if err := unix.Fstatat(int(directory.Fd()), name, &entry, unix.AT_SYMLINK_NOFOLLOW); err != nil || !privateFile(entry) || entry.Dev != fd.Dev || entry.Ino != fd.Ino {
		return fd, errors.Join(ErrUnsafeStorage, err)
	}
	return fd, nil
}

func sameStamp(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func (s *Segment) unchanged() error {
	st, err := s.attest()
	if err != nil || !sameStamp(st, s.stamp) {
		s.poisoned = true
		return errors.Join(ErrChanged, err)
	}
	return nil
}

func (s *Segment) usable() error {
	if s.file == nil {
		return ErrClosed
	}
	if s.poisoned {
		return ErrCommitUncertain
	}
	return nil
}

func acquire(directory *os.File, name string, start contracts.JournalCursor, limits Limits, create bool) (*Segment, error) {
	if err := validateOptions(name, start, limits); err != nil {
		return nil, err
	}
	dir, err := openDirectory(directory)
	if err != nil {
		return nil, err
	}
	flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_NOCTTY
	if create {
		flags = unix.O_CREAT | unix.O_EXCL | unix.O_RDWR | unix.O_APPEND | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_NOCTTY
	} else {
		var st unix.Stat_t
		if err = unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil || !privateFile(st) || st.Size > int64(limits.MaxBytes) {
			return nil, errors.Join(ErrUnsafeStorage, err, dir.Close())
		}
	}
	fd, err := unix.Openat(int(dir.Fd()), name, flags, 0600)
	if err != nil {
		return nil, errors.Join(err, dir.Close())
	}
	s := &Segment{directory: dir, file: diskFile{os.NewFile(uintptr(fd), "journal-segment")}, name: name, limits: limits, receipt: Receipt{Start: start, End: start}, sealed: !create, created: create}
	st, err := s.attest()
	if err != nil || st.Size > int64(limits.MaxBytes) || (create && st.Size != 0) {
		return nil, errors.Join(ErrUnsafeStorage, err, s.Close())
	}
	s.stamp = st
	return s, nil
}

// CreateSegment exclusively creates a new private segment in an independently
// trusted directory. It never resolves ancestors, changes permissions, replaces
// collisions or deletes files on failure. File and directory sync must succeed
// before the handle is returned. The caller must not close directory concurrently.
func CreateSegment(directory *os.File, name string, start contracts.JournalCursor, limits Limits) (*Segment, error) {
	s, err := acquire(directory, name, start, limits, true)
	if err != nil {
		return nil, err
	}
	if err = s.syncCreation(s.directory.Sync); err != nil {
		return nil, errors.Join(err, s.Close())
	}
	return s, nil
}

func (s *Segment) syncCreation(syncDirectory func() error) error {
	if err := s.file.Sync(); err != nil {
		return errors.Join(ErrCommitUncertain, err)
	}
	if err := syncDirectory(); err != nil {
		return errors.Join(ErrCommitUncertain, err)
	}
	return s.unchanged()
}

// OpenSealedSegment verifies exact existing bytes against independently trusted
// checkpoint context. It never appends to authenticated history or commits the
// proposed anchor. New writes need a separately created segment and an external
// continuity decision. A failed open preserves every byte, including partial tails.
func OpenSealedSegment(directory *os.File, name string, checkpoint, signature []byte, context contracts.JournalCheckpointContext, limits Limits) (*Segment, error) {
	if err := validateOptions(name, context.Anchor.Cursor, limits); err != nil {
		return nil, err
	}
	if _, _, err := contracts.VerifyJournalCheckpoint(checkpoint, signature, context); err != nil {
		return nil, err
	}
	s, err := acquire(directory, name, context.Anchor.Cursor, limits, false)
	if err != nil {
		return nil, err
	}
	data, err := s.readExact()
	if err != nil {
		return nil, errors.Join(err, s.Close())
	}
	scan, _, err := contracts.ReadAuthenticatedJournalSegment(data, checkpoint, signature, context, limits.MaxBytes, limits.MaxFrames)
	if err != nil {
		return nil, errors.Join(err, s.Close())
	}
	s.receipt.End = scan.Cursor
	s.receipt.Bytes = len(data)
	s.receipt.Frames = len(scan.Records)
	return s, nil
}

func (s *Segment) readExact() ([]byte, error) {
	if err := s.unchanged(); err != nil {
		return nil, err
	}
	if s.stamp.Size < 0 || s.stamp.Size > int64(s.limits.MaxBytes) {
		return nil, ErrUnsafeStorage
	}
	data := make([]byte, int(s.stamp.Size))
	n, err := s.file.ReadAt(data, 0)
	if err != nil || n != len(data) {
		s.poisoned = true
		return nil, errors.Join(ErrChanged, err)
	}
	if err = s.unchanged(); err != nil {
		return nil, err
	}
	return data, nil
}

// Append acknowledges only a complete write followed by successful fsync and
// metadata verification. A short write or any uncertain result poisons this handle.
// It never retries, truncates, repairs, evicts or acknowledges an uncertain frame.
func (s *Segment) Append(expected contracts.JournalCursor, payload []byte) (Receipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return Receipt{}, err
	}
	if s.sealed {
		return Receipt{}, ErrSealed
	}
	if expected != s.receipt.End {
		return Receipt{}, ErrConflict
	}
	if err := s.unchanged(); err != nil {
		return Receipt{}, err
	}
	frame, next, err := contracts.EncodeEventJournalFrame(payload, expected)
	if err != nil {
		return Receipt{}, err
	}
	if s.receipt.Frames >= s.limits.MaxFrames || len(frame) > s.limits.MaxBytes-s.receipt.Bytes {
		return Receipt{}, ErrFull
	}
	n, err := s.file.Write(frame)
	if err == nil && n != len(frame) {
		err = io.ErrShortWrite
	}
	if err != nil {
		s.poisoned = true
		return Receipt{}, errors.Join(ErrCommitUncertain, err)
	}
	if err = s.file.Sync(); err != nil {
		s.poisoned = true
		return Receipt{}, errors.Join(ErrCommitUncertain, err)
	}
	st, err := s.attest()
	if err != nil || st.Size != int64(s.receipt.Bytes+len(frame)) || st.Dev != s.stamp.Dev || st.Ino != s.stamp.Ino || st.Gid != s.stamp.Gid {
		s.poisoned = true
		return Receipt{}, errors.Join(ErrCommitUncertain, err)
	}
	s.receipt.End = next
	s.receipt.Bytes += len(frame)
	s.receipt.Frames++
	s.stamp = st
	return s.receipt, nil
}

// Snapshot validates the complete file against this handle's known boundary.
// It can supply bytes to a future authorized checkpoint workflow but does not
// freeze a writable handle, create a signature or persist any continuity state.
func (s *Segment) Snapshot() (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshot()
}

func (s *Segment) snapshot() (Snapshot, error) {
	if err := s.usable(); err != nil {
		return Snapshot{}, err
	}
	data, err := s.readExact()
	if err != nil {
		return Snapshot{}, err
	}
	scan, err := contracts.ReadEventJournalSegment(data, contracts.JournalReadContext{Start: s.receipt.Start, MaxBytes: s.limits.MaxBytes, MaxFrames: s.limits.MaxFrames}, s.receipt.End)
	if err != nil || len(scan.Records) != s.receipt.Frames {
		s.poisoned = true
		return Snapshot{}, errors.Join(ErrChanged, err)
	}
	return Snapshot{Receipt: s.receipt, Data: data}, nil
}

// Close releases owned descriptors and their lock, even after failed writes.
// It is idempotent and never deletes, repairs or retries synchronization.
func (s *Segment) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file == nil {
		return nil
	}
	err := errors.Join(s.file.Close(), s.directory.Close())
	s.file = nil
	s.directory = nil
	return err
}
