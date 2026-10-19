package fleetregistry

import (
	"errors"
	"os"
	"sync"

	"golang.org/x/sys/unix"
	contracts "syswarden-core/contracts/v5"
)

const SnapshotFileName = "registry-v1.swr"

var (
	ErrUnsafeStorage = errors.New("fleet registry storage ownership or metadata is unsafe")
	ErrLocked        = errors.New("fleet registry directory is already leased")
	ErrChanged       = errors.New("fleet registry storage changed; close and perform verified recovery")
	ErrClosed        = errors.New("fleet registry snapshot store is closed")
)

type snapshotFile interface {
	Fd() uintptr
	ReadAt([]byte, int64) (int, error)
	Close() error
}

// Store holds an exclusive advisory directory lease and a read-only file.
// Do not copy it. It never creates, repairs, chmods, writes or removes storage.
// The directory and independent expected state must be trusted startup inputs.
// Private service-UID ownership protects against other ordinary UIDs, not root
// or a compromised process sharing that UID. This is not a deployment sandbox.
type Store struct {
	mu        sync.Mutex
	directory *os.File
	file      snapshotFile
	dirStamp  unix.Stat_t
	stamp     unix.Stat_t
	poisoned  bool
}

func privateDirectory(st unix.Stat_t) bool {
	return st.Mode&(unix.S_IFMT|07777) == unix.S_IFDIR|0700 && int64(st.Uid) == int64(os.Geteuid()) && st.Nlink > 0
}

func privateFile(st unix.Stat_t) bool {
	return st.Mode&(unix.S_IFMT|07777) == unix.S_IFREG|0600 && int64(st.Uid) == int64(os.Geteuid()) && st.Nlink == 1 && st.Size > 0 && st.Size <= int64(MaxSnapshotBytes)
}

func sameStamp(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Nlink == b.Nlink && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func openDirectory(directory *os.File) (*os.File, unix.Stat_t, error) {
	var stamp unix.Stat_t
	if directory == nil {
		return nil, stamp, ErrUnsafeStorage
	}
	raw, err := directory.SyscallConn()
	if err != nil {
		return nil, stamp, ErrUnsafeStorage
	}
	fd := -1
	var openErr error
	err = raw.Control(func(parent uintptr) {
		fd, openErr = unix.Openat(int(parent), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	})
	if err != nil || openErr != nil {
		return nil, stamp, errors.Join(ErrUnsafeStorage, err, openErr)
	}
	dir := os.NewFile(uintptr(fd), "fleet-registry-directory")
	if err = unix.Fstat(fd, &stamp); err != nil || !privateDirectory(stamp) {
		return nil, stamp, errors.Join(ErrUnsafeStorage, err, dir.Close())
	}
	// A fresh open description is necessary; dup would share the caller's lock.
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, stamp, errors.Join(ErrLocked, err, dir.Close())
	}
	return dir, stamp, nil
}

// OpenSnapshotStore opens only the fixed already-provisioned filename. It
// validates all bytes against independent current continuity before returning a
// handle. The caller must not close directory concurrently with this call.
// Reopening does not prove previous fsync or acknowledge a durable commit.
func OpenSnapshotStore(directory *os.File, expected contracts.NodeRegistryContinuityContext) (*Store, error) {
	dir, ds, err := openDirectory(directory)
	if err != nil {
		return nil, err
	}
	s := &Store{directory: dir, dirStamp: ds}
	fail := func(err error) (*Store, error) { return nil, errors.Join(err, s.Close()) }
	var entry unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), SnapshotFileName, &entry, unix.AT_SYMLINK_NOFOLLOW); err != nil || !privateFile(entry) {
		return fail(errors.Join(ErrUnsafeStorage, err))
	}
	fd, err := unix.Openat(int(dir.Fd()), SnapshotFileName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if err != nil {
		return fail(errors.Join(ErrUnsafeStorage, err))
	}
	s.file = os.NewFile(uintptr(fd), "fleet-registry-snapshot")
	s.stamp = entry
	if _, err := s.Read(expected); err != nil {
		return fail(err)
	}
	return s, nil
}

func (s *Store) unchanged() bool {
	var dir, file, entry unix.Stat_t
	return unix.Fstat(int(s.directory.Fd()), &dir) == nil && privateDirectory(dir) && sameStamp(dir, s.dirStamp) &&
		unix.Fstat(int(s.file.Fd()), &file) == nil && privateFile(file) && sameStamp(file, s.stamp) &&
		unix.Fstatat(int(s.directory.Fd()), SnapshotFileName, &entry, unix.AT_SYMLINK_NOFOLLOW) == nil && privateFile(entry) && sameStamp(entry, file)
}

// Read reattests directory, descriptor, named entry and complete bytes. Expected
// must be refreshed independently for each operation, not copied from this file.
// Failure poisons the handle and returns no prefix or last-known-good snapshot.
// Disabled snapshots remain readable for administration; they grant no admission.
func (s *Store) Read(expected contracts.NodeRegistryContinuityContext) (Snapshot, error) {
	if s == nil {
		return Snapshot{}, ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.directory == nil || s.file == nil {
		return Snapshot{}, ErrClosed
	}
	if s.poisoned {
		return Snapshot{}, ErrChanged
	}
	s.poisoned = true
	if !s.unchanged() {
		return Snapshot{}, ErrChanged
	}
	data := make([]byte, int(s.stamp.Size))
	n, err := s.file.ReadAt(data, 0)
	if err != nil || n != len(data) {
		return Snapshot{}, errors.Join(ErrChanged, err)
	}
	result, err := DecodeSnapshot(data, expected)
	if err != nil || !s.unchanged() {
		return Snapshot{}, errors.Join(ErrChanged, err)
	}
	s.poisoned = false
	return result, nil
}

// Close releases only owned descriptors and the directory lease. It neither
// deletes state nor changes the caller's descriptor or its independent flock.
func (s *Store) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var err error
	if s.file != nil {
		err = s.file.Close()
		s.file = nil
	}
	if s.directory != nil {
		err = errors.Join(err, s.directory.Close())
		s.directory = nil
	}
	return err
}
