package journal

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
	contracts "syswarden-core/contracts/v5"
)

const (
	checkpointBundleMagic    = "SWJCP1\x00\x00"
	checkpointBundlePrefix   = 12
	maxCheckpointBundleBytes = checkpointBundlePrefix + contracts.MaxCheckpointBytes + ed25519.SignatureSize
)

var (
	ErrCheckpointState     = errors.New("checkpoint publication requires a frozen segment created by this handle")
	ErrCheckpointCollision = errors.New("checkpoint publication path already exists; preserve retained evidence")
	ErrCheckpointBundle    = errors.New("invalid bounded checkpoint bundle")
)

// Publication is a synchronized local artifact receipt. Next is only a proposed
// anchor: a separate protected authority must compare and commit it durably.
// This receipt is neither that commit nor a global anti-rollback guarantee.
type Publication struct {
	SegmentName    string
	CheckpointName string
	Next           contracts.JournalCheckpointAnchor
}

// Freeze verifies a snapshot and disables Append under the same mutex. A stale
// expected cursor does not freeze the segment. Repeating Freeze is read-only.
// The lock stays held for this handle's lifetime; no signature is made here.
func (s *Segment) Freeze(expected contracts.JournalCursor) (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return Snapshot{}, err
	}
	if expected != s.receipt.End {
		return Snapshot{}, ErrConflict
	}
	result, err := s.snapshot()
	if err != nil {
		return Snapshot{}, err
	}
	s.sealed = true
	return result, nil
}

func encodeCheckpointBundle(checkpoint, signature []byte) ([]byte, error) {
	size := len(checkpoint)
	if size == 0 || size > contracts.MaxCheckpointBytes || len(signature) != ed25519.SignatureSize {
		return nil, ErrCheckpointBundle
	}
	if _, err := contracts.DecodeJournalCheckpoint(checkpoint); err != nil {
		return nil, err
	}
	b := make([]byte, checkpointBundlePrefix+len(checkpoint)+len(signature))
	copy(b, checkpointBundleMagic)
	// The preceding size check bounds this conversion on every supported host.
	binary.BigEndian.PutUint32(b[8:12], uint32(size))
	copy(b[checkpointBundlePrefix:], checkpoint)
	copy(b[checkpointBundlePrefix+len(checkpoint):], signature)
	return b, nil
}

func decodeCheckpointBundle(data []byte) ([]byte, []byte, error) {
	if len(data) < checkpointBundlePrefix+1+ed25519.SignatureSize || len(data) > maxCheckpointBundleBytes || string(data[:8]) != checkpointBundleMagic {
		return nil, nil, ErrCheckpointBundle
	}
	n := binary.BigEndian.Uint32(data[8:12])
	if n == 0 || n > contracts.MaxCheckpointBytes || len(data) != checkpointBundlePrefix+int(n)+ed25519.SignatureSize {
		return nil, nil, ErrCheckpointBundle
	}
	end := checkpointBundlePrefix + int(n)
	if _, err := contracts.DecodeJournalCheckpoint(data[checkpointBundlePrefix:end]); err != nil {
		return nil, nil, err
	}
	return bytes.Clone(data[checkpointBundlePrefix:end]), bytes.Clone(data[end:]), nil
}

func checkpointNames(segmentName string) (string, string) {
	final := segmentName + ".checkpoint"
	return final + ".pending", final
}

// Both paths are derived from a validated segment name, not caller path input.
func requireAbsent(directory *os.File, name string) error {
	var st unix.Stat_t
	err := unix.Fstatat(int(directory.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	return ErrCheckpointCollision
}

type publicationOps struct {
	create        func(string) (segmentFile, error)
	rename        func(string, string) error
	syncDirectory func() error
}

func (s *Segment) publicationOps() publicationOps {
	return publicationOps{
		create: func(name string) (segmentFile, error) {
			fd, err := unix.Openat(int(s.directory.Fd()), name, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOCTTY, 0600)
			if err != nil {
				return nil, err
			}
			return diskFile{os.NewFile(uintptr(fd), "journal-checkpoint")}, nil
		},
		rename: func(from, to string) error {
			return unix.Renameat2(int(s.directory.Fd()), from, int(s.directory.Fd()), to, unix.RENAME_NOREPLACE)
		},
		syncDirectory: s.directory.Sync,
	}
}

// PublishCheckpoint authenticates and rechecks a frozen segment, then publishes
// one bounded checkpoint/signature file with no-replace rename and directory
// sync. Any uncertain storage result preserves pending/final bytes and poisons
// this handle. It neither owns a signing key nor advances a protected anchor.
func (s *Segment) PublishCheckpoint(checkpoint, signature []byte, context contracts.JournalCheckpointContext) (Publication, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usable(); err != nil {
		return Publication{}, err
	}
	return s.publishCheckpoint(checkpoint, signature, context, s.publicationOps())
}

func (s *Segment) publishCheckpoint(checkpoint, signature []byte, context contracts.JournalCheckpointContext, ops publicationOps) (Publication, error) {
	if !s.created || !s.sealed {
		return Publication{}, ErrCheckpointState
	}
	if context.Anchor.Cursor != s.receipt.Start {
		return Publication{}, contracts.ErrCheckpointNotAuthorized
	}
	if _, _, err := contracts.VerifyJournalCheckpoint(checkpoint, signature, context); err != nil {
		return Publication{}, err
	}
	data, err := s.snapshot()
	if err != nil {
		return Publication{}, err
	}
	_, next, err := contracts.ReadAuthenticatedJournalSegment(data.Data, checkpoint, signature, context, s.limits.MaxBytes, s.limits.MaxFrames)
	if err != nil {
		return Publication{}, err
	}
	if next.Cursor != s.receipt.End {
		return Publication{}, contracts.ErrCheckpointSegment
	}
	bundle, err := encodeCheckpointBundle(checkpoint, signature)
	if err != nil {
		return Publication{}, err
	}
	pending, final := checkpointNames(s.name)
	if err = requireAbsent(s.directory, final); err != nil {
		return Publication{}, err
	}
	if err = requireAbsent(s.directory, pending); err != nil {
		return Publication{}, err
	}
	file, err := ops.create(pending)
	if err != nil {
		s.poisoned = true
		return Publication{}, errors.Join(ErrCommitUncertain, err)
	}
	// After creation every failure is uncertain. Never unlink or retry a tail.
	err = s.commitPublication(file, pending, final, bundle, ops)
	err = errors.Join(err, file.Close())
	if err != nil {
		s.poisoned = true
		return Publication{}, errors.Join(ErrCommitUncertain, err)
	}
	return Publication{SegmentName: s.name, CheckpointName: final, Next: next}, nil
}

func (s *Segment) commitPublication(file segmentFile, pending, final string, bundle []byte, ops publicationOps) error {
	st, err := attestEntry(s.directory, file, pending)
	if err != nil || st.Size != 0 {
		return errors.Join(ErrUnsafeStorage, err)
	}
	n, err := file.Write(bundle)
	if err != nil {
		return err
	}
	if n != len(bundle) {
		return io.ErrShortWrite
	}
	if err = file.Sync(); err != nil {
		return err
	}
	// Read back the exact artifact before making it visible under its final name.
	if err = verifyArtifact(s.directory, file, pending, bundle); err != nil {
		return err
	}
	if err = s.unchanged(); err != nil {
		return err
	}
	if err = ops.rename(pending, final); err != nil {
		return err
	}
	if err = ops.syncDirectory(); err != nil {
		return err
	}
	if err = verifyArtifact(s.directory, file, final, bundle); err != nil {
		return err
	}
	return s.unchanged()
}

func verifyArtifact(directory *os.File, file segmentFile, name string, want []byte) error {
	before, err := attestEntry(directory, file, name)
	if err != nil || before.Size != int64(len(want)) {
		return errors.Join(ErrUnsafeStorage, err)
	}
	data := make([]byte, len(want))
	n, err := file.ReadAt(data, 0)
	if err != nil || n != len(data) || !bytes.Equal(data, want) {
		return errors.Join(ErrCheckpointBundle, err)
	}
	after, err := attestEntry(directory, file, name)
	if err != nil || !sameStamp(before, after) {
		return errors.Join(ErrChanged, err)
	}
	return nil
}

func readCheckpointArtifact(directory *os.File, name string) ([]byte, error) {
	data, _, err := readCheckpointSnapshot(directory, name)
	return data, err
}

func readCheckpointSnapshot(directory *os.File, name string) ([]byte, unix.Stat_t, error) {
	var before unix.Stat_t
	if err := unix.Fstatat(int(directory.Fd()), name, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil || !privateFile(before) || before.Size > maxCheckpointBundleBytes {
		return nil, unix.Stat_t{}, errors.Join(ErrUnsafeStorage, err)
	}
	fd, err := unix.Openat(int(directory.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, unix.Stat_t{}, err
	}
	file := diskFile{os.NewFile(uintptr(fd), "journal-checkpoint")}
	data, err := readCheckpointFile(directory, file, name, before)
	err = errors.Join(err, file.Close())
	if err != nil {
		return nil, unix.Stat_t{}, err
	}
	return data, before, nil
}

func readCheckpointFile(directory *os.File, file segmentFile, name string, expected unix.Stat_t) ([]byte, error) {
	st, err := attestEntry(directory, file, name)
	if err != nil || !sameStamp(st, expected) {
		return nil, errors.Join(ErrChanged, err)
	}
	// The caller checked nonnegative size, ownership and the small wire ceiling.
	if st.Size < 0 || st.Size > maxCheckpointBundleBytes {
		return nil, ErrCheckpointBundle
	}
	data := make([]byte, int(st.Size))
	n, err := file.ReadAt(data, 0)
	if err != nil || n != len(data) {
		return nil, errors.Join(ErrCheckpointBundle, err)
	}
	after, err := attestEntry(directory, file, name)
	if err != nil || !sameStamp(st, after) {
		return nil, errors.Join(ErrChanged, err)
	}
	return data, nil
}

// OpenPublishedSegment authenticates a stored bundle and its complete segment
// under one directory lock, using independently supplied prior trust. It rejects
// pending publication evidence. Success is a historical read, not a new durable
// acknowledgement or permission to adopt the checkpoint as the trusted head.
func OpenPublishedSegment(directory *os.File, name string, context contracts.JournalCheckpointContext, limits Limits) (*Segment, error) {
	s, err := acquire(directory, name, context.Anchor.Cursor, limits, false)
	if err != nil {
		return nil, err
	}
	err = s.readPublication(context)
	if err != nil {
		return nil, errors.Join(err, s.Close())
	}
	return s, nil
}

func (s *Segment) readPublication(context contracts.JournalCheckpointContext) error {
	pending, final := checkpointNames(s.name)
	if err := requireAbsent(s.directory, pending); err != nil {
		return err
	}
	bundle, err := readCheckpointArtifact(s.directory, final)
	if err != nil {
		return err
	}
	checkpoint, signature, err := decodeCheckpointBundle(bundle)
	if err != nil {
		return err
	}
	if _, _, err = contracts.VerifyJournalCheckpoint(checkpoint, signature, context); err != nil {
		return err
	}
	data, err := s.readExact()
	if err != nil {
		return err
	}
	scan, _, err := contracts.ReadAuthenticatedJournalSegment(data, checkpoint, signature, context, s.limits.MaxBytes, s.limits.MaxFrames)
	if err != nil {
		return err
	}
	s.receipt.End = scan.Cursor
	s.receipt.Bytes = len(data)
	s.receipt.Frames = len(scan.Records)
	return nil
}
