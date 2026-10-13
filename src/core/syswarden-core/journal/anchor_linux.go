package journal

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"strconv"
	"sync"

	"golang.org/x/sys/unix"
	contracts "syswarden-core/contracts/v5"
)

const (
	// MaxAnchorRecords includes the independently supplied bootstrap record.
	// Exhaustion requires a separately authorized migration, never eviction.
	MaxAnchorRecords  = 1024
	anchorName        = "continuity-v1.swa"
	anchorSchema      = "syswarden.journal-anchor.v1"
	anchorDomain      = "syswarden/journal-anchor-record/v1\x00"
	maxAnchorDocument = 2048
	maxAnchorFile     = MaxAnchorRecords * (4 + maxAnchorDocument + sha256.Size)
)

var (
	ErrAnchorFormat   = errors.New("invalid bounded journal continuity file")
	ErrAnchorConflict = errors.New("journal continuity differs from independently expected state")
)

// This is local protected state, not a signed public schema or an export.
type anchorDocument struct {
	Schema             string                    `json:"schema"`
	JournalID          string                    `json:"journal_id"`
	Identity           contracts.NodeIdentity    `json:"identity"`
	Position           contracts.JournalPosition `json:"position"`
	CheckpointSequence string                    `json:"checkpoint_sequence"`
	CheckpointSHA256   string                    `json:"checkpoint_sha256"`
}

func encodeAnchor(a contracts.JournalCheckpointAnchor) ([]byte, error) {
	if len(a.PreviousSHA256) != sha256.Size*2 {
		return nil, ErrAnchorFormat
	}
	_, err := contracts.ScanEventJournal(nil, contracts.JournalReadContext{Start: a.Cursor, MaxBytes: 1, MaxFrames: 1})
	digest, digestErr := hex.DecodeString(a.PreviousSHA256)
	if err != nil || a.NextSequence == 0 || digestErr != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != a.PreviousSHA256 {
		return nil, ErrAnchorFormat
	}
	d := anchorDocument{Schema: anchorSchema, JournalID: a.Cursor.JournalID, Identity: a.Cursor.Identity,
		Position:           contracts.JournalPosition{NextSequence: strconv.FormatUint(a.Cursor.NextSequence, 10), PreviousSHA256: a.Cursor.PreviousSHA256},
		CheckpointSequence: strconv.FormatUint(a.NextSequence, 10), CheckpointSHA256: a.PreviousSHA256}
	b, err := json.Marshal(d)
	if err != nil || len(b) > maxAnchorDocument {
		return nil, ErrAnchorFormat
	}
	return b, nil
}

func decodeAnchor(b []byte) (contracts.JournalCheckpointAnchor, error) {
	var d anchorDocument
	if len(b) == 0 || len(b) > maxAnchorDocument || json.Unmarshal(b, &d) != nil || d.Schema != anchorSchema {
		return contracts.JournalCheckpointAnchor{}, ErrAnchorFormat
	}
	position, e1 := strconv.ParseUint(d.Position.NextSequence, 10, 64)
	sequence, e2 := strconv.ParseUint(d.CheckpointSequence, 10, 64)
	a := contracts.JournalCheckpointAnchor{Cursor: contracts.JournalCursor{JournalID: d.JournalID, Identity: d.Identity, NextSequence: position, PreviousSHA256: d.Position.PreviousSHA256}, NextSequence: sequence, PreviousSHA256: d.CheckpointSHA256}
	canonical, err := encodeAnchor(a)
	// Exact re-encoding also rejects duplicates, unknown fields and null aliases.
	if e1 != nil || e2 != nil || err != nil || !bytes.Equal(canonical, b) {
		return contracts.JournalCheckpointAnchor{}, ErrAnchorFormat
	}
	return a, nil
}

func anchorHash(previous [sha256.Size]byte, document []byte) [sha256.Size]byte {
	h := sha256.New()
	_, _ = h.Write([]byte(anchorDomain))
	_, _ = h.Write(previous[:])
	_, _ = h.Write(document)
	var result [sha256.Size]byte
	copy(result[:], h.Sum(nil))
	return result
}

func anchorFrame(a contracts.JournalCheckpointAnchor, previous [sha256.Size]byte) ([]byte, error) {
	doc, err := encodeAnchor(a)
	if err != nil {
		return nil, err
	}
	size := len(doc)
	if size > maxAnchorDocument {
		return nil, ErrAnchorFormat
	}
	frame := make([]byte, 4+size+sha256.Size)
	binary.BigEndian.PutUint32(frame[:4], uint32(size))
	copy(frame[4:], doc)
	digest := anchorHash(previous, doc)
	copy(frame[4+size:], digest[:])
	return frame, nil
}

type anchorState struct {
	head  contracts.JournalCheckpointAnchor
	hash  [sha256.Size]byte
	count int
	bytes int
}

func anchorTransition(before, after contracts.JournalCheckpointAnchor) bool {
	return before.NextSequence < math.MaxUint64 && after.NextSequence == before.NextSequence+1 &&
		before.Cursor.JournalID == after.Cursor.JournalID && before.Cursor.Identity == after.Cursor.Identity &&
		after.Cursor.NextSequence >= before.Cursor.NextSequence && after.Cursor.NextSequence-before.Cursor.NextSequence <= contracts.MaxJournalScanFrames &&
		(after.Cursor.NextSequence != before.Cursor.NextSequence || after.Cursor == before.Cursor)
}

func scanAnchors(data []byte, initial contracts.JournalCheckpointAnchor) (anchorState, error) {
	if len(data) == 0 || len(data) > maxAnchorFile {
		return anchorState{}, ErrAnchorFormat
	}
	var state anchorState
	for offset := 0; offset < len(data); {
		if state.count >= MaxAnchorRecords || len(data)-offset < 4 {
			return anchorState{}, ErrAnchorFormat
		}
		size := binary.BigEndian.Uint32(data[offset : offset+4])
		if size == 0 || size > maxAnchorDocument || len(data)-offset-4 < int(size)+sha256.Size {
			return anchorState{}, ErrAnchorFormat
		}
		end := offset + 4 + int(size)
		doc := data[offset+4 : end]
		a, err := decodeAnchor(doc)
		if err != nil || (state.count == 0 && a != initial) || (state.count > 0 && !anchorTransition(state.head, a)) {
			return anchorState{}, ErrAnchorFormat
		}
		digest := anchorHash(state.hash, doc)
		if !bytes.Equal(data[end:end+sha256.Size], digest[:]) {
			return anchorState{}, ErrAnchorFormat
		}
		state.head, state.hash = a, digest
		state.count++
		offset = end + sha256.Size
	}
	state.bytes = len(data)
	return state, nil
}

// AnchorStore is a bounded local continuity coordinator. Do not copy it.
// Its independently provisioned directory must be distinct from journal storage
// and inaccessible to untrusted producers. This package does not provision a
// separate UID, protect against root, discover authority or supply a witness.
// Reopen requires independently retained initial and expected anchors. A missing
// or unexpected tail is never adopted, truncated or silently retried.
type AnchorStore struct {
	mu        sync.Mutex
	directory *os.File
	file      segmentFile
	initial   contracts.JournalCheckpointAnchor
	state     anchorState
	stamp     unix.Stat_t
	poisoned  bool
}

func acquireAnchor(directory *os.File, initial contracts.JournalCheckpointAnchor, create bool) (*AnchorStore, error) {
	return acquireAnchorMode(directory, initial, create, false)
}

func acquireAnchorMode(directory *os.File, initial contracts.JournalCheckpointAnchor, create, readOnly bool) (*AnchorStore, error) {
	if create && readOnly {
		return nil, ErrInvalidOptions
	}
	if _, err := encodeAnchor(initial); err != nil {
		return nil, err
	}
	dir, err := openDirectory(directory)
	if err != nil {
		return nil, err
	}
	flags := unix.O_RDWR | unix.O_APPEND | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_NOCTTY
	if readOnly {
		flags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK | unix.O_NOCTTY
	}
	if create {
		flags |= unix.O_CREAT | unix.O_EXCL
	} else {
		var st unix.Stat_t
		if err = unix.Fstatat(int(dir.Fd()), anchorName, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil || !privateFile(st) || st.Size > maxAnchorFile {
			return nil, errors.Join(ErrUnsafeStorage, err, dir.Close())
		}
	}
	fd, err := unix.Openat(int(dir.Fd()), anchorName, flags, 0600)
	if err != nil {
		return nil, errors.Join(err, dir.Close())
	}
	a := &AnchorStore{directory: dir, file: diskFile{os.NewFile(uintptr(fd), "journal-continuity")}, initial: initial}
	st, err := attestEntry(dir, a.file, anchorName)
	if err != nil || st.Size > maxAnchorFile || (create && st.Size != 0) {
		return nil, errors.Join(ErrUnsafeStorage, err, a.Close())
	}
	a.stamp = st
	return a, nil
}

// CreateAnchorStore explicitly establishes the caller-authorized initial state.
// Existing paths are never adopted or replaced. Creation and sync failures retain
// all artifacts; retrying Create cannot overwrite an uncertain bootstrap.
func CreateAnchorStore(directory *os.File, initial contracts.JournalCheckpointAnchor) (*AnchorStore, error) {
	a, err := acquireAnchor(directory, initial, true)
	if err != nil {
		return nil, err
	}
	err = a.initialize()
	if err != nil {
		return nil, errors.Join(ErrCommitUncertain, err, a.Close())
	}
	return a, nil
}

func (a *AnchorStore) initialize() error {
	err := a.appendAnchor(a.initial)
	if err == nil {
		err = a.directory.Sync()
	}
	if err == nil {
		err = a.unchanged()
	}
	return err
}

// OpenAnchorStore resumes only an exact independently expected head. It checks
// the complete bounded chain and synchronizes the accepted file and directory.
// It is not an uncertain-outcome recovery or a mechanism for discovering trust.
func OpenAnchorStore(directory *os.File, initial, expected contracts.JournalCheckpointAnchor) (*AnchorStore, error) {
	if _, err := encodeAnchor(expected); err != nil {
		return nil, err
	}
	a, err := acquireAnchor(directory, initial, false)
	if err != nil {
		return nil, err
	}
	state, err := a.readState()
	if err == nil && state.head != expected {
		err = ErrAnchorConflict
	}
	if err != nil {
		return nil, errors.Join(err, a.Close())
	}
	a.state = state
	if err = a.file.Sync(); err == nil {
		err = a.directory.Sync()
	}
	if err == nil {
		err = a.unchanged()
	}
	if err != nil {
		return nil, errors.Join(ErrCommitUncertain, err, a.Close())
	}
	return a, nil
}

func (a *AnchorStore) usable() error {
	if a.file == nil {
		return ErrClosed
	}
	if a.poisoned {
		return ErrCommitUncertain
	}
	return nil
}

func (a *AnchorStore) unchanged() error {
	st, err := attestEntry(a.directory, a.file, anchorName)
	if err != nil || !sameStamp(st, a.stamp) {
		a.poisoned = true
		return errors.Join(ErrChanged, err)
	}
	return nil
}

func (a *AnchorStore) readState() (anchorState, error) {
	data, err := a.readExact()
	if err != nil {
		return anchorState{}, err
	}
	return scanAnchors(data, a.initial)
}

func (a *AnchorStore) readExact() ([]byte, error) {
	if err := a.unchanged(); err != nil {
		return nil, err
	}
	if a.stamp.Size <= 0 || a.stamp.Size > maxAnchorFile {
		return nil, ErrAnchorFormat
	}
	data := make([]byte, int(a.stamp.Size))
	n, err := a.file.ReadAt(data, 0)
	if err != nil || n != len(data) {
		return nil, errors.Join(ErrAnchorFormat, err)
	}
	if err = a.unchanged(); err != nil {
		return nil, err
	}
	return data, nil
}

// Current returns a value only after checking the entire protected file.
func (a *AnchorStore) Current() (contracts.JournalCheckpointAnchor, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.usable(); err != nil {
		return contracts.JournalCheckpointAnchor{}, err
	}
	state, err := a.readState()
	if err != nil || state != a.state {
		a.poisoned = true
		return contracts.JournalCheckpointAnchor{}, errors.Join(ErrChanged, err)
	}
	return state.head, nil
}

func (a *AnchorStore) appendAnchor(next contracts.JournalCheckpointAnchor) error {
	if a.state.count >= MaxAnchorRecords {
		return ErrFull
	}
	if err := a.unchanged(); err != nil {
		return err
	}
	frame, err := anchorFrame(next, a.state.hash)
	if err != nil {
		return err
	}
	n, err := a.file.Write(frame)
	if err == nil && n != len(frame) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = a.file.Sync()
	}
	if err != nil {
		a.poisoned = true
		return errors.Join(ErrCommitUncertain, err)
	}
	st, err := attestEntry(a.directory, a.file, anchorName)
	if err != nil || st.Dev != a.stamp.Dev || st.Ino != a.stamp.Ino || st.Gid != a.stamp.Gid || st.Size != int64(a.state.bytes+len(frame)) {
		a.poisoned = true
		return errors.Join(ErrCommitUncertain, err)
	}
	a.stamp = st
	state, err := a.readState()
	var expectedHash [sha256.Size]byte
	copy(expectedHash[:], frame[len(frame)-sha256.Size:])
	if err != nil || state.head != next || state.count != a.state.count+1 || state.hash != expectedHash {
		a.poisoned = true
		return errors.Join(ErrCommitUncertain, err)
	}
	a.state = state
	return nil
}

// CommitPublished reopens and authenticates the actual stored publication under
// its directory lock, resynchronizes its files and directory, then appends and
// synchronizes one protected anchor record. No mutable Publication is accepted.
// Lock order is anchor then journal, both nonblocking between processes. The
// publisher must close its segment handle before calling this operation.
func (a *AnchorStore) CommitPublished(expected contracts.JournalCheckpointAnchor, directory *os.File, name string, authority contracts.JournalCheckpointAuthority, limits Limits) (contracts.JournalCheckpointAnchor, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.commitPublished(expected, directory, name, authority, limits, OpenPublishedSegment)
}

type publicationOpener func(*os.File, string, contracts.JournalCheckpointContext, Limits) (*Segment, error)

func (a *AnchorStore) commitPublished(expected contracts.JournalCheckpointAnchor, directory *os.File, name string, authority contracts.JournalCheckpointAuthority, limits Limits, open publicationOpener) (contracts.JournalCheckpointAnchor, error) {
	if err := a.usable(); err != nil {
		return contracts.JournalCheckpointAnchor{}, err
	}
	if expected != a.state.head {
		return contracts.JournalCheckpointAnchor{}, ErrAnchorConflict
	}
	state, err := a.readState()
	if err != nil || state != a.state {
		a.poisoned = true
		return contracts.JournalCheckpointAnchor{}, errors.Join(ErrChanged, err)
	}
	if state.count >= MaxAnchorRecords {
		return contracts.JournalCheckpointAnchor{}, ErrFull
	}
	context := contracts.JournalCheckpointContext{Anchor: expected, Authority: authority}
	s, err := open(directory, name, context, limits)
	if err != nil {
		return contracts.JournalCheckpointAnchor{}, err
	}
	next, err := s.synchronizePublication(context)
	if err == nil {
		err = a.appendAnchor(next)
	}
	err = errors.Join(err, s.Close())
	if err != nil {
		a.poisoned = true
		return contracts.JournalCheckpointAnchor{}, errors.Join(ErrCommitUncertain, err)
	}
	return next, nil
}

func (s *Segment) synchronizePublication(context contracts.JournalCheckpointContext) (contracts.JournalCheckpointAnchor, error) {
	pending, final := checkpointNames(s.name)
	if err := requireAbsent(s.directory, pending); err != nil {
		return contracts.JournalCheckpointAnchor{}, err
	}
	bundle, err := readCheckpointArtifact(s.directory, final)
	if err != nil {
		return contracts.JournalCheckpointAnchor{}, err
	}
	cp, sig, err := decodeCheckpointBundle(bundle)
	if err != nil {
		return contracts.JournalCheckpointAnchor{}, err
	}
	data, err := s.snapshot()
	if err != nil {
		return contracts.JournalCheckpointAnchor{}, err
	}
	_, next, err := contracts.ReadAuthenticatedJournalSegment(data.Data, cp, sig, context, s.limits.MaxBytes, s.limits.MaxFrames)
	if err != nil {
		return contracts.JournalCheckpointAnchor{}, err
	}
	fd, err := unix.Openat(int(s.directory.Fd()), final, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if err != nil {
		return contracts.JournalCheckpointAnchor{}, err
	}
	file := diskFile{os.NewFile(uintptr(fd), "journal-checkpoint")}
	err = verifyArtifact(s.directory, file, final, bundle)
	if err == nil {
		err = s.file.Sync()
	}
	if err == nil {
		err = file.Sync()
	}
	if err == nil {
		err = s.directory.Sync()
	}
	if err == nil {
		err = verifyArtifact(s.directory, file, final, bundle)
	}
	if err == nil {
		err = s.unchanged()
	}
	if err == nil {
		err = requireAbsent(s.directory, pending)
	}
	err = errors.Join(err, file.Close())
	if err != nil {
		return contracts.JournalCheckpointAnchor{}, err
	}
	return next, nil
}

// Close is idempotent and preserves every byte, including uncertain tails.
func (a *AnchorStore) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file == nil {
		return nil
	}
	err := errors.Join(a.file.Close(), a.directory.Close())
	a.file = nil
	a.directory = nil
	return err
}
