package journal

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
	contracts "syswarden-core/contracts/v5"
)

const testName = "segment-0123456789abcdef0123456789abcdef.swj"
const otherName = "segment-1123456789abcdef0123456789abcdef.swj"

func startCursor() contracts.JournalCursor {
	return contracts.JournalCursor{JournalID: "journal.fixture.1", Identity: contracts.NodeIdentity{ClusterID: "cluster.fixture.1", NodeID: "node.fixture.1", Epoch: "generation.fixture.1"}, NextSequence: 1, PreviousSHA256: strings.Repeat("0", 64)}
}
func testLimits() Limits {
	return Limits{MaxBytes: contracts.MaxJournalScanBytes, MaxFrames: contracts.MaxJournalScanFrames}
}

func testDirectory(t *testing.T) (*os.File, string) {
	t.Helper()
	path := t.TempDir()
	if err := chmodFixture(path, 0700); err != nil {
		t.Fatal(err)
	}
	f, err := openFixtureDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f, path
}

// These helpers confine test fixture operations to an opened directory. Mode
// changes deliberately construct unsafe inputs, independently of the test umask.
func openFixtureDirectory(path string) (*os.File, error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return root.Open(".")
}
func chmodFixture(path string, mode os.FileMode) error {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	return root.Chmod(filepath.Base(path), mode)
}
func event(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("../contracts/v5/testdata/native-ip.json")
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func create(t *testing.T, dir *os.File, limits Limits) *Segment {
	t.Helper()
	s, err := CreateSegment(dir, testName, startCursor(), limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s
}
func readFile(t *testing.T, path string) []byte {
	t.Helper()
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	b, err := root.ReadFile(filepath.Base(path))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func snapshot(t *testing.T, s *Segment) Snapshot {
	t.Helper()
	b, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func appendEvent(t *testing.T, s *Segment) Receipt {
	t.Helper()
	r, err := s.Append(s.receipt.End, event(t))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func signed(t *testing.T, s Snapshot) ([]byte, []byte, contracts.JournalCheckpointContext) {
	t.Helper()
	// Public deterministic synthetic key with no operational authority.
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	ctx := contracts.JournalCheckpointContext{
		Anchor:    contracts.JournalCheckpointAnchor{Cursor: s.Start, NextSequence: 1, PreviousSHA256: strings.Repeat("0", 64)},
		Authority: contracts.JournalCheckpointAuthority{JournalID: s.Start.JournalID, Identity: s.Start.Identity, KeyID: "key.fixture.1", PublicKey: key.Public().(ed25519.PublicKey), FirstSequence: 1, LastSequence: 10},
	}
	cp := contracts.JournalCheckpoint{Schema: contracts.JournalCheckpointSchema, CheckpointID: "checkpoint.fixture.1", Sequence: "1", KeyID: ctx.Authority.KeyID, JournalID: s.Start.JournalID, Identity: s.Start.Identity, PreviousCheckpointSHA256: ctx.Anchor.PreviousSHA256,
		Start: contracts.JournalPosition{NextSequence: strconv.FormatUint(s.Start.NextSequence, 10), PreviousSHA256: s.Start.PreviousSHA256},
		End:   contracts.JournalPosition{NextSequence: strconv.FormatUint(s.End.NextSequence, 10), PreviousSHA256: s.End.PreviousSHA256}, SegmentBytes: strconv.Itoa(len(s.Data)), RecordedAt: "2026-01-01T00:00:02Z", ClockQuality: "unknown"}
	data, err := contracts.EncodeJournalCheckpoint(cp)
	if err != nil {
		t.Fatal(err)
	}
	message, err := contracts.JournalCheckpointSigningMessage(cp)
	if err != nil {
		t.Fatal(err)
	}
	return data, ed25519.Sign(key, message), ctx
}

func TestSegmentDurableAppendAndSealedRead(t *testing.T) {
	for _, count := range []int{0, 1, 3} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			dir, path := testDirectory(t)
			s := create(t, dir, testLimits())
			var want []byte
			cursor := startCursor()
			for i := 0; i < count; i++ {
				frame, next, err := contracts.EncodeEventJournalFrame(event(t), cursor)
				if err != nil {
					t.Fatal(err)
				}
				want = append(want, frame...)
				r := appendEvent(t, s)
				if r.Start != startCursor() || r.End != next || r.Bytes != len(want) || r.Frames != i+1 {
					t.Fatal("incorrect receipt", r)
				}
				cursor = next
			}
			got := snapshot(t, s)
			if !bytes.Equal(got.Data, want) || !bytes.Equal(readFile(t, filepath.Join(path, testName)), want) {
				t.Fatal("exact bytes changed")
			}
			info, err := os.Stat(filepath.Join(path, testName))
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("unsafe file mode", err)
			}
			cp, sig, ctx := signed(t, got)
			if len(got.Data) > 0 {
				got.Data[0] ^= 0xff
				if !bytes.Equal(snapshot(t, s).Data, want) {
					t.Fatal("snapshot aliases file")
				}
			}
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			sealed, err := OpenSealedSegment(dir, testName, cp, sig, ctx, testLimits())
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := sealed.Close(); err != nil {
					t.Error(err)
				}
			}()
			if !bytes.Equal(snapshot(t, sealed).Data, want) {
				t.Fatal("sealed read changed bytes")
			}
			if r, err := sealed.Append(cursor, event(t)); !errors.Is(err, ErrSealed) || r != (Receipt{}) {
				t.Fatal("sealed history was writable", err)
			}
		})
	}
}

func TestSegmentDirectoryLockAndCallerDescriptor(t *testing.T) {
	dir, path := testDirectory(t)
	s := create(t, dir, testLimits())
	if next, err := CreateSegment(dir, otherName, startCursor(), testLimits()); !errors.Is(err, ErrLocked) || next != nil {
		t.Fatal("second handle bypassed lock", err)
	}
	if _, err := os.Stat(filepath.Join(path, otherName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("contending handle created file", err)
	}
	if err := dir.Close(); err != nil {
		t.Fatal(err)
	}
	other, err := openFixtureDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close() }()
	if next, err := CreateSegment(other, otherName, startCursor(), testLimits()); !errors.Is(err, ErrLocked) || next != nil {
		t.Fatal("caller close released independent lock", err)
	}
	appendEvent(t, s)
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := CreateSegment(other, otherName, startCursor(), testLimits())
	if err != nil {
		t.Fatal("close did not release lock", err)
	}
	if err = next.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSegmentConcurrentCursorAndReads(t *testing.T) {
	dir, _ := testDirectory(t)
	s := create(t, dir, testLimits())
	payload := event(t)
	const workers = 16
	results := make(chan error, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() { _, err := s.Append(startCursor(), payload); results <- err })
	}
	wg.Wait()
	close(results)
	passed, conflicts := 0, 0
	for err := range results {
		if err == nil {
			passed++
		} else if errors.Is(err, ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if passed != 1 || conflicts != workers-1 || snapshot(t, s).Frames != 1 {
		t.Fatal("cursor compare-and-swap failed")
	}
	for range workers {
		wg.Go(func() {
			if _, err := s.Snapshot(); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
}

func TestSegmentBoundsAndInvalidInputsDoNotMutate(t *testing.T) {
	frame, _, err := contracts.EncodeEventJournalFrame(event(t), startCursor())
	if err != nil {
		t.Fatal(err)
	}
	for name, limits := range map[string]Limits{"bytes": {MaxBytes: len(frame), MaxFrames: 3}, "frames": {MaxBytes: contracts.MaxJournalScanBytes, MaxFrames: 1}} {
		t.Run(name, func(t *testing.T) {
			dir, path := testDirectory(t)
			s := create(t, dir, limits)
			if r, err := s.Append(startCursor(), []byte("invalid")); err == nil || r != (Receipt{}) {
				t.Fatal("invalid payload accepted")
			}
			appendEvent(t, s)
			if r, err := s.Append(startCursor(), event(t)); !errors.Is(err, ErrConflict) || r != (Receipt{}) {
				t.Fatal("stale cursor accepted", err)
			}
			if r, err := s.Append(s.receipt.End, event(t)); !errors.Is(err, ErrFull) || r != (Receipt{}) {
				t.Fatal("capacity exceeded", err)
			}
			if !bytes.Equal(readFile(t, filepath.Join(path, testName)), frame) || snapshot(t, s).Frames != 1 {
				t.Fatal("refused input modified storage")
			}
		})
	}
	for _, limits := range []Limits{{}, {MaxBytes: -1, MaxFrames: 1}, {MaxBytes: 1, MaxFrames: 0}, {MaxBytes: contracts.MaxJournalScanBytes + 1, MaxFrames: 1}, {MaxBytes: 1, MaxFrames: contracts.MaxJournalScanFrames + 1}} {
		dir, path := testDirectory(t)
		if s, err := CreateSegment(dir, testName, startCursor(), limits); s != nil || !errors.Is(err, ErrInvalidOptions) {
			t.Fatal("invalid limits", err)
		}
		entries, err := os.ReadDir(path)
		if err != nil || len(entries) != 0 {
			t.Fatal("invalid options created state", err)
		}
	}
}

func TestSegmentNamesAndDirectoryOwnership(t *testing.T) {
	for _, name := range []string{"", ".", "..", "../" + testName, testName + "/child", "\x00", strings.ToUpper(testName), "segment-0123456789abcdef0123456789abcdeg.swj"} {
		dir, _ := testDirectory(t)
		if s, err := CreateSegment(dir, name, startCursor(), testLimits()); s != nil || !errors.Is(err, ErrInvalidOptions) {
			t.Fatal("unsafe name accepted", err)
		}
	}
	for _, mode := range []os.FileMode{0755, 0770, 0600, 0700 | os.ModeSetgid} {
		t.Run(mode.String(), func(t *testing.T) {
			dir, path := testDirectory(t)
			if err := chmodFixture(path, mode); err != nil {
				t.Fatal(err)
			}
			defer func() { _ = chmodFixture(path, 0700) }()
			if s, err := CreateSegment(dir, testName, startCursor(), testLimits()); s != nil || !errors.Is(err, ErrUnsafeStorage) {
				t.Fatal("unsafe directory accepted", err)
			}
		})
	}
	if s, err := CreateSegment(nil, testName, startCursor(), testLimits()); s != nil || !errors.Is(err, ErrUnsafeStorage) {
		t.Fatal("nil directory accepted", err)
	}
	dir, _ := testDirectory(t)
	if err := dir.Close(); err != nil {
		t.Fatal(err)
	}
	if s, err := CreateSegment(dir, testName, startCursor(), testLimits()); s != nil || !errors.Is(err, ErrUnsafeStorage) {
		t.Fatal("closed directory accepted", err)
	}
	st := unix.Stat_t{Mode: unix.S_IFDIR | 0700, Nlink: 2}
	// Test owner mismatch without changing host users or requiring root.
	if os.Geteuid() == 0 {
		st.Uid = 1
	}
	if privateDirectory(st) {
		t.Fatal("foreign directory owner accepted")
	}
	st.Mode = unix.S_IFREG | 0600
	st.Nlink = 1
	if privateFile(st) {
		t.Fatal("foreign file owner accepted")
	}
}

func TestSegmentReopenRejectsUnsafeEntriesAndCollision(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "fifo", "directory", "permissions", "oversize", "missing"} {
		t.Run(kind, func(t *testing.T) {
			dir, path := testDirectory(t)
			s := create(t, dir, testLimits())
			appendEvent(t, s)
			got := snapshot(t, s)
			cp, sig, ctx := signed(t, got)
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(path, testName)
			target := filepath.Join(path, "retained-original")
			if err := os.Rename(file, target); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink(target, file)
			case "hardlink":
				err = os.Link(target, file)
			case "fifo":
				err = unix.Mkfifo(file, 0600)
			case "directory":
				err = os.Mkdir(file, 0700)
			case "permissions":
				err = os.WriteFile(file, got.Data, 0600)
				if err == nil {
					err = chmodFixture(file, 0644)
				}
			case "oversize":
				err = os.WriteFile(file, bytes.Repeat([]byte{0}, contracts.MaxJournalScanBytes+1), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if next, err := OpenSealedSegment(dir, testName, cp, sig, ctx, testLimits()); next != nil || !errors.Is(err, ErrUnsafeStorage) {
				t.Fatal("unsafe existing entry accepted", err)
			}
			if !bytes.Equal(readFile(t, target), got.Data) {
				t.Fatal("unrelated original modified")
			}
		})
	}
	dir, path := testDirectory(t)
	s := create(t, dir, testLimits())
	appendEvent(t, s)
	before := snapshot(t, s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if next, err := CreateSegment(dir, testName, startCursor(), testLimits()); next != nil || !errors.Is(err, os.ErrExist) {
		t.Fatal("existing segment overwritten", err)
	}
	if !bytes.Equal(readFile(t, filepath.Join(path, testName)), before.Data) {
		t.Fatal("collision changed bytes")
	}
}

func TestSegmentReopenRejectsUnauthenticatedOrIncompleteHistory(t *testing.T) {
	for _, kind := range []string{"signature", "key", "scope", "truncate-byte", "truncate-frame", "extend-frame", "partial-tail", "corrupt", "frame-budget", "byte-budget"} {
		t.Run(kind, func(t *testing.T) {
			dir, path := testDirectory(t)
			s := create(t, dir, testLimits())
			appendEvent(t, s)
			first := snapshot(t, s)
			appendEvent(t, s)
			got := snapshot(t, s)
			cp, sig, ctx := signed(t, got)
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			limits := testLimits()
			data := bytes.Clone(got.Data)
			switch kind {
			case "signature":
				sig[0] ^= 1
			case "key":
				ctx.Authority.PublicKey[0] ^= 1
			case "scope":
				ctx.Authority.Identity.NodeID = "foreign.node"
			case "truncate-byte":
				data = data[:len(data)-1]
			case "truncate-frame":
				data = bytes.Clone(first.Data)
			case "extend-frame":
				frame, _, err := contracts.EncodeEventJournalFrame(event(t), got.End)
				if err != nil {
					t.Fatal(err)
				}
				data = append(data, frame...)
			case "partial-tail":
				data = append(data, 1, 2, 3)
			case "corrupt":
				data[30] ^= 1
			case "frame-budget":
				limits.MaxFrames = 1
			case "byte-budget":
				limits.MaxBytes = len(data) - 1
			}
			file := filepath.Join(path, testName)
			if err := os.WriteFile(file, data, 0600); err != nil {
				t.Fatal(err)
			}
			if next, err := OpenSealedSegment(dir, testName, cp, sig, ctx, limits); next != nil || err == nil {
				t.Fatal("unverified history accepted")
			}
			if !bytes.Equal(readFile(t, file), data) {
				t.Fatal("failed recovery modified evidence")
			}
			next, err := CreateSegment(dir, otherName, startCursor(), testLimits())
			if err != nil {
				t.Fatal("failed open retained lock", err)
			}
			if err = next.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSegmentDetectsExternalChange(t *testing.T) {
	for _, kind := range []string{"append", "rewrite", "chmod", "directory-mode", "replace", "symlink", "hardlink", "unlink"} {
		t.Run(kind, func(t *testing.T) {
			dir, path := testDirectory(t)
			s := create(t, dir, testLimits())
			appendEvent(t, s)
			file := filepath.Join(path, testName)
			saved := snapshot(t, s)
			var err error
			switch kind {
			case "append":
				err = os.WriteFile(file, append(bytes.Clone(saved.Data), 0), 0600)
			case "rewrite":
				data := bytes.Clone(saved.Data)
				data[20] ^= 1
				err = os.WriteFile(file, data, 0600)
			case "chmod":
				err = chmodFixture(file, 0644)
			case "directory-mode":
				err = chmodFixture(path, 0755)
			case "replace", "symlink":
				err = os.Rename(file, filepath.Join(path, "original"))
				if err != nil {
					t.Fatal(err)
				}
				if kind == "replace" {
					err = os.WriteFile(file, saved.Data, 0600)
				} else {
					err = os.Symlink("original", file)
				}
			case "hardlink":
				err = os.Link(file, filepath.Join(path, "alias"))
			case "unlink":
				err = os.Remove(file)
			}
			if err != nil {
				t.Fatal(err)
			}
			var before []byte
			if kind != "unlink" {
				before = readFile(t, file)
			}
			if r, err := s.Append(saved.End, event(t)); !errors.Is(err, ErrChanged) || r != (Receipt{}) {
				t.Fatal("changed storage acknowledged", err)
			}
			if got, err := s.Snapshot(); !errors.Is(err, ErrCommitUncertain) || got.Data != nil {
				t.Fatal("poisoned snapshot exposed", err)
			}
			if kind != "unlink" && !bytes.Equal(readFile(t, file), before) {
				t.Fatal("changed storage overwritten")
			}
		})
	}
}

type faultFile struct {
	segmentFile
	write func([]byte) (int, error)
	sync  func() error
	read  func([]byte, int64) (int, error)
	close func() error
}

func (f *faultFile) Write(b []byte) (int, error) {
	if f.write != nil {
		return f.write(b)
	}
	return f.segmentFile.Write(b)
}
func (f *faultFile) Sync() error {
	if f.sync != nil {
		return f.sync()
	}
	return f.segmentFile.Sync()
}
func (f *faultFile) ReadAt(b []byte, o int64) (int, error) {
	if f.read != nil {
		return f.read(b, o)
	}
	return f.segmentFile.ReadAt(b, o)
}
func (f *faultFile) Close() error {
	if f.close != nil {
		return f.close()
	}
	return f.segmentFile.Close()
}

func TestSegmentUncertainAppendPreservesExactTail(t *testing.T) {
	for _, kind := range []string{"zero", "short", "enospc", "eio", "full-write-error", "sync", "replace-after-sync"} {
		t.Run(kind, func(t *testing.T) {
			dir, path := testDirectory(t)
			s := create(t, dir, testLimits())
			before := s.receipt
			file := s.file
			frame, _, err := contracts.EncodeEventJournalFrame(event(t), startCursor())
			if err != nil {
				t.Fatal(err)
			}
			writes, syncs := 0, 0
			want := []byte{}
			fault := &faultFile{segmentFile: file}
			fault.write = func(b []byte) (int, error) {
				writes++
				switch kind {
				case "zero":
					return 0, nil
				case "short":
					want = bytes.Clone(b[:17])
					return file.Write(want)
				case "enospc":
					return 0, unix.ENOSPC
				case "eio":
					want = bytes.Clone(b[:23])
					n, err := file.Write(want)
					return n, errors.Join(unix.EIO, err)
				case "full-write-error":
					want = bytes.Clone(b)
					n, err := file.Write(b)
					return n, errors.Join(unix.EIO, err)
				default:
					want = bytes.Clone(b)
					return file.Write(b)
				}
			}
			fault.sync = func() error {
				syncs++
				if kind == "sync" {
					return unix.EIO
				}
				if kind == "replace-after-sync" {
					if err := os.Rename(filepath.Join(path, testName), filepath.Join(path, "original")); err != nil {
						return err
					}
					if err := os.WriteFile(filepath.Join(path, testName), []byte("unrelated"), 0600); err != nil {
						return err
					}
				}
				return file.Sync()
			}
			s.file = fault
			r, err := s.Append(startCursor(), event(t))
			if !errors.Is(err, ErrCommitUncertain) || r != (Receipt{}) || s.receipt != before {
				t.Fatal("uncertain append acknowledged", err)
			}
			if kind == "short" && !errors.Is(err, io.ErrShortWrite) {
				t.Fatal("short write not exposed", err)
			}
			if kind == "enospc" && !errors.Is(err, unix.ENOSPC) {
				t.Fatal("capacity error not exposed", err)
			}
			if strings.Contains(kind, "eio") && !errors.Is(err, unix.EIO) {
				t.Fatal("I/O error not exposed", err)
			}
			if _, err = s.Append(startCursor(), event(t)); !errors.Is(err, ErrCommitUncertain) {
				t.Fatal("uncertain handle reused", err)
			}
			if _, err = s.Snapshot(); !errors.Is(err, ErrCommitUncertain) {
				t.Fatal("uncertain snapshot accepted", err)
			}
			if writes != 1 || syncs > 1 {
				t.Fatal("uncertain operation retried")
			}
			filePath := filepath.Join(path, testName)
			if kind == "replace-after-sync" {
				filePath = filepath.Join(path, "original")
				if string(readFile(t, filepath.Join(path, testName))) != "unrelated" {
					t.Fatal("replacement changed")
				}
			}
			if !bytes.Equal(readFile(t, filePath), want) {
				t.Fatal("tail changed after failure")
			}
			if len(want) > 0 && !bytes.Equal(want, frame[:len(want)]) {
				t.Fatal("unexpected fixture bytes")
			}
		})
	}
}

func TestSegmentSyncCreationFailurePreservesFileAndReleasesLock(t *testing.T) {
	for _, kind := range []string{"file-sync", "directory-sync", "success"} {
		t.Run(kind, func(t *testing.T) {
			dir, path := testDirectory(t)
			s, err := acquire(dir, testName, startCursor(), testLimits(), true)
			if err != nil {
				t.Fatal(err)
			}
			var order []string
			file := s.file
			s.file = &faultFile{segmentFile: file, sync: func() error {
				order = append(order, "file")
				if kind == "file-sync" {
					return unix.EIO
				}
				return file.Sync()
			}}
			err = s.syncCreation(func() error {
				order = append(order, "directory")
				if kind == "directory-sync" {
					return unix.ENOSPC
				}
				return s.directory.Sync()
			})
			if kind == "success" {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, ErrCommitUncertain) {
				t.Fatal("sync failure lost", err)
			}
			if len(order) == 0 || order[0] != "file" || (kind != "file-sync" && strings.Join(order, ",") != "file,directory") || (kind == "file-sync" && len(order) != 1) {
				t.Fatal("wrong sync ordering", order)
			}
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			if len(readFile(t, filepath.Join(path, testName))) != 0 {
				t.Fatal("failed creation removed or changed artifact")
			}
			next, err := CreateSegment(dir, otherName, startCursor(), testLimits())
			if err != nil {
				t.Fatal(err)
			}
			if err = next.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSegmentReadAndCloseFailures(t *testing.T) {
	dir, _ := testDirectory(t)
	s := create(t, dir, testLimits())
	appendEvent(t, s)
	file := s.file
	s.file = &faultFile{segmentFile: file, read: func(b []byte, o int64) (int, error) {
		n, err := file.ReadAt(b[:10], o)
		return n, errors.Join(unix.EIO, err)
	}, close: func() error { return errors.Join(unix.EIO, file.Close()) }}
	if got, err := s.Snapshot(); err == nil || got.Data != nil {
		t.Fatal("partial read exposed")
	}
	if err := s.Close(); !errors.Is(err, unix.EIO) {
		t.Fatal("close error lost", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal("close not idempotent", err)
	}
	if _, err := s.Append(startCursor(), event(t)); !errors.Is(err, ErrClosed) {
		t.Fatal("closed append", err)
	}
	if _, err := s.Snapshot(); !errors.Is(err, ErrClosed) {
		t.Fatal("closed read", err)
	}
	next, err := CreateSegment(dir, otherName, startCursor(), testLimits())
	if err != nil {
		t.Fatal("close failure retained lock", err)
	}
	if err = next.Close(); err != nil {
		t.Fatal(err)
	}
	var zero Segment
	if _, err = zero.Snapshot(); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if err = zero.Close(); err != nil {
		t.Fatal(err)
	}
}

// A separate process proves flock exclusion and preserves a deliberately partial
// frame on abrupt exit. This is process interruption, not a power-loss experiment.
func TestSegmentProcessHelper(t *testing.T) {
	mode := os.Getenv("SYSWARDEN_JOURNAL_TEST_CHILD")
	if mode == "" {
		return
	}
	if mode != "locked" && mode != "interrupt" {
		t.Fatal("invalid child mode")
	}
	dir := os.NewFile(3, "journal-test-directory")
	if dir == nil {
		t.Fatal("missing inherited directory")
	}
	s, err := CreateSegment(dir, otherName, startCursor(), testLimits())
	if mode == "locked" {
		if s != nil || !errors.Is(err, ErrLocked) {
			t.Fatal("cross-process lock bypass", err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	frame, _, err := contracts.EncodeEventJournalFrame(event(t), startCursor())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.file.Write(frame[:31]); err != nil {
		t.Fatal(err)
	}
	if err = s.file.Sync(); err != nil {
		t.Fatal(err)
	}
	os.Exit(0)
}

func TestSegmentProcessExclusionAndInterruptedTail(t *testing.T) {
	dir, path := testDirectory(t)
	s := create(t, dir, testLimits())
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	run := func(mode string) {
		t.Helper()
		cmd := exec.Command(exe, "-test.run=^TestSegmentProcessHelper$")
		cmd.Env = append(os.Environ(), "SYSWARDEN_JOURNAL_TEST_CHILD="+mode)
		cmd.ExtraFiles = []*os.File{dir}
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("child failed: %v %s", err, output)
		}
	}
	run("locked")
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	run("interrupt")
	before := readFile(t, filepath.Join(path, otherName))
	if len(before) != 31 {
		t.Fatal("partial fixture missing")
	}
	cp, sig, ctx := signed(t, Snapshot{Receipt: Receipt{Start: startCursor(), End: startCursor()}})
	if reopened, err := OpenSealedSegment(dir, otherName, cp, sig, ctx, testLimits()); reopened != nil || err == nil {
		t.Fatal("interrupted tail accepted")
	}
	if !bytes.Equal(before, readFile(t, filepath.Join(path, otherName))) {
		t.Fatal("interrupted tail discarded")
	}
}
