package journal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
	contracts "syswarden-core/contracts/v5"
)

func freeze(t *testing.T, s *Segment) Snapshot {
	t.Helper()
	b, err := s.Freeze(s.receipt.End)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPublicationRoundTripAndFrozenBoundary(t *testing.T) {
	for _, count := range []int{0, 1, 3} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			dir, path := testDirectory(t)
			s := create(t, dir, testLimits())
			for range count {
				appendEvent(t, s)
			}
			frozen := freeze(t, s)
			cp, sig, ctx := signed(t, frozen)
			if _, err := s.Append(frozen.End, event(t)); !errors.Is(err, ErrSealed) {
				t.Fatal("frozen append accepted", err)
			}
			if !bytes.Equal(freeze(t, s).Data, frozen.Data) {
				t.Fatal("repeated freeze changed bytes")
			}
			pub, err := s.PublishCheckpoint(cp, sig, ctx)
			if err != nil {
				t.Fatal(err)
			}
			pending, final := checkpointNames(testName)
			_, next, err := contracts.VerifyJournalCheckpoint(cp, sig, ctx)
			if err != nil || pub != (Publication{SegmentName: testName, CheckpointName: final, Next: next}) {
				t.Fatal("publication receipt mismatch", err)
			}
			if _, err = os.Lstat(filepath.Join(path, pending)); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("pending file remained", err)
			}
			bundle := readFile(t, filepath.Join(path, final))
			got, gotSig, err := decodeCheckpointBundle(bundle)
			if err != nil || !bytes.Equal(got, cp) || !bytes.Equal(gotSig, sig) {
				t.Fatal("stored bytes differ", err)
			}
			if again, err := s.PublishCheckpoint(cp, sig, ctx); !errors.Is(err, ErrCheckpointCollision) || again != (Publication{}) {
				t.Fatal("publication overwrote history", err)
			}
			if err = s.Close(); err != nil {
				t.Fatal(err)
			}
			r, err := OpenPublishedSegment(dir, testName, ctx, testLimits())
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := r.Close(); err != nil {
					t.Error(err)
				}
			}()
			if !bytes.Equal(snapshot(t, r).Data, frozen.Data) {
				t.Fatal("published read differs")
			}
			if _, err = r.PublishCheckpoint(cp, sig, ctx); !errors.Is(err, ErrCheckpointState) {
				t.Fatal("historical reader gained publication authority", err)
			}
			if _, err = r.Append(frozen.End, event(t)); !errors.Is(err, ErrSealed) {
				t.Fatal("historical append accepted", err)
			}
		})
	}
}

func TestFreezeRejectsStaleCursorAndSerializesAppend(t *testing.T) {
	dir, _ := testDirectory(t)
	s := create(t, dir, testLimits())
	appendEvent(t, s)
	if got, err := s.Freeze(startCursor()); !errors.Is(err, ErrConflict) || got.Data != nil {
		t.Fatal("stale freeze accepted", err)
	}
	appendEvent(t, s)
	start := s.receipt.End
	payload := event(t)
	var wg sync.WaitGroup
	var appendErr, freezeErr error
	var view Snapshot
	wg.Go(func() { _, appendErr = s.Append(start, payload) })
	wg.Go(func() { view, freezeErr = s.Freeze(start) })
	wg.Wait()
	if appendErr == nil {
		if !errors.Is(freezeErr, ErrConflict) || view.Data != nil {
			t.Fatal("stale snapshot froze later writes", freezeErr)
		}
	} else if freezeErr != nil || !errors.Is(appendErr, ErrSealed) || view.End != start {
		t.Fatal("freeze was not serialized", freezeErr, appendErr)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Freeze(start); !errors.Is(err, ErrClosed) || got.Data != nil {
		t.Fatal("closed freeze accepted", err)
	}
	if got, err := s.PublishCheckpoint(nil, nil, contracts.JournalCheckpointContext{}); !errors.Is(err, ErrClosed) || got != (Publication{}) {
		t.Fatal("closed publication accepted", err)
	}
}

func TestPublicationValidatesBeforeCreatingArtifacts(t *testing.T) {
	for _, kind := range []string{"unfrozen", "signature", "scope", "empty-foreign-scope", "wrong-end", "wrong-size", "external-change"} {
		t.Run(kind, func(t *testing.T) {
			dir, path := testDirectory(t)
			s := create(t, dir, testLimits())
			if kind != "empty-foreign-scope" {
				appendEvent(t, s)
			}
			b := snapshot(t, s)
			if kind != "unfrozen" {
				b = freeze(t, s)
			}
			if kind == "empty-foreign-scope" {
				b.Start.Identity.NodeID = "foreign.node"
				b.End = b.Start
			}
			if kind == "wrong-end" {
				b.End = startCursor()
				b.Data = nil
			}
			if kind == "wrong-size" {
				b.Data = append(bytes.Clone(b.Data), 0)
			}
			cp, sig, ctx := signed(t, b)
			switch kind {
			case "signature":
				sig[0] ^= 1
			case "scope":
				ctx.Anchor.Cursor.Identity.Epoch = "foreign.epoch"
			case "external-change":
				if err := os.WriteFile(filepath.Join(path, testName), []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if got, err := s.PublishCheckpoint(cp, sig, ctx); err == nil || got != (Publication{}) {
				t.Fatal("invalid checkpoint accepted")
			}
			entries, err := os.ReadDir(path)
			if err != nil || len(entries) != 1 {
				t.Fatal("invalid checkpoint created artifacts", err)
			}
		})
	}
}

func TestPublicationCollisionsPreserveAllObjects(t *testing.T) {
	for _, target := range []string{"pending", "final"} {
		for _, kind := range []string{"file", "symlink", "hardlink", "directory", "fifo"} {
			t.Run(target+"/"+kind, func(t *testing.T) {
				dir, path := testDirectory(t)
				s := create(t, dir, testLimits())
				appendEvent(t, s)
				cp, sig, ctx := signed(t, freeze(t, s))
				pending, final := checkpointNames(testName)
				name := pending
				if target == "final" {
					name = final
				}
				file := filepath.Join(path, name)
				original := filepath.Join(path, "unrelated")
				if err := os.WriteFile(original, []byte("administrator-owned"), 0600); err != nil {
					t.Fatal(err)
				}
				var err error
				switch kind {
				case "file":
					err = os.WriteFile(file, []byte("retained"), 0600)
				case "symlink":
					err = os.Symlink("unrelated", file)
				case "hardlink":
					err = os.Link(original, file)
				case "directory":
					err = os.Mkdir(file, 0700)
				case "fifo":
					err = unix.Mkfifo(file, 0600)
				}
				if err != nil {
					t.Fatal(err)
				}
				if pub, err := s.PublishCheckpoint(cp, sig, ctx); !errors.Is(err, ErrCheckpointCollision) || pub != (Publication{}) {
					t.Fatal("collision accepted", err)
				}
				if string(readFile(t, original)) != "administrator-owned" {
					t.Fatal("unrelated object changed")
				}
				if _, err = os.Lstat(file); err != nil {
					t.Fatal("collision removed", err)
				}
				if kind == "file" && string(readFile(t, file)) != "retained" {
					t.Fatal("collision bytes changed")
				}
				if _, err = s.Snapshot(); err != nil {
					t.Fatal("preflight collision poisoned unchanged handle", err)
				}
			})
		}
	}
}

func TestPublicationOrderAndConcurrentAttempts(t *testing.T) {
	dir, _ := testDirectory(t)
	s := create(t, dir, testLimits())
	appendEvent(t, s)
	cp, sig, ctx := signed(t, freeze(t, s))
	ops := s.publicationOps()
	originalCreate, originalRename, originalSync := ops.create, ops.rename, ops.syncDirectory
	var order []string
	ops.create = func(name string) (segmentFile, error) {
		order = append(order, "create")
		file, err := originalCreate(name)
		if err != nil {
			return nil, err
		}
		return &faultFile{segmentFile: file, write: func(b []byte) (int, error) { order = append(order, "write"); return file.Write(b) }, sync: func() error { order = append(order, "file-sync"); return file.Sync() }, close: func() error { order = append(order, "close"); return file.Close() }}, nil
	}
	ops.rename = func(a, b string) error { order = append(order, "rename"); return originalRename(a, b) }
	ops.syncDirectory = func() error { order = append(order, "directory-sync"); return originalSync() }
	if _, err := s.publishCheckpoint(cp, sig, ctx, ops); err != nil {
		t.Fatal(err)
	}
	want := []string{"create", "write", "file-sync", "rename", "directory-sync", "close"}
	if len(order) != len(want) {
		t.Fatal(order)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatal(order)
		}
	}
	dir2, _ := testDirectory(t)
	s2 := create(t, dir2, testLimits())
	appendEvent(t, s2)
	cp2, sig2, ctx2 := signed(t, freeze(t, s2))
	const workers = 8
	results := make(chan error, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() { _, err := s2.PublishCheckpoint(cp2, sig2, ctx2); results <- err })
	}
	wg.Wait()
	close(results)
	passed := 0
	for err := range results {
		if err == nil {
			passed++
		} else if !errors.Is(err, ErrCheckpointCollision) {
			t.Fatal(err)
		}
	}
	if passed != 1 {
		t.Fatal("duplicate publication accepted", passed)
	}
}

func TestPublicationFailuresPreservePendingOrFinalBytes(t *testing.T) {
	for _, kind := range []string{"create-error", "zero-write", "short-write", "write-eio", "full-write-eio", "sync", "rename", "unsupported-rename", "rename-collision", "directory-sync", "final-change", "readback", "segment-change", "close"} {
		t.Run(kind, func(t *testing.T) {
			dir, path := testDirectory(t)
			s := create(t, dir, testLimits())
			appendEvent(t, s)
			frozen := freeze(t, s)
			cp, sig, ctx := signed(t, frozen)
			bundle, err := encodeCheckpointBundle(cp, sig)
			if err != nil {
				t.Fatal(err)
			}
			ops := s.publicationOps()
			originalCreate, originalRename, originalSync := ops.create, ops.rename, ops.syncDirectory
			writes, renames, syncs := 0, 0, 0
			expected := bundle
			pending, final := checkpointNames(testName)
			ops.create = func(name string) (segmentFile, error) {
				file, err := originalCreate(name)
				if err != nil {
					return nil, err
				}
				if kind == "create-error" {
					expected = nil
					return nil, errors.Join(unix.EIO, file.Close())
				}
				return &faultFile{segmentFile: file,
					write: func(b []byte) (int, error) {
						writes++
						switch kind {
						case "zero-write":
							expected = nil
							return 0, nil
						case "short-write":
							expected = bytes.Clone(b[:19])
							return file.Write(expected)
						case "write-eio":
							expected = bytes.Clone(b[:31])
							n, err := file.Write(expected)
							return n, errors.Join(unix.EIO, err)
						case "full-write-eio":
							n, err := file.Write(b)
							return n, errors.Join(unix.EIO, err)
						default:
							return file.Write(b)
						}
					},
					sync: func() error {
						if kind == "sync" {
							return unix.ENOSPC
						}
						if kind == "segment-change" {
							if err := os.WriteFile(filepath.Join(path, testName), []byte("changed segment"), 0600); err != nil {
								return err
							}
						}
						return file.Sync()
					},
					read: func(b []byte, o int64) (int, error) {
						if kind == "readback" {
							return 0, unix.EIO
						}
						return file.ReadAt(b, o)
					},
					close: func() error {
						err := file.Close()
						if kind == "close" {
							return errors.Join(unix.EIO, err)
						}
						return err
					},
				}, nil
			}
			ops.rename = func(a, b string) error {
				renames++
				switch kind {
				case "rename":
					return unix.EIO
				case "unsupported-rename":
					return unix.EOPNOTSUPP
				case "rename-collision":
					if err := os.WriteFile(filepath.Join(path, final), []byte("unrelated"), 0600); err != nil {
						return err
					}
				}
				return originalRename(a, b)
			}
			ops.syncDirectory = func() error {
				syncs++
				if kind == "directory-sync" {
					return unix.EIO
				}
				if kind == "final-change" {
					expected = bytes.Clone(bundle)
					expected[12] ^= 1
					if err := os.WriteFile(filepath.Join(path, final), expected, 0600); err != nil {
						return err
					}
				}
				return originalSync()
			}
			pub, err := s.publishCheckpoint(cp, sig, ctx, ops)
			if !errors.Is(err, ErrCommitUncertain) || pub != (Publication{}) {
				t.Fatal("uncertain publication acknowledged", err)
			}
			if kind == "short-write" && !errors.Is(err, io.ErrShortWrite) {
				t.Fatal("short write hidden", err)
			}
			if kind == "sync" && !errors.Is(err, unix.ENOSPC) {
				t.Fatal("storage exhaustion hidden", err)
			}
			expectedWrites := 1
			if kind == "create-error" {
				expectedWrites = 0
			}
			if writes != expectedWrites || renames > 1 || syncs > 1 {
				t.Fatal("operation retried")
			}
			if _, err = s.PublishCheckpoint(cp, sig, ctx); !errors.Is(err, ErrCommitUncertain) {
				t.Fatal("poisoned publication reused", err)
			}
			if got, err := s.Freeze(frozen.End); !errors.Is(err, ErrCommitUncertain) || got.Data != nil {
				t.Fatal("poisoned freeze accepted", err)
			}
			if _, err = s.Snapshot(); !errors.Is(err, ErrCommitUncertain) {
				t.Fatal("poisoned snapshot accepted", err)
			}
			kept := pending
			if kind == "directory-sync" || kind == "final-change" || kind == "close" {
				kept = final
			}
			if !bytes.Equal(readFile(t, filepath.Join(path, kept)), expected) {
				t.Fatal("uncertain bytes altered")
			}
			if kind == "rename-collision" && string(readFile(t, filepath.Join(path, final))) != "unrelated" {
				t.Fatal("no-replace rename overwrote collision")
			}
		})
	}
}

func TestPublishedReadRejectsUnsafeAndAlteredBundles(t *testing.T) {
	for _, kind := range []string{"missing", "pending", "mode", "symlink", "hardlink", "fifo", "oversize", "truncate", "extend", "signature", "context", "segment"} {
		t.Run(kind, func(t *testing.T) {
			dir, path := testDirectory(t)
			s := create(t, dir, testLimits())
			appendEvent(t, s)
			frozen := freeze(t, s)
			cp, sig, ctx := signed(t, frozen)
			if _, err := s.PublishCheckpoint(cp, sig, ctx); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			pending, final := checkpointNames(testName)
			file := filepath.Join(path, final)
			data := readFile(t, file)
			var err error
			switch kind {
			case "missing":
				err = os.Remove(file)
			case "pending":
				err = os.WriteFile(filepath.Join(path, pending), data, 0600)
			case "mode":
				err = chmodFixture(file, 0644)
			case "symlink", "hardlink", "fifo":
				err = os.Rename(file, filepath.Join(path, "retained"))
				if err != nil {
					t.Fatal(err)
				}
				if kind == "symlink" {
					err = os.Symlink("retained", file)
				} else if kind == "hardlink" {
					err = os.Link(filepath.Join(path, "retained"), file)
				} else {
					err = unix.Mkfifo(file, 0600)
				}
			case "oversize":
				err = os.WriteFile(file, bytes.Repeat([]byte{0}, maxCheckpointBundleBytes+1), 0600)
			case "truncate":
				err = os.WriteFile(file, data[:len(data)-1], 0600)
			case "extend":
				err = os.WriteFile(file, append(data, 0), 0600)
			case "signature":
				data[len(data)-1] ^= 1
				err = os.WriteFile(file, data, 0600)
			case "context":
				ctx.Anchor.NextSequence++
			case "segment":
				err = os.WriteFile(filepath.Join(path, testName), frozen.Data[:len(frozen.Data)-1], 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if got, err := OpenPublishedSegment(dir, testName, ctx, testLimits()); got != nil || err == nil {
				t.Fatal("unverified published read accepted")
			}
			next, err := CreateSegment(dir, otherName, startCursor(), testLimits())
			if err != nil {
				t.Fatal("failed read retained lock", err)
			}
			if err = next.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCheckpointBundleBoundsAndOwnership(t *testing.T) {
	dir, _ := testDirectory(t)
	s := create(t, dir, testLimits())
	appendEvent(t, s)
	cp, sig, _ := signed(t, freeze(t, s))
	b, err := encodeCheckpointBundle(cp, sig)
	if err != nil {
		t.Fatal(err)
	}
	if string(b[:8]) != "SWJCP1\x00\x00" || int64(binary.BigEndian.Uint32(b[8:12])) != int64(len(cp)) || len(b) != 12+len(cp)+64 {
		t.Fatal("wire format changed")
	}
	for n := 0; n < len(b); n++ {
		if cp, sig, err := decodeCheckpointBundle(b[:n]); err == nil || cp != nil || sig != nil {
			t.Fatal("truncated bundle accepted", n)
		}
	}
	for _, mutation := range []string{"magic", "length-zero", "length-max", "length-mismatch", "invalid-json", "extension", "oversize"} {
		data := bytes.Clone(b)
		switch mutation {
		case "magic":
			data[7] ^= 1
		case "length-zero":
			binary.BigEndian.PutUint32(data[8:12], 0)
		case "length-max":
			binary.BigEndian.PutUint32(data[8:12], 0xffffffff)
		case "length-mismatch":
			data[11] ^= 1
		case "invalid-json":
			data[12] = '['
		case "extension":
			data = append(data, 0)
		case "oversize":
			data = bytes.Repeat([]byte{0}, maxCheckpointBundleBytes+1)
		}
		if cp, sig, err := decodeCheckpointBundle(data); err == nil || cp != nil || sig != nil {
			t.Fatal("invalid bundle accepted", mutation)
		}
	}
	for _, args := range [][2][]byte{{nil, sig}, {bytes.Repeat([]byte{0}, contracts.MaxCheckpointBytes+1), sig}, {cp, sig[:len(sig)-1]}, {[]byte("{}"), sig}} {
		if b, err := encodeCheckpointBundle(args[0], args[1]); b != nil || err == nil {
			t.Fatal("invalid encode accepted")
		}
	}
	got, gotSig, err := decodeCheckpointBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	for i := range b {
		b[i] = 0
	}
	if !bytes.Equal(got, cp) || !bytes.Equal(gotSig, sig) {
		t.Fatal("decoder aliases input")
	}
}

func FuzzCheckpointPublicationBundle(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("SWJCP1\x00\x00\xff\xff\xff\xff"))
	cp, err := os.ReadFile("../contracts/v5/testdata/checkpoint-two-events.json")
	if err != nil {
		f.Fatal(err)
	}
	cp = bytes.TrimSuffix(cp, []byte("\n"))
	seed, err := encodeCheckpointBundle(cp, make([]byte, 64))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Fuzz(func(t *testing.T, data []byte) {
		cp, sig, err := decodeCheckpointBundle(data)
		if err != nil {
			if cp != nil || sig != nil {
				t.Fatal("failure exposed data")
			}
			return
		}
		b, err := encodeCheckpointBundle(cp, sig)
		if err != nil || !bytes.Equal(b, data) {
			t.Fatal("noncanonical round trip", err)
		}
		if len(b) > maxCheckpointBundleBytes {
			t.Fatal("bundle exceeded ceiling")
		}
	})
}

func TestPublicationProcessHelper(t *testing.T) {
	mode := os.Getenv("SYSWARDEN_PUBLICATION_TEST_CHILD")
	if mode == "" {
		return
	}
	if mode != "before-rename" && mode != "after-rename" {
		t.Fatal("invalid child mode")
	}
	dir := os.NewFile(3, "publication-test-directory")
	if dir == nil {
		t.Fatal("missing directory")
	}
	s := create(t, dir, testLimits())
	appendEvent(t, s)
	cp, sig, ctx := signed(t, freeze(t, s))
	ops := s.publicationOps()
	rename := ops.rename
	ops.rename = func(a, b string) error {
		if mode == "before-rename" {
			os.Exit(0)
		}
		if err := rename(a, b); err != nil {
			return err
		}
		os.Exit(0)
		return nil
	}
	_, err := s.publishCheckpoint(cp, sig, ctx, ops)
	t.Fatal("child did not interrupt", err)
}

func TestPublicationProcessInterruption(t *testing.T) {
	for _, mode := range []string{"before-rename", "after-rename"} {
		t.Run(mode, func(t *testing.T) {
			dir, path := testDirectory(t)
			// Linux's self executable avoids selecting a child binary from a path
			// supplied by the environment or the caller.
			cmd := exec.Command("/proc/self/exe", "-test.run=^TestPublicationProcessHelper$")
			cmd.Env = append(os.Environ(), "SYSWARDEN_PUBLICATION_TEST_CHILD="+mode)
			cmd.ExtraFiles = []*os.File{dir}
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("interruption child: %v %s", err, output)
			}
			pending, final := checkpointNames(testName)
			kept := pending
			if mode == "after-rename" {
				kept = final
			}
			before := readFile(t, filepath.Join(path, kept))
			// Resolve a synthetic independent trust context without adopting disk data.
			_, _, ctx := signed(t, Snapshot{Receipt: Receipt{Start: startCursor(), End: startCursor()}})
			r, err := OpenPublishedSegment(dir, testName, ctx, testLimits())
			if mode == "before-rename" {
				if r != nil || err == nil {
					t.Fatal("pending publication accepted")
				}
			} else {
				// Complete historical bytes are readable, but this is not a durable
				// publication acknowledgement or an automatic trusted-anchor commit.
				if err != nil {
					t.Fatal(err)
				}
				if snapshot(t, r).Frames != 1 {
					t.Fatal("history changed")
				}
				if err = r.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if !bytes.Equal(readFile(t, filepath.Join(path, kept)), before) {
				t.Fatal("interrupted evidence modified")
			}
		})
	}
}
