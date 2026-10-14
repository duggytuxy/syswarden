package journal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
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

func initialAnchor() contracts.JournalCheckpointAnchor {
	return contracts.JournalCheckpointAnchor{Cursor: startCursor(), NextSequence: 1, PreviousSHA256: strings.Repeat("0", 64)}
}

func anchorFixture(t *testing.T) (*AnchorStore, *os.File, string) {
	t.Helper()
	dir, path := testDirectory(t)
	a, err := CreateAnchorStore(dir, initialAnchor())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := a.Close(); err != nil {
			t.Error(err)
		}
	})
	return a, dir, path
}

func publishForAnchor(t *testing.T, prior contracts.JournalCheckpointAnchor, count int) (*os.File, string, Publication, contracts.JournalCheckpointAuthority) {
	t.Helper()
	dir, path := testDirectory(t)
	s, err := CreateSegment(dir, testName, prior.Cursor, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	for range count {
		appendEvent(t, s)
	}
	cp, _, ctx := signed(t, freeze(t, s))
	d, err := contracts.DecodeJournalCheckpoint(cp)
	if err != nil {
		t.Fatal(err)
	}
	d.Sequence = strconv.FormatUint(prior.NextSequence, 10)
	d.PreviousCheckpointSHA256 = prior.PreviousSHA256
	ctx.Anchor = prior
	cp, err = contracts.EncodeJournalCheckpoint(d)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := contracts.JournalCheckpointSigningMessage(d)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	pub, err := s.PublishCheckpoint(cp, ed25519.Sign(key, msg), ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	return dir, path, pub, ctx.Authority
}

func TestAnchorCommitReopenAndReplay(t *testing.T) {
	a, dir, path := anchorFixture(t)
	prior := initialAnchor()
	original := readFile(t, filepath.Join(path, anchorName))
	for _, count := range []int{0, 1, 2} {
		journal, _, publication, authority := publishForAnchor(t, prior, count)
		next, err := a.CommitPublished(prior, journal, testName, authority, testLimits())
		if err != nil || next != publication.Next {
			t.Fatal("commit mismatch", err)
		}
		if head, err := a.Current(); err != nil || head != next {
			t.Fatal("head mismatch", err)
		}
		if head, err := a.CommitPublished(prior, journal, testName, authority, testLimits()); !errors.Is(err, ErrAnchorConflict) || head != (contracts.JournalCheckpointAnchor{}) {
			t.Fatal("replay accepted", err)
		}
		if !bytes.HasPrefix(readFile(t, filepath.Join(path, anchorName)), original) {
			t.Fatal("prior anchor bytes changed")
		}
		prior = next
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	for _, wrong := range []contracts.JournalCheckpointAnchor{initialAnchor(), {}} {
		if r, err := OpenAnchorStore(dir, initialAnchor(), wrong); err == nil || r != nil {
			t.Fatal("unexpected durable head adopted")
		}
	}
	r, err := OpenAnchorStore(dir, initialAnchor(), prior)
	if err != nil {
		t.Fatal(err)
	}
	if head, err := r.Current(); err != nil || head != prior {
		t.Fatal("reopen mismatch", err)
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	if err = r.Close(); err != nil {
		t.Fatal(err)
	}
	if head, err := r.Current(); !errors.Is(err, ErrClosed) || head != (contracts.JournalCheckpointAnchor{}) {
		t.Fatal("closed head returned")
	}
}

func TestAnchorLocksAndIndependentDirectory(t *testing.T) {
	a, dir, _ := anchorFixture(t)
	if r, err := OpenAnchorStore(dir, initialAnchor(), initialAnchor()); !errors.Is(err, ErrLocked) || r != nil {
		t.Fatal("concurrent open accepted", err)
	}
	if r, err := CreateAnchorStore(dir, initialAnchor()); !errors.Is(err, ErrLocked) || r != nil {
		t.Fatal("concurrent bootstrap accepted", err)
	}
	_, _, _, authority := publishForAnchor(t, initialAnchor(), 0)
	if head, err := a.CommitPublished(initialAnchor(), dir, testName, authority, testLimits()); !errors.Is(err, ErrLocked) || head != (contracts.JournalCheckpointAnchor{}) {
		t.Fatal("same-directory authority accepted", err)
	}
	if head, err := a.Current(); err != nil || head != initialAnchor() {
		t.Fatal("preflight rejection poisoned store", err)
	}
	if err := dir.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Current(); err != nil {
		t.Fatal("caller descriptor lifetime retained", err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	var zero AnchorStore
	if _, err := zero.Current(); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if _, err := zero.CommitPublished(initialAnchor(), nil, testName, authority, testLimits()); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}

func TestAnchorConcurrentExpectedState(t *testing.T) {
	a, _, _ := anchorFixture(t)
	dir, _, pub, key := publishForAnchor(t, initialAnchor(), 1)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			next, err := a.CommitPublished(initialAnchor(), dir, testName, key, testLimits())
			if err == nil && next != pub.Next {
				t.Error("wrong committed head")
			}
			results <- err
		})
	}
	wg.Wait()
	close(results)
	ok, conflict := 0, 0
	for err := range results {
		if err == nil {
			ok++
		} else if errors.Is(err, ErrAnchorConflict) {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if ok != 1 || conflict != 1 || a.state.count != 2 {
		t.Fatal("concurrent double commit", ok, conflict)
	}
}

func TestAnchorRejectsUnprovenPublicationWithoutWriting(t *testing.T) {
	for _, kind := range []string{"missing", "pending", "corrupt-segment", "corrupt-bundle", "foreign-key", "revoked-range", "foreign-scope", "stricter-budget", "invalid-name"} {
		t.Run(kind, func(t *testing.T) {
			a, _, path := anchorFixture(t)
			dir, jpath, _, key := publishForAnchor(t, initialAnchor(), 1)
			before := readFile(t, filepath.Join(path, anchorName))
			pending, final := checkpointNames(testName)
			name, limits := testName, testLimits()
			switch kind {
			case "missing":
				if err := os.Remove(filepath.Join(jpath, final)); err != nil {
					t.Fatal(err)
				}
			case "pending":
				if err := os.WriteFile(filepath.Join(jpath, pending), []byte("retained"), 0600); err != nil {
					t.Fatal(err)
				}
			case "corrupt-segment":
				if err := os.WriteFile(filepath.Join(jpath, testName), []byte("retained"), 0600); err != nil {
					t.Fatal(err)
				}
			case "corrupt-bundle":
				if err := os.WriteFile(filepath.Join(jpath, final), []byte("retained"), 0600); err != nil {
					t.Fatal(err)
				}
			case "foreign-key":
				key.PublicKey = bytes.Repeat([]byte{0x21}, 32)
			case "revoked-range":
				key.FirstSequence = 2
			case "foreign-scope":
				key.Identity.Epoch = "other.epoch"
			case "stricter-budget":
				limits.MaxBytes = 1
			case "invalid-name":
				name = "../escape"
			}
			if next, err := a.CommitPublished(initialAnchor(), dir, name, key, limits); err == nil || next != (contracts.JournalCheckpointAnchor{}) {
				t.Fatal("unproven state committed")
			}
			if !bytes.Equal(before, readFile(t, filepath.Join(path, anchorName))) {
				t.Fatal("invalid input changed anchor")
			}
			if head, err := a.Current(); err != nil || head != initialAnchor() {
				t.Fatal("preflight poisoned valid state", err)
			}
		})
	}
}

func TestAnchorUnsafeStorageAndNoAutomaticBootstrap(t *testing.T) {
	for _, kind := range []string{"missing", "mode", "hardlink", "symlink", "fifo", "directory", "oversize", "truncated", "unexpected-complete-tail", "wrong-initial"} {
		t.Run(kind, func(t *testing.T) {
			a, dir, path := anchorFixture(t)
			original := readFile(t, filepath.Join(path, anchorName))
			if err := a.Close(); err != nil {
				t.Fatal(err)
			}
			initial := initialAnchor()
			file := filepath.Join(path, anchorName)
			switch kind {
			case "missing":
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := chmodFixture(file, 0644); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(file, filepath.Join(path, "other")); err != nil {
					t.Fatal(err)
				}
			case "symlink", "fifo", "directory":
				if err := os.Rename(file, filepath.Join(path, "saved")); err != nil {
					t.Fatal(err)
				}
				var err error
				if kind == "symlink" {
					err = os.Symlink("saved", file)
				} else if kind == "fifo" {
					err = unix.Mkfifo(file, 0600)
				} else {
					err = os.Mkdir(file, 0700)
				}
				if err != nil {
					t.Fatal(err)
				}
			case "oversize":
				if err := os.Truncate(file, maxAnchorFile+1); err != nil {
					t.Fatal(err)
				}
			case "truncated":
				if err := os.Truncate(file, int64(len(original)-1)); err != nil {
					t.Fatal(err)
				}
			case "unexpected-complete-tail":
				state, err := scanAnchors(original, initial)
				if err != nil {
					t.Fatal(err)
				}
				next := initial
				next.NextSequence++
				frame, err := anchorFrame(next, state.hash)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(file, append(original, frame...), 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong-initial":
				initial.Cursor.Identity.NodeID = "other.node"
			}
			if r, err := OpenAnchorStore(dir, initial, initialAnchor()); err == nil || r != nil {
				t.Fatal("unsafe state opened")
			}
			if kind != "missing" {
				if r, err := CreateAnchorStore(dir, initialAnchor()); err == nil || r != nil {
					t.Fatal("existing state reinitialized")
				}
			}
		})
	}
}

func TestAnchorWriteFailuresPreserveTailAndDisableHandle(t *testing.T) {
	for _, kind := range []string{"zero", "short", "enospc", "partial-error", "full-error", "sync", "readback", "replace", "close-publication", "sync-publication"} {
		t.Run(kind, func(t *testing.T) {
			a, dir, path := anchorFixture(t)
			journal, _, _, key := publishForAnchor(t, initialAnchor(), 1)
			original := readFile(t, filepath.Join(path, anchorName))
			file := a.file
			fault := &faultFile{segmentFile: file}
			a.file = fault
			switch kind {
			case "zero":
				fault.write = func([]byte) (int, error) { return 0, nil }
			case "short":
				fault.write = func(b []byte) (int, error) { return file.Write(b[:len(b)/2]) }
			case "enospc":
				fault.write = func([]byte) (int, error) { return 0, unix.ENOSPC }
			case "partial-error":
				fault.write = func(b []byte) (int, error) { n, _ := file.Write(b[:len(b)/2]); return n, unix.EIO }
			case "full-error":
				fault.write = func(b []byte) (int, error) { n, _ := file.Write(b); return n, unix.EIO }
			case "sync":
				fault.sync = func() error { return unix.EIO }
			case "readback":
				fault.write = func(b []byte) (int, error) {
					n, err := file.Write(b)
					fault.read = func([]byte, int64) (int, error) { return 0, unix.EIO }
					return n, err
				}
			case "replace":
				fault.sync = func() error {
					if err := os.Rename(filepath.Join(path, anchorName), filepath.Join(path, "saved")); err != nil {
						return err
					}
					return os.WriteFile(filepath.Join(path, anchorName), original, 0600)
				}
			}
			opener := OpenPublishedSegment
			if kind == "close-publication" || kind == "sync-publication" {
				opener = func(d *os.File, n string, c contracts.JournalCheckpointContext, l Limits) (*Segment, error) {
					s, err := OpenPublishedSegment(d, n, c, l)
					if err != nil {
						return nil, err
					}
					f := s.file
					wrapped := &faultFile{segmentFile: f}
					if kind == "close-publication" {
						wrapped.close = func() error { return errors.Join(f.Close(), unix.EIO) }
					} else {
						wrapped.sync = func() error { return unix.EIO }
					}
					s.file = wrapped
					return s, nil
				}
			}
			next, err := a.commitPublished(initialAnchor(), journal, testName, key, testLimits(), opener)
			if !errors.Is(err, ErrCommitUncertain) || next != (contracts.JournalCheckpointAnchor{}) {
				t.Fatal("uncertain commit acknowledged", err)
			}
			retained := readFile(t, filepath.Join(path, anchorName))
			if !bytes.HasPrefix(retained, original) {
				t.Fatal("original bytes lost")
			}
			if head, err := a.Current(); !errors.Is(err, ErrCommitUncertain) || head != (contracts.JournalCheckpointAnchor{}) {
				t.Fatal("poisoned state exposed", err)
			}
			if _, err := a.CommitPublished(initialAnchor(), journal, testName, key, testLimits()); !errors.Is(err, ErrCommitUncertain) {
				t.Fatal("poisoned retry accepted", err)
			}
			if !bytes.Equal(retained, readFile(t, filepath.Join(path, anchorName))) {
				t.Fatal("retry changed evidence")
			}
			if err := a.Close(); err != nil {
				t.Fatal(err)
			}
			if kind == "short" || kind == "partial-error" || kind == "full-error" || kind == "sync" || kind == "readback" || kind == "close-publication" {
				if r, err := OpenAnchorStore(dir, initialAnchor(), initialAnchor()); err == nil || r != nil {
					t.Fatal("unexpected tail silently adopted")
				}
			}
		})
	}
}

func TestAnchorDetectsChangesAndExhaustion(t *testing.T) {
	a, _, path := anchorFixture(t)
	original := readFile(t, filepath.Join(path, anchorName))
	original[len(original)-1] ^= 1
	if err := os.WriteFile(filepath.Join(path, anchorName), original, 0600); err != nil {
		t.Fatal(err)
	}
	if head, err := a.Current(); err == nil || head != (contracts.JournalCheckpointAnchor{}) {
		t.Fatal("modified anchor accepted")
	}
	for _, kind := range []string{"limit", "counter-exhaustion"} {
		t.Run(kind, func(t *testing.T) {
			dir, p := testDirectory(t)
			initial := initialAnchor()
			if kind == "counter-exhaustion" {
				initial.NextSequence = math.MaxUint64
			}
			frame, err := anchorFrame(initial, [sha256.Size]byte{})
			if err != nil {
				t.Fatal(err)
			}
			data := bytes.Clone(frame)
			state, err := scanAnchors(data, initial)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "limit" {
				for i := 1; i < MaxAnchorRecords; i++ {
					next := state.head
					next.NextSequence++
					frame, err = anchorFrame(next, state.hash)
					if err != nil {
						t.Fatal(err)
					}
					data = append(data, frame...)
					state.head = next
					doc, err := encodeAnchor(next)
					if err != nil {
						t.Fatal(err)
					}
					state.hash = anchorHash(state.hash, doc)
				}
			}
			if err = os.WriteFile(filepath.Join(p, anchorName), data, 0600); err != nil {
				t.Fatal(err)
			}
			r, err := OpenAnchorStore(dir, initial, state.head)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = r.Close() }()
			if kind == "limit" {
				if head, err := r.CommitPublished(state.head, nil, testName, contracts.JournalCheckpointAuthority{}, testLimits()); !errors.Is(err, ErrFull) || head != (contracts.JournalCheckpointAnchor{}) {
					t.Fatal("capacity not enforced", err)
				}
				if !bytes.Equal(data, readFile(t, filepath.Join(p, anchorName))) {
					t.Fatal("capacity evicted evidence")
				}
			} else {
				next := state.head
				next.NextSequence = 1
				if anchorTransition(state.head, next) {
					t.Fatal("exhausted counter wrapped")
				}
			}
		})
	}
}

func TestAnchorParserStrictness(t *testing.T) {
	initial := initialAnchor()
	frame, err := anchorFrame(initial, [sha256.Size]byte{})
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < len(frame); n++ {
		if got, err := scanAnchors(frame[:n], initial); err == nil || got != (anchorState{}) {
			t.Fatalf("partial record accepted at %d", n)
		}
	}
	doc, err := encodeAnchor(initial)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{nil, append(bytes.Clone(doc), '\n'), bytes.Replace(doc, []byte(`"schema":`), []byte(`"extra":0,"schema":`), 1), bytes.Replace(doc, []byte(`"schema":`), []byte(`"schema":"other","schema":`), 1), bytes.Replace(doc, []byte(`"checkpoint_sequence":"1"`), []byte(`"checkpoint_sequence":"01"`), 1), []byte(`null`)} {
		if _, err := decodeAnchor(bad); err == nil {
			t.Fatal("noncanonical record accepted")
		}
	}
	bad := bytes.Clone(frame)
	binary.BigEndian.PutUint32(bad[:4], math.MaxUint32)
	if _, err := scanAnchors(bad, initial); err == nil {
		t.Fatal("hostile length accepted")
	}
	for _, change := range []func(*contracts.JournalCheckpointAnchor){func(a *contracts.JournalCheckpointAnchor) { a.NextSequence = 0 }, func(a *contracts.JournalCheckpointAnchor) { a.PreviousSHA256 = strings.Repeat("A", 64) }, func(a *contracts.JournalCheckpointAnchor) { a.Cursor.NextSequence = 0 }} {
		a := initial
		change(&a)
		if _, err := encodeAnchor(a); err == nil {
			t.Fatal("invalid anchor encoded")
		}
	}
}

func TestAnchorBootstrapFailureNeverReinitializes(t *testing.T) {
	for _, kind := range []string{"short", "write-error", "sync", "readback"} {
		t.Run(kind, func(t *testing.T) {
			dir, path := testDirectory(t)
			a, err := acquireAnchor(dir, initialAnchor(), true)
			if err != nil {
				t.Fatal(err)
			}
			file := a.file
			fault := &faultFile{segmentFile: file}
			a.file = fault
			switch kind {
			case "short":
				fault.write = func(b []byte) (int, error) { return file.Write(b[:len(b)/2]) }
			case "write-error":
				fault.write = func(b []byte) (int, error) { n, _ := file.Write(b); return n, unix.EIO }
			case "sync":
				fault.sync = func() error { return unix.ENOSPC }
			case "readback":
				fault.read = func([]byte, int64) (int, error) { return 0, unix.EIO }
			}
			if err = a.initialize(); !errors.Is(err, ErrCommitUncertain) {
				t.Fatal("failed bootstrap accepted", err)
			}
			if err = a.Close(); err != nil {
				t.Fatal(err)
			}
			before := readFile(t, filepath.Join(path, anchorName))
			if r, err := CreateAnchorStore(dir, initialAnchor()); err == nil || r != nil {
				t.Fatal("bootstrap retry overwrote evidence")
			}
			if !bytes.Equal(before, readFile(t, filepath.Join(path, anchorName))) {
				t.Fatal("bootstrap evidence changed")
			}
		})
	}
}

func TestAnchorChainCorruptionAndReordering(t *testing.T) {
	initial := initialAnchor()
	first, err := anchorFrame(initial, [sha256.Size]byte{})
	if err != nil {
		t.Fatal(err)
	}
	state, err := scanAnchors(first, initial)
	if err != nil {
		t.Fatal(err)
	}
	next := initial
	next.NextSequence++
	second, err := anchorFrame(next, state.hash)
	if err != nil {
		t.Fatal(err)
	}
	valid := append(bytes.Clone(first), second...)
	if got, err := scanAnchors(valid, initial); err != nil || got.head != next || got.count != 2 {
		t.Fatal("valid chain rejected", err)
	}
	badHash := bytes.Clone(valid)
	badHash[len(badHash)-1] ^= 1
	for _, bad := range [][]byte{append(bytes.Clone(second), first...), append(bytes.Clone(first), first...), second, badHash, append(valid, 0)} {
		if got, err := scanAnchors(bad, initial); err == nil || got != (anchorState{}) {
			t.Fatal("corrupt chain accepted")
		}
	}
	for _, change := range []func(*contracts.JournalCheckpointAnchor){func(a *contracts.JournalCheckpointAnchor) { a.NextSequence++ }, func(a *contracts.JournalCheckpointAnchor) { a.Cursor.Identity.Epoch = "other.epoch" }, func(a *contracts.JournalCheckpointAnchor) { a.Cursor.PreviousSHA256 = strings.Repeat("1", 64) }, func(a *contracts.JournalCheckpointAnchor) {
		a.Cursor.NextSequence += contracts.MaxJournalScanFrames + 1
	}} {
		altered := next
		change(&altered)
		frame, err := anchorFrame(altered, state.hash)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := scanAnchors(append(bytes.Clone(first), frame...), initial); err == nil || got != (anchorState{}) {
			t.Fatal("discontinuous anchor accepted")
		}
	}
}

func TestAnchorCanonicalChecksumVector(t *testing.T) {
	doc, err := encodeAnchor(initialAnchor())
	if err != nil {
		t.Fatal(err)
	}
	const expected = `{"schema":"syswarden.journal-anchor.v1","journal_id":"journal.fixture.1","identity":{"cluster_id":"cluster.fixture.1","node_id":"node.fixture.1","epoch":"generation.fixture.1"},"position":{"next_sequence":"1","previous_sha256":"0000000000000000000000000000000000000000000000000000000000000000"},"checkpoint_sequence":"1","checkpoint_sha256":"0000000000000000000000000000000000000000000000000000000000000000"}`
	if string(doc) != expected {
		t.Fatal("canonical format changed")
	}
	digest := anchorHash([sha256.Size]byte{}, doc)
	// Independently reproduced with Python hashlib using the documented format.
	if hex.EncodeToString(digest[:]) != "fc3310290c05ab3d01e7d7499430f8f16b11b0194d86f95fad3f7ba8835e4a85" {
		t.Fatal("checksum domain or format changed")
	}
}

func TestAnchorReadbackBindsEntirePriorChain(t *testing.T) {
	a, _, path := anchorFixture(t)
	dir, _, first, key := publishForAnchor(t, initialAnchor(), 0)
	if _, err := a.CommitPublished(initialAnchor(), dir, testName, key, testLimits()); err != nil {
		t.Fatal(err)
	}
	dir, _, second, key := publishForAnchor(t, first.Next, 0)
	root, err := anchorFrame(initialAnchor(), [sha256.Size]byte{})
	if err != nil {
		t.Fatal(err)
	}
	rootState, err := scanAnchors(root, initialAnchor())
	if err != nil {
		t.Fatal(err)
	}
	changed := first.Next
	changed.PreviousSHA256 = strings.Repeat("1", 64)
	middle, err := anchorFrame(changed, rootState.hash)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append(bytes.Clone(root), middle...)
	state, err := scanAnchors(tampered, initialAnchor())
	if err != nil {
		t.Fatal(err)
	}
	last, err := anchorFrame(second.Next, state.hash)
	if err != nil {
		t.Fatal(err)
	}
	tampered = append(tampered, last...)
	file := a.file
	a.file = &faultFile{segmentFile: file, write: func(b []byte) (int, error) {
		n, err := file.Write(b)
		if err != nil {
			return n, err
		}
		return n, os.WriteFile(filepath.Join(path, anchorName), tampered, 0600)
	}}
	if next, err := a.CommitPublished(first.Next, dir, testName, key, testLimits()); !errors.Is(err, ErrCommitUncertain) || next != (contracts.JournalCheckpointAnchor{}) {
		t.Fatal("rewritten prior chain accepted", err)
	}
	if !bytes.Equal(tampered, readFile(t, filepath.Join(path, anchorName))) {
		t.Fatal("failure repaired or deleted evidence")
	}
}

func TestAnchorAbruptProcessExit(t *testing.T) {
	if os.Getenv("SYSWARDEN_ANCHOR_EXIT_FIXTURE") == "1" {
		dir := os.NewFile(3, "synthetic-anchor-directory")
		a, err := OpenAnchorStore(dir, initialAnchor(), initialAnchor())
		if err != nil {
			t.Fatal(err)
		}
		next := initialAnchor()
		next.NextSequence++
		frame, err := anchorFrame(next, a.state.hash)
		if err != nil {
			t.Fatal(err)
		}
		if os.Getenv("SYSWARDEN_ANCHOR_PARTIAL") == "1" {
			frame = frame[:len(frame)/2]
		}
		if _, err = a.file.Write(frame); err != nil {
			t.Fatal(err)
		}
		os.Exit(0)
	}
	for _, partial := range []bool{false, true} {
		t.Run(strconv.FormatBool(partial), func(t *testing.T) {
			a, dir, path := anchorFixture(t)
			if err := a.Close(); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("/proc/self/exe", "-test.run=^TestAnchorAbruptProcessExit$")
			cmd.ExtraFiles = []*os.File{dir}
			cmd.Env = append(os.Environ(), "SYSWARDEN_ANCHOR_EXIT_FIXTURE=1")
			if partial {
				cmd.Env = append(cmd.Env, "SYSWARDEN_ANCHOR_PARTIAL=1")
			}
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatal(err, string(out))
			}
			before := readFile(t, filepath.Join(path, anchorName))
			if r, err := OpenAnchorStore(dir, initialAnchor(), initialAnchor()); err == nil || r != nil {
				t.Fatal("unacknowledged child tail adopted")
			}
			if !bytes.Equal(before, readFile(t, filepath.Join(path, anchorName))) {
				t.Fatal("failed open changed evidence")
			}
		})
	}
}

func FuzzAnchorLedger(f *testing.F) {
	frame, err := anchorFrame(initialAnchor(), [sha256.Size]byte{})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(frame)
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		state, err := scanAnchors(data, initialAnchor())
		if err != nil {
			if state != (anchorState{}) {
				t.Fatal("failure exposed partial authority")
			}
			return
		}
		if state.count < 1 || state.count > MaxAnchorRecords || state.bytes != len(data) {
			t.Fatal("unbounded ledger")
		}
		doc, err := encodeAnchor(state.head)
		if err != nil {
			t.Fatal(err)
		}
		if decoded, err := decodeAnchor(doc); err != nil || decoded != state.head {
			t.Fatal("anchor round trip", err)
		}
	})
}
