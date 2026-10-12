package journal

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
	contracts "syswarden-core/contracts/v5"
)

type recoveryFixture struct {
	anchor, journal         *os.File
	anchorPath, journalPath string
	expected, next          contracts.JournalCheckpointAnchor
	authority               contracts.JournalCheckpointAuthority
}

func interruptedAnchor(t *testing.T, count int, priorCommit bool, partial bool) recoveryFixture {
	t.Helper()
	a, dir, path := anchorFixture(t)
	expected := initialAnchor()
	if priorCommit {
		j, _, p, key := publishForAnchor(t, expected, 1)
		if _, err := a.CommitPublished(expected, j, testName, key, testLimits()); err != nil {
			t.Fatal(err)
		}
		expected = p.Next
	}
	j, jpath, pub, key := publishForAnchor(t, expected, count)
	file := a.file
	a.file = &faultFile{segmentFile: file, write: func(b []byte) (int, error) {
		if partial {
			b = b[:len(b)/2]
		}
		n, err := file.Write(b)
		return n, errors.Join(err, unix.EIO)
	}}
	if next, err := a.CommitPublished(expected, j, testName, key, testLimits()); !errors.Is(err, ErrCommitUncertain) || next != (contracts.JournalCheckpointAnchor{}) {
		t.Fatal("fixture was not uncertain", err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	return recoveryFixture{anchor: dir, journal: j, anchorPath: path, journalPath: jpath, expected: expected, next: pub.Next, authority: key}
}

func (f recoveryFixture) plan(t *testing.T) AnchorRecoveryPlan {
	t.Helper()
	p, err := PlanAnchorRecovery(f.anchor, f.journal, initialAnchor(), f.expected, testName, f.authority, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func (f recoveryFixture) apply(digest string) (contracts.JournalCheckpointAnchor, error) {
	return ApplyAnchorRecovery(f.anchor, f.journal, initialAnchor(), f.expected, testName, f.authority, testLimits(), digest)
}

func (f recoveryFixture) bytes(t *testing.T) [][]byte {
	t.Helper()
	_, final := checkpointNames(testName)
	return [][]byte{readFile(t, filepath.Join(f.anchorPath, anchorName)), readFile(t, filepath.Join(f.journalPath, testName)), readFile(t, filepath.Join(f.journalPath, final))}
}

func requireSameRecoveryBytes(t *testing.T, before, after [][]byte) {
	t.Helper()
	if len(before) != len(after) {
		t.Fatal("resource count changed")
	}
	for i := range before {
		if !bytes.Equal(before[i], after[i]) {
			t.Fatal("recovery rewrote stored bytes", i)
		}
	}
}

func TestReviewedRecoveryReadOnlyPlanAndExactApply(t *testing.T) {
	for _, prior := range []bool{false, true} {
		for _, count := range []int{0, 2} {
			t.Run(strconv.FormatBool(prior)+"/"+strconv.Itoa(count), func(t *testing.T) {
				f := interruptedAnchor(t, count, prior, false)
				before := f.bytes(t)
				plan := f.plan(t)
				var d recoveryDocument
				if err := json.Unmarshal(plan.Document, &d); err != nil {
					t.Fatal(err)
				}
				if d.Schema != anchorRecoverySchema || d.Operation != "resynchronize-complete-anchor" || d.AnchorSHA256 != recoveryDigest(before[0]) || d.SegmentSHA256 != recoveryDigest(before[1]) || d.CheckpointSHA256 != recoveryDigest(before[2]) {
					t.Fatal("incorrect plan binding")
				}
				candidate, err := decodeAnchor(d.Candidate)
				if err != nil || candidate != f.next {
					t.Fatal("incorrect candidate", err)
				}
				if plan.SHA256 != recoveryDigest(append([]byte(anchorRecoveryDomain), plan.Document...)) {
					t.Fatal("incorrect plan digest")
				}
				if len(plan.Document) > maxRecoveryPlanBytes {
					t.Fatal("unbounded plan")
				}
				again := f.plan(t)
				if !bytes.Equal(plan.Document, again.Document) || plan.SHA256 != again.SHA256 {
					t.Fatal("read-only inspection changed plan")
				}
				requireSameRecoveryBytes(t, before, f.bytes(t))
				if next, err := f.apply(plan.SHA256); err != nil || next != f.next {
					t.Fatal("authorized recovery failed", err)
				}
				// Repeating exactly the same resynchronization cannot append an anchor.
				if next, err := f.apply(plan.SHA256); err != nil || next != f.next {
					t.Fatal("idempotent resynchronization failed", err)
				}
				requireSameRecoveryBytes(t, before, f.bytes(t))
				resumed, err := OpenAnchorStore(f.anchor, initialAnchor(), f.next)
				if err != nil {
					t.Fatal(err)
				}
				j, _, pub, key := publishForAnchor(t, f.next, 1)
				if next, err := resumed.CommitPublished(f.next, j, testName, key, testLimits()); err != nil || next != pub.Next {
					t.Fatal("normal continuation failed", err)
				}
				if err = resumed.Close(); err != nil {
					t.Fatal(err)
				}
				if next, err := f.apply(plan.SHA256); err == nil || next != (contracts.JournalCheckpointAnchor{}) {
					t.Fatal("old plan accepted after later commit")
				}
			})
		}
	}
}

func TestRecoveryPlanOwnsBytesAndDoesNotAuthorize(t *testing.T) {
	f := interruptedAnchor(t, 1, false, false)
	plan := f.plan(t)
	original := bytes.Clone(plan.Document)
	plan.Document[0] ^= 1
	if !bytes.Equal(original, f.plan(t).Document) {
		t.Fatal("plan aliases state")
	}
	for _, bad := range []string{"", strings.Repeat("0", 63), strings.Repeat("g", 64), strings.ToUpper(plan.SHA256), " " + plan.SHA256, strings.Repeat("0", 64), recoveryDigest(plan.Document)} {
		if head, err := f.apply(bad); !errors.Is(err, ErrRecoveryApproval) || head != (contracts.JournalCheckpointAnchor{}) {
			t.Fatal("unreviewed digest accepted", err)
		}
	}
	if _, err := ApplyAnchorRecovery(nil, nil, initialAnchor(), initialAnchor(), testName, contracts.JournalCheckpointAuthority{}, testLimits(), ""); !errors.Is(err, ErrRecoveryApproval) {
		t.Fatal("missing approval reached storage", err)
	}
}

func TestRecoveryRefusesAmbiguousOrUnprovenTail(t *testing.T) {
	for _, kind := range []string{"partial", "corrupt", "two-extra", "no-extra", "wrong-initial", "wrong-expected", "wrong-candidate", "pending", "missing-checkpoint", "missing-segment", "signature", "foreign-key", "scope", "revoked", "unsafe-mode", "same-directory"} {
		t.Run(kind, func(t *testing.T) {
			f := interruptedAnchor(t, 1, false, kind == "partial")
			initial, expected := initialAnchor(), f.expected
			_, final := checkpointNames(testName)
			ledger := filepath.Join(f.anchorPath, anchorName)
			switch kind {
			case "corrupt":
				b := readFile(t, ledger)
				b[len(b)-1] ^= 1
				if err := os.WriteFile(ledger, b, 0600); err != nil {
					t.Fatal(err)
				}
			case "two-extra":
				b := readFile(t, ledger)
				state, err := scanAnchors(b, initial)
				if err != nil {
					t.Fatal(err)
				}
				next := state.head
				next.NextSequence++
				frame, err := anchorFrame(next, state.hash)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(ledger, append(b, frame...), 0600); err != nil {
					t.Fatal(err)
				}
			case "no-extra":
				expected = f.next
			case "wrong-initial":
				initial.Cursor.Identity.NodeID = "foreign.node"
			case "wrong-expected":
				expected.PreviousSHA256 = strings.Repeat("1", 64)
			case "wrong-candidate":
				root, err := anchorFrame(initial, [sha256.Size]byte{})
				if err != nil {
					t.Fatal(err)
				}
				state, err := scanAnchors(root, initial)
				if err != nil {
					t.Fatal(err)
				}
				next := f.next
				next.PreviousSHA256 = strings.Repeat("1", 64)
				frame, err := anchorFrame(next, state.hash)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(ledger, append(root, frame...), 0600); err != nil {
					t.Fatal(err)
				}
			case "pending":
				pending, _ := checkpointNames(testName)
				if err := os.WriteFile(filepath.Join(f.journalPath, pending), []byte("retained"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-checkpoint":
				if err := os.Remove(filepath.Join(f.journalPath, final)); err != nil {
					t.Fatal(err)
				}
			case "missing-segment":
				if err := os.Remove(filepath.Join(f.journalPath, testName)); err != nil {
					t.Fatal(err)
				}
			case "signature":
				p := filepath.Join(f.journalPath, final)
				b := readFile(t, p)
				b[len(b)-1] ^= 1
				if err := os.WriteFile(p, b, 0600); err != nil {
					t.Fatal(err)
				}
			case "scope":
				f.authority.Identity.Epoch = "foreign.epoch"
			case "foreign-key":
				f.authority.PublicKey = bytes.Repeat([]byte{0x21}, 32)
			case "revoked":
				f.authority.FirstSequence = 2
			case "unsafe-mode":
				if err := chmodFixture(ledger, 0644); err != nil {
					t.Fatal(err)
				}
			case "same-directory":
				f.journal = f.anchor
			}
			before := readFile(t, ledger)
			if plan, err := PlanAnchorRecovery(f.anchor, f.journal, initial, expected, testName, f.authority, testLimits()); err == nil || plan.Document != nil || plan.SHA256 != "" {
				t.Fatal("ineligible recovery planned")
			}
			if !bytes.Equal(before, readFile(t, ledger)) {
				t.Fatal("rejection rewrote ledger")
			}
		})
	}
}

func TestRecoveryApprovalBindsResourcesAndAuthority(t *testing.T) {
	for _, kind := range []string{"anchor-inode", "segment-inode", "checkpoint-inode", "authority-range", "limits", "copied-store", "later-tail", "corrupt-segment"} {
		t.Run(kind, func(t *testing.T) {
			f := interruptedAnchor(t, 1, false, false)
			plan := f.plan(t)
			limits := testLimits()
			switch kind {
			case "anchor-inode", "segment-inode", "checkpoint-inode":
				p := filepath.Join(f.anchorPath, anchorName)
				if kind == "segment-inode" {
					p = filepath.Join(f.journalPath, testName)
				}
				if kind == "checkpoint-inode" {
					_, name := checkpointNames(testName)
					p = filepath.Join(f.journalPath, name)
				}
				b := readFile(t, p)
				if err := os.Rename(p, p+".saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, b, 0600); err != nil {
					t.Fatal(err)
				}
			case "authority-range":
				f.authority.LastSequence++
			case "limits":
				limits.MaxFrames--
			case "copied-store":
				b := readFile(t, filepath.Join(f.anchorPath, anchorName))
				dir, path := testDirectory(t)
				if err := os.WriteFile(filepath.Join(path, anchorName), b, 0600); err != nil {
					t.Fatal(err)
				}
				f.anchor, f.anchorPath = dir, path
			case "later-tail":
				p := filepath.Join(f.anchorPath, anchorName)
				b := readFile(t, p)
				state, err := scanAnchors(b, initialAnchor())
				if err != nil {
					t.Fatal(err)
				}
				next := state.head
				next.NextSequence++
				frame, err := anchorFrame(next, state.hash)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(p, append(b, frame...), 0600); err != nil {
					t.Fatal(err)
				}
			case "corrupt-segment":
				p := filepath.Join(f.journalPath, testName)
				b := readFile(t, p)
				b[0] ^= 1
				if err := os.WriteFile(p, b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := f.bytes(t)
			next, err := ApplyAnchorRecovery(f.anchor, f.journal, initialAnchor(), f.expected, testName, f.authority, limits, plan.SHA256)
			if err == nil || next != (contracts.JournalCheckpointAnchor{}) {
				t.Fatal("changed plan accepted")
			}
			if kind != "later-tail" && kind != "corrupt-segment" && !errors.Is(err, ErrRecoveryApproval) {
				t.Fatal("valid changed resource did not invalidate approval", err)
			}
			requireSameRecoveryBytes(t, before, f.bytes(t))
		})
	}
}

func TestRecoveryReadOnlyDescriptorsAndSynchronizationOrder(t *testing.T) {
	f := interruptedAnchor(t, 1, false, false)
	r, plan, err := openRecovery(f.anchor, f.journal, initialAnchor(), f.expected, testName, f.authority, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range []segmentFile{r.anchor.file, r.segment.file} {
		flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
		if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY {
			t.Fatal("inspection acquired writable descriptor", err)
		}
	}
	if second, err := OpenAnchorStore(f.anchor, initialAnchor(), f.next); !errors.Is(err, ErrLocked) || second != nil {
		t.Fatal("authority lock missing", err)
	}
	if second, err := OpenPublishedSegment(f.journal, testName, contracts.JournalCheckpointContext{Anchor: f.expected, Authority: f.authority}, testLimits()); !errors.Is(err, ErrLocked) || second != nil {
		t.Fatal("journal lock missing", err)
	}
	var order []string
	ops := recoverySyncOps{
		publication: func(c contracts.JournalCheckpointContext) (contracts.JournalCheckpointAnchor, error) {
			order = append(order, "publication")
			return r.segment.synchronizePublication(c)
		},
		anchor:    func() error { order = append(order, "anchor"); return r.anchor.file.Sync() },
		directory: func() error { order = append(order, "directory"); return r.anchor.directory.Sync() },
	}
	if next, err := r.apply(plan.SHA256, ops); err != nil || next != f.next {
		t.Fatal(err)
	}
	if strings.Join(order, ",") != "publication,anchor,directory" {
		t.Fatal("unsafe synchronization order", order)
	}
}

func TestRecoveryFailuresReturnNoAnchorAndPreserveBytes(t *testing.T) {
	for _, kind := range []string{"publication-sync", "anchor-sync", "directory-sync", "wrong-next", "anchor-close", "segment-close", "changed-after-sync", "readback"} {
		t.Run(kind, func(t *testing.T) {
			f := interruptedAnchor(t, 1, false, false)
			before := f.bytes(t)
			r, plan, err := openRecovery(f.anchor, f.journal, initialAnchor(), f.expected, testName, f.authority, testLimits())
			if err != nil {
				t.Fatal(err)
			}
			afile, sfile := r.anchor.file, r.segment.file
			if kind == "anchor-close" {
				r.anchor.file = &faultFile{segmentFile: afile, close: func() error { return errors.Join(afile.Close(), unix.EIO) }}
			}
			if kind == "segment-close" {
				r.segment.file = &faultFile{segmentFile: sfile, close: func() error { return errors.Join(sfile.Close(), unix.EIO) }}
			}
			op := recoverySyncOps{publication: r.segment.synchronizePublication, anchor: r.anchor.file.Sync, directory: r.anchor.directory.Sync}
			switch kind {
			case "publication-sync":
				op.publication = func(contracts.JournalCheckpointContext) (contracts.JournalCheckpointAnchor, error) {
					return contracts.JournalCheckpointAnchor{}, unix.EIO
				}
			case "anchor-sync":
				op.anchor = func() error { return unix.EIO }
			case "directory-sync":
				op.directory = func() error { return unix.ENOSPC }
			case "wrong-next":
				op.publication = func(contracts.JournalCheckpointContext) (contracts.JournalCheckpointAnchor, error) {
					return f.expected, nil
				}
			case "changed-after-sync":
				op.directory = func() error {
					path := filepath.Join(f.anchorPath, anchorName)
					if err := os.Rename(path, path+".saved"); err != nil {
						return err
					}
					return os.WriteFile(path, before[0], 0600)
				}
			case "readback":
				op.directory = func() error {
					r.anchor.file = &faultFile{segmentFile: afile, read: func([]byte, int64) (int, error) { return 0, unix.EIO }}
					return nil
				}
			}
			if next, err := r.apply(plan.SHA256, op); !errors.Is(err, ErrCommitUncertain) || next != (contracts.JournalCheckpointAnchor{}) {
				t.Fatal("failed recovery acknowledged", err)
			}
			requireSameRecoveryBytes(t, before, f.bytes(t))
			// Failed recovery closes both locks; it never leaks a usable authority.
			if r.anchor.file != nil || r.segment.file != nil {
				t.Fatal("failed recovery leaked handle")
			}
		})
	}
}

func TestConcurrentRecoveryDoesNotAppend(t *testing.T) {
	f := interruptedAnchor(t, 1, false, false)
	plan := f.plan(t)
	before := f.bytes(t)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			next, err := f.apply(plan.SHA256)
			if err == nil && next != f.next {
				t.Error("wrong recovered head")
			}
			results <- err
		})
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else if !errors.Is(err, ErrLocked) {
			t.Fatal(err)
		}
	}
	if success < 1 {
		t.Fatal("no recovery succeeded")
	}
	requireSameRecoveryBytes(t, before, f.bytes(t))
}

func FuzzAnchorRecoveryTail(f *testing.F) {
	initial := initialAnchor()
	first, err := anchorFrame(initial, [sha256.Size]byte{})
	if err != nil {
		f.Fatal(err)
	}
	state, err := scanAnchors(first, initial)
	if err != nil {
		f.Fatal(err)
	}
	next := initial
	next.NextSequence++
	second, err := anchorFrame(next, state.hash)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(append(bytes.Clone(first), second...))
	f.Add(first)
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		state, err := inspectRecoveryTail(b, initial, initial)
		if err != nil {
			if state != (anchorState{}) {
				t.Fatal("partial recovery authority exposed")
			}
			return
		}
		if state.count != 2 || state.head.NextSequence != 2 || state.bytes != len(b) {
			t.Fatal("unbounded or discontinuous recovery tail")
		}
	})
}
