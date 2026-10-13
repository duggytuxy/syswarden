package journal

import (
	"bytes"
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

// This synthetic state-machine double is deliberately test-only. Its memory is
// not persistent, independent restart custody or a deployable authority service.
type testCustody struct {
	mu                                               sync.Mutex
	state                                            RestartState
	fault, approved                                  string
	stages                                           []string
	hook                                             func(string)
	loads, preparations, finishes, approvals, closes int
}

func (b *testCustody) stage(name string) error {
	b.stages = append(b.stages, name)
	if b.hook != nil {
		b.hook(name)
	}
	if name == b.fault {
		return unix.EIO
	}
	return nil
}

func (b *testCustody) Acquire() (RestartLease, error) {
	if !b.mu.TryLock() {
		return nil, ErrLocked
	}
	if err := b.stage("acquire"); err != nil {
		b.mu.Unlock()
		return nil, err
	}
	return b, nil
}
func (b *testCustody) State() (RestartState, error) {
	b.loads++
	if err := b.stage("state"); err != nil {
		return RestartState{}, err
	}
	s := b.state
	s.Authority.PublicKey = bytes.Clone(s.Authority.PublicKey)
	return s, nil
}
func (b *testCustody) Prepare(p CustodyIntent) error {
	b.preparations++
	if err := b.stage("prepare-before"); err != nil {
		return err
	}
	if b.state.Pending != (CustodyIntent{}) || b.state.Head != p.Before {
		return ErrCustodyState
	}
	b.state.Pending = p
	return b.stage("prepare-after")
}
func (b *testCustody) Finish(p CustodyIntent) error {
	b.finishes++
	if err := b.stage("finish-before"); err != nil {
		return err
	}
	if b.state.Pending != p || b.state.Head != p.Before {
		return ErrCustodyState
	}
	b.state.Head, b.state.Pending = p.After, CustodyIntent{}
	return b.stage("finish-after")
}
func (b *testCustody) AuthorizeRecovery(digest string) error {
	b.approvals++
	if err := b.stage("authorize"); err != nil {
		return err
	}
	if digest != b.approved {
		return ErrRecoveryApproval
	}
	return nil
}
func (b *testCustody) Close() error {
	b.closes++
	err := b.stage("close")
	b.mu.Unlock()
	return err
}

func custodyFixture(t *testing.T, count int) (recoveryFixture, *testCustody) {
	t.Helper()
	a, dir, path := anchorFixture(t)
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	j, jpath, p, key := publishForAnchor(t, initialAnchor(), count)
	f := recoveryFixture{anchor: dir, journal: j, anchorPath: path, journalPath: jpath, expected: initialAnchor(), next: p.Next, authority: key}
	b := &testCustody{state: RestartState{Initial: initialAnchor(), Head: initialAnchor(), Authority: key}}
	return f, b
}
func custodyCommit(f recoveryFixture, b RestartCustody) (contracts.JournalCheckpointAnchor, error) {
	return CommitCustodiedPublication(b, f.anchor, f.journal, testName, testLimits())
}
func requireNoCustodyResult(t *testing.T, a contracts.JournalCheckpointAnchor, err error) {
	t.Helper()
	if err == nil || a != (contracts.JournalCheckpointAnchor{}) {
		t.Fatal("failure exposed a result", a, err)
	}
}

func TestCustodyCommitResumeAndReplay(t *testing.T) {
	for _, count := range []int{0, 2} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			f, b := custodyFixture(t, count)
			before := f.bytes(t)
			b.hook = func(stage string) {
				switch stage {
				case "prepare-before", "prepare-after":
					if !bytes.Equal(before[0], readFile(t, filepath.Join(f.anchorPath, anchorName))) {
						t.Fatal("local append preceded prepared custody")
					}
				case "finish-before":
					// The local commit is complete and descriptors are closed before
					// custody may finish. Both independent locks must be available.
					a, err := OpenAnchorStore(f.anchor, initialAnchor(), f.next)
					if err != nil {
						t.Fatal("finish preceded verified local closure", err)
					}
					if err = a.Close(); err != nil {
						t.Fatal(err)
					}
					s, err := OpenPublishedSegment(f.journal, testName, contracts.JournalCheckpointContext{Anchor: f.expected, Authority: f.authority}, testLimits())
					if err != nil {
						t.Fatal("journal still locked", err)
					}
					if err = s.Close(); err != nil {
						t.Fatal(err)
					}
				}
			}
			next, err := custodyCommit(f, b)
			if err != nil || next != f.next || b.state.Head != next || b.state.Pending != (CustodyIntent{}) {
				t.Fatal("commit failed", err)
			}
			if b.preparations != 1 || b.finishes != 1 || b.closes != 1 {
				t.Fatal("incorrect transaction count")
			}
			b.hook = nil
			if got, err := ResumeCustodiedAnchor(b, f.anchor); err != nil || got != next {
				t.Fatal("resume failed", err)
			}
			committed := f.bytes(t)
			got, err := custodyCommit(f, b)
			requireNoCustodyResult(t, got, err)
			requireSameRecoveryBytes(t, committed, f.bytes(t))
			if !bytes.Equal(before[1], committed[1]) || !bytes.Equal(before[2], committed[2]) {
				t.Fatal("publication changed")
			}
		})
	}
}

func TestCustodyFailureIntervals(t *testing.T) {
	for _, fault := range []string{"acquire", "state", "prepare-before", "prepare-after", "finish-before", "finish-after", "close"} {
		t.Run(fault, func(t *testing.T) {
			f, b := custodyFixture(t, 1)
			before := f.bytes(t)
			b.fault = fault
			next, err := custodyCommit(f, b)
			requireNoCustodyResult(t, next, err)
			if b.finishes > 1 || b.preparations > 1 {
				t.Fatal("automatic retry")
			}
			b.fault = ""
			switch fault {
			case "acquire", "state", "prepare-before":
				requireSameRecoveryBytes(t, before, f.bytes(t))
				if b.state.Pending != (CustodyIntent{}) || b.state.Head != f.expected {
					t.Fatal("unexpected state")
				}
			case "prepare-after":
				requireSameRecoveryBytes(t, before, f.bytes(t))
				if b.state.Pending == (CustodyIntent{}) {
					t.Fatal("lost prepared intent")
				}
				if _, err = PlanCustodiedRecovery(b, f.anchor, f.journal); err == nil {
					t.Fatal("no-append intent treated as complete")
				}
				got, e := ResumeCustodiedAnchor(b, f.anchor)
				requireNoCustodyResult(t, got, e)
			case "finish-before":
				if b.state.Pending == (CustodyIntent{}) || b.state.Head != f.expected {
					t.Fatal("lost pending local commit")
				}
				got, e := ResumeCustodiedAnchor(b, f.anchor)
				requireNoCustodyResult(t, got, e)
				if _, err = PlanCustodiedRecovery(b, f.anchor, f.journal); err != nil {
					t.Fatal("complete pending commit not inspectable", err)
				}
			case "finish-after", "close":
				if b.state.Pending != (CustodyIntent{}) || b.state.Head != f.next {
					t.Fatal("lost final durable state")
				}
				if got, e := ResumeCustodiedAnchor(b, f.anchor); e != nil || got != f.next {
					t.Fatal("independent completed state not resumable", e)
				}
			}
		})
	}
}

func TestCustodyReadbackNeverTrustsMethodSuccess(t *testing.T) {
	for _, phase := range []string{"prepared", "finished", "initial", "key"} {
		t.Run(phase, func(t *testing.T) {
			f, b := custodyFixture(t, 1)
			before := f.bytes(t)
			b.hook = func(stage string) {
				if stage == "prepare-after" {
					switch phase {
					case "prepared":
						b.state.Pending = CustodyIntent{}
					case "initial":
						b.state.Initial.Cursor.Identity.NodeID = "node.other"
					case "key":
						b.state.Authority.PublicKey = bytes.Repeat([]byte{1}, 32)
					}
				}
				if phase == "finished" && stage == "finish-after" {
					b.state.Head = f.expected
				}
			}
			next, err := custodyCommit(f, b)
			requireNoCustodyResult(t, next, err)
			if !errors.Is(err, ErrCustodyState) {
				t.Fatal(err)
			}
			if phase != "finished" {
				requireSameRecoveryBytes(t, before, f.bytes(t))
				if b.finishes != 0 {
					t.Fatal("finished unverified state")
				}
			}
		})
	}
}

func TestCustodyLocalFailuresRetainIntent(t *testing.T) {
	for _, fault := range []string{"partial", "complete-write-error", "sync", "close"} {
		t.Run(fault, func(t *testing.T) {
			f, b := custodyFixture(t, 1)
			opener := func(d *os.File, i, h contracts.JournalCheckpointAnchor) (*AnchorStore, error) {
				a, err := OpenAnchorStore(d, i, h)
				if err != nil {
					return nil, err
				}
				file := a.file
				wrapped := &faultFile{segmentFile: file}
				switch fault {
				case "partial", "complete-write-error":
					wrapped.write = func(data []byte) (int, error) {
						if fault == "partial" {
							data = data[:len(data)/2]
						}
						n, e := file.Write(data)
						return n, errors.Join(e, unix.EIO)
					}
				case "sync":
					wrapped.sync = func() error { return unix.EIO }
				case "close":
					wrapped.close = func() error { return errors.Join(file.Close(), unix.EIO) }
				}
				a.file = wrapped
				return a, nil
			}
			next, err := withCustody(b, func(c *custodySession) (contracts.JournalCheckpointAnchor, error) {
				return c.commit(f.anchor, f.journal, testName, testLimits(), opener)
			})
			requireNoCustodyResult(t, next, err)
			if b.finishes != 0 || b.state.Pending == (CustodyIntent{}) || b.state.Head != f.expected {
				t.Fatal("local error lost pending state")
			}
			got, e := ResumeCustodiedAnchor(b, f.anchor)
			requireNoCustodyResult(t, got, e)
			_, e = PlanCustodiedRecovery(b, f.anchor, f.journal)
			if fault == "partial" && e == nil {
				t.Fatal("partial local tail eligible")
			}
			if fault != "partial" && e != nil {
				t.Fatal("complete tail not inspectable", e)
			}
		})
	}
}

func completePendingCustody(t *testing.T) (recoveryFixture, *testCustody, AnchorRecoveryPlan) {
	t.Helper()
	f, b := custodyFixture(t, 2)
	b.fault = "finish-before"
	next, err := custodyCommit(f, b)
	requireNoCustodyResult(t, next, err)
	b.fault = ""
	plan, err := PlanCustodiedRecovery(b, f.anchor, f.journal)
	if err != nil {
		t.Fatal(err)
	}
	return f, b, plan
}

func TestCustodyRecoveryRequiresIndependentApproval(t *testing.T) {
	f, b, p := completePendingCustody(t)
	before := f.bytes(t)
	for _, digest := range []string{"", strings.ToUpper(p.SHA256), strings.Repeat("0", 64), p.SHA256} {
		next, err := ApplyCustodiedRecovery(b, f.anchor, f.journal, digest)
		requireNoCustodyResult(t, next, err)
		requireSameRecoveryBytes(t, before, f.bytes(t))
		if b.state.Head != f.expected || b.state.Pending == (CustodyIntent{}) {
			t.Fatal("unapproved recovery changed custody")
		}
	}
	if b.approvals != 1 {
		t.Fatal("authorizer called without exact plan")
	}
	b.approved = p.SHA256
	next, err := ApplyCustodiedRecovery(b, f.anchor, f.journal, p.SHA256)
	if err != nil || next != f.next || b.state.Head != next || b.state.Pending != (CustodyIntent{}) {
		t.Fatal("approved recovery failed", err)
	}
	requireSameRecoveryBytes(t, before, f.bytes(t))
	next, err = ApplyCustodiedRecovery(b, f.anchor, f.journal, p.SHA256)
	requireNoCustodyResult(t, next, err)
	if b.approvals != 2 {
		t.Fatal("replay reached authorizer")
	}
	if got, e := ResumeCustodiedAnchor(b, f.anchor); e != nil || got != f.next {
		t.Fatal("recovered custody not resumable", e)
	}
}

func TestCustodyRecoveryFailuresAndStateChanges(t *testing.T) {
	for _, fault := range []string{"authorize", "finish-before", "finish-after", "close", "authority-change", "intent-change", "byte-change"} {
		t.Run(fault, func(t *testing.T) {
			f, b, p := completePendingCustody(t)
			b.approved = p.SHA256
			b.fault = fault
			before := f.bytes(t)
			b.hook = func(stage string) {
				if stage == "authorize" {
					switch fault {
					case "authority-change":
						b.state.Authority.LastSequence--
					case "intent-change":
						b.state.Pending.SegmentSHA256 = strings.Repeat("0", 64)
					case "byte-change":
						data := bytes.Clone(before[1])
						data[len(data)-1] ^= 1
						if err := os.WriteFile(filepath.Join(f.journalPath, testName), data, 0600); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			next, err := ApplyCustodiedRecovery(b, f.anchor, f.journal, p.SHA256)
			requireNoCustodyResult(t, next, err)
			if fault != "byte-change" {
				requireSameRecoveryBytes(t, before, f.bytes(t))
			}
			if fault == "finish-after" || fault == "close" {
				if b.state.Head != f.next {
					t.Fatal("completed custody lost")
				}
			} else if b.state.Head != f.expected {
				t.Fatal("failed recovery advanced")
			}
		})
	}
}

func TestCustodyPendingBindingAndMalformedState(t *testing.T) {
	mutators := map[string]func(*RestartState){
		"head":                  func(s *RestartState) { s.Head.NextSequence = 0 },
		"initial":               func(s *RestartState) { s.Initial.Cursor.Identity.NodeID = "node.other" },
		"key-size":              func(s *RestartState) { s.Authority.PublicKey = make([]byte, 33) },
		"key-scope":             func(s *RestartState) { s.Authority.JournalID = "journal.other" },
		"range":                 func(s *RestartState) { s.Authority.FirstSequence = 0 },
		"name":                  func(s *RestartState) { s.Pending.SegmentName = "../segment" },
		"budget":                func(s *RestartState) { s.Pending.Limits.MaxBytes = 0 },
		"before":                func(s *RestartState) { s.Pending.Before.NextSequence++ },
		"after":                 func(s *RestartState) { s.Pending.After.NextSequence++ },
		"digest-format":         func(s *RestartState) { s.Pending.CheckpointSHA256 = "bad" },
		"different-publication": func(s *RestartState) { s.Pending.CheckpointSHA256 = strings.Repeat("0", 64) },
		"different-segment":     func(s *RestartState) { s.Pending.SegmentSHA256 = strings.Repeat("0", 64) },
		"different-key":         func(s *RestartState) { s.Pending.PublicKeySHA256 = strings.Repeat("0", 64) },
	}
	for name, mutate := range mutators {
		t.Run(name, func(t *testing.T) {
			f, b, _ := completePendingCustody(t)
			before := f.bytes(t)
			mutate(&b.state)
			p, err := PlanCustodiedRecovery(b, f.anchor, f.journal)
			if err == nil || len(p.Document) != 0 || p.SHA256 != "" {
				t.Fatal("invalid state produced plan", err)
			}
			requireSameRecoveryBytes(t, before, f.bytes(t))
		})
	}
}

func TestCustodyConcurrencyAndPendingExclusion(t *testing.T) {
	f, b := custodyFixture(t, 1)
	entered, release := make(chan struct{}), make(chan struct{})
	b.hook = func(stage string) {
		if stage == "prepare-after" {
			close(entered)
			<-release
		}
	}
	done := make(chan error, 1)
	go func() { _, err := custodyCommit(f, b); done <- err }()
	<-entered
	next, err := custodyCommit(f, b)
	requireNoCustodyResult(t, next, err)
	if !errors.Is(err, ErrLocked) {
		t.Fatal(err)
	}
	next, err = ResumeCustodiedAnchor(b, f.anchor)
	requireNoCustodyResult(t, next, err)
	close(release)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if b.preparations != 1 || b.finishes != 1 {
		t.Fatal("multiple transitions")
	}
	f, b, _ = completePendingCustody(t)
	before := f.bytes(t)
	next, err = custodyCommit(f, b)
	requireNoCustodyResult(t, next, err)
	if !errors.Is(err, ErrCustodyPending) {
		t.Fatal(err)
	}
	requireSameRecoveryBytes(t, before, f.bytes(t))
}

func TestCustodyRejectsChangedPublicationAfterPrepare(t *testing.T) {
	f, b := custodyFixture(t, 1)
	before := f.bytes(t)
	b.hook = func(stage string) {
		if stage == "prepare-after" {
			data := bytes.Clone(before[1])
			data[len(data)-1] ^= 1
			if err := os.WriteFile(filepath.Join(f.journalPath, testName), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	next, err := custodyCommit(f, b)
	requireNoCustodyResult(t, next, err)
	if b.state.Pending == (CustodyIntent{}) || b.finishes != 0 {
		t.Fatal("changed publication advanced")
	}
	if !bytes.Equal(before[0], readFile(t, filepath.Join(f.anchorPath, anchorName))) {
		t.Fatal("changed publication appended")
	}
}

func TestCustodyNilAndScopeMismatch(t *testing.T) {
	f, b := custodyFixture(t, 1)
	next, err := custodyCommit(f, nil)
	requireNoCustodyResult(t, next, err)
	b.state.Head.Cursor.Identity.NodeID = "node.other"
	next, err = custodyCommit(f, b)
	requireNoCustodyResult(t, next, err)
	if b.preparations != 0 || b.closes != 1 {
		t.Fatal("invalid state acquired write authority")
	}
}

func TestCustodyPreflightPreservesStableState(t *testing.T) {
	for _, kind := range []string{"wrong-key", "wrong-head", "missing-anchor", "pending-publication", "byte-budget", "frame-budget", "anchor-locked", "journal-locked"} {
		t.Run(kind, func(t *testing.T) {
			f, b := custodyFixture(t, 2)
			before := f.bytes(t)
			limits := testLimits()
			switch kind {
			case "wrong-key":
				b.state.Authority.PublicKey = bytes.Repeat([]byte{2}, 32)
			case "wrong-head":
				b.state.Head = f.next
			case "missing-anchor":
				if err := os.Rename(filepath.Join(f.anchorPath, anchorName), filepath.Join(f.anchorPath, "retained")); err != nil {
					t.Fatal(err)
				}
			case "pending-publication":
				name, _ := checkpointNames(testName)
				if err := os.WriteFile(filepath.Join(f.journalPath, name), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "byte-budget":
				limits.MaxBytes = 1
			case "frame-budget":
				limits.MaxFrames = 1
			case "anchor-locked":
				a, err := OpenAnchorStore(f.anchor, initialAnchor(), initialAnchor())
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = a.Close() }()
			case "journal-locked":
				s, err := OpenPublishedSegment(f.journal, testName, contracts.JournalCheckpointContext{Anchor: f.expected, Authority: f.authority}, limits)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = s.Close() }()
			}
			next, err := CommitCustodiedPublication(b, f.anchor, f.journal, testName, limits)
			requireNoCustodyResult(t, next, err)
			if b.preparations != 0 || b.finishes != 0 || b.state.Pending != (CustodyIntent{}) || b.closes != 1 {
				t.Fatal("preflight acquired transition authority")
			}
			if kind != "missing-anchor" {
				requireSameRecoveryBytes(t, before, f.bytes(t))
			}
		})
	}
}

func TestCustodyStateReadErrorsAtEveryBoundary(t *testing.T) {
	// Initial read, pre-prepare compare, prepared readback, pre-finish compare,
	// and completed readback must all independently fail closed.
	for failAt := 1; failAt <= 5; failAt++ {
		t.Run(strconv.Itoa(failAt), func(t *testing.T) {
			f, b := custodyFixture(t, 1)
			b.hook = func(stage string) {
				if stage == "state" && b.loads == failAt {
					b.fault = "state"
				}
			}
			next, err := custodyCommit(f, b)
			requireNoCustodyResult(t, next, err)
			if b.loads != failAt || b.closes != 1 {
				t.Fatal("boundary was skipped or retried")
			}
			if failAt <= 3 && b.finishes != 0 {
				t.Fatal("finished before local commit")
			}
			if failAt == 4 && b.state.Pending == (CustodyIntent{}) {
				t.Fatal("lost pending local transition")
			}
			if failAt == 5 && b.state.Head != f.next {
				t.Fatal("lost independently completed transition")
			}
		})
	}
}

func TestCustodyPlanCloseErrorReturnsNoPlan(t *testing.T) {
	f, b, _ := completePendingCustody(t)
	b.fault = "close"
	p, err := PlanCustodiedRecovery(b, f.anchor, f.journal)
	if err == nil || len(p.Document) != 0 || p.SHA256 != "" {
		t.Fatal("close error exposed plan")
	}
}
