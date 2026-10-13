package journal

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
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

func testEnrollment() CustodyEnrollment {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	a := initialAnchor()
	return CustodyEnrollment{Initial: a, Authority: contracts.JournalCheckpointAuthority{JournalID: a.Cursor.JournalID, Identity: a.Cursor.Identity, KeyID: "key.fixture.1", PublicKey: key.Public().(ed25519.PublicKey), FirstSequence: 1, LastSequence: 10}}
}
func syntheticIntent() CustodyIntent {
	e := testEnrollment()
	next := e.Initial
	next.NextSequence++
	return CustodyIntent{Before: e.Initial, After: next, SegmentName: testName, SegmentSHA256: strings.Repeat("a", 64), CheckpointSHA256: strings.Repeat("b", 64), Limits: testLimits(), KeyID: e.Authority.KeyID, PublicKeySHA256: recoveryDigest(e.Authority.PublicKey), FirstSequence: 1, LastSequence: 10}
}
func localCustodyFixture(t *testing.T, auth CustodyRecoveryAuthorizer) (*LocalCustody, *os.File, string) {
	t.Helper()
	dir, path := testDirectory(t)
	if err := BootstrapLocalCustody(dir, testEnrollment()); err != nil {
		t.Fatal(err)
	}
	b, err := OpenLocalCustody(dir, testEnrollment(), auth)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b, dir, path
}
func localLease(t *testing.T, b *LocalCustody) *fileCustodyLease {
	t.Helper()
	lease, err := b.Acquire()
	if err != nil {
		t.Fatal(err)
	}
	l := lease.(*fileCustodyLease)
	t.Cleanup(func() { _ = l.Close() })
	return l
}
func custodyState(t *testing.T, l RestartLease) RestartState {
	t.Helper()
	s, err := l.State()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

type testRecoveryAuthorizer struct {
	calls    int
	request  CustodyRecoveryRequest
	decision string
	err      error
}

func (a *testRecoveryAuthorizer) AuthorizeCustodyRecovery(r CustodyRecoveryRequest) (string, error) {
	a.calls++
	a.request = r
	return a.decision, a.err
}

func TestLocalCustodyPersistsTransitionsAndOwnedState(t *testing.T) {
	b, dir, path := localCustodyFixture(t, nil)
	l := localLease(t, b)
	root := custodyState(t, l)
	copyKey := custodyState(t, l)
	copyKey.Authority.PublicKey[0] ^= 1
	if !sameRestartState(root, custodyState(t, l)) {
		t.Fatal("state key alias escaped")
	}
	intent := syntheticIntent()
	if err := l.Prepare(intent); err != nil {
		t.Fatal(err)
	}
	pending := custodyState(t, l)
	if pending.Head != intent.Before || pending.Pending != intent {
		t.Fatal("pending transition lost")
	}
	before := readFile(t, filepath.Join(path, custodyFileName))
	if err := l.Prepare(intent); !errors.Is(err, ErrCustodyState) {
		t.Fatal("duplicate prepare", err)
	}
	wrong := intent
	wrong.CheckpointSHA256 = strings.Repeat("c", 64)
	if err := l.Finish(wrong); !errors.Is(err, ErrCustodyState) {
		t.Fatal("wrong finish", err)
	}
	if !bytes.Equal(before, readFile(t, filepath.Join(path, custodyFileName))) {
		t.Fatal("rejection wrote ledger")
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenLocalCustody(dir, testEnrollment(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	l = localLease(t, reopened)
	if !sameRestartState(pending, custodyState(t, l)) {
		t.Fatal("restart forgot pending")
	}
	if err = l.Finish(intent); err != nil {
		t.Fatal(err)
	}
	final := custodyState(t, l)
	if final.Head != intent.After || final.Pending != (CustodyIntent{}) {
		t.Fatal("finish not durable")
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	if got := custodyState(t, localLease(t, reopened)); !sameRestartState(got, final) {
		t.Fatal("restart forgot completed state")
	}
	if !bytes.HasPrefix(readFile(t, filepath.Join(path, custodyFileName)), before) {
		t.Fatal("old records changed")
	}
}

func TestLocalCustodyCoordinatorAndRecovery(t *testing.T) {
	for _, count := range []int{0, 2} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			f, _ := custodyFixture(t, count)
			b, _, _ := localCustodyFixture(t, nil)
			got, err := custodyCommit(f, b)
			if err != nil || got != f.next {
				t.Fatal("real backend commit", err)
			}
			got, err = ResumeCustodiedAnchor(b, f.anchor)
			if err != nil || got != f.next {
				t.Fatal("real backend resume", err)
			}
		})
	}
	f := interruptedAnchor(t, 2, false, false)
	auth := &testRecoveryAuthorizer{decision: strings.Repeat("d", 64)}
	b, _, path := localCustodyFixture(t, auth)
	l := localLease(t, b)
	s, err := OpenPublishedSegment(f.journal, testName, contracts.JournalCheckpointContext{Anchor: f.expected, Authority: f.authority}, testLimits())
	if err != nil {
		t.Fatal(err)
	}
	intent, err := publicationIntent(s, contracts.JournalCheckpointContext{Anchor: f.expected, Authority: f.authority})
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if err = l.Prepare(intent); err != nil {
		t.Fatal(err)
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	plan, err := PlanCustodiedRecovery(b, f.anchor, f.journal)
	if err != nil {
		t.Fatal(err)
	}
	before := f.bytes(t)
	next, err := ApplyCustodiedRecovery(b, f.anchor, f.journal, plan.SHA256)
	if err != nil || next != f.next || auth.calls != 1 || auth.request.Intent != intent || auth.request.PlanSHA256 != plan.SHA256 {
		t.Fatal("audited recovery", err)
	}
	requireSameRecoveryBytes(t, before, f.bytes(t))
	root, _ := custodyEnrollment(testEnrollment())
	tip, err := scanCustody(readFile(t, filepath.Join(path, custodyFileName)), root)
	if err != nil || tip.count != 4 || tip.state.Head != f.next {
		t.Fatal("approval not retained", err)
	}
	data := readFile(t, filepath.Join(path, custodyFileName))
	if !bytes.Contains(data, []byte(plan.SHA256)) || !bytes.Contains(data, []byte(auth.decision)) {
		t.Fatal("missing audit binding")
	}
	next, err = ApplyCustodiedRecovery(b, f.anchor, f.journal, plan.SHA256)
	requireNoCustodyResult(t, next, err)
	if auth.calls != 1 {
		t.Fatal("replayed approval reached authorizer")
	}
}

func TestLocalCustodyRecoveryDeniesWithoutAudit(t *testing.T) {
	for _, kind := range []string{"nil", "denied", "bad-receipt", "malformed-plan", "no-pending"} {
		t.Run(kind, func(t *testing.T) {
			auth := &testRecoveryAuthorizer{decision: strings.Repeat("d", 64)}
			var configured CustodyRecoveryAuthorizer = auth
			if kind == "nil" {
				configured = nil
			}
			if kind == "denied" {
				auth.err = ErrRecoveryApproval
			}
			if kind == "bad-receipt" {
				auth.decision = ""
			}
			b, _, path := localCustodyFixture(t, configured)
			l := localLease(t, b)
			if kind != "no-pending" {
				if err := l.Prepare(syntheticIntent()); err != nil {
					t.Fatal(err)
				}
			}
			before := readFile(t, filepath.Join(path, custodyFileName))
			plan := strings.Repeat("e", 64)
			if kind == "malformed-plan" {
				plan = "E"
			}
			if err := l.AuthorizeRecovery(plan); !errors.Is(err, ErrRecoveryApproval) {
				t.Fatal("unauthorized approval", err)
			}
			if !bytes.Equal(before, readFile(t, filepath.Join(path, custodyFileName))) {
				t.Fatal("denied approval wrote ledger")
			}
		})
	}
}

func TestLocalCustodyWriteFailuresPreserveUncertainState(t *testing.T) {
	for _, phase := range []string{"prepare", "finish", "approve"} {
		for _, failure := range []string{"zero", "short", "full-write-error", "file-sync", "dir-sync", "readback", "replace"} {
			t.Run(phase+"/"+failure, func(t *testing.T) {
				auth := &testRecoveryAuthorizer{decision: strings.Repeat("d", 64)}
				b, dir, path := localCustodyFixture(t, auth)
				l := localLease(t, b)
				intent := syntheticIntent()
				if phase != "prepare" {
					if err := l.Prepare(intent); err != nil {
						t.Fatal(err)
					}
				}
				before := readFile(t, filepath.Join(path, custodyFileName))
				file := l.file
				wrapped := &faultFile{segmentFile: file}
				switch failure {
				case "zero":
					wrapped.write = func([]byte) (int, error) { return 0, unix.ENOSPC }
				case "short", "full-write-error":
					wrapped.write = func(data []byte) (int, error) {
						if failure == "short" {
							data = data[:len(data)/2]
						}
						n, err := file.Write(data)
						return n, errors.Join(err, unix.EIO)
					}
				case "file-sync":
					wrapped.sync = func() error { return unix.EIO }
				case "dir-sync":
					l.syncDirectory = func() error { return unix.EIO }
				case "readback":
					wrapped.sync = func() error {
						wrapped.read = func([]byte, int64) (int, error) { return 0, unix.EIO }
						return file.Sync()
					}
				case "replace":
					wrapped.sync = func() error {
						if err := file.Sync(); err != nil {
							return err
						}
						target := filepath.Join(path, custodyFileName)
						data := readFile(t, target)
						if err := os.Rename(target, target+".retained"); err != nil {
							return err
						}
						return os.WriteFile(target, data, 0600)
					}
				}
				l.file = wrapped
				var err error
				switch phase {
				case "prepare":
					err = l.Prepare(intent)
				case "finish":
					err = l.Finish(intent)
				case "approve":
					err = l.AuthorizeRecovery(strings.Repeat("e", 64))
				}
				if !errors.Is(err, ErrCommitUncertain) {
					t.Fatal("write failure not uncertain", err)
				}
				if got, e := l.State(); e == nil || !sameRestartState(got, RestartState{}) {
					t.Fatal("poisoned lease returned state")
				}
				if e := l.Prepare(intent); !errors.Is(e, ErrCommitUncertain) {
					t.Fatal("poisoned lease retried", e)
				}
				after := readFile(t, filepath.Join(path, custodyFileName))
				if !bytes.HasPrefix(after, before) {
					t.Fatal("failure rewrote prior bytes")
				}
				if err = l.Close(); err != nil {
					t.Fatal(err)
				}
				reopen, e := OpenLocalCustody(dir, testEnrollment(), auth)
				if failure == "short" {
					if e == nil || reopen != nil {
						t.Fatal("partial tail accepted")
					}
				} else {
					if e != nil {
						t.Fatal("complete protected state rejected", e)
					}
					defer func() { _ = reopen.Close() }()
					got := custodyState(t, localLease(t, reopen))
					if failure == "zero" {
						if phase == "prepare" && got.Pending != (CustodyIntent{}) {
							t.Fatal("invented intent")
						}
					} else if phase == "finish" {
						if got.Head != intent.After || got.Pending != (CustodyIntent{}) {
							t.Fatal("lost complete finish")
						}
					} else if got.Pending != intent {
						t.Fatal("lost complete intent")
					}
				}
				if !bytes.Equal(after, readFile(t, filepath.Join(path, custodyFileName))) {
					t.Fatal("reopen repaired bytes")
				}
			})
		}
	}
}

func TestLocalCustodyUnsafeStorageAndEnrollment(t *testing.T) {
	for _, kind := range []string{"missing", "symlink", "hardlink", "fifo", "directory", "mode", "directory-mode", "oversize", "corrupt", "truncated", "foreign-key", "foreign-epoch"} {
		t.Run(kind, func(t *testing.T) {
			b, dir, path := localCustodyFixture(t, nil)
			if err := b.Close(); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(path, custodyFileName)
			original := readFile(t, file)
			e := testEnrollment()
			var err error
			switch kind {
			case "missing":
				err = os.Rename(file, file+".retained")
			case "symlink", "hardlink", "fifo", "directory":
				err = os.Rename(file, file+".retained")
				if err == nil {
					switch kind {
					case "symlink":
						err = os.Symlink(file+".retained", file)
					case "hardlink":
						err = os.Link(file+".retained", file)
					case "fifo":
						err = unix.Mkfifo(file, 0600)
					case "directory":
						err = os.Mkdir(file, 0700)
					}
				}
			case "mode":
				err = chmodFixture(file, 0644)
			case "directory-mode":
				err = chmodFixture(path, 0755)
			case "oversize":
				err = os.Truncate(file, maxCustodyFile+1)
			case "corrupt":
				data := bytes.Clone(original)
				data[len(data)-1] ^= 1
				err = os.WriteFile(file, data, 0600)
			case "truncated":
				err = os.WriteFile(file, original[:len(original)-1], 0600)
			case "foreign-key":
				e.Authority.PublicKey = bytes.Repeat([]byte{1}, 32)
			case "foreign-epoch":
				e.Initial.Cursor.Identity.Epoch = "epoch.other"
				e.Authority.Identity = e.Initial.Cursor.Identity
			}
			if err != nil {
				t.Fatal(err)
			}
			if got, err := OpenLocalCustody(dir, e, nil); err == nil || got != nil {
				t.Fatal("unsafe storage accepted")
			}
			if kind == "symlink" || kind == "hardlink" || kind == "fifo" || kind == "directory" || kind == "missing" {
				if !bytes.Equal(original, readFile(t, file+".retained")) {
					t.Fatal("unrelated evidence changed")
				}
			}
		})
	}
}

func TestLocalCustodyLocksLifecycleAndNoBootstrapFallback(t *testing.T) {
	b, dir, path := localCustodyFixture(t, nil)
	original := readFile(t, filepath.Join(path, custodyFileName))
	if err := BootstrapLocalCustody(dir, testEnrollment()); !errors.Is(err, os.ErrExist) {
		t.Fatal("existing bootstrap replaced", err)
	}
	if !bytes.Equal(original, readFile(t, filepath.Join(path, custodyFileName))) {
		t.Fatal("bootstrap collision changed bytes")
	}
	l := localLease(t, b)
	if got, err := b.Acquire(); !errors.Is(err, ErrLocked) || got != nil {
		t.Fatal("second process lock accepted", err)
	}
	if err := dir.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if got, err := b.Acquire(); !errors.Is(err, ErrClosed) || got != nil {
		t.Fatal("closed factory acquired")
	}
	if err := l.Prepare(syntheticIntent()); err != nil {
		t.Fatal("factory close revoked independent lease", err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := l.State(); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	var zero LocalCustody
	if _, err := zero.Acquire(); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}

func TestLocalCustodyConcurrentCompareAndPrepare(t *testing.T) {
	b, _, _ := localCustodyFixture(t, nil)
	l := localLease(t, b)
	intent := syntheticIntent()
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Go(func() { results <- l.Prepare(intent) })
	}
	wg.Wait()
	close(results)
	ok, rejected := 0, 0
	for err := range results {
		if err == nil {
			ok++
		} else if errors.Is(err, ErrCustodyState) {
			rejected++
		} else {
			t.Fatal(err)
		}
	}
	if ok != 1 || rejected != 1 || l.tip.count != 2 {
		t.Fatal("duplicate prepare", ok, rejected)
	}
}

func TestLocalCustodyAbruptProcessExit(t *testing.T) {
	if os.Getenv("SYSWARDEN_CUSTODY_EXIT_FIXTURE") == "1" {
		dir := os.NewFile(3, "synthetic-custody-directory")
		b, err := OpenLocalCustody(dir, testEnrollment(), nil)
		if err != nil {
			t.Fatal(err)
		}
		l := localLease(t, b)
		state := l.tip.state
		state.Pending = syntheticIntent()
		frame, err := custodyFrame(state, 2, "prepare", "", "", l.tip.hash)
		if err != nil {
			t.Fatal(err)
		}
		if os.Getenv("SYSWARDEN_CUSTODY_PARTIAL") == "1" {
			frame = frame[:len(frame)/2]
		}
		if _, err = l.file.Write(frame); err != nil {
			t.Fatal(err)
		}
		os.Exit(0)
	}
	for _, partial := range []bool{false, true} {
		t.Run(strconv.FormatBool(partial), func(t *testing.T) {
			b, dir, path := localCustodyFixture(t, nil)
			if err := b.Close(); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("/proc/self/exe", "-test.run=^TestLocalCustodyAbruptProcessExit$")
			cmd.ExtraFiles = []*os.File{dir}
			cmd.Env = append(os.Environ(), "SYSWARDEN_CUSTODY_EXIT_FIXTURE=1")
			if partial {
				cmd.Env = append(cmd.Env, "SYSWARDEN_CUSTODY_PARTIAL=1")
			}
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatal(err, string(out))
			}
			before := readFile(t, filepath.Join(path, custodyFileName))
			r, err := OpenLocalCustody(dir, testEnrollment(), nil)
			if partial {
				if err == nil || r != nil {
					t.Fatal("partial interrupted record adopted")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = r.Close() }()
				if got := custodyState(t, localLease(t, r)); got.Pending != syntheticIntent() {
					t.Fatal("complete intent lost")
				}
			}
			if !bytes.Equal(before, readFile(t, filepath.Join(path, custodyFileName))) {
				t.Fatal("interrupted evidence changed")
			}
		})
	}
}

func TestLocalCustodyCodecBoundsAndTransitions(t *testing.T) {
	root, _ := custodyEnrollment(testEnrollment())
	frame, err := custodyFrame(root, 1, "bootstrap", "", "", [sha256.Size]byte{})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"empty", "prefix", "huge", "trailing", "checksum", "sequence", "unknown", "duplicate", "noncanonical", "finish-without-prepare", "approve-without-prepare", "second-bootstrap", "changed-authority"} {
		t.Run(kind, func(t *testing.T) {
			data := bytes.Clone(frame)
			switch kind {
			case "empty":
				data = nil
			case "prefix":
				data = data[:3]
			case "huge":
				binary.BigEndian.PutUint32(data[:4], ^uint32(0))
			case "trailing":
				data = append(data, 0)
			case "checksum":
				data[len(data)-1] ^= 1
			case "sequence", "unknown", "duplicate", "noncanonical":
				doc, err := encodeCustodyRecord(root, 1, "bootstrap", "", "")
				if err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "sequence":
					doc = bytes.Replace(doc, []byte(`"sequence":"1"`), []byte(`"sequence":"01"`), 1)
				case "unknown":
					doc = append([]byte(`{"extra":null,`), doc[1:]...)
				case "duplicate":
					doc = append([]byte(`{"sequence":"1",`), doc[1:]...)
				case "noncanonical":
					doc = append(doc, '\n')
				}
				size := len(doc)
				if size < 0 || size > maxCustodyDocument {
					t.Fatal("fixture size")
					return
				}
				data = make([]byte, 4+size+sha256.Size)
				binary.BigEndian.PutUint32(data[:4], uint32(size))
				copy(data[4:], doc)
				sum := custodyHash([sha256.Size]byte{}, doc)
				copy(data[4+size:], sum[:])
			default:
				tip, err := scanCustody(frame, root)
				if err != nil {
					t.Fatal(err)
				}
				state := root
				op, plan, decision := "finish", "", ""
				switch kind {
				case "approve-without-prepare":
					op = "approve"
					plan, decision = strings.Repeat("e", 64), strings.Repeat("d", 64)
				case "second-bootstrap":
					op = "bootstrap"
				case "changed-authority":
					op = "prepare"
					state.Authority.KeyID = "key.other"
					state.Pending = syntheticIntent()
					state.Pending.KeyID = "key.other"
				}
				extra, err := custodyFrame(state, 2, op, plan, decision, tip.hash)
				if err != nil {
					t.Fatal(err)
				}
				data = append(data, extra...)
			}
			if tip, err := scanCustody(data, root); err == nil || tip.count != 0 || tip.bytes != 0 || tip.hash != ([sha256.Size]byte{}) || !sameRestartState(tip.state, RestartState{}) {
				t.Fatal("invalid history exposed authority", err)
			}
		})
	}
	if got, err := scanCustody(frame, root); err != nil || !sameRestartState(got.state, root) {
		t.Fatal("valid codec failed", err)
	}
}

func TestLocalCustodyExhaustionPreservesHistory(t *testing.T) {
	b, _, path := localCustodyFixture(t, nil)
	l := localLease(t, b)
	root := l.enrollment
	data := readFile(t, filepath.Join(path, custodyFileName))
	tip, err := scanCustody(data, root)
	if err != nil {
		t.Fatal(err)
	}
	state := root
	state.Pending = syntheticIntent()
	for sequence := 2; sequence <= MaxCustodyRecords; sequence++ {
		op, plan, decision := "approve", strings.Repeat("e", 64), strings.Repeat("d", 64)
		if sequence == 2 {
			op, plan, decision = "prepare", "", ""
		}
		frame, err := custodyFrame(state, sequence, op, plan, decision, tip.hash)
		if err != nil {
			t.Fatal(err)
		}
		copy(tip.hash[:], frame[len(frame)-sha256.Size:])
		data = append(data, frame...)
	}
	if err = l.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(path, custodyFileName), data, 0600); err != nil {
		t.Fatal(err)
	}
	l = localLease(t, b)
	if err = l.Finish(syntheticIntent()); !errors.Is(err, ErrFull) {
		t.Fatal("capacity reset", err)
	}
	if !bytes.Equal(data, readFile(t, filepath.Join(path, custodyFileName))) {
		t.Fatal("capacity evicted history")
	}
	if l.tip.count != MaxCustodyRecords {
		t.Fatal("wrong count")
	}
}

func FuzzLocalCustodyLedger(f *testing.F) {
	root, err := custodyEnrollment(testEnrollment())
	if err != nil {
		f.Fatal(err)
	}
	frame, err := custodyFrame(root, 1, "bootstrap", "", "", [sha256.Size]byte{})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(frame)
	f.Add([]byte{})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		tip, err := scanCustody(data, root)
		if err != nil {
			if tip.count != 0 || tip.bytes != 0 || !sameRestartState(tip.state, RestartState{}) {
				t.Fatal("failure exposed partial state")
			}
			return
		}
		if tip.count < 1 || tip.count > MaxCustodyRecords || tip.bytes != len(data) || validateRestartState(tip.state) != nil {
			t.Fatal("unbounded state")
		}
	})
}

func TestLocalCustodyBootstrapGolden(t *testing.T) {
	root, _ := custodyEnrollment(testEnrollment())
	doc, err := encodeCustodyRecord(root, 1, "bootstrap", "", "")
	if err != nil {
		t.Fatal(err)
	}
	sum := custodyHash([sha256.Size]byte{}, doc)
	if len(doc) != 1276 || hex.EncodeToString(sum[:]) != "c77f661fc4cc85ef9670152891c34700796805541e3beff47666390d96c1bf70" {
		t.Fatal("independent bootstrap vector changed")
	}
}

func TestLocalCustodyProcessLock(t *testing.T) {
	if os.Getenv("SYSWARDEN_CUSTODY_LOCK_FIXTURE") == "1" {
		dir := os.NewFile(3, "synthetic-custody-directory")
		if b, err := OpenLocalCustody(dir, testEnrollment(), nil); !errors.Is(err, ErrLocked) || b != nil {
			t.Fatal("child bypassed process lock", err)
		}
		return
	}
	b, dir, _ := localCustodyFixture(t, nil)
	_ = localLease(t, b)
	cmd := exec.Command("/proc/self/exe", "-test.run=^TestLocalCustodyProcessLock$")
	cmd.ExtraFiles = []*os.File{dir}
	cmd.Env = append(os.Environ(), "SYSWARDEN_CUSTODY_LOCK_FIXTURE=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatal(err, string(out))
	}
}

func TestLocalCustodyBootstrapFailureRetainsEveryByte(t *testing.T) {
	for _, kind := range []string{"short", "complete", "file-sync", "dir-sync"} {
		t.Run(kind, func(t *testing.T) {
			dir, path := testDirectory(t)
			root, err := custodyEnrollment(testEnrollment())
			if err != nil {
				t.Fatal(err)
			}
			locked, err := openDirectory(dir)
			if err != nil {
				t.Fatal(err)
			}
			l, err := openCustodyLease(locked, root, nil, true)
			if err != nil {
				t.Fatal(err)
			}
			file := l.file
			wrapped := &faultFile{segmentFile: file}
			switch kind {
			case "short", "complete":
				wrapped.write = func(data []byte) (int, error) {
					if kind == "short" {
						data = data[:len(data)/2]
					}
					n, e := file.Write(data)
					return n, errors.Join(e, unix.EIO)
				}
			case "file-sync":
				wrapped.sync = func() error { return unix.EIO }
			case "dir-sync":
				l.syncDirectory = func() error { return unix.EIO }
			}
			l.file = wrapped
			if err = l.append(root, "bootstrap", "", ""); !errors.Is(err, ErrCommitUncertain) {
				t.Fatal(err)
			}
			if err = l.Close(); err != nil {
				t.Fatal(err)
			}
			before := readFile(t, filepath.Join(path, custodyFileName))
			if err = BootstrapLocalCustody(dir, testEnrollment()); !errors.Is(err, os.ErrExist) {
				t.Fatal("uncertain bootstrap overwritten", err)
			}
			if !bytes.Equal(before, readFile(t, filepath.Join(path, custodyFileName))) {
				t.Fatal("bootstrap evidence changed")
			}
		})
	}
}

func TestLocalCustodyCloseFailureReleasesLock(t *testing.T) {
	b, _, _ := localCustodyFixture(t, nil)
	l := localLease(t, b)
	file := l.file
	l.file = &faultFile{segmentFile: file, close: func() error { return errors.Join(file.Close(), unix.EIO) }}
	if err := l.Close(); !errors.Is(err, unix.EIO) {
		t.Fatal(err)
	}
	_ = custodyState(t, localLease(t, b))
}

func TestLocalCustodyReservesFinishAndRevalidatesRepeatedApproval(t *testing.T) {
	auth := &testRecoveryAuthorizer{decision: strings.Repeat("d", 64)}
	b, _, path := localCustodyFixture(t, auth)
	l := localLease(t, b)
	if err := l.Prepare(syntheticIntent()); err != nil {
		t.Fatal(err)
	}
	plan := strings.Repeat("e", 64)
	if err := l.AuthorizeRecovery(plan); err != nil {
		t.Fatal(err)
	}
	before := readFile(t, filepath.Join(path, custodyFileName))
	if err := l.AuthorizeRecovery(plan); err != nil {
		t.Fatal(err)
	}
	if auth.calls != 2 || !bytes.Equal(before, readFile(t, filepath.Join(path, custodyFileName))) {
		t.Fatal("repeat skipped authorization or duplicated record")
	}
	auth.err = ErrRecoveryApproval
	if err := l.AuthorizeRecovery(plan); !errors.Is(err, ErrRecoveryApproval) {
		t.Fatal("old receipt bypassed current denial", err)
	}
	auth.err = nil
	// Fill a synthetic valid history to leave only the reserved finish record.
	tip := l.tip
	data := bytes.Clone(before)
	for sequence := tip.count + 1; sequence < MaxCustodyRecords; sequence++ {
		frame, err := custodyFrame(tip.state, sequence, "approve", plan, auth.decision, tip.hash)
		if err != nil {
			t.Fatal(err)
		}
		copy(tip.hash[:], frame[len(frame)-sha256.Size:])
		data = append(data, frame...)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, custodyFileName), data, 0600); err != nil {
		t.Fatal(err)
	}
	l = localLease(t, b)
	if err := l.AuthorizeRecovery(strings.Repeat("f", 64)); !errors.Is(err, ErrFull) {
		t.Fatal("approval consumed final slot", err)
	}
	if err := l.AuthorizeRecovery(plan); err != nil {
		t.Fatal("exact audited retry failed", err)
	}
	if err := l.Finish(syntheticIntent()); err != nil {
		t.Fatal("reserved finish unavailable", err)
	}
	if l.tip.count != MaxCustodyRecords {
		t.Fatal("wrong final count")
	}
}
