package journal

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func signedPolicySnapshot(t testing.TB, p CustodyAccessPolicy, enabled bool) CustodyPolicySnapshot {
	t.Helper()
	data, sig, trust := signTestPolicy(t, p)
	trust.Enabled = enabled
	return CustodyPolicySnapshot{Trust: trust, Document: data, Signature: sig}
}
func policyFixture(t *testing.T, p CustodyAccessPolicy) (*LocalCustodyPolicy, *os.File, string, CustodyPolicySnapshot) {
	t.Helper()
	dir, path := testDirectory(t)
	s := signedPolicySnapshot(t, p, true)
	if err := BootstrapLocalCustodyPolicy(dir, s, policyNow(p)); err != nil {
		t.Fatal(err)
	}
	b, err := OpenLocalCustodyPolicy(dir, s.Trust)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b, dir, path, s
}
func policyCurrent(t *testing.T, b *LocalCustodyPolicy) CustodyPolicySnapshot {
	t.Helper()
	s, e := b.Current()
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func requireNoPolicy(t *testing.T, s CustodyPolicySnapshot, err error) {
	t.Helper()
	if err == nil || !reflect.DeepEqual(s, CustodyPolicySnapshot{}) {
		t.Fatal("invalid update exposed state", err)
	}
}

func TestPolicyStoreReopenTransitionsAndOwnedSnapshots(t *testing.T) {
	p := testCustodyPolicy()
	b, dir, path, root := policyFixture(t, p)
	before := readFile(t, filepath.Join(path, policyFileName))
	copy := policyCurrent(t, b)
	copy.Document[0] ^= 1
	copy.Signature[0] ^= 1
	copy.Trust.IssuerPublicKey[0] ^= 1
	if !samePolicySnapshot(root, policyCurrent(t, b)) {
		t.Fatal("caller alias changed state")
	}
	p.Revision++
	p.Grants = p.Grants[:1]
	next := signedPolicySnapshot(t, p, true)
	got, err := b.Install(root.Trust, next, policyNow(p))
	if err != nil || !samePolicySnapshot(got, next) {
		t.Fatal("install", err)
	}
	if !bytes.HasPrefix(readFile(t, filepath.Join(path, policyFileName)), before) {
		t.Fatal("install rewrote history")
	}
	got, err = b.Install(root.Trust, next, policyNow(p))
	requireNoPolicy(t, got, err)
	got, err = b.Disable(next.Trust)
	if err != nil || got.Trust.Enabled {
		t.Fatal("disable", err)
	}
	disabled := got
	if _, err = b.Install(disabled.Trust, next, policyNow(p)); err == nil {
		t.Fatal("reenabled old signed revision")
	}
	if err = b.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenLocalCustodyPolicy(dir, root.Trust)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	if !samePolicySnapshot(disabled, policyCurrent(t, reopened)) {
		t.Fatal("restart revived disabled policy")
	}
	p.Revision++
	next = signedPolicySnapshot(t, p, true)
	if got, err = reopened.Install(disabled.Trust, next, policyNow(p)); err != nil || !samePolicySnapshot(next, got) {
		t.Fatal("new signed revision did not reenable", err)
	}
}

func TestPolicyStoreRejectsUnapprovedShapesAndScopeChanges(t *testing.T) {
	for _, name := range []string{"old", "skip", "other-policy", "other-root", "other-issuer", "changed-checkpoint-key", "changed-range", "wrong-pin", "wrong-signature", "expired", "not-yet-valid", "zero-time", "wrong-expected-enabled"} {
		t.Run(name, func(t *testing.T) {
			p := testCustodyPolicy()
			b, _, path, root := policyFixture(t, p)
			p.Revision++
			switch name {
			case "old":
				p.Revision--
			case "skip":
				p.Revision++
			case "other-policy":
				p.PolicyID = "other.policy"
			case "other-root":
				p.Enrollment.Initial.PreviousSHA256 = strings.Repeat("a", 64)
			case "other-issuer":
				p.IssuerKeyID = "other.issuer"
			case "changed-checkpoint-key":
				p.Enrollment.Authority.PublicKey[0] ^= 1
			case "changed-range":
				p.Enrollment.Authority.LastSequence++
			}
			next := signedPolicySnapshot(t, p, true)
			expected := root.Trust
			now := policyNow(p)
			switch name {
			case "wrong-pin":
				next.Trust.PolicySHA256 = strings.Repeat("a", 64)
			case "wrong-signature":
				next.Signature[0] ^= 1
			case "expired":
				now = time.Unix(p.NotAfter, 0)
			case "not-yet-valid":
				now = time.Unix(p.NotBefore-1, 0)
			case "zero-time":
				now = time.Time{}
			case "wrong-expected-enabled":
				expected.Enabled = false
			}
			before := readFile(t, filepath.Join(path, policyFileName))
			got, err := b.Install(expected, next, now)
			requireNoPolicy(t, got, err)
			if !bytes.Equal(before, readFile(t, filepath.Join(path, policyFileName))) {
				t.Fatal("rejected update wrote policy")
			}
		})
	}
}

func TestPolicyStorePrivateStorageAndExplicitBootstrap(t *testing.T) {
	for _, name := range []string{"missing", "symlink", "hardlink", "fifo", "directory", "mode", "dir-mode", "oversize", "partial", "corrupt", "wrong-root"} {
		t.Run(name, func(t *testing.T) {
			p := testCustodyPolicy()
			b, dir, path, root := policyFixture(t, p)
			if err := b.Close(); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(path, policyFileName)
			original := readFile(t, file)
			switch name {
			case "missing":
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(file, file+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(file+".original", file); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(file, file+".linked"); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
				if err := unix.Mkfifo(file, 0600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(file, 0700); err != nil {
					t.Fatal(err)
				}
			case "mode":
				if err := chmodFixture(file, 0640); err != nil {
					t.Fatal(err)
				}
			case "dir-mode":
				if err := chmodFixture(path, 0750); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				if err := os.Truncate(file, maxPolicyFile+1); err != nil {
					t.Fatal(err)
				}
			case "partial":
				if err := os.WriteFile(file, original[:len(original)-1], 0600); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				original[len(original)-1] ^= 1
				if err := os.WriteFile(file, original, 0600); err != nil {
					t.Fatal(err)
				}
			case "wrong-root":
				root.Trust.Revision++
			}
			opened, err := OpenLocalCustodyPolicy(dir, root.Trust)
			if err == nil || opened != nil {
				t.Fatal("unsafe storage accepted")
			}
			if name == "missing" {
				if _, err := os.Lstat(file); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("open bootstrapped")
				}
			}
		})
	}
	p := testCustodyPolicy()
	_, dir, path, root := policyFixture(t, p)
	before := readFile(t, filepath.Join(path, policyFileName))
	if err := BootstrapLocalCustodyPolicy(dir, root, policyNow(p)); err == nil {
		t.Fatal("bootstrap replaced existing file")
	}
	if !bytes.Equal(before, readFile(t, filepath.Join(path, policyFileName))) {
		t.Fatal("bootstrap changed existing file")
	}
}

func TestPolicyStoreFaultsRetainBytesAndAuthoritativeCompleteRecords(t *testing.T) {
	for _, kind := range []string{"zero", "short", "full-error", "sync", "dir-sync", "readback", "replace", "close"} {
		t.Run(kind, func(t *testing.T) {
			p := testCustodyPolicy()
			b, dir, path, root := policyFixture(t, p)
			l, err := b.acquire()
			if err != nil {
				t.Fatal(err)
			}
			before := readFile(t, filepath.Join(path, policyFileName))
			p.Revision++
			next := signedPolicySnapshot(t, p, true)
			file := l.file
			fault := &faultFile{segmentFile: file}
			switch kind {
			case "zero":
				fault.write = func([]byte) (int, error) { return 0, unix.ENOSPC }
			case "short":
				fault.write = func(data []byte) (int, error) { return file.Write(data[:len(data)/2]) }
			case "full-error":
				fault.write = func(data []byte) (int, error) { n, e := file.Write(data); return n, errors.Join(e, unix.EIO) }
			case "sync":
				fault.sync = func() error { return unix.EIO }
			case "dir-sync":
				l.syncDirectory = func() error { return unix.EIO }
			case "readback":
				fault.read = func([]byte, int64) (int, error) { return 0, unix.EIO }
			case "replace":
				fault.sync = func() error {
					data := readFile(t, filepath.Join(path, policyFileName))
					if e := os.Rename(filepath.Join(path, policyFileName), filepath.Join(path, "retained")); e != nil {
						return e
					}
					return os.WriteFile(filepath.Join(path, policyFileName), data, 0600)
				}
			case "close":
				fault.close = func() error { return errors.Join(file.Close(), unix.EIO) }
			}
			l.file = fault
			got, err := l.changeAndClose(root.Trust, next, "install")
			requireNoPolicy(t, got, err)
			after := readFile(t, filepath.Join(path, policyFileName))
			if !bytes.HasPrefix(after, before) {
				t.Fatal("failure lost original bytes")
			}
			if err = b.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := OpenLocalCustodyPolicy(dir, root.Trust)
			if kind == "short" {
				if err == nil || reopened != nil {
					t.Fatal("partial tail accepted")
				}
				return
			}
			if err != nil {
				t.Fatal("complete authoritative file did not reopen", err)
			}
			defer func() { _ = reopened.Close() }()
			expected := next
			if kind == "zero" {
				expected = root
			}
			if !samePolicySnapshot(policyCurrent(t, reopened), expected) {
				t.Fatal("restart chose wrong protected state")
			}
		})
	}
}

func TestPolicyStoreReservesFinalDisableAndNeverEvicts(t *testing.T) {
	p := testCustodyPolicy()
	b, _, path, root := policyFixture(t, p)
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	var history []byte
	var previous [sha256.Size]byte
	current := root
	for n := 1; n < MaxPolicyRecords; n++ {
		op := "bootstrap"
		if n > 1 {
			p.Revision++
			current = signedPolicySnapshot(t, p, true)
			op = "install"
		}
		frame, err := policyFrame(current, n, op, previous)
		if err != nil {
			t.Fatal(err)
		}
		copy(previous[:], frame[len(frame)-sha256.Size:])
		history = append(history, frame...)
	}
	file := filepath.Join(path, policyFileName)
	if err := os.WriteFile(file, history, 0600); err != nil {
		t.Fatal(err)
	}
	dir, err := openFixtureDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dir.Close() }()
	b, err = OpenLocalCustodyPolicy(dir, root.Trust)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	p.Revision++
	next := signedPolicySnapshot(t, p, true)
	got, err := b.Install(current.Trust, next, policyNow(p))
	requireNoPolicy(t, got, err)
	if !errors.Is(err, ErrFull) {
		t.Fatal(err)
	}
	disabled, err := b.Disable(current.Trust)
	if err != nil || disabled.Trust.Enabled {
		t.Fatal("reserved disable failed", err)
	}
	final := readFile(t, file)
	if !bytes.HasPrefix(final, history) {
		t.Fatal("history evicted")
	}
	got, err = b.Install(disabled.Trust, next, policyNow(p))
	requireNoPolicy(t, got, err)
	if !bytes.Equal(final, readFile(t, file)) {
		t.Fatal("full ledger changed")
	}
}

func TestPolicyStoreConcurrentCASAndFactoryLifetime(t *testing.T) {
	p := testCustodyPolicy()
	b, dir, _, root := policyFixture(t, p)
	p.Revision++
	next := signedPolicySnapshot(t, p, true)
	var group sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		group.Go(func() { _, err := b.Install(root.Trust, next, policyNow(p)); results <- err })
	}
	group.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatal("CAS admitted multiple updates", success)
	}
	l, err := b.acquire()
	if err != nil {
		t.Fatal(err)
	}
	if err = b.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = b.Current(); !errors.Is(err, ErrClosed) {
		t.Fatal("closed factory acquired", err)
	}
	if err = l.refresh(); err != nil {
		t.Fatal("factory close revoked live lease", err)
	}
	if _, err = OpenLocalCustodyPolicy(dir, root.Trust); !errors.Is(err, ErrLocked) {
		t.Fatal("live lease lost process lock", err)
	}
	if err = l.close(); err != nil {
		t.Fatal(err)
	}
	b, err = OpenLocalCustodyPolicy(dir, root.Trust)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
}

func TestPolicyStoreChild(t *testing.T) {
	if os.Getenv("SYSWARDEN_SYNTHETIC_POLICY_CHILD") != "1" {
		return
	}
	dir := os.NewFile(3, "synthetic-policy-directory")
	defer func() { _ = dir.Close() }()
	root := signedPolicySnapshot(t, testCustodyPolicy(), true)
	if _, err := OpenLocalCustodyPolicy(dir, root.Trust); !errors.Is(err, ErrLocked) {
		t.Fatal("process lock bypassed", err)
	}
}
func TestPolicyStoreActualProcessLock(t *testing.T) {
	b, dir, _, _ := policyFixture(t, testCustodyPolicy())
	l, err := b.acquire()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.close() }()
	cmd := exec.Command("/proc/self/exe", "-test.run=^TestPolicyStoreChild$", "-test.timeout=10s")
	cmd.Env = append(os.Environ(), "SYSWARDEN_SYNTHETIC_POLICY_CHILD=1")
	cmd.ExtraFiles = []*os.File{dir}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatal(err, string(out))
	}
}

func TestPolicyStoreCanonicalAndInvalidTransitions(t *testing.T) {
	p := testCustodyPolicy()
	root := signedPolicySnapshot(t, p, true)
	first, err := policyFrame(root, 1, "bootstrap", [sha256.Size]byte{})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"partial", "hash", "duplicate", "unknown", "sequence", "repeat-bootstrap", "same-revision", "unsigned-disable", "unknown-operation", "enabled-final"} {
		t.Run(name, func(t *testing.T) {
			data := bytes.Clone(first)
			doc := bytes.Clone(first[4 : len(first)-sha256.Size])
			switch name {
			case "partial":
				data = data[:len(data)-1]
			case "hash":
				data[len(data)-1] ^= 1
			case "duplicate":
				doc = bytes.Replace(doc, []byte(`"sequence":"1"`), []byte(`"sequence":"0","sequence":"1"`), 1)
			case "unknown":
				doc = bytes.Replace(doc, []byte(`"sequence":"1"`), []byte(`"extra":true,"sequence":"1"`), 1)
			case "sequence":
				doc = bytes.Replace(doc, []byte(`"sequence":"1"`), []byte(`"sequence":"2"`), 1)
			case "unknown-operation":
				doc = bytes.Replace(doc, []byte(`"operation":"bootstrap"`), []byte(`"operation":"reset"`), 1)
			case "unsigned-disable":
				doc = bytes.Replace(doc, []byte(`"enabled":true`), []byte(`"enabled":false`), 1)
			case "repeat-bootstrap", "same-revision":
				var prev [sha256.Size]byte
				copy(prev[:], first[len(first)-sha256.Size:])
				op := "bootstrap"
				if name == "same-revision" {
					op = "install"
				}
				frame, e := policyFrame(root, 2, op, prev)
				if e != nil {
					t.Fatal(e)
				}
				data = append(data, frame...)
			case "enabled-final":
				if _, e := policyFrame(root, MaxPolicyRecords, "install", [sha256.Size]byte{}); e == nil {
					t.Fatal("enabled final record accepted")
				}
				return
			}
			if !bytes.Equal(doc, first[4:len(first)-sha256.Size]) {
				size := len(doc)
				if size > maxPolicyRecord {
					t.Fatal("fixture too large")
					return
				}
				data = make([]byte, 4+size+sha256.Size)
				binary.BigEndian.PutUint32(data[:4], uint32(size))
				copy(data[4:], doc)
				sum := policyHash([sha256.Size]byte{}, doc)
				copy(data[4+len(doc):], sum[:])
			}
			got, err := scanPolicies(data, root.Trust)
			if err == nil || !reflect.DeepEqual(got, policyTip{}) {
				t.Fatal("invalid ledger exposed a prefix")
			}
		})
	}
}
func TestPolicyStoreGolden(t *testing.T) {
	root := signedPolicySnapshot(t, testCustodyPolicy(), true)
	doc, err := encodePolicyRecord(root, 1, "bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	sum := policyHash([sha256.Size]byte{}, doc)
	if len(doc) != 1275 || hex.EncodeToString(sum[:]) != "a6554fd863cac22139ccc4590e444b05ecb0194fc977950c53b49a94c2635699" {
		t.Fatal("canonical policy ledger vector changed")
	}
}
func FuzzCustodyPolicyLedger(f *testing.F) {
	root := signedPolicySnapshot(f, testCustodyPolicy(), true)
	frame, err := policyFrame(root, 1, "bootstrap", [sha256.Size]byte{})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(frame)
	p := testCustodyPolicy()
	p.Revision++
	next := signedPolicySnapshot(f, p, true)
	var previous [sha256.Size]byte
	copy(previous[:], frame[len(frame)-sha256.Size:])
	audit := policyChangeAudit{PlanSHA256: strings.Repeat("a", 64), DecisionSHA256: strings.Repeat("d", 64), UID: "0", NotBefore: "1800000001", NotAfter: "1800000121"}
	reviewed, err := policyFrameWithApproval(next, 2, "install", previous, &audit)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(append(bytes.Clone(frame), reviewed...))
	f.Add([]byte{})
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxPolicyRecord*3 {
			return
		}
		tip, err := scanPolicies(data, root.Trust)
		if err != nil {
			if !reflect.DeepEqual(tip, policyTip{}) {
				t.Fatal("failed scan exposed state")
			}
			return
		}
		if tip.count < 1 || tip.count > MaxPolicyRecords || tip.bytes != len(data) {
			t.Fatal("invalid scan bounds")
		}
		if _, err = authenticatePolicySnapshot(tip.snapshot); err != nil {
			t.Fatal(err)
		}
	})
}

func TestPolicyStoreExpiredHistoryAndDisable(t *testing.T) {
	p := testCustodyPolicy()
	b, _, _, root := policyFixture(t, p)
	// History is authenticated at its stated validity start, not silently renewed.
	s := policyCurrent(t, b)
	if _, err := VerifyCustodyAccessPolicy(s.Document, s.Signature, s.Trust, time.Unix(p.NotAfter, 0)); err == nil {
		t.Fatal("expired policy admitted")
	}
	if _, err := b.Disable(root.Trust); err != nil {
		t.Fatal("expiry prevented emergency disable", err)
	}
}
