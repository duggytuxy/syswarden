package journal

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// This synthetic authorizer models a separately authenticated decision registry.
// It is not a human identity provider or a permissive production default.
type testPolicyAdministrator struct {
	calls    int
	approved string
	now      time.Time
	hook     func(PolicyAdministrationRequest, *PolicyAdministrationDecision) error
	requests []PolicyAdministrationRequest
}

func (a *testPolicyAdministrator) AuthorizePolicyAdministration(r PolicyAdministrationRequest) (PolicyAdministrationDecision, error) {
	a.calls++
	a.requests = append(a.requests, r)
	d := PolicyAdministrationDecision{Mode: r.Mode, PlanSHA256: r.Plan.SHA256, DecisionSHA256: strings.Repeat("d", 64), UID: r.UID, NotBefore: a.now.Unix(), NotAfter: a.now.Unix() + 120}
	if r.Mode == "apply" && r.Plan.SHA256 != a.approved {
		return PolicyAdministrationDecision{}, ErrPolicyApproval
	}
	if a.hook != nil {
		if err := a.hook(r, &d); err != nil {
			return PolicyAdministrationDecision{}, err
		}
	}
	return d, nil
}
func adminFixture(t *testing.T) (*LocalCustodyPolicy, *os.File, string, CustodyPolicySnapshot, CustodyPolicyRequest, *testPolicyAdministrator, CustodyPolicyChange) {
	t.Helper()
	p := peerTestPolicy(t, CustodyCommit, CustodyResume)
	b, dir, path, root := policyFixture(t, p)
	r := policyRequest(t, p)
	a := &testPolicyAdministrator{now: policyNow(p)}
	p.Revision++
	change := CustodyPolicyChange{Operation: "install", Next: signedPolicySnapshot(t, p, true)}
	return b, dir, path, root, r, a, change
}
func adminPlan(t *testing.T, b *LocalCustodyPolicy, r CustodyPolicyRequest, a *testPolicyAdministrator, c CustodyPolicyChange) CustodyPolicyChangePlan {
	t.Helper()
	plan, err := PlanCustodyPolicyChange(b, r, a, c)
	if err != nil {
		t.Fatal(err)
	}
	a.approved = plan.SHA256
	return plan
}
func noPolicyPlan(t *testing.T, p CustodyPolicyChangePlan, err error) {
	t.Helper()
	if err == nil || !reflect.DeepEqual(p, CustodyPolicyChangePlan{}) {
		t.Fatal("failed inspection exposed plan", err)
	}
}

func TestPolicyAdministrationInspectApplyAuditAndReopen(t *testing.T) {
	b, dir, path, root, r, a, c := adminFixture(t)
	before := readFile(t, filepath.Join(path, policyFileName))
	plan, err := PlanCustodyPolicyChange(b, r, a, c)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, readFile(t, filepath.Join(path, policyFileName))) {
		t.Fatal("inspection wrote policy")
	}
	if a.calls != 1 || a.requests[0].UID != hostTestUID(t) {
		t.Fatal("inspection skipped kernel-bound authorization")
	}
	got, err := ApplyCustodyPolicyChange(b, r, a, c, plan.SHA256)
	requireNoPolicy(t, got, err) // Inspection cannot approve apply.
	if !bytes.Equal(before, readFile(t, filepath.Join(path, policyFileName))) {
		t.Fatal("unapproved apply wrote")
	}
	a.approved = plan.SHA256
	got, err = ApplyCustodyPolicyChange(b, r, a, c, plan.SHA256)
	if err != nil || !samePolicySnapshot(got, c.Next) {
		t.Fatal("approved install", err)
	}
	stored := readFile(t, filepath.Join(path, policyFileName))
	if !bytes.HasPrefix(stored, before) || !bytes.Contains(stored, []byte(plan.SHA256)) || !bytes.Contains(stored, []byte(strings.Repeat("d", 64))) {
		t.Fatal("atomic audit binding missing")
	}
	if err = b.Close(); err != nil {
		t.Fatal(err)
	}
	b, err = OpenLocalCustodyPolicy(dir, root.Trust)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	if !samePolicySnapshot(policyCurrent(t, b), c.Next) {
		t.Fatal("reopen lost approved transition")
	}
	calls := a.calls
	got, err = ApplyCustodyPolicyChange(b, r, a, c, plan.SHA256)
	requireNoPolicy(t, got, err)
	if a.calls != calls {
		t.Fatal("replay reached authorizer")
	}
	if !bytes.Equal(stored, readFile(t, filepath.Join(path, policyFileName))) {
		t.Fatal("replay changed bytes")
	}
}

func TestPolicyAdministrationDisableExpiredAndReenable(t *testing.T) {
	b, _, path, _, r, a, c := adminFixture(t)
	p, _ := DecodeCustodyAccessPolicy(c.Next.Document)
	now := time.Unix(p.NotAfter, 0)
	r.Now = func() time.Time { return now }
	a.now = now
	disable := CustodyPolicyChange{Operation: "disable"}
	plan := adminPlan(t, b, r, a, disable)
	got, err := ApplyCustodyPolicyChange(b, r, a, disable, plan.SHA256)
	if err != nil || got.Trust.Enabled {
		t.Fatal("expired policy blocked approved disable", err)
	}
	p.NotAfter += 3600
	c.Next = signedPolicySnapshot(t, p, true)
	plan = adminPlan(t, b, r, a, c)
	got, err = ApplyCustodyPolicyChange(b, r, a, c, plan.SHA256)
	if err != nil || !got.Trust.Enabled {
		t.Fatal("approved new revision did not reenable", err)
	}
	if bytes.Count(readFile(t, filepath.Join(path, policyFileName)), []byte(`"approval":`)) != 2 {
		t.Fatal("missing reviewed transitions")
	}
}

func TestPolicyAdministrationDenialsDoNotWrite(t *testing.T) {
	for _, kind := range []string{"nil", "denied", "wrong-mode", "wrong-plan", "wrong-uid", "no-audit", "uppercase-audit", "expired", "future", "excess-window", "zero-start", "overflow-time", "inspect-only"} {
		t.Run(kind, func(t *testing.T) {
			b, _, path, _, r, a, c := adminFixture(t)
			plan := adminPlan(t, b, r, a, c)
			before := readFile(t, filepath.Join(path, policyFileName))
			var authorizer PolicyAdministrationAuthorizer = a
			if kind == "nil" {
				authorizer = nil
			}
			a.hook = func(_ PolicyAdministrationRequest, d *PolicyAdministrationDecision) error {
				switch kind {
				case "denied":
					return ErrPolicyApproval
				case "wrong-mode", "inspect-only":
					d.Mode = "inspect"
				case "wrong-plan":
					d.PlanSHA256 = strings.Repeat("e", 64)
				case "wrong-uid":
					d.UID ^= 1
				case "no-audit":
					d.DecisionSHA256 = ""
				case "uppercase-audit":
					d.DecisionSHA256 = strings.Repeat("D", 64)
				case "expired":
					d.NotAfter = a.now.Unix()
					d.NotBefore = d.NotAfter - 120
				case "future":
					d.NotBefore = a.now.Unix() + 1
					d.NotAfter = d.NotBefore + 120
				case "excess-window":
					d.NotAfter = d.NotBefore + MaxPolicyApprovalSeconds + 1
				case "zero-start":
					d.NotBefore = 0
				case "overflow-time":
					d.NotAfter = maxPolicyTime + 1
				}
				return nil
			}
			got, err := ApplyCustodyPolicyChange(b, r, authorizer, c, plan.SHA256)
			requireNoPolicy(t, got, err)
			if !bytes.Equal(before, readFile(t, filepath.Join(path, policyFileName))) {
				t.Fatal("denial wrote policy")
			}
		})
	}
}

func TestPolicyAdministrationOperationGrantCannotInspect(t *testing.T) {
	b, _, path, _, r, a, c := adminFixture(t)
	before := readFile(t, filepath.Join(path, policyFileName))
	plan, err := PlanCustodyPolicyChange(b, r, nil, c)
	noPolicyPlan(t, plan, err)
	a.hook = func(PolicyAdministrationRequest, *PolicyAdministrationDecision) error { return ErrPolicyApproval }
	plan, err = PlanCustodyPolicyChange(b, r, a, c)
	noPolicyPlan(t, plan, err)
	if !bytes.Equal(before, readFile(t, filepath.Join(path, policyFileName))) {
		t.Fatal("denied inspection mutated")
	}
}

func TestPolicyAdministrationMalformedAndStalePlans(t *testing.T) {
	for _, kind := range []string{"changed-next", "wrong-digest", "malformed-digest", "changed-history", "replaced-file", "other-directory", "changed-directory", "changed-signature", "wrong-operation", "disable-payload", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			b, _, path, root, r, a, c := adminFixture(t)
			plan := adminPlan(t, b, r, a, c)
			switch kind {
			case "changed-next":
				p, _ := DecodeCustodyAccessPolicy(c.Next.Document)
				p.Grants = nil
				c.Next = signedPolicySnapshot(t, p, true)
			case "wrong-digest":
				plan.SHA256 = strings.Repeat("a", 64)
			case "malformed-digest":
				plan.SHA256 = "BAD"
			case "changed-history":
				if _, err := b.Disable(root.Trust); err != nil {
					t.Fatal(err)
				}
			case "replaced-file":
				file := filepath.Join(path, policyFileName)
				data := readFile(t, file)
				if err := os.Rename(file, file+".retained"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(file, data, 0600); err != nil {
					t.Fatal(err)
				}
			case "other-directory":
				b, _, path, _ = policyFixture(t, peerTestPolicy(t, CustodyCommit, CustodyResume))
			case "changed-directory":
				if err := os.WriteFile(filepath.Join(path, "unrelated"), []byte("synthetic"), 0600); err != nil {
					t.Fatal(err)
				}
			case "changed-signature":
				c.Next.Signature[0] ^= 1
			case "wrong-operation":
				c.Operation = "bootstrap"
			case "disable-payload":
				c.Operation = "disable"
			case "oversized":
				c.Next.Document = make([]byte, MaxCustodyPolicyBytes+1)
			}
			before := readFile(t, filepath.Join(path, policyFileName))
			calls := a.calls
			got, err := ApplyCustodyPolicyChange(b, r, a, c, plan.SHA256)
			requireNoPolicy(t, got, err)
			if a.calls != calls {
				t.Fatal("stale or malformed plan reached authorizer")
			}
			if !bytes.Equal(before, readFile(t, filepath.Join(path, policyFileName))) {
				t.Fatal("invalid plan wrote")
			}
		})
	}
}

func TestPolicyAdministrationRechecksAfterApproval(t *testing.T) {
	for _, kind := range []string{"expiry", "next-expiry", "clock-rollback", "closed-peer", "replace-policy", "change-directory", "callback-error", "mutate-request", "factory-close"} {
		t.Run(kind, func(t *testing.T) {
			b, _, path, _, r, a, c := adminFixture(t)
			now := a.now
			r.Now = func() time.Time { return now }
			if kind == "next-expiry" {
				p, _ := DecodeCustodyAccessPolicy(c.Next.Document)
				p.NotAfter = now.Unix() + 30
				c.Next = signedPolicySnapshot(t, p, true)
			}
			plan := adminPlan(t, b, r, a, c)
			before := readFile(t, filepath.Join(path, policyFileName))
			a.hook = func(req PolicyAdministrationRequest, _ *PolicyAdministrationDecision) error {
				switch kind {
				case "expiry":
					now = now.Add(120 * time.Second)
				case "next-expiry":
					now = now.Add(30 * time.Second)
				case "clock-rollback":
					now = now.Add(-time.Nanosecond)
				case "closed-peer":
					return r.Peer.Close()
				case "replace-policy":
					file := filepath.Join(path, policyFileName)
					if err := os.Rename(file, file+".retained"); err != nil {
						return err
					}
					return os.WriteFile(file, before, 0600)
				case "change-directory":
					return os.WriteFile(filepath.Join(path, "new-resource"), []byte("synthetic"), 0600)
				case "callback-error":
					return unix.EIO
				case "mutate-request":
					req.Plan.Document[0] ^= 1
				case "factory-close":
					return b.Close()
				}
				return nil
			}
			got, err := ApplyCustodyPolicyChange(b, r, a, c, plan.SHA256)
			if kind == "mutate-request" || kind == "factory-close" {
				if err != nil || !samePolicySnapshot(got, c.Next) {
					t.Fatal("owned data or lease lost", err)
				}
			} else {
				requireNoPolicy(t, got, err)
				if !bytes.Equal(before, readFile(t, filepath.Join(path, policyFileName))) {
					t.Fatal("changed authorization wrote")
				}
			}
		})
	}
}

func TestPolicyAdministrationExpiryAfterWriteRetainsAudit(t *testing.T) {
	b, dir, path, root, r, a, c := adminFixture(t)
	plan := adminPlan(t, b, r, a, c)
	before := readFile(t, filepath.Join(path, policyFileName))
	r.Now = func() time.Time {
		if !bytes.Equal(before, readFile(t, filepath.Join(path, policyFileName))) {
			return a.now.Add(120 * time.Second)
		}
		return a.now
	}
	got, err := ApplyCustodyPolicyChange(b, r, a, c, plan.SHA256)
	requireNoPolicy(t, got, err)
	if err = b.Close(); err != nil {
		t.Fatal(err)
	}
	b, err = OpenLocalCustodyPolicy(dir, root.Trust)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	if !samePolicySnapshot(policyCurrent(t, b), c.Next) {
		t.Fatal("completed approved update lost after reply failure")
	}
	if !bytes.Contains(readFile(t, filepath.Join(path, policyFileName)), []byte(plan.SHA256)) {
		t.Fatal("lost atomic approval audit")
	}
}

func TestPolicyAdministrationHoldsPolicyLockThroughAuthorizer(t *testing.T) {
	b, _, _, root, r, a, c := adminFixture(t)
	a.hook = func(PolicyAdministrationRequest, *PolicyAdministrationDecision) error {
		if _, err := b.Disable(root.Trust); !errors.Is(err, ErrLocked) {
			t.Fatal("disable interleaved", err)
		}
		if _, err := b.Install(root.Trust, c.Next, a.now); !errors.Is(err, ErrLocked) {
			t.Fatal("install interleaved", err)
		}
		return nil
	}
	plan := adminPlan(t, b, r, a, c)
	if _, err := ApplyCustodyPolicyChange(b, r, a, c, plan.SHA256); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Disable(c.Next.Trust); err != nil {
		t.Fatal("lease leaked", err)
	}
}

func TestPolicyAdministrationAuditRecordCanonicalAndCompatibility(t *testing.T) {
	root := signedPolicySnapshot(t, testCustodyPolicy(), true)
	first, err := policyFrame(root, 1, "bootstrap", [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	var prev [32]byte
	copy(prev[:], first[len(first)-32:])
	p := testCustodyPolicy()
	p.Revision++
	next := signedPolicySnapshot(t, p, true)
	a := policyChangeAudit{PlanSHA256: strings.Repeat("a", 64), DecisionSHA256: strings.Repeat("d", 64), UID: "0", NotBefore: "1800000001", NotAfter: "1800000121"}
	frame, err := policyFrameWithApproval(next, 2, "install", prev, &a)
	if err != nil {
		t.Fatal(err)
	}
	tip, err := scanPolicies(append(bytes.Clone(first), frame...), root.Trust)
	if err != nil || !samePolicySnapshot(tip.snapshot, next) {
		t.Fatal("reviewed history", err)
	}
	doc := frame[4 : len(frame)-sha256.Size]
	if len(doc) != 1519 || hex.EncodeToString(frame[len(frame)-32:]) != "4a1ab5e146b7c30addc05817bbe2c2b5153c7da820ce0ff120bd765204d9ba1e" {
		t.Fatal("reviewed canonical vector changed")
	}
	for _, kind := range []string{"empty-plan", "invalid-uid", "noncanonical-uid", "invalid-window", "bootstrap-audit", "null", "unknown", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			bad := a
			switch kind {
			case "empty-plan":
				bad.PlanSHA256 = ""
			case "invalid-uid":
				bad.UID = "4294967295"
			case "noncanonical-uid":
				bad.UID = "00"
			case "invalid-window":
				bad.NotAfter = "1800000900"
			case "bootstrap-audit":
				if _, err := policyFrameWithApproval(root, 1, "bootstrap", [32]byte{}, &bad); err == nil {
					t.Fatal("bootstrap approved through update")
				}
				return
			case "null", "unknown", "duplicate":
				changed := bytes.Clone(doc)
				if kind == "null" {
					wire := policyRecord{}
					if err := json.Unmarshal(doc, &wire); err != nil {
						t.Fatal(err)
					}
					wire.Approval = nil
					changed, err = json.Marshal(wire)
					if err != nil {
						t.Fatal(err)
					}
					changed = append(changed[:len(changed)-1], []byte(`,"approval":null}`)...)
				}
				if kind == "unknown" {
					changed = append(changed[:len(changed)-1], []byte(`,"extra":1}`)...)
				}
				if kind == "duplicate" {
					changed = bytes.Replace(changed, []byte(`"actor_uid":"0"`), []byte(`"actor_uid":"0","actor_uid":"0"`), 1)
				}
				if _, _, err := decodePolicyRecord(changed, root.Trust); err == nil {
					t.Fatal("noncanonical audit accepted")
				}
				return
			}
			if _, err := policyFrameWithApproval(next, 2, "install", prev, &bad); err == nil {
				t.Fatal("invalid audit accepted")
			}
		})
	}
}

func TestPolicyAdministrationInvalidPeersAndClocks(t *testing.T) {
	for _, kind := range []string{"nil-clock", "zero-clock", "nil-peer", "closed-peer", "datagram", "nil-store"} {
		t.Run(kind, func(t *testing.T) {
			b, _, path, _, r, a, c := adminFixture(t)
			before := readFile(t, filepath.Join(path, policyFileName))
			switch kind {
			case "nil-clock":
				r.Now = nil
			case "zero-clock":
				r.Now = func() time.Time { return time.Time{} }
			case "nil-peer":
				r.Peer = nil
			case "closed-peer":
				if err := r.Peer.Close(); err != nil {
					t.Fatal(err)
				}
			case "datagram":
				r.Peer, _ = custodySocketPair(t, unix.SOCK_DGRAM)
			case "nil-store":
				b = nil
			}
			plan, err := PlanCustodyPolicyChange(b, r, a, c)
			noPolicyPlan(t, plan, err)
			if a.calls != 0 || !bytes.Equal(before, readFile(t, filepath.Join(path, policyFileName))) {
				t.Fatal("invalid peer reached authorization or mutation")
			}
		})
	}
}

func TestPolicyAdministrationAuditAndTransitionShareFailureOutcome(t *testing.T) {
	for _, kind := range []string{"zero", "short", "full-error", "file-sync", "directory-sync", "readback", "close"} {
		t.Run(kind, func(t *testing.T) {
			b, dir, path, root, r, a, c := adminFixture(t)
			plan := adminPlan(t, b, r, a, c)
			l, err := b.acquire()
			if err != nil {
				t.Fatal(err)
			}
			before := readFile(t, filepath.Join(path, policyFileName))
			file := l.file
			fault := faultFile{segmentFile: file}
			switch kind {
			case "zero":
				fault.write = func([]byte) (int, error) { return 0, unix.ENOSPC }
			case "short":
				fault.write = func(data []byte) (int, error) { return file.Write(data[:len(data)/2]) }
			case "full-error":
				fault.write = func(data []byte) (int, error) { n, e := file.Write(data); return n, errors.Join(e, unix.EIO) }
			case "file-sync":
				fault.sync = func() error { return unix.EIO }
			case "directory-sync":
				l.syncDirectory = func() error { return unix.EIO }
			case "readback":
				fault.read = func([]byte, int64) (int, error) { return 0, unix.EIO }
			case "close":
				fault.close = func() error { return errors.Join(file.Close(), unix.EIO) }
			}
			l.file = &fault
			audit := policyChangeAudit{PlanSHA256: plan.SHA256, DecisionSHA256: strings.Repeat("d", 64), UID: strconv.FormatUint(uint64(hostTestUID(t)), 10), NotBefore: strconv.FormatInt(a.now.Unix(), 10), NotAfter: strconv.FormatInt(a.now.Unix()+120, 10)}
			err = errors.Join(l.appendWithApproval(c.Next, "install", &audit), l.close())
			if err == nil {
				t.Fatal("injected failure returned success")
			}
			after := readFile(t, filepath.Join(path, policyFileName))
			if !bytes.HasPrefix(after, before) {
				t.Fatal("lost existing history")
			}
			if err := b.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := OpenLocalCustodyPolicy(dir, root.Trust)
			if kind == "short" {
				if err == nil || reopened != nil {
					t.Fatal("partial reviewed frame exposed authority")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = reopened.Close() }()
			expected := c.Next
			if kind == "zero" {
				expected = root
			}
			if !samePolicySnapshot(policyCurrent(t, reopened), expected) {
				t.Fatal("incorrect protected completion")
			}
			if kind != "zero" && !bytes.Contains(after, []byte(plan.SHA256)) {
				t.Fatal("transition persisted without its audit binding")
			}
		})
	}
}
