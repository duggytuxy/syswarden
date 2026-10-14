package journal

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	contracts "syswarden-core/contracts/v5"
)

type authorityFixtureState struct {
	config                  LocalAuthorityConfig
	policy                  CustodyAccessPolicy
	root                    CustodyPolicySnapshot
	files                   recoveryFixture
	policyPath, custodyPath string
	peer                    *net.UnixConn
	administrator           *testPolicyAdministrator
}

func authorityFixture(t *testing.T) authorityFixtureState {
	t.Helper()
	p := peerTestPolicy(t, CustodyApplyRecovery, CustodyCommit, CustodyInspectRecovery, CustodyResume)
	policies, policyDir, policyPath, root := policyFixture(t, p)
	b, custodyDir, custodyPath := localCustodyFixture(t, nil)
	f, _ := custodyFixture(t, 2)
	peer, _ := custodySocketPair(t, unix.SOCK_STREAM)
	admin := &testPolicyAdministrator{now: policyNow(p)}
	if err := errors.Join(policies.Close(), b.Close()); err != nil {
		t.Fatal(err)
	}
	return authorityFixtureState{config: LocalAuthorityConfig{PolicyDirectory: policyDir, CustodyDirectory: custodyDir, AnchorDirectory: f.anchor, JournalDirectory: f.journal, PolicyRoot: root.Trust, Enrollment: testEnrollment(), Limits: testLimits(), Now: func() time.Time { return policyNow(p) }, PolicyAdministrator: admin}, policy: p, root: root, files: f, policyPath: policyPath, custodyPath: custodyPath, peer: peer, administrator: admin}
}
func openAuthority(t *testing.T, c LocalAuthorityConfig) *LocalAuthority {
	t.Helper()
	a, err := OpenLocalAuthority(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}
func authorityMessage(t testing.TB, r authorityRequest) []byte {
	t.Helper()
	r.Schema = AuthorityRequestSchema
	r.ID = "request.fixture.1"
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
func authorityReply(t *testing.T, a *LocalAuthority, peer *net.UnixConn, r authorityRequest) authorityResponse {
	t.Helper()
	data, err := a.Execute(peer, authorityMessage(t, r))
	if err != nil {
		t.Fatal(err)
	}
	var out authorityResponse
	if json.Unmarshal(data, &out) != nil || out.Schema != AuthorityResponseSchema || out.ID != "request.fixture.1" || out.Operation != r.Operation || len(data) > MaxAuthorityResponseBytes {
		t.Fatal("invalid response")
	}
	encoded, err := json.Marshal(out)
	if err != nil || !bytes.Equal(encoded, data) {
		t.Fatal("noncanonical response")
	}
	return out
}
func authorityDenied(t *testing.T, a *LocalAuthority, peer *net.UnixConn, data []byte) error {
	t.Helper()
	out, err := a.Execute(peer, data)
	if err == nil || out != nil {
		t.Fatal("denial exposed response", err)
	}
	return err
}
func authorityAnchor(t *testing.T, r authorityResponse, want contracts.JournalCheckpointAnchor) {
	t.Helper()
	got, err := decodeAnchor(r.Anchor)
	if err != nil || got != want || len(r.Plan) != 0 || r.Policy != nil || r.PlanSHA256 != "" {
		t.Fatal("wrong anchor response", err)
	}
}
func (f authorityFixtureState) bytes(t *testing.T) [][]byte {
	t.Helper()
	out := [][]byte{readFile(t, filepath.Join(f.policyPath, policyFileName)), readFile(t, filepath.Join(f.custodyPath, custodyFileName))}
	return append(out, f.files.bytes(t)...)
}
func authorityInstall(t testing.TB, p CustodyAccessPolicy) *authorityChange {
	t.Helper()
	doc, sig, _ := signTestPolicy(t, p)
	enabled := true
	return &authorityChange{Operation: "install", Enabled: &enabled, Policy: doc, Signature: hex.EncodeToString(sig)}
}

func TestLocalAuthorityCommitResumeOwnedStartupAndReopen(t *testing.T) {
	f := authorityFixture(t)
	originalRoot := clonePolicyTrust(f.root.Trust)
	a := openAuthority(t, f.config)
	// Neither caller keys nor borrowed descriptor lifetime controls the handle.
	f.config.PolicyRoot.IssuerPublicKey[0] ^= 1
	f.config.Enrollment.Authority.PublicKey[0] ^= 1
	for _, dir := range []*os.File{f.config.PolicyDirectory, f.config.CustodyDirectory, f.config.AnchorDirectory, f.config.JournalDirectory} {
		if err := dir.Close(); err != nil {
			t.Fatal(err)
		}
	}
	authorityAnchor(t, authorityReply(t, a, f.peer, authorityRequest{Operation: "resume"}), f.files.expected)
	authorityAnchor(t, authorityReply(t, a, f.peer, authorityRequest{Operation: "commit", Segment: testName}), f.files.next)
	authorityAnchor(t, authorityReply(t, a, f.peer, authorityRequest{Operation: "resume"}), f.files.next)
	before := f.bytes(t)
	_ = authorityDenied(t, a, f.peer, authorityMessage(t, authorityRequest{Operation: "commit", Segment: testName}))
	if !reflect.DeepEqual(before, f.bytes(t)) {
		t.Fatal("duplicate commit mutated state")
	}
	// A new independent handle opens the durable result using the original roots.
	c := f.config
	c.PolicyRoot = originalRoot
	c.Enrollment = testEnrollment()
	var err error
	paths := []string{f.policyPath, f.custodyPath, f.files.anchorPath, f.files.journalPath}
	dirs := make([]*os.File, 0, 4)
	for _, path := range paths {
		dir, e := openFixtureDirectory(path)
		if e != nil {
			t.Fatal(e)
		}
		dirs = append(dirs, dir)
		defer func() { _ = dir.Close() }()
	}
	c.PolicyDirectory, c.CustodyDirectory, c.AnchorDirectory, c.JournalDirectory = dirs[0], dirs[1], dirs[2], dirs[3]
	if err = a.Close(); err != nil {
		t.Fatal(err)
	}
	authorityAnchor(t, authorityReply(t, openAuthority(t, c), f.peer, authorityRequest{Operation: "resume"}), f.files.next)
}

func TestLocalAuthorityStartupFailuresDoNotCreateOrLock(t *testing.T) {
	for _, kind := range []string{"nil-clock", "invalid-root", "wrong-root", "wrong-enrollment", "invalid-limits", "nil-directory", "closed-directory", "shared-directory", "unsafe-directory", "missing-policy", "missing-custody"} {
		t.Run(kind, func(t *testing.T) {
			f := authorityFixture(t)
			c := f.config
			switch kind {
			case "nil-clock":
				c.Now = nil
			case "invalid-root":
				c.PolicyRoot.PolicyID = ""
			case "wrong-root":
				c.PolicyRoot = clonePolicyTrust(c.PolicyRoot)
				c.PolicyRoot.IssuerPublicKey[0] ^= 1
			case "wrong-enrollment":
				c.Enrollment.Authority.LastSequence++
			case "invalid-limits":
				c.Limits.MaxFrames = 0
			case "nil-directory":
				c.JournalDirectory = nil
			case "closed-directory":
				if err := c.JournalDirectory.Close(); err != nil {
					t.Fatal(err)
				}
			case "shared-directory":
				c.JournalDirectory = c.AnchorDirectory
			case "unsafe-directory":
				if err := chmodFixture(f.files.journalPath, 0755); err != nil {
					t.Fatal(err)
				}
			case "missing-policy":
				c.PolicyDirectory, _ = testDirectory(t)
			case "missing-custody":
				c.CustodyDirectory, _ = testDirectory(t)
			}
			before := f.bytes(t)
			a, err := OpenLocalAuthority(c)
			if err == nil || a != nil {
				t.Fatal("unsafe startup accepted", err)
			}
			if !reflect.DeepEqual(before, f.bytes(t)) {
				t.Fatal("failed startup mutated state")
			}
			if kind == "missing-policy" || kind == "missing-custody" {
				dir := c.PolicyDirectory
				if kind == "missing-custody" {
					dir = c.CustodyDirectory
				}
				entries, e := dir.ReadDir(-1)
				if e != nil || len(entries) != 0 {
					t.Fatal("implicit bootstrap", e)
				}
			}
			// All earlier acquired locks must be released after a later failure.
			for _, dir := range []*os.File{f.config.PolicyDirectory, f.config.CustodyDirectory, f.config.AnchorDirectory} {
				opened, e := openDirectory(dir)
				if e != nil {
					t.Fatal("startup leaked lock", e)
				}
				if e = opened.Close(); e != nil {
					t.Fatal(e)
				}
			}
		})
	}
}

func TestLocalAuthorityRequestAndPeerDenialsPreserveBytes(t *testing.T) {
	for _, kind := range []string{"nil-peer", "closed-peer", "datagram-peer", "malformed", "oversize", "path-injection", "wrong-grant", "expired", "disabled", "changed-directory", "nil-admin"} {
		t.Run(kind, func(t *testing.T) {
			f := authorityFixture(t)
			if kind == "expired" {
				f.config.Now = func() time.Time { return time.Unix(f.policy.NotAfter, 0) }
			}
			if kind == "nil-admin" {
				f.config.PolicyAdministrator = nil
			}
			if kind == "wrong-grant" || kind == "disabled" {
				b, err := OpenLocalCustodyPolicy(f.config.PolicyDirectory, f.root.Trust)
				if err != nil {
					t.Fatal(err)
				}
				if kind == "disabled" {
					_, err = b.Disable(f.root.Trust)
				} else {
					p := f.policy
					p.Revision++
					p.Grants[0].UID ^= 1
					_, err = b.Install(f.root.Trust, signedPolicySnapshot(t, p, true), policyNow(p))
				}
				if err = errors.Join(err, b.Close()); err != nil {
					t.Fatal(err)
				}
			}
			a := openAuthority(t, f.config)
			data := authorityMessage(t, authorityRequest{Operation: "resume"})
			peer := f.peer
			switch kind {
			case "nil-peer":
				peer = nil
			case "closed-peer":
				if err := peer.Close(); err != nil {
					t.Fatal(err)
				}
			case "datagram-peer":
				peer, _ = custodySocketPair(t, unix.SOCK_DGRAM)
			case "malformed":
				data = []byte("{")
			case "oversize":
				data = bytes.Repeat([]byte("x"), MaxAuthorityRequestBytes+1)
			case "path-injection":
				data = authorityMessage(t, authorityRequest{Operation: "commit", Segment: "../" + testName})
			case "changed-directory":
				if err := chmodFixture(f.files.journalPath, 0755); err != nil {
					t.Fatal(err)
				}
			case "nil-admin":
				data = authorityMessage(t, authorityRequest{Operation: "inspect-policy", Change: &authorityChange{Operation: "disable"}})
			}
			before := f.bytes(t)
			_ = authorityDenied(t, a, peer, data)
			if !reflect.DeepEqual(before, f.bytes(t)) {
				t.Fatal("denial mutated state")
			}
		})
	}
}

func TestLocalAuthorityReviewedInstallDisableAndIndependentAdministration(t *testing.T) {
	f := authorityFixture(t)
	a := openAuthority(t, f.config)
	p := f.policy
	p.Revision++
	change := authorityInstall(t, p)
	for _, proposal := range []*authorityChange{change, {Operation: "disable"}} {
		before := f.bytes(t)
		plan := authorityReply(t, a, f.peer, authorityRequest{Operation: "inspect-policy", Change: proposal})
		if len(plan.Plan) == 0 || !validRecoveryApproval(plan.PlanSHA256) || len(plan.Anchor) != 0 || plan.Policy != nil {
			t.Fatal("invalid policy plan response")
		}
		if !reflect.DeepEqual(before, f.bytes(t)) {
			t.Fatal("inspection wrote")
		}
		req := authorityRequest{Operation: "apply-policy", Change: proposal, PlanSHA256: plan.PlanSHA256}
		_ = authorityDenied(t, a, f.peer, authorityMessage(t, req))
		if !reflect.DeepEqual(before, f.bytes(t)) {
			t.Fatal("unapproved apply wrote")
		}
		f.administrator.approved = plan.PlanSHA256
		out := authorityReply(t, a, f.peer, req)
		if out.Policy == nil || out.Policy.Enabled != (proposal.Operation == "install") || out.Policy.Revision != "8" || len(out.Plan) != 0 || len(out.Anchor) != 0 {
			t.Fatal("wrong policy summary")
		}
		stored := f.bytes(t)
		_ = authorityDenied(t, a, f.peer, authorityMessage(t, req))
		if !reflect.DeepEqual(stored, f.bytes(t)) {
			t.Fatal("approval replay wrote")
		}
	}
	_ = authorityDenied(t, a, f.peer, authorityMessage(t, authorityRequest{Operation: "resume"}))
	// A disabled operational policy cannot block independently approved renewal.
	p.Revision++
	change = authorityInstall(t, p)
	plan := authorityReply(t, a, f.peer, authorityRequest{Operation: "inspect-policy", Change: change})
	f.administrator.approved = plan.PlanSHA256
	authorityReply(t, a, f.peer, authorityRequest{Operation: "apply-policy", Change: change, PlanSHA256: plan.PlanSHA256})
	authorityAnchor(t, authorityReply(t, a, f.peer, authorityRequest{Operation: "resume"}), f.files.expected)
}

func TestLocalAuthorityRecoveryUsesFixedAuditedProvider(t *testing.T) {
	for _, decision := range []string{"nil", "denied", "approved"} {
		t.Run(decision, func(t *testing.T) {
			f := authorityFixture(t)
			f.files = interruptedAnchor(t, 2, false, false)
			f.config.AnchorDirectory, f.config.JournalDirectory = f.files.anchor, f.files.journal
			auth := &testRecoveryAuthorizer{decision: strings.Repeat("d", 64)}
			if decision != "nil" {
				f.config.RecoveryAuthorizer = auth
			}
			if decision == "denied" {
				auth.err = ErrRecoveryApproval
			}
			b, err := OpenLocalCustody(f.config.CustodyDirectory, testEnrollment(), nil)
			if err != nil {
				t.Fatal(err)
			}
			s, err := OpenPublishedSegment(f.files.journal, testName, contracts.JournalCheckpointContext{Anchor: f.files.expected, Authority: f.files.authority}, testLimits())
			if err != nil {
				t.Fatal(err)
			}
			intent, err := publicationIntent(s, contracts.JournalCheckpointContext{Anchor: f.files.expected, Authority: f.files.authority})
			if err = errors.Join(err, s.Close()); err != nil {
				t.Fatal(err)
			}
			l := localLease(t, b)
			if err = errors.Join(l.Prepare(intent), l.Close(), b.Close()); err != nil {
				t.Fatal(err)
			}
			a := openAuthority(t, f.config)
			before := f.bytes(t)
			plan := authorityReply(t, a, f.peer, authorityRequest{Operation: "inspect-recovery"})
			if len(plan.Plan) == 0 || !validRecoveryApproval(plan.PlanSHA256) || !reflect.DeepEqual(before, f.bytes(t)) {
				t.Fatal("invalid recovery inspection")
			}
			req := authorityRequest{Operation: "apply-recovery", PlanSHA256: plan.PlanSHA256}
			if decision == "approved" {
				authorityAnchor(t, authorityReply(t, a, f.peer, req), f.files.next)
				if auth.calls != 1 || auth.request.PlanSHA256 != plan.PlanSHA256 {
					t.Fatal("fixed recovery authorizer bypassed")
				}
				authorityAnchor(t, authorityReply(t, a, f.peer, authorityRequest{Operation: "resume"}), f.files.next)
			} else {
				_ = authorityDenied(t, a, f.peer, authorityMessage(t, req))
				if !reflect.DeepEqual(before, f.bytes(t)) {
					t.Fatal("denied recovery wrote")
				}
			}
		})
	}
}

func TestLocalAuthoritySingleSlotAndDrainingClose(t *testing.T) {
	f := authorityFixture(t)
	a := openAuthority(t, f.config)
	entered, release := make(chan struct{}), make(chan struct{})
	f.administrator.hook = func(PolicyAdministrationRequest, *PolicyAdministrationDecision) error {
		close(entered)
		<-release
		return nil
	}
	done := make(chan error, 1)
	data := authorityMessage(t, authorityRequest{Operation: "inspect-policy", Change: &authorityChange{Operation: "disable"}})
	go func() {
		out, err := a.Execute(f.peer, data)
		if err == nil && len(out) == 0 {
			err = errors.New("missing accepted response")
		}
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("operation did not enter")
	}
	peer, _ := custodySocketPair(t, unix.SOCK_STREAM)
	if err := authorityDenied(t, a, peer, authorityMessage(t, authorityRequest{Operation: "resume"})); !errors.Is(err, ErrAuthorityBusy) {
		t.Fatal("concurrent request queued", err)
	}
	if err := a.Close(); !errors.Is(err, ErrAuthorityBusy) {
		t.Fatal("close did not drain", err)
	}
	if err := authorityDenied(t, a, peer, data); !errors.Is(err, ErrClosed) {
		t.Fatal("draining authority admitted new work", err)
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("inflight resources closed prematurely", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("draining deadlock")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if a.policies != nil || a.custody != nil {
		t.Fatal("drained stores retained")
	}
	for _, dir := range a.directories {
		if dir != nil {
			t.Fatal("drained descriptors retained")
		}
	}
	// Closing the authority must not own or close the caller's peer.
	if _, err := custodyPeer(peer); err != nil {
		t.Fatal("authority closed external peer", err)
	}
	_ = authorityDenied(t, a, peer, data)
	var nilAuthority *LocalAuthority
	_ = authorityDenied(t, nilAuthority, peer, data)
	if err := nilAuthority.Close(); err != nil {
		t.Fatal(err)
	}
	var zero LocalAuthority
	_ = authorityDenied(t, &zero, peer, data)
	if err := zero.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLocalAuthorityProviderFailureReleasesSlot(t *testing.T) {
	f := authorityFixture(t)
	a := openAuthority(t, f.config)
	f.administrator.hook = func(PolicyAdministrationRequest, *PolicyAdministrationDecision) error {
		return errors.New("synthetic provider failure")
	}
	before := f.bytes(t)
	_ = authorityDenied(t, a, f.peer, authorityMessage(t, authorityRequest{Operation: "inspect-policy", Change: &authorityChange{Operation: "disable"}}))
	if !reflect.DeepEqual(before, f.bytes(t)) {
		t.Fatal("provider failure wrote")
	}
	authorityAnchor(t, authorityReply(t, a, f.peer, authorityRequest{Operation: "resume"}), f.files.expected)
}

func TestLocalAuthorityFixedBoundsAndTrustCannotBeReplaced(t *testing.T) {
	for _, kind := range []string{"frame-limit", "bad-signature", "different-policy", "different-enrollment", "changed-during-callback", "expired-during-callback"} {
		t.Run(kind, func(t *testing.T) {
			f := authorityFixture(t)
			now := policyNow(f.policy)
			f.config.Now = func() time.Time { return now }
			if kind == "frame-limit" {
				f.config.Limits.MaxFrames = 1
			}
			a := openAuthority(t, f.config)
			p := f.policy
			p.Revision++
			if kind == "different-policy" {
				p.PolicyID = "policy.other"
			}
			if kind == "different-enrollment" {
				p.Enrollment.Authority.LastSequence++
			}
			change := authorityInstall(t, p)
			if kind == "bad-signature" {
				change.Signature = strings.Repeat("0", 128)
			}
			req := authorityRequest{Operation: "inspect-policy", Change: change}
			if kind == "frame-limit" {
				req = authorityRequest{Operation: "commit", Segment: testName}
			}
			if kind == "changed-during-callback" {
				f.administrator.hook = func(PolicyAdministrationRequest, *PolicyAdministrationDecision) error {
					return chmodFixture(f.files.journalPath, 0755)
				}
			}
			if kind == "expired-during-callback" {
				f.administrator.hook = func(PolicyAdministrationRequest, *PolicyAdministrationDecision) error {
					now = time.Unix(p.NotAfter, 0)
					return nil
				}
			}
			before := f.bytes(t)
			_ = authorityDenied(t, a, f.peer, authorityMessage(t, req))
			if !reflect.DeepEqual(before, f.bytes(t)) {
				t.Fatal("invalid bound input wrote")
			}
		})
	}
}

func TestLocalAuthoritySeparateHandlesAndReentrantClose(t *testing.T) {
	f := authorityFixture(t)
	a := openAuthority(t, f.config)
	other := openAuthority(t, f.config)
	request := authorityMessage(t, authorityRequest{Operation: "inspect-policy", Change: &authorityChange{Operation: "disable"}})
	f.administrator.hook = func(PolicyAdministrationRequest, *PolicyAdministrationDecision) error {
		if out, err := a.Execute(f.peer, request); !errors.Is(err, ErrAuthorityBusy) || out != nil {
			return errors.New("recursive request did not fail immediately")
		}
		if out, err := other.Execute(f.peer, authorityMessage(t, authorityRequest{Operation: "resume"})); err == nil || out != nil {
			return errors.New("second handle bypassed protected policy lock")
		}
		if err := a.Close(); !errors.Is(err, ErrAuthorityBusy) {
			return errors.New("reentrant close did not drain")
		}
		return nil
	}
	authorityReply(t, a, f.peer, authorityRequest{Operation: "inspect-policy", Change: &authorityChange{Operation: "disable"}})
	_ = authorityDenied(t, a, f.peer, request)
	authorityAnchor(t, authorityReply(t, other, f.peer, authorityRequest{Operation: "resume"}), f.files.expected)
}
