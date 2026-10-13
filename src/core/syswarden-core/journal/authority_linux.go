package journal

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	contracts "syswarden-core/contracts/v5"
)

var ErrAuthorityBusy = errors.New("local authority already has an admitted operation")

// LocalAuthorityConfig is privileged startup configuration, never request input.
// Directories, independent root/enrollment, limits, clock and authorizers must be
// provisioned through a trusted OS/service boundary. Nil authorizers deny their
// operations. They are not supplied by a producer, browser or accepted socket.
type LocalAuthorityConfig struct {
	PolicyDirectory     *os.File
	CustodyDirectory    *os.File
	AnchorDirectory     *os.File
	JournalDirectory    *os.File
	PolicyRoot          CustodyPolicyTrust
	Enrollment          CustodyEnrollment
	Limits              Limits
	Now                 func() time.Time
	RecoveryAuthorizer  CustodyRecoveryAuthorizer
	PolicyAdministrator PolicyAdministrationAuthorizer
}

// LocalAuthority owns a fixed resource binding and a single nonqueued execution
// slot. Do not copy it. This is an inactive dispatcher, not a listener, network
// framing implementation, bootstrap service or cross-UID isolation mechanism.
type LocalAuthority struct {
	mu                    sync.Mutex
	busy, closing, closed bool
	directories           [4]*os.File
	stamps                [4]unix.Stat_t
	policies              *LocalCustodyPolicy
	custody               *LocalCustody
	root                  CustodyPolicyTrust
	limits                Limits
	now                   func() time.Time
	administrator         PolicyAdministrationAuthorizer
}

// OpenLocalAuthority only opens already provisioned state. It neither creates
// files/accounts nor discovers paths, issuers or enrollment from client input.
// Pending custody and expired/disabled policy may open for reviewed recovery;
// each operation still enforces its own current authority and exact state.
func OpenLocalAuthority(c LocalAuthorityConfig) (*LocalAuthority, error) {
	if c.Now == nil || !validPolicyRoot(c.PolicyRoot) {
		return nil, ErrInvalidOptions
	}
	enrolled, err := custodyEnrollment(c.Enrollment)
	if err != nil {
		return nil, err
	}
	if _, err = contracts.ScanEventJournal(nil, contracts.JournalReadContext{Start: c.Enrollment.Initial.Cursor, MaxBytes: c.Limits.MaxBytes, MaxFrames: c.Limits.MaxFrames}); err != nil {
		return nil, ErrInvalidOptions
	}
	a := &LocalAuthority{root: clonePolicyTrust(c.PolicyRoot), limits: c.Limits, now: c.Now, administrator: c.PolicyAdministrator}
	fail := func(err error) (*LocalAuthority, error) { return nil, errors.Join(err, a.closeResources()) }
	for i, dir := range [4]*os.File{c.PolicyDirectory, c.CustodyDirectory, c.AnchorDirectory, c.JournalDirectory} {
		owned, e := openDirectory(dir)
		if e != nil {
			return fail(e)
		}
		a.directories[i] = owned
		if e = unix.Fstat(int(owned.Fd()), &a.stamps[i]); e != nil {
			return fail(e)
		}
		for j := 0; j < i; j++ {
			if a.stamps[i].Dev == a.stamps[j].Dev && a.stamps[i].Ino == a.stamps[j].Ino {
				return fail(ErrUnsafeStorage)
			}
		}
		if e = unix.Flock(int(owned.Fd()), unix.LOCK_UN); e != nil {
			return fail(e)
		}
	}
	a.policies, err = OpenLocalCustodyPolicy(a.directories[0], a.root)
	if err != nil {
		return fail(err)
	}
	current, err := a.policies.Current()
	if err != nil {
		return fail(err)
	}
	policy, err := authenticatePolicySnapshot(current)
	if err != nil {
		return fail(err)
	}
	policyEnrollment, err := custodyEnrollment(policy.Enrollment)
	if err != nil || !sameRestartState(policyEnrollment, enrolled) {
		return fail(errors.Join(ErrCustodyState, err))
	}
	a.custody, err = OpenLocalCustody(a.directories[1], c.Enrollment, c.RecoveryAuthorizer)
	if err != nil {
		return fail(err)
	}
	if err = a.attestDirectories(); err != nil {
		return fail(err)
	}
	return a, nil
}

func (a *LocalAuthority) attestDirectories() error {
	for i, dir := range a.directories {
		if dir == nil {
			return ErrClosed
		}
		var st unix.Stat_t
		if err := unix.Fstat(int(dir.Fd()), &st); err != nil || !privateDirectory(st) || st.Dev != a.stamps[i].Dev || st.Ino != a.stamps[i].Ino || st.Gid != a.stamps[i].Gid {
			return errors.Join(ErrUnsafeStorage, err)
		}
	}
	return nil
}

func (a *LocalAuthority) begin() error {
	if a == nil {
		return ErrClosed
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closing || a.closed || a.policies == nil || a.custody == nil {
		return ErrClosed
	}
	if a.busy {
		return ErrAuthorityBusy
	}
	a.busy = true
	return nil
}
func (a *LocalAuthority) finish() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.busy = false
	if a.closing {
		return a.closeResources()
	}
	return nil
}
func (a *LocalAuthority) closeResources() error {
	var err error
	if a.policies != nil {
		err = errors.Join(err, a.policies.Close())
		a.policies = nil
	}
	if a.custody != nil {
		err = errors.Join(err, a.custody.Close())
		a.custody = nil
	}
	for i, dir := range a.directories {
		if dir != nil {
			err = errors.Join(err, dir.Close())
			a.directories[i] = nil
		}
	}
	a.closed = true
	return err
}

// Close prevents new work immediately. If one operation is active it returns
// ErrAuthorityBusy; that operation keeps owned resources until completion, then
// closes them. Call Close again to observe closure. It does not cancel disk I/O,
// interrupt authority callbacks, revoke an issued approval or close peer sockets.
func (a *LocalAuthority) Close() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.closing = true
	if a.closed {
		return nil
	}
	if a.busy {
		return ErrAuthorityBusy
	}
	return a.closeResources()
}

// Execute handles one already bounded canonical message on a live accepted Unix
// peer. It owns neither the socket nor its I/O; a future transport must bound
// framing, connections, timeouts and denial handling before calling this method.
// One execution is admitted per handle, with no queued request or automatic retry.
// Errors return no response bytes. Internal error details and successful plans
// are private: a transport must not echo them to an unauthenticated requester.
// Every mutating operation delegates its existing policy/custody/approval checks.
func (a *LocalAuthority) Execute(peer *net.UnixConn, data []byte) (response []byte, err error) {
	if err = a.begin(); err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, a.finish())
		if err != nil {
			response = nil
		}
	}()
	if err = a.attestDirectories(); err != nil {
		return nil, err
	}
	request, err := decodeAuthorityRequest(data)
	if err != nil {
		return nil, err
	}
	if _, err = custodyPeer(peer); err != nil {
		return nil, err
	}
	bound := CustodyPolicyRequest{Peer: peer, Now: a.now}
	out := authorityResponse{Schema: AuthorityResponseSchema, ID: request.ID, Operation: request.Operation}
	var anchor contracts.JournalCheckpointAnchor
	switch request.Operation {
	case "resume":
		anchor, err = ResumePolicyCustody(a.policies, bound, a.custody, a.directories[2])
	case "commit":
		anchor, err = CommitPolicyPublication(a.policies, bound, a.custody, a.directories[2], a.directories[3], request.Segment, a.limits)
	case "inspect-recovery":
		var plan AnchorRecoveryPlan
		plan, err = PlanPolicyRecovery(a.policies, bound, a.custody, a.directories[2], a.directories[3])
		out.Plan, out.PlanSHA256 = plan.Document, plan.SHA256
	case "apply-recovery":
		anchor, err = ApplyPolicyRecovery(a.policies, bound, a.custody, a.directories[2], a.directories[3], request.PlanSHA256)
	case "inspect-policy", "apply-policy":
		var change CustodyPolicyChange
		change, err = authorityChangeProposal(request.Change, a.root)
		if err != nil {
			return nil, err
		}
		if request.Operation == "inspect-policy" {
			var plan CustodyPolicyChangePlan
			plan, err = PlanCustodyPolicyChange(a.policies, bound, a.administrator, change)
			out.Plan, out.PlanSHA256 = plan.Document, plan.SHA256
		} else {
			var next CustodyPolicySnapshot
			next, err = ApplyCustodyPolicyChange(a.policies, bound, a.administrator, change, request.PlanSHA256)
			if err == nil {
				out.Policy = authorityPolicySummary(next)
			}
		}
	default:
		return nil, ErrAuthorityRequest
	}
	if err != nil {
		return nil, err
	}
	if request.Operation == "resume" || request.Operation == "commit" || request.Operation == "apply-recovery" {
		out.Anchor, err = encodeAnchor(anchor)
		if err != nil {
			return nil, err
		}
	}
	if err = a.attestDirectories(); err != nil {
		return nil, err
	}
	response, err = json.Marshal(out)
	if err != nil || len(response) > MaxAuthorityResponseBytes {
		return nil, errors.Join(ErrAuthorityRequest, err)
	}
	return response, nil
}
