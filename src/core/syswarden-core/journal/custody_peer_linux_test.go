package journal

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	contracts "syswarden-core/contracts/v5"
)

func custodySocketPair(t *testing.T, kind int) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, kind|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	connections := make([]*net.UnixConn, 0, 2)
	for _, fd := range fds {
		f := os.NewFile(uintptr(fd), "synthetic-custody-peer")
		conn, err := net.FileConn(f)
		closeErr := f.Close()
		if err != nil || closeErr != nil {
			t.Fatal(errors.Join(err, closeErr))
		}
		u, ok := conn.(*net.UnixConn)
		if !ok {
			_ = conn.Close()
			t.Fatal("not a Unix connection")
		}
		t.Cleanup(func() { _ = u.Close() })
		connections = append(connections, u)
	}
	return connections[0], connections[1]
}
func hostTestUID(t *testing.T) uint32 {
	t.Helper()
	n, err := strconv.ParseUint(strconv.Itoa(os.Geteuid()), 10, 32)
	if err != nil || n >= 1<<32-1 {
		t.Fatal("invalid test UID")
	}
	return uint32(n)
}
func peerTestPolicy(t *testing.T, ops ...CustodyOperation) CustodyAccessPolicy {
	t.Helper()
	p := testCustodyPolicy()
	p.Grants = []CustodyLocalGrant{{UID: hostTestUID(t), Operations: ops}}
	return p
}
func requireNoAdmission(t *testing.T, got CustodyAdmission, err error) {
	t.Helper()
	if err == nil || !reflect.DeepEqual(got, CustodyAdmission{}) {
		t.Fatal("rejection exposed admission", err)
	}
}

func TestCustodyPeerAdmissionMatrix(t *testing.T) {
	conn, other := custodySocketPair(t, unix.SOCK_STREAM)
	ops := []CustodyOperation{CustodyApplyRecovery, CustodyCommit, CustodyInspectRecovery, CustodyResume}
	for _, grant := range ops {
		for _, requested := range append(append([]CustodyOperation{}, ops...), "prepare", "finish", "bootstrap", "", "COMMIT", "rotate-key") {
			t.Run(string(grant)+"/"+string(requested), func(t *testing.T) {
				p := peerTestPolicy(t, grant)
				data, sig, trust := signTestPolicy(t, p)
				got, err := AdmitLocalCustody(conn, data, sig, trust, policyNow(p), requested)
				if requested != grant {
					requireNoAdmission(t, got, err)
					return
				}
				if err != nil || got.UID != hostTestUID(t) || int(got.GID) != os.Getegid() || int(got.PID) != os.Getpid() || got.Operation != grant || got.PolicySHA256 != trust.PolicySHA256 || got.Revision != p.Revision || got.Enrollment.Initial != p.Enrollment.Initial || got.NotAfter != p.NotAfter {
					t.Fatal("incorrect kernel-bound admission", err)
				}
			})
		}
	}
	// Admission must neither consume request bytes nor close either descriptor.
	if _, err := other.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1)
	if _, err := io.ReadFull(conn, b); err != nil || b[0] != 'x' {
		t.Fatal("admission changed socket ownership", err)
	}
}

func TestCustodyPeerRefusesInvalidSocketsAndUnlistedIdentity(t *testing.T) {
	for _, kind := range []string{"nil", "closed", "datagram", "unconnected", "no-grants", "wrong-uid", "revoked", "expired"} {
		t.Run(kind, func(t *testing.T) {
			p := peerTestPolicy(t, CustodyResume)
			var conn *net.UnixConn
			if kind != "nil" {
				mode := unix.SOCK_STREAM
				if kind == "datagram" {
					mode = unix.SOCK_DGRAM
				}
				conn, _ = custodySocketPair(t, mode)
			}
			if kind == "closed" {
				_ = conn.Close()
			}
			if kind == "unconnected" {
				fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
				if err != nil {
					t.Fatal(err)
				}
				f := os.NewFile(uintptr(fd), "unconnected-custody")
				raw, err := net.FileConn(f)
				_ = f.Close()
				if err != nil {
					t.Fatal(err)
				}
				conn = raw.(*net.UnixConn)
				defer func() { _ = conn.Close() }()
			}
			if kind == "no-grants" {
				p.Grants = nil
			}
			if kind == "wrong-uid" {
				if p.Grants[0].UID == 0 {
					p.Grants[0].UID = 1
				} else {
					p.Grants[0].UID = 0
				}
			}
			data, sig, trust := signTestPolicy(t, p)
			now := policyNow(p)
			if kind == "revoked" {
				trust.Enabled = false
			}
			if kind == "expired" {
				now = time.Unix(p.NotAfter, 0)
			}
			got, err := AdmitLocalCustody(conn, data, sig, trust, now, CustodyResume)
			requireNoAdmission(t, got, err)
		})
	}
}

func TestCustodyPeerRechecksPolicyOnExistingConnection(t *testing.T) {
	conn, _ := custodySocketPair(t, unix.SOCK_STREAM)
	p := peerTestPolicy(t, CustodyCommit, CustodyResume)
	data, sig, trust := signTestPolicy(t, p)
	if _, err := AdmitLocalCustody(conn, data, sig, trust, policyNow(p), CustodyCommit); err != nil {
		t.Fatal(err)
	}
	p.Revision++
	p.Grants[0].Operations = []CustodyOperation{CustodyResume}
	newData, newSig, newTrust := signTestPolicy(t, p)
	got, err := AdmitLocalCustody(conn, data, sig, newTrust, policyNow(p), CustodyCommit)
	requireNoAdmission(t, got, err)
	got, err = AdmitLocalCustody(conn, newData, newSig, newTrust, policyNow(p), CustodyCommit)
	requireNoAdmission(t, got, err)
	if _, err := AdmitLocalCustody(conn, newData, newSig, newTrust, policyNow(p), CustodyResume); err != nil {
		t.Fatal("new read policy rejected", err)
	}
	newTrust.Enabled = false
	got, err = AdmitLocalCustody(conn, newData, newSig, newTrust, policyNow(p), CustodyResume)
	requireNoAdmission(t, got, err)
}

func TestCustodyPeerConcurrentIndependentResults(t *testing.T) {
	conn, _ := custodySocketPair(t, unix.SOCK_STREAM)
	p := peerTestPolicy(t, CustodyResume)
	data, sig, trust := signTestPolicy(t, p)
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			for range 10 {
				got, err := AdmitLocalCustody(conn, data, sig, trust, policyNow(p), CustodyResume)
				if err != nil {
					t.Error(err)
					return
				}
				got.Enrollment.Authority.PublicKey[0] ^= 1
			}
		})
	}
	group.Wait()
	if _, err := AdmitLocalCustody(conn, data, sig, trust, policyNow(p), CustodyResume); err != nil {
		t.Fatal(err)
	}
}

func TestCustodyPeerChild(t *testing.T) {
	path := os.Getenv("SYSWARDEN_SYNTHETIC_CUSTODY_SOCKET")
	if path == "" {
		return
	}
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Net: "unix", Name: path})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err = conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// Claimed UID in request bytes is deliberately unrelated to kernel identity.
	if _, err = conn.Write([]byte("uid=0\n")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1)
	if _, err = io.ReadFull(conn, b); err != nil {
		t.Fatal(err)
	}
}

func TestCustodyPeerActualProcessCredentials(t *testing.T) {
	path, err := os.MkdirTemp("", "swj-peer-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(path) })
	socket := filepath.Join(path, "authority.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: socket})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	if err = listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/proc/self/exe", "-test.run=^TestCustodyPeerChild$", "-test.timeout=10s")
	cmd.Env = append(os.Environ(), "SYSWARDEN_SYNTHETIC_CUSTODY_SOCKET="+socket)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	conn, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	p := peerTestPolicy(t, CustodyResume)
	data, sig, trust := signTestPolicy(t, p)
	got, err := AdmitLocalCustody(conn, data, sig, trust, policyNow(p), CustodyResume)
	if err != nil || int(got.PID) != cmd.Process.Pid || got.UID != hostTestUID(t) {
		t.Fatal("peer did not come from child kernel credentials", err)
	}
	if err = conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	claimed := make([]byte, 6)
	if _, err = io.ReadFull(conn, claimed); err != nil || string(claimed) != "uid=0\n" {
		t.Fatal("claimed UID fixture", err)
	}
	if _, err = conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err = cmd.Wait(); err != nil {
		t.Fatal(err, output.String())
	}
}

func TestCustodyPeerAdmissionCannotAuthorizeRecovery(t *testing.T) {
	f := interruptedAnchor(t, 1, false, false)
	b, _, path := localCustodyFixture(t, nil)
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
	lease := localLease(t, b)
	if err = lease.Prepare(intent); err != nil {
		t.Fatal(err)
	}
	if err = lease.Close(); err != nil {
		t.Fatal(err)
	}
	plan, err := PlanCustodiedRecovery(b, f.anchor, f.journal)
	if err != nil {
		t.Fatal(err)
	}
	before := f.bytes(t)
	custodyBefore := readFile(t, filepath.Join(path, custodyFileName))
	conn, _ := custodySocketPair(t, unix.SOCK_STREAM)
	p := peerTestPolicy(t, CustodyApplyRecovery)
	data, sig, trust := signTestPolicy(t, p)
	if _, err = AdmitLocalCustody(conn, data, sig, trust, policyNow(p), CustodyApplyRecovery); err != nil {
		t.Fatal(err)
	}
	next, err := ApplyCustodiedRecovery(b, f.anchor, f.journal, plan.SHA256)
	if !errors.Is(err, ErrRecoveryApproval) || next != (contracts.JournalCheckpointAnchor{}) {
		t.Fatal("socket grant bypassed independent recovery approval", err)
	}
	requireSameRecoveryBytes(t, before, f.bytes(t))
	if !bytes.Equal(custodyBefore, readFile(t, filepath.Join(path, custodyFileName))) {
		t.Fatal("denied recovery changed custody")
	}
}
