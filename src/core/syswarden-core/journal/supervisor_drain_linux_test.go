package journal

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestAuthorityServerDrainRetainsRecoveryCustody(t *testing.T) {
	for _, kind := range []string{"approved", "denied", "expired", "changed-pin", "concurrent-close", "without-serve"} {
		t.Run(kind, func(t *testing.T) {
			f, c, path := serverFixture(t)
			s := testServer(t, c)
			request := authorityRequest{Operation: "inspect-policy", Change: &authorityChange{Operation: "disable"}}
			plan := authorityReply(t, s.transport.authority, f.peer, request)
			f.administrator.approved = plan.PlanSHA256
			before := f.bytes(t)
			entered, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			defer once.Do(func() { close(release) })
			f.administrator.hook = func(_ PolicyAdministrationRequest, d *PolicyAdministrationDecision) error {
				close(entered)
				<-release
				if kind == "denied" {
					return ErrPolicyApproval
				}
				if kind == "expired" {
					d.NotAfter = d.NotBefore
					d.NotBefore -= 60 // Valid interval, expired at the current boundary.
				}
				return nil
			}
			var done <-chan error
			var peer *net.UnixConn
			if kind == "without-serve" {
				// Defensive internal composition case: no supervisor worker set,
				// but an independently admitted transport call still owns custody.
				serverPeer, clientPeer := custodySocketPair(t, unix.SOCK_STREAM)
				peer = clientPeer
				result := make(chan error, 1)
				go func() { result <- s.transport.ServePeer(serverPeer) }()
				done = result
			} else {
				done = runServer(s)
				peer = serverClient(t, path)
			}
			request.Operation, request.PlanSHA256 = "apply-policy", plan.PlanSHA256
			transportSend(t, peer, transportFrame(authorityMessage(t, request)))
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("admitted operation did not reach decision boundary")
			}
			pinPath := filepath.Join(c.PinDirectory.Name(), AuthorityEndpointPinName)
			if kind == "changed-pin" {
				if err := os.WriteFile(pinPath, append(readFile(t, pinPath), ' '), 0600); err != nil {
					t.Fatal(err)
				}
			}
			paths := []string{path, filepath.Join(filepath.Dir(path), AuthorityEndpointRecordName), pinPath}
			lifecycle := endpointRecoverySnapshot(t, paths)
			if !errors.Is(s.Close(), ErrAuthorityServerBusy) {
				t.Fatal("active operation did not retain busy lifecycle")
			}
			if kind == "concurrent-close" {
				results := make(chan error, 8)
				for range 8 {
					go func() { results <- s.Close() }()
				}
				for range 8 {
					if err := transportResult(t, results); !errors.Is(err, ErrAuthorityServerBusy) {
						t.Fatal("concurrent close lost drain", err)
					}
				}
			}
			requireEndpointRecoverySnapshot(t, lifecycle, paths)
			if conn, err := net.DialTimeout("unix", path, time.Second); !errors.Is(err, unix.ECONNREFUSED) {
				if conn != nil {
					_ = conn.Close()
				}
				t.Fatal("stopping retained active listener", err)
			}
			if p, err := readEndpointPin(c.PinDirectory); p != nil || !errors.Is(err, ErrLocked) {
				t.Fatal("drain released private pin lock", err)
			}
			if next, err := openAuthoritySocket(c.Directory, c.GroupID, 1); next != nil || !errors.Is(err, ErrLocked) {
				t.Fatal("drain released endpoint lock", err)
			}
			recovery := EndpointRecoveryConfig{Directory: c.Directory, PinDirectory: c.PinDirectory, GroupID: c.GroupID, Peer: f.peer, Now: c.Authority.Now,
				Authorizer: endpointTestAuthorizer(func(EndpointRecoveryRequest) (EndpointRecoveryDecision, error) {
					t.Fatal("offline recovery reached approval while service was draining")
					return EndpointRecoveryDecision{}, ErrEndpointRecoveryApproval
				}),
			}
			for range 2 {
				if _, err := PlanEndpointRecovery(recovery); !errors.Is(err, ErrLocked) {
					t.Fatal("draining recovery inspection admitted", err)
				}
				if _, err := ApplyEndpointRecovery(recovery, strings.Repeat("0", 64)); !errors.Is(err, ErrLocked) {
					t.Fatal("draining recovery apply admitted", err)
				}
				// The external pin provider must obey the same endpoint lease.
				recovery.PinDirectory = nil
				recovery.ExpectedRecordSHA256 = recoveryDigest(s.socket.record)
			}
			requireEndpointRecoverySnapshot(t, lifecycle, paths)
			if !reflect.DeepEqual(before, f.bytes(t)) {
				t.Fatal("pre-decision shutdown modified authority state")
			}
			select {
			case err := <-done:
				t.Fatal("service returned before approved work completed", err)
			default:
			}
			once.Do(func() { close(release) })
			err := transportResult(t, done)
			if kind == "changed-pin" {
				if !errors.Is(err, ErrAuthorityEndpoint) {
					t.Fatal("changed lifecycle cleanup was accepted", err)
				}
				requireEndpointRecoverySnapshot(t, lifecycle, paths)
			} else {
				if kind == "without-serve" {
					if !errors.Is(err, ErrClosed) {
						t.Fatal("drained transport did not suppress reply", err)
					}
					err = s.Close()
				}
				if err != nil {
					t.Fatal("drained service cleanup failed", err)
				}
				for _, path := range paths {
					if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
						t.Fatal("completed drain retained owned artifact", err)
					}
				}
			}
			if data, err := io.ReadAll(peer); err != nil || len(data) != 0 {
				t.Fatal("shutdown exposed an uncertain operation reply", err)
			}
			policy, err := OpenLocalCustodyPolicy(c.Authority.PolicyDirectory, f.root.Trust)
			if err != nil {
				t.Fatal(err)
			}
			wantEnabled := kind == "denied" || kind == "expired"
			if policyCurrent(t, policy).Trust.Enabled != wantEnabled {
				t.Fatal("shutdown changed the approved operation's outcome")
			}
			if err := policy.Close(); err != nil {
				t.Fatal(err)
			}
			if wantEnabled && !reflect.DeepEqual(before, f.bytes(t)) {
				t.Fatal("denied approval wrote state during shutdown")
			}
			// Independently opened descriptions become available only after drain.
			pin, err := openEndpointPinDirectory(c.PinDirectory)
			if err != nil {
				t.Fatal("completed drain retained private lease", err)
			}
			if err := pin.close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAuthoritySocketStopsAcceptsBeforeExactCleanup(t *testing.T) {
	dir, path, gid := endpointFixture(t)
	s := testEndpoint(t, dir, gid)
	paths := []string{filepath.Join(path, AuthoritySocketName), filepath.Join(path, AuthorityEndpointRecordName)}
	before := endpointRecoverySnapshot(t, paths)
	for range 2 {
		if err := s.stopListening(); err != nil {
			t.Fatal(err)
		}
		if err := s.Attest(); err != nil {
			t.Fatal("stopped endpoint lost custody", err)
		}
		requireEndpointRecoverySnapshot(t, before, paths)
	}
	if err := s.Close(); err != nil {
		t.Fatal("final close repeated listener close", err)
	}
	if err := s.stopListening(); err != nil {
		t.Fatal("stopped listener lost cached result", err)
	}
	for _, path := range paths {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("exact cleanup incomplete", err)
		}
	}
}
