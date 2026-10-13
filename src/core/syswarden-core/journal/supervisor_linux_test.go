package journal

import (
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"
)

func serverFixture(t *testing.T) (authorityFixtureState, AuthorityServerConfig, string) {
	t.Helper()
	f := authorityFixture(t)
	dir, path, gid := endpointFixture(t)
	pin, _ := testDirectory(t)
	return f, AuthorityServerConfig{Authority: f.config, Transport: testTransportLimits(), Directory: dir, PinDirectory: pin, GroupID: gid, AcceptInterval: MinAuthorityAcceptInterval}, filepath.Join(path, AuthoritySocketName)
}
func testServer(t *testing.T, c AuthorityServerConfig) *LocalAuthorityServer {
	t.Helper()
	s, err := OpenLocalAuthorityServer(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
func runServer(s *LocalAuthorityServer) <-chan error {
	done := make(chan error, 1)
	go func() { done <- s.Serve() }()
	return done
}
func serverWait(t *testing.T, s *LocalAuthorityServer, predicate func(AuthorityServerStatus) bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if predicate(s.Status()) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("server state not reached", s.Status())
}
func serverClient(t *testing.T, path string) *net.UnixConn {
	t.Helper()
	c, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	peer, ok := c.(*net.UnixConn)
	if !ok {
		_ = c.Close()
		t.Fatal("unexpected socket type")
	}
	t.Cleanup(func() { _ = peer.Close() })
	if err := peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return peer
}
func serverRequest(t *testing.T, path string, req authorityRequest) authorityResponse {
	t.Helper()
	c := serverClient(t, path)
	transportSend(t, c, transportFrame(authorityMessage(t, req)))
	body := transportRead(t, c)
	var out authorityResponse
	if err := json.Unmarshal(body, &out); err != nil || out.Schema != AuthorityResponseSchema || out.Operation != req.Operation {
		t.Fatal("invalid server response", err)
	}
	return out
}
func stopServer(t *testing.T, s *LocalAuthorityServer, done <-chan error) {
	t.Helper()
	err := s.Close()
	if err != nil && !errors.Is(err, ErrAuthorityServerBusy) {
		t.Fatal(err)
	}
	if err := transportResult(t, done); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	st := s.Status()
	if st.Running || !st.Closing || st.Active != 0 {
		t.Fatal("server not drained", st)
	}
}
func TestAuthorityServerRoundTripDenialAndReopen(t *testing.T) {
	f, c, path := serverFixture(t)
	s := testServer(t, c)
	done := runServer(s)
	serverWait(t, s, func(st AuthorityServerStatus) bool { return st.Running })
	if !errors.Is(s.Serve(), ErrAuthorityServerBusy) {
		t.Fatal("second worker set started")
	}
	before := f.bytes(t)
	peer := serverClient(t, path)
	transportSend(t, peer, transportFrame([]byte(`{"uid":0}`)))
	transportDenial(t, peer)
	if !reflect.DeepEqual(before, f.bytes(t)) {
		t.Fatal("invalid request changed state")
	}
	authorityAnchor(t, serverRequest(t, path, authorityRequest{Operation: "resume"}), f.files.expected)
	authorityAnchor(t, serverRequest(t, path, authorityRequest{Operation: "commit", Segment: testName}), f.files.next)
	serverWait(t, s, func(st AuthorityServerStatus) bool { return st.Completed == 2 && st.Failed == 1 && st.Active == 0 })
	if s.Status().Accepted != 3 {
		t.Fatal("wrong bounded diagnostics", s.Status())
	}
	stopServer(t, s, done)
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("socket retained", err)
	}
	s = testServer(t, c)
	done = runServer(s)
	authorityAnchor(t, serverRequest(t, path, authorityRequest{Operation: "resume"}), f.files.next)
	stopServer(t, s, done)
}
func TestAuthorityServerCapacityAndCloseWaiters(t *testing.T) {
	_, c, path := serverFixture(t)
	c.Transport.ReadTimeout = MaxAuthorityIOTimeout
	s := testServer(t, c)
	done := runServer(s)
	a, b := serverClient(t, path), serverClient(t, path)
	serverWait(t, s, func(st AuthorityServerStatus) bool { return st.Active == 2 })
	// The third connected peer waits in the kernel backlog; no user-space queue
	// or worker is created for it while both fixed workers are occupied.
	extra := serverClient(t, path)
	if _, err := extra.Write(transportFrame([]byte(`{}`))); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	if st := s.Status(); st.Active != 2 || st.Accepted != 2 {
		t.Fatal("connection capacity bypass", st)
	}
	stopServer(t, s, done)
	for _, peer := range []*net.UnixConn{a, b, extra} {
		transportDenial(t, peer)
	}
}
func TestAuthorityServerTimeoutContinuesAndIdleClose(t *testing.T) {
	f, c, path := serverFixture(t)
	c.Transport.MaxPeers, c.Transport.MaxPeersPerUID = 1, 1
	c.Transport.ReadTimeout = 30 * time.Millisecond
	s := testServer(t, c)
	done := runServer(s)
	peer := serverClient(t, path)
	transportDenial(t, peer)
	authorityAnchor(t, serverRequest(t, path, authorityRequest{Operation: "resume"}), f.files.expected)
	stopServer(t, s, done)
}
func TestAuthorityServerStopsAndPreservesChangedEndpoint(t *testing.T) {
	f, c, path := serverFixture(t)
	s := testServer(t, c)
	done := runServer(s)
	serverWait(t, s, func(st AuthorityServerStatus) bool { return st.Running })
	before := f.bytes(t)
	if err := chmodFixture(path, 0600); err != nil {
		t.Fatal(err)
	}
	peer := serverClient(t, path)
	// Do not send a frame: the metadata check must precede request processing.
	transportDenial(t, peer)
	if !errors.Is(transportResult(t, done), ErrAuthorityEndpoint) {
		t.Fatal("unsafe endpoint not fatal")
	}
	if !errors.Is(s.Close(), ErrAuthorityEndpoint) {
		t.Fatal("cleanup loss not retained")
	}
	if !reflect.DeepEqual(before, f.bytes(t)) {
		t.Fatal("unsafe endpoint changed state")
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatal("modified endpoint removed", err)
	}
}
func TestAuthorityServerDrainsApprovedMutation(t *testing.T) {
	f, c, path := serverFixture(t)
	s := testServer(t, c)
	plan := authorityReply(t, s.transport.authority, f.peer, authorityRequest{Operation: "inspect-policy", Change: &authorityChange{Operation: "disable"}})
	f.administrator.approved = plan.PlanSHA256
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	f.administrator.hook = func(PolicyAdministrationRequest, *PolicyAdministrationDecision) error {
		close(entered)
		<-release
		return nil
	}
	done := runServer(s)
	peer := serverClient(t, path)
	transportSend(t, peer, transportFrame(authorityMessage(t, authorityRequest{Operation: "apply-policy", Change: &authorityChange{Operation: "disable"}, PlanSHA256: plan.PlanSHA256})))
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("approved write not reached")
	}
	if !errors.Is(s.Close(), ErrAuthorityServerBusy) {
		t.Fatal("active drain not reported")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("admission endpoint retained", err)
	}
	select {
	case err := <-done:
		t.Fatal("active mutation abandoned", err)
	default:
	}
	once.Do(func() { close(release) })
	if err := transportResult(t, done); err != nil {
		t.Fatal(err)
	}
	if data, err := io.ReadAll(peer); err != nil || len(data) != 0 {
		t.Fatal("lost reply exposed result", err)
	}
	b, err := OpenLocalCustodyPolicy(f.config.PolicyDirectory, f.root.Trust)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	if policyCurrent(t, b).Trust.Enabled {
		t.Fatal("approved mutation rolled back on close")
	}
}
func TestAuthorityServerPacingAndCancellation(t *testing.T) {
	_, c, path := serverFixture(t)
	c.Transport.MaxPeers, c.Transport.MaxPeersPerUID = 1, 1
	c.AcceptInterval = 100 * time.Millisecond
	s := testServer(t, c)
	done := runServer(s)
	started := time.Now()
	for range 4 {
		peer := serverClient(t, path)
		transportSend(t, peer, transportFrame([]byte(`{}`)))
		transportDenial(t, peer)
	}
	// Even immediately rejected frames must consume accept slots. Generous upper
	// bounds avoid treating unrelated CI scheduling pressure as a protocol defect.
	if elapsed := time.Since(started); elapsed < 3*c.AcceptInterval || elapsed > 4*time.Second {
		t.Fatal("accept pacing not bounded", elapsed)
	}
	stopServer(t, s, done)
	// Test cancellation of a long reserved pacing wait without sleeping through it.
	pending := &LocalAuthorityServer{config: AuthorityServerConfig{AcceptInterval: time.Second}, stop: make(chan struct{}), next: time.Now().Add(time.Hour)}
	result := make(chan bool, 1)
	go func() { result <- pending.permit() }()
	if err := pending.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case ok := <-result:
		if ok {
			t.Fatal("closing admitted paced work")
		}
	case <-time.After(time.Second):
		t.Fatal("pacing did not cancel")
	}
}
func TestAuthorityServerCountersSaturate(t *testing.T) {
	s := &LocalAuthorityServer{}
	s.status.Accepted = math.MaxUint64
	s.count(&s.status.Accepted)
	if s.status.Accepted != math.MaxUint64 || !s.status.Saturated {
		t.Fatal("counter wrapped")
	}
}
func TestAuthorityServerInvalidStartupAndClose(t *testing.T) {
	for _, kind := range []string{"no-interval", "short-interval", "long-interval", "no-authority", "no-directory", "private-directory", "no-transport"} {
		t.Run(kind, func(t *testing.T) {
			f, c, path := serverFixture(t)
			switch kind {
			case "no-interval":
				c.AcceptInterval = 0
			case "short-interval":
				c.AcceptInterval = MinAuthorityAcceptInterval - 1
			case "long-interval":
				c.AcceptInterval = MaxAuthorityAcceptInterval + 1
			case "no-authority":
				c.Authority = LocalAuthorityConfig{}
			case "no-directory":
				c.Directory = nil
			case "private-directory":
				c.Directory = f.config.PolicyDirectory
			case "no-transport":
				c.Transport = AuthorityTransportLimits{}
			}
			s, err := OpenLocalAuthorityServer(c)
			if err == nil || s != nil {
				t.Fatal("invalid server accepted", err)
			}
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid startup created path", err)
			}
			a := openAuthority(t, f.config)
			if err := a.Close(); err != nil {
				t.Fatal("failed startup retained private locks", err)
			}
		})
	}
	var nilServer *LocalAuthorityServer
	for _, s := range []*LocalAuthorityServer{nilServer, {}} {
		if !errors.Is(s.Serve(), ErrClosed) || s.Close() != nil || !s.Status().Closing {
			t.Fatal("invalid empty lifecycle")
		}
	}
	_, c, path := serverFixture(t)
	s := testServer(t, c)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(s.Serve(), ErrClosed) {
		t.Fatal("server restarted after close")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unused endpoint retained", err)
	}
}
