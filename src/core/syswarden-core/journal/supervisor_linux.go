package journal

import (
	"context"
	"errors"
	"math"
	"os"
	"sync"
	"time"
)

const (
	MinAuthorityAcceptInterval = 10 * time.Millisecond
	MaxAuthorityAcceptInterval = time.Second
)

var ErrAuthorityServerBusy = errors.New("local authority server is running or draining")

// AuthorityServerConfig is trusted startup input. Provision a distinct 0750
// endpoint directory owned by the service UID and explicitly selected group.
// PinDirectory must be separately provisioned, service-owned 0700 storage with
// no ACL, distinct from the endpoint and all four private authority resources.
// Group reachability never grants an operation; signed UID policy still applies.
type AuthorityServerConfig struct {
	Authority      LocalAuthorityConfig
	Transport      AuthorityTransportLimits
	Directory      *os.File
	PinDirectory   *os.File
	GroupID        uint32
	AcceptInterval time.Duration
}

// AuthorityServerStatus is bounded process-local transport diagnostics, not an
// authoritative security verdict, durable audit, KPI or enforcement-success count.
type AuthorityServerStatus struct {
	Running, Closing, Saturated bool
	Active                      int
	Accepted, Completed, Failed uint64
}

// LocalAuthorityServer owns its endpoint and transport. Serve starts a fixed
// worker set; there is no goroutine-per-peer, retry loop or user-space accept queue.
// The opt-in process is not installed or activated by native packages.
type LocalAuthorityServer struct {
	mu        sync.Mutex
	config    AuthorityServerConfig
	socket    *authoritySocket
	transport *LocalAuthorityTransport
	stop      chan struct{}
	next      time.Time
	started   bool
	status    AuthorityServerStatus
	failure   error
	layout    *authorityLayout
}

func OpenLocalAuthorityServer(c AuthorityServerConfig) (*LocalAuthorityServer, error) {
	if c.AcceptInterval < MinAuthorityAcceptInterval || c.AcceptInterval > MaxAuthorityAcceptInterval {
		return nil, ErrInvalidOptions
	}
	tr, err := OpenLocalAuthorityTransport(c.Authority, c.Transport)
	if err != nil {
		return nil, err
	}
	socket, err := openPinnedAuthoritySocket(c)
	if err != nil {
		return nil, errors.Join(err, tr.Close())
	}
	return &LocalAuthorityServer{config: AuthorityServerConfig{Transport: c.Transport, AcceptInterval: c.AcceptInterval}, socket: socket, transport: tr, stop: make(chan struct{})}, nil
}
func (s *LocalAuthorityServer) Status() AuthorityServerStatus {
	if s == nil {
		return AuthorityServerStatus{Closing: true}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}
func (s *LocalAuthorityServer) count(n *uint64) {
	if *n == math.MaxUint64 {
		s.status.Saturated = true
	} else {
		*n++
	}
}
func (s *LocalAuthorityServer) permit() bool {
	s.mu.Lock()
	if s.status.Closing {
		s.mu.Unlock()
		return false
	}
	now := time.Now()
	at := s.next
	if at.Before(now) {
		at = now
	}
	s.next = at.Add(s.config.AcceptInterval)
	s.mu.Unlock()
	timer := time.NewTimer(time.Until(at))
	defer timer.Stop()
	select {
	case <-s.stop:
		return false
	case <-timer.C:
		return !s.Status().Closing
	}
}
func (s *LocalAuthorityServer) failed(err error) {
	s.mu.Lock()
	if !s.status.Closing && s.failure == nil {
		s.failure = err
	}
	s.mu.Unlock()
	_ = s.Close()
}
func (s *LocalAuthorityServer) worker() {
	for s.permit() {
		if err := errors.Join(s.layout.attest(), s.socket.Attest()); err != nil {
			s.failed(err)
			return
		}
		peer, err := s.socket.listener.AcceptUnix()
		if err != nil {
			s.failed(err)
			return
		}
		if err = errors.Join(s.layout.attest(), s.socket.Attest()); err != nil {
			_ = peer.Close()
			s.failed(err)
			return
		}
		s.mu.Lock()
		s.count(&s.status.Accepted)
		s.status.Active++
		s.mu.Unlock()
		err = s.transport.ServePeer(peer)
		s.mu.Lock()
		s.status.Active--
		if err == nil {
			s.count(&s.status.Completed)
		} else {
			s.count(&s.status.Failed)
		}
		s.mu.Unlock()
		if errors.Is(err, ErrUnsafeStorage) {
			s.failed(err)
			return
		}
	}
}

// Serve may be called once. It returns after all workers drain and owned resources
// close. An external Close wakes pacing/accept/I/O waits. Trusted durable operations
// retain the transport's non-cancellable semantics; no hard stop time is promised.
func (s *LocalAuthorityServer) Serve() error {
	return s.serveContext(context.Background(), nil)
}

// serveContext owns the cancellation watcher until all workers drain. The ready
// callback is trusted, nonblocking startup I/O, never request-supplied code.
func (s *LocalAuthorityServer) serveContext(ctx context.Context, ready func() error) error {
	if ctx == nil {
		return ErrInvalidOptions
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil {
		return ErrClosed
	}
	s.mu.Lock()
	if s.status.Closing || s.socket == nil || s.transport == nil {
		s.mu.Unlock()
		return ErrClosed
	}
	if s.started {
		s.mu.Unlock()
		return ErrAuthorityServerBusy
	}
	s.started, s.status.Running = true, true
	workers := s.config.Transport.MaxPeers
	s.mu.Unlock()
	finishWatch := s.watchCancellation(ctx)
	var startupErr error
	if ready != nil {
		startupErr = ctx.Err()
		if startupErr == nil {
			startupErr = ready()
		}
		if startupErr != nil {
			_ = s.Close()
		}
	}
	var group sync.WaitGroup
	for range workers {
		group.Go(s.worker)
	}
	group.Wait()
	stopErr := finishWatch()
	s.mu.Lock()
	s.status.Running = false
	failure := s.failure
	s.mu.Unlock()
	return errors.Join(startupErr, failure, stopErr, s.Close())
}

// Close stops admission and invokes the existing transport drain. A running
// Serve returns ErrAuthorityServerBusy here until workers finish. It does not
// cancel approved durable writes or delete an endpoint whose inode was replaced.
// Endpoint/pin evidence and locks remain held until every worker has returned.
func (s *LocalAuthorityServer) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if !s.status.Closing {
		s.status.Closing = true
		if s.stop != nil {
			close(s.stop)
		}
	}
	busy := s.status.Running
	tr, socket := s.transport, s.socket
	s.mu.Unlock()
	// Stop new transport admission and kernel accepts, retaining endpoint custody
	// while an approved callback/write or accepted peer is still draining. A
	// stopped listener and ECONNREFUSED must not permit early offline recovery.
	err := errors.Join(tr.Close(), socket.stopListening())
	if busy || errors.Is(err, ErrAuthorityTransportBusy) || errors.Is(err, ErrAuthorityBusy) {
		return errors.Join(err, ErrAuthorityServerBusy)
	}
	return errors.Join(err, socket.Close(), s.layout.close())
}

// A cancelled context stops admission but cannot cancel an approved durable
// operation. Join the watcher before final cleanup; do not leak it on failure.
func (s *LocalAuthorityServer) watchCancellation(ctx context.Context) func() error {
	if ctx.Done() == nil {
		return func() error { return nil }
	}
	finished, stopped := make(chan struct{}), make(chan error, 1)
	go func() {
		select {
		case <-ctx.Done():
			stopped <- authorityStopError(s.Close())
		case <-finished:
			stopped <- nil
		}
	}()
	return func() error { close(finished); return <-stopped }
}

// Busy is expected only while draining. Retain every other shutdown error,
// including one joined with a busy result, for the process exit status.
func authorityStopError(err error) error {
	if err == ErrAuthorityServerBusy || err == ErrAuthorityTransportBusy || err == ErrAuthorityBusy {
		return nil
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var out error
		for _, item := range joined.Unwrap() {
			out = errors.Join(out, authorityStopError(item))
		}
		return out
	}
	return err
}
