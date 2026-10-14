package journal

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func readinessPipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	r, w := os.NewFile(uintptr(fds[0]), "ready-reader"), os.NewFile(uintptr(fds[1]), "ready-writer")
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	return r, w
}

func TestAuthorityReadinessIsBoundedAndExact(t *testing.T) {
	for _, kind := range []string{"valid", "nil", "closed", "read-end", "blocking", "regular", "full", "disconnected"} {
		t.Run(kind, func(t *testing.T) {
			r, w := readinessPipe(t)
			file := w
			switch kind {
			case "nil":
				file = nil
			case "closed":
				_ = w.Close()
			case "read-end":
				file = r
			case "blocking":
				if err := unix.SetNonblock(int(w.Fd()), false); err != nil {
					t.Fatal(err)
				}
			case "regular":
				var err error
				file, err = os.CreateTemp(t.TempDir(), "ordinary")
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = file.Close() }()
			case "full":
				fd := int(w.Fd())
				buffer := make([]byte, 4096)
				full := false
				for range 1024 {
					_, err := unix.Write(fd, buffer)
					if errors.Is(err, unix.EAGAIN) {
						full = true
						break
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				if !full {
					t.Fatal("fixture pipe did not fill within its bound")
				}
			case "disconnected":
				_ = r.Close()
			}
			if kind == "full" || kind == "disconnected" || kind == "valid" {
				if err := authorityReadiness(file, false); err != nil {
					t.Fatal("valid metadata rejected", err)
				}
			}
			err := authorityReadiness(file, true)
			if kind != "valid" {
				if err == nil {
					t.Fatal("unsafe readiness accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			_ = w.Close()
			data, err := io.ReadAll(r)
			if err != nil || string(data) != "R" {
				t.Fatal("readiness was not exactly one byte", err)
			}
		})
	}
}

func TestAuthorityProcessRejectsBeforeStartup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, input := range []struct {
		context context.Context
		want    error
	}{{nil, ErrInvalidOptions}, {ctx, context.Canceled}} {
		if err := RunAuthorityProcess(input.context, AuthorityProcessConfig{}); !errors.Is(err, input.want) {
			t.Fatal(err)
		}
	}
	if err := RunAuthorityProcess(context.Background(), AuthorityProcessConfig{}); !errors.Is(err, ErrAuthorityReadiness) {
		t.Fatal(err)
	}
	r, w := readinessPipe(t)
	if err := RunAuthorityProcess(context.Background(), AuthorityProcessConfig{Readiness: w}); !errors.Is(err, ErrAuthorityLaunch) {
		t.Fatal(err)
	}
	_ = w.Close()
	if data, err := io.ReadAll(r); err != nil || len(data) != 0 {
		t.Fatal("failed startup reported readiness", err)
	}
}

func TestAuthorityProcessCancellationAndStartupFailure(t *testing.T) {
	for _, kind := range []string{"cancel", "deadline", "cancel-at-ready", "ready-failure", "cancel-and-ready-failure", "worker-failure", "changed-evidence"} {
		t.Run(kind, func(t *testing.T) {
			f, c, path := serverFixture(t)
			s := testServer(t, c)
			before := f.bytes(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "deadline" {
				var release context.CancelFunc
				ctx, release = context.WithDeadline(ctx, time.Now().Add(100*time.Millisecond))
				defer release()
			}
			ready := make(chan struct{})
			sentinel := errors.New("readiness failed")
			done := make(chan error, 1)
			go func() {
				done <- s.serveContext(ctx, func() error {
					close(ready)
					if kind == "cancel-at-ready" || kind == "cancel-and-ready-failure" {
						cancel()
					}
					if kind == "ready-failure" || kind == "cancel-and-ready-failure" {
						return sentinel
					}
					return nil
				})
			}()
			select {
			case <-ready:
			case <-time.After(3 * time.Second):
				t.Fatal("missing readiness")
			}
			if kind == "cancel" {
				authorityAnchor(t, serverRequest(t, path, authorityRequest{Operation: "resume"}), f.files.expected)
				cancel()
			}
			if kind == "worker-failure" || kind == "changed-evidence" {
				if err := os.WriteFile(filepath.Join(c.PinDirectory.Name(), AuthorityEndpointPinName), []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
				if kind == "changed-evidence" {
					cancel()
				} else if peer, err := net.DialTimeout("unix", path, time.Second); err == nil {
					_ = peer.Close() // Wake a worker already blocked in accept.
				}
			}
			err := transportResult(t, done)
			switch kind {
			case "ready-failure", "cancel-and-ready-failure":
				if !errors.Is(err, sentinel) {
					t.Fatal("readiness error was hidden", err)
				}
			case "worker-failure", "changed-evidence":
				if !errors.Is(err, ErrAuthorityEndpoint) {
					t.Fatal("changed evidence was hidden", err)
				}
				if _, err := os.Lstat(path); err != nil {
					t.Fatal("uncertain endpoint was removed", err)
				}
			default:
				if err != nil {
					t.Fatal(err)
				}
			}
			if !reflect.DeepEqual(before, f.bytes(t)) {
				t.Fatal("lifecycle changed journal resources")
			}
			if status := s.Status(); status.Running || !status.Closing || status.Active != 0 {
				t.Fatal("process did not drain", status)
			}
			if kind != "worker-failure" && kind != "changed-evidence" {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("clean stop retained endpoint", err)
				}
			}
		})
	}
}

func TestAuthorityProcessCancellationRetainsApprovedWork(t *testing.T) {
	f, c, path := serverFixture(t)
	s := testServer(t, c)
	request := authorityRequest{Operation: "inspect-policy", Change: &authorityChange{Operation: "disable"}}
	plan := authorityReply(t, s.transport.authority, f.peer, request)
	f.administrator.approved = plan.PlanSHA256
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	f.administrator.hook = func(_ PolicyAdministrationRequest, _ *PolicyAdministrationDecision) error {
		close(entered)
		<-release
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.serveContext(ctx, nil) }()
	peer := serverClient(t, path)
	request.Operation, request.PlanSHA256 = "apply-policy", plan.PlanSHA256
	transportSend(t, peer, transportFrame(authorityMessage(t, request)))
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("approval not entered")
	}
	cancel()
	serverWait(t, s, func(st AuthorityServerStatus) bool { return st.Closing })
	if pin, err := readEndpointPin(c.PinDirectory); pin != nil || !errors.Is(err, ErrLocked) {
		t.Fatal("cancellation released custody during approved write", err)
	}
	select {
	case err := <-done:
		t.Fatal("process exited before drain", err)
	default:
	}
	once.Do(func() { close(release) })
	if err := transportResult(t, done); err != nil {
		t.Fatal(err)
	}
	policy, err := OpenLocalCustodyPolicy(c.Authority.PolicyDirectory, f.root.Trust)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = policy.Close() }()
	if policyCurrent(t, policy).Trust.Enabled {
		t.Fatal("cancellation discarded approved policy change")
	}
	if data, err := io.ReadAll(peer); err != nil || len(data) != 0 {
		t.Fatal("shutdown emitted an uncertain reply", err)
	}
}

func TestAuthorityProcessStopErrorsPreserveUnexpectedFailures(t *testing.T) {
	sentinel := errors.New("stop failure")
	if err := authorityStopError(errors.Join(ErrAuthorityServerBusy, errors.Join(ErrAuthorityTransportBusy, ErrAuthorityBusy))); err != nil {
		t.Fatal(err)
	}
	if err := authorityStopError(errors.Join(ErrAuthorityServerBusy, sentinel)); !errors.Is(err, sentinel) || errors.Is(err, ErrAuthorityServerBusy) {
		t.Fatal("shutdown failure hidden", err)
	}
}
