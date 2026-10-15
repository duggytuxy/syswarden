package journal

import (
	"context"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type lifecycleFixture struct {
	ready func(context.Context) error
	stop  func() error
	wait  func(context.Context) (*os.ProcessState, error)
	close func() error
}

func (f lifecycleFixture) AwaitReady(c context.Context) error { return f.ready(c) }
func (f lifecycleFixture) RequestStop() error                 { return f.stop() }
func (f lifecycleFixture) Wait(c context.Context) (*os.ProcessState, error) {
	return f.wait(c)
}
func (f lifecycleFixture) Close() error { return f.close() }

func TestAuthorityLifecycleExitHelper(t *testing.T) {
	if os.Getenv("SYSWARDEN_LIFECYCLE_EXIT_HELPER") == "1" {
		os.Exit(0)
	}
}

func TestAuthorityChildLifecycle(t *testing.T) { testAuthorityChildLifecycle(t) }

func testAuthorityChildLifecycle(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	p, err := os.StartProcess(executable, []string{executable, "-test.run=^TestAuthorityLifecycleExitHelper$"}, &os.ProcAttr{Env: []string{"SYSWARDEN_LIFECYCLE_EXIT_HELPER=1", "GOMAXPROCS=2"}})
	if err != nil {
		t.Fatal(err)
	}
	state, err := p.Wait()
	if err != nil || !state.Success() {
		t.Fatal("cannot obtain real exit verdict", state, err)
	}
	for _, kind := range []string{"clean-cancel", "observation-window", "joined-timeout-error", "readiness-refused", "cancel-before-ready", "stop-refused", "drain-timeout", "drain-error", "observation-error", "missing-observation", "close-error", "unexpected-zero-exit", "unexpected-exit-error", "drain-exit-error"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls, stops, closes := 0, 0, 0
			want := error(nil)
			f := lifecycleFixture{
				ready: func(context.Context) error {
					if kind == "readiness-refused" {
						want = unix.EIO
						return want
					}
					if kind == "cancel-before-ready" {
						cancel()
						want = context.Canceled
						return want
					}
					return nil
				},
				stop: func() error {
					stops++
					if kind == "stop-refused" {
						want = unix.EPERM
						return want
					}
					return nil
				},
				close: func() error {
					closes++
					if kind == "close-error" {
						want = os.ErrClosed
						return want
					}
					return nil
				},
			}
			f.wait = func(observation context.Context) (*os.ProcessState, error) {
				calls++
				if stops == 0 {
					switch kind {
					case "observation-window":
						if calls == 1 {
							return nil, context.DeadlineExceeded
						}
					case "joined-timeout-error":
						want = unix.EIO
						return nil, errors.Join(context.DeadlineExceeded, want)
					case "observation-error":
						want = unix.EBADF
						return nil, want
					case "missing-observation":
						want = ErrAuthorityChildLifecycle
						return nil, nil
					case "unexpected-zero-exit":
						want = ErrAuthorityChildLifecycle
						return state, nil
					case "unexpected-exit-error":
						want = ErrAuthorityChildExit
						return state, want
					}
					cancel()
					return nil, ctx.Err()
				}
				deadline, ok := observation.Deadline()
				if !ok || observation.Err() != nil || time.Until(deadline) <= 0 || time.Until(deadline) > MaxAuthorityChildObservation {
					t.Fatal("drain reused cancellation or lacked a bound")
				}
				switch kind {
				case "drain-timeout":
					want = context.DeadlineExceeded
					return nil, want
				case "drain-error":
					want = unix.EIO
					return nil, want
				case "drain-exit-error":
					want = ErrAuthorityChildExit
					return state, want
				}
				return state, nil
			}
			out, err := superviseAuthorityChild(ctx, f)
			if want == nil && err != nil || want != nil && (!errors.Is(err, want) || !errors.Is(err, ErrAuthorityChildLifecycle)) {
				t.Fatal("lost lifecycle verdict", out, err, want)
			}
			retained := kind == "drain-timeout" || kind == "drain-error"
			unexpected := kind == "unexpected-zero-exit" || kind == "unexpected-exit-error"
			if out.Ready != (kind != "readiness-refused" && kind != "cancel-before-ready") || out.StopRequested != (!unexpected && kind != "stop-refused") || (out.State == nil) != retained || out.Closed != (!retained && kind != "close-error") {
				t.Fatal("conflated observation outcomes", out)
			}
			if stops > 1 || closes > 1 || (retained && closes != 0) || (unexpected && stops != 0) || calls > 3 {
				t.Fatal("retry, premature cleanup or duplicate stop", calls, stops, closes)
			}
		})
	}
}

func TestAuthorityChildLifecycleInvalid(t *testing.T) {
	for _, c := range []*AuthorityChild{nil, {}, {process: &os.Process{Pid: 1}, lifecycleUsed: true}, {process: &os.Process{Pid: 1}, closed: true}} {
		if out, err := SuperviseAuthorityChild(context.Background(), c); out != (AuthorityChildOutcome{}) || !errors.Is(err, ErrAuthorityChildLifecycle) {
			t.Fatal("invalid lifecycle admitted", out, err)
		}
	}
	child := &AuthorityChild{process: &os.Process{Pid: 1}}
	var absent context.Context
	if _, err := SuperviseAuthorityChild(absent, child); err == nil || child.lifecycleUsed {
		t.Fatal("invalid context consumed child", err)
	}
}

func TestAuthorityChildLifecycleRetainsStartupFailure(t *testing.T) {
	child := &AuthorityChild{process: &os.Process{Pid: 1}, startErr: unix.EIO}
	// Missing private handles must prevent every signal/wait operation. The
	// diagnostic PID is deliberately never an alternate signaling capability.
	out, err := SuperviseAuthorityChild(context.Background(), child)
	if !errors.Is(err, unix.EIO) || out != (AuthorityChildOutcome{}) || !child.lifecycleUsed {
		t.Fatal("startup failure or ownership lost", out, err)
	}
}

func testActualAuthorityChildLifecycle(t *testing.T, images executableImages) {
	for _, kind := range []string{"cancel-after-client", "duplicate-lifecycle", "unexpected-stop", "canceled-startup"} {
		t.Run(kind, func(t *testing.T) {
			policy := testCustodyPolicy()
			policy.NotBefore, policy.NotAfter = time.Now().Add(-time.Minute).Unix(), time.Now().Add(time.Hour).Unix()
			c, _ := provisionProcessFixture(t, policy)
			launch, err := os.Open(c.LaunchPath)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = launch.Close() }()
			runtimeImages := images
			runtimeImages.launch = launch
			prepareActualAuthorityRuntimeInputs(t, t, &runtimeImages, &c)
			input, _ := authorityChildInputFixture(t, images, c)
			before := adversarialSnapshot(t, c.Paths)
			handles := authorityChildHandleInventory(t)
			child, err := StartAuthorityChildFromInputs(input)
			if child != nil {
				cleanupAuthorityTestChild(t, child)
			}
			if child == nil || err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if kind == "canceled-startup" {
				cancel()
			}
			type result struct {
				out AuthorityChildOutcome
				err error
			}
			done := make(chan result, 1)
			joined := false
			defer func() {
				cancel()
				if !joined {
					<-done
				}
			}()
			go func() {
				out, err := SuperviseAuthorityChild(ctx, child)
				done <- result{out, err}
			}()
			// Test-only lock-protected observation, without consuming readiness twice.
			if kind != "canceled-startup" {
				deadline := time.Now().Add(5 * time.Second)
				for {
					ready := false
					if child.readyMu.TryLock() {
						ready = child.readiness.waited
						child.readyMu.Unlock()
					}
					if ready {
						break
					}
					if time.Now().After(deadline) {
						cancel()
						<-done
						joined = true
						t.Fatal("lifecycle did not observe readiness")
					}
					time.Sleep(time.Millisecond)
				}
				requireExecutableIdentity(t, child.PID())
				client := c
				client.ServicePID = child.PID()
				runProcessClient(t, "resume", client, processClientID)
				if kind == "duplicate-lifecycle" {
					if out, err := SuperviseAuthorityChild(ctx, child); out != (AuthorityChildOutcome{}) || !errors.Is(err, ErrAuthorityChildLifecycle) {
						t.Error("concurrent lifecycle admitted", out, err)
					}
				}
				if kind == "unexpected-stop" {
					// Model an external stop while the lifecycle still expects service.
					if err := child.RequestStop(); err != nil {
						t.Error(err)
					}
				} else {
					cancel()
				}
			}
			r := <-done
			joined = true
			failed := kind == "unexpected-stop" || kind == "canceled-startup"
			if r.out.State == nil || !r.out.Closed || (!failed && (r.err != nil || !r.out.Ready || !r.out.StopRequested || !r.out.State.Success())) || (failed && !errors.Is(r.err, ErrAuthorityChildLifecycle)) {
				t.Fatal("incorrect actual lifecycle verdict", r.out, r.err)
			}
			if kind == "canceled-startup" && r.out.Ready {
				t.Fatal("canceled startup reported readiness")
			}
			if kind == "unexpected-stop" && (r.out.StopRequested || !r.out.State.Success()) {
				t.Fatal("unexpected zero exit hidden", r.out)
			}
			if _, err := SuperviseAuthorityChild(context.Background(), child); err == nil {
				t.Fatal("reused completed lifecycle")
			}
			requireAdversarialSnapshot(t, before, c.Paths)
			// A stop before readiness can interrupt startup and intentionally retain
			// endpoint evidence in its separate provisioning fixture. Process exit
			// and handle cleanup must not imply clean private storage.
			if kind != "canceled-startup" {
				requireExecutableCleanup(t, c)
			}
			if !reflect.DeepEqual(handles, authorityChildHandleInventory(t)) {
				t.Fatal("lifecycle leaked supervisor handles")
			}
		})
	}
}
