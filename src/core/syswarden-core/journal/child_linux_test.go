package journal

import (
	"context"
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestAuthorityChildInvalid(t *testing.T) {
	for _, c := range []*AuthorityChild{nil, {}} {
		if c.PID() != 0 || c.AwaitReady(context.Background()) == nil || c.RequestStop() == nil {
			t.Fatal("invalid supervisor admitted")
		}
		if state, err := c.Wait(context.Background()); state != nil || err == nil {
			t.Fatal("invalid child reaped")
		}
	}
	var c *AuthorityChild
	if c.Close() != nil {
		t.Fatal("nil close")
	}
	if !errors.Is((&AuthorityChild{}).Close(), ErrAuthorityChildRunning) {
		t.Fatal("unreaped ownership discarded")
	}
	if child, err := StartAuthorityChild(AuthorityChildConfig{}); child != nil || err == nil {
		t.Fatal("invalid creation admitted")
	}
	if os.Getuid() != 0 {
		config := AuthorityChildConfig{Bundle: &AuthorityLaunchBundle{}, LaunchSHA256: strings.Repeat("a", 64), ImageSHA256: strings.Repeat("b", 64), LauncherSHA256: strings.Repeat("c", 64)}
		if child, err := StartAuthorityChild(config); child != nil || !errors.Is(err, ErrAuthorityChild) {
			t.Fatal("non-root admission")
		}
	}
}

func TestAuthorityChildPoll(t *testing.T) {
	for _, tc := range []struct {
		name         string
		n            int
		event        int16
		err          error
		done, failed bool
	}{
		{"running", 0, 0, nil, false, false}, {"exited", 1, unix.POLLIN, nil, true, false}, {"reaped", 1, unix.POLLHUP, nil, true, false}, {"both", 1, unix.POLLIN | unix.POLLHUP, nil, true, false},
		{"interrupted", 0, 0, unix.EINTR, false, false}, {"unsupported", 0, 0, unix.ENOSYS, false, true}, {"bad-fd", 1, unix.POLLNVAL, nil, false, true}, {"error", 1, unix.POLLERR, nil, false, true},
		{"writable", 1, unix.POLLOUT, nil, false, true}, {"missing-event", 1, 0, nil, false, true}, {"missing-count", 0, unix.POLLIN, nil, false, true}, {"extra-count", 2, unix.POLLIN, nil, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			done, err := pollAuthorityChild(42, func(fds []unix.PollFd, timeout int) (int, error) {
				calls++
				if timeout != 0 || len(fds) != 1 || fds[0].Fd != 42 || fds[0].Events != unix.POLLIN {
					t.Fatal("unbounded or unrelated poll")
				}
				fds[0].Revents = tc.event
				return tc.n, tc.err
			})
			if calls != 1 || done != tc.done || (err != nil) != tc.failed {
				t.Fatal("unexpected poll result", done, err, calls)
			}
		})
	}
	if _, err := pollAuthorityChild(uintptr(math.MaxInt32)+1, unix.Poll); err == nil {
		t.Fatal("descriptor narrowing")
	}
	if _, err := pollAuthorityChild(1, nil); err == nil {
		t.Fatal("missing poll")
	}
}

// The ordinary suite also checks real pidfd exit accounting without privileged
// provisioning. Only this exact helper mode exits early in the test executable.
func TestAuthorityChildExitHelper(t *testing.T) {
	if os.Getenv("SYSWARDEN_CHILD_EXIT_HELPER") == "1" {
		os.Exit(23)
	}
}

func TestAuthorityChildNonzeroExit(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = null.Close() }()
	fd := -1
	p, err := os.StartProcess(executable, []string{executable, "-test.run=^TestAuthorityChildExitHelper$"}, &os.ProcAttr{Env: []string{"SYSWARDEN_CHILD_EXIT_HELPER=1", "GOMAXPROCS=2"}, Files: []*os.File{null, null, null}, Sys: &syscall.SysProcAttr{PidFD: &fd}})
	if err != nil {
		t.Fatal(err)
	}
	ready, err := NewAuthorityReadinessChannel()
	if err != nil {
		_ = p.Kill()
		_, _ = p.Wait()
		t.Fatal(err)
	}
	child := &AuthorityChild{process: p, pidfd: os.NewFile(uintptr(fd), "test-child-pidfd"), readiness: ready}
	cleanupAuthorityTestChild(t, child)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	state, err := child.Wait(ctx)
	if !errors.Is(err, ErrAuthorityChildExit) || state == nil || state.ExitCode() != 23 {
		t.Fatal("failed exit became success", state, err)
	}
	if cached, e := child.Wait(ctx); cached != state || !errors.Is(e, ErrAuthorityChildExit) {
		t.Fatal("lost exit verdict", e)
	}
	if !errors.Is(child.AwaitReady(ctx), ErrAuthorityChild) {
		t.Fatal("reaped child became ready")
	}
	// An externally broken owned handle must remain an explicit sticky failure,
	// while closing the other resources after a failed child exit.
	if err := child.pidfd.Close(); err != nil {
		t.Fatal(err)
	}
	first := child.Close()
	if first == nil || child.Close() != first {
		t.Fatal("lost close failure")
	}
}

func testAuthorityChildSupervision(t *testing.T, binary executableImages, c processFixtureConfig) {
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = null.Close() }()
	config := AuthorityChildConfig{Bundle: &AuthorityLaunchBundle{Launch: binary.launch, State: binary.state, Endpoint: binary.endpoint, Image: binary.authority}, Launcher: binary.launcher, Null: null, LaunchSHA256: c.LaunchDigest, ImageSHA256: binary.digest, LauncherSHA256: os.Getenv("SYSWARDEN_AUTHORITY_LAUNCHER_SHA256")}
	before := adversarialSnapshot(t, c.Paths)
	for _, kind := range []string{"nil-bundle", "missing-launch", "closed-launcher", "wrong-launch-digest", "wrong-image-digest", "wrong-launcher-digest", "uppercase-launcher-digest", "swapped-directories", "same-directories", "read-only-null", "regular-null", "named-launch"} {
		t.Run(kind, func(t *testing.T) {
			input := config
			bundle := *config.Bundle
			input.Bundle = &bundle
			switch kind {
			case "nil-bundle":
				input.Bundle = nil
			case "missing-launch":
				bundle.Launch = nil
			case "closed-launcher":
				input.Launcher = duplicateReadinessWriter(t, config.Launcher)
				_ = input.Launcher.Close()
			case "wrong-launch-digest":
				input.LaunchSHA256 = strings.Repeat("0", 64)
			case "wrong-image-digest":
				input.ImageSHA256 = strings.Repeat("0", 64)
			case "wrong-launcher-digest":
				input.LauncherSHA256 = strings.Repeat("0", 64)
			case "uppercase-launcher-digest":
				input.LauncherSHA256 = strings.ToUpper(input.LauncherSHA256)
			case "swapped-directories":
				bundle.State, bundle.Endpoint = bundle.Endpoint, bundle.State
			case "same-directories":
				bundle.Endpoint = bundle.State
			case "read-only-null":
				input.Null, err = os.Open(os.DevNull)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = input.Null.Close() }()
			case "regular-null":
				input.Null, err = os.CreateTemp(t.TempDir(), "not-null")
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = input.Null.Close() }()
			case "named-launch":
				data, err := os.ReadFile("/proc/self/fd/" + strconv.FormatUint(uint64(bundle.Launch.Fd()), 10))
				if err != nil {
					t.Fatal(err)
				}
				root, err := os.OpenRoot(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = root.Close() }()
				if err := root.WriteFile("launch.json", data, 0600); err != nil {
					t.Fatal(err)
				}
				bundle.Launch, err = root.Open("launch.json")
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = bundle.Launch.Close() }()
			}
			child, err := StartAuthorityChild(input)
			if child != nil {
				cleanupAuthorityTestChild(t, child)
			}
			if child != nil || err == nil {
				t.Fatal("invalid resources created a child", err)
			}
			requireAdversarialSnapshot(t, before, c.Paths)
			requireExecutableCleanup(t, c)
		})
	}
	t.Run("creation-failure", func(t *testing.T) {
		// A controlled syscall failure after all attestations proves bounded cleanup
		// without weakening the public API or asking the kernel to run malformed code.
		handles := authorityChildHandleInventory(t)
		for range 12 {
			calls := 0
			child, err := startAuthorityChild(config, func(path string, args []string, a *os.ProcAttr) (*os.Process, error) {
				calls++
				if path != "/proc/self/fd/8" || !reflect.DeepEqual(args, []string{"syswarden-authority-launch", "--launch-sha256", c.LaunchDigest, "--image-sha256", binary.digest}) || a.Dir != "/" || !reflect.DeepEqual(a.Env, []string{"GOMAXPROCS=2"}) || len(a.Files) != 9 || !a.Sys.Setsid || a.Sys.PidFD == nil || *a.Sys.PidFD != -1 || !reflect.DeepEqual(a.Sys.Credential, &syscall.Credential{Uid: 0, Gid: 0, Groups: []uint32{}}) {
					t.Fatal("unexpected child contract")
				}
				for _, file := range a.Files {
					if file == nil {
						t.Fatal("missing child handle")
					}
				}
				return nil, unix.EAGAIN
			})
			if child != nil || !errors.Is(err, unix.EAGAIN) || calls != 1 {
				t.Fatal("creation retried or failure discarded", err)
			}
		}
		if !reflect.DeepEqual(handles, authorityChildHandleInventory(t)) {
			t.Fatal("failed creation leaked descriptors")
		}
		requireAdversarialSnapshot(t, before, c.Paths)
		requireExecutableCleanup(t, c)
	})
	t.Run("post-creation-failure", func(t *testing.T) {
		child, err := startAuthorityChild(config, func(path string, args []string, attr *os.ProcAttr) (*os.Process, error) {
			process, e := os.StartProcess(path, args, attr)
			if e == nil {
				// Simulate a failed ownership handoff after the real child exists.
				// This closes only a private duplicate, never a borrowed input.
				if closeErr := attr.Files[3].Close(); closeErr != nil {
					t.Error(closeErr)
				}
			}
			return process, e
		})
		if child != nil {
			cleanupAuthorityTestChild(t, child)
		}
		if child == nil || !errors.Is(err, os.ErrClosed) {
			t.Fatal("lost partial creation ownership", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if !errors.Is(child.AwaitReady(ctx), ErrAuthorityChild) {
			t.Fatal("uncertain handoff reported ready")
		}
		// Test-only observation allows deterministic graceful teardown. The public
		// supervisor must continue reporting the original uncertainty throughout.
		if err := child.readiness.Wait(ctx); err != nil {
			t.Fatal(err)
		}
		if err := child.RequestStop(); err != nil {
			t.Fatal(err)
		}
		state, err := child.Wait(ctx)
		if state == nil || !state.Success() || !errors.Is(err, os.ErrClosed) {
			t.Fatal("cleanup erased earlier failure", state, err)
		}
		if _, err := child.Wait(ctx); !errors.Is(err, os.ErrClosed) {
			t.Fatal("cached wait lost failure", err)
		}
		if !errors.Is(child.Close(), os.ErrClosed) {
			t.Fatal("close lost handoff failure")
		}
		requireAdversarialSnapshot(t, before, c.Paths)
		requireExecutableCleanup(t, c)
	})
	for _, kind := range []string{"lifecycle", "independent-handoff", "concurrent-observation", "startup-failure"} {
		t.Run(kind, func(t *testing.T) {
			input := config
			bundle := *config.Bundle
			input.Bundle = &bundle
			var borrowed []*os.File
			if kind == "independent-handoff" {
				for _, slot := range []**os.File{&bundle.Launch, &bundle.State, &bundle.Endpoint, &bundle.Image, &input.Launcher, &input.Null} {
					*slot = duplicateReadinessWriter(t, *slot)
					borrowed = append(borrowed, *slot)
				}
				defer func() {
					for _, file := range borrowed {
						_ = file.Close()
					}
				}()
			}
			if kind == "startup-failure" {
				dir := t.TempDir()
				if err := os.Chown(dir, int(processServiceID), int(processServiceID)); err != nil {
					t.Fatal(err)
				}
				if err := chmodFixture(dir, 0700); err != nil {
					t.Fatal(err)
				}
				bundle.State, err = openFixtureDirectory(dir)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = bundle.State.Close() }()
			}
			parent := authorityChildParentSnapshot(t, config)
			child, err := StartAuthorityChild(input)
			if child != nil {
				cleanupAuthorityTestChild(t, child)
			}
			if err != nil || child == nil || child.PID() <= 0 {
				t.Fatal("creation failed", err)
			}
			for _, file := range borrowed {
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if !reflect.DeepEqual(parent, authorityChildParentSnapshot(t, config)) {
				t.Fatal("parent identity, limits, or descriptor flags changed")
			}
			seal, e := unix.FcntlInt(child.pidfd.Fd(), unix.F_GETFD, 0)
			if e != nil || seal&unix.FD_CLOEXEC == 0 {
				t.Fatal("pidfd leaked across exec", e)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err = child.AwaitReady(ctx)
			if kind == "startup-failure" {
				if err == nil {
					t.Fatal("missing private state reported ready")
				}
				state, err := child.Wait(ctx)
				if state == nil || state.ExitCode() != 1 || !errors.Is(err, ErrAuthorityChildExit) {
					t.Fatal("failed startup verdict lost", state, err)
				}
			} else {
				if err != nil {
					t.Fatal("readiness failed", err)
				}
				requireExecutableIdentity(t, child.PID())
				sid, e := unix.Getsid(child.PID())
				if e != nil || sid != child.PID() {
					t.Fatal("child shares parent session", sid, e)
				}
				env, e := os.ReadFile(filepath.Join("/proc", strconv.Itoa(child.PID()), "environ"))
				if e != nil || string(env) != "GOMAXPROCS=2\x00" {
					t.Fatal("unexpected child environment", e)
				}
				client := c
				client.ServicePID = child.PID()
				runProcessClient(t, "resume", client, processClientID)
				if !errors.Is(child.Close(), ErrAuthorityChildRunning) {
					t.Fatal("live child abandoned")
				}
				canceled, stop := context.WithCancel(ctx)
				stop()
				if state, err := child.Wait(canceled); state != nil || !errors.Is(err, context.Canceled) {
					t.Fatal("cancellation changed child", state, err)
				}
				short, stop := context.WithTimeout(ctx, time.Millisecond)
				if state, err := child.Wait(short); state != nil || !errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("timeout changed child", state, err)
				}
				stop()
				if kind == "concurrent-observation" {
					observed := make(chan error, 1)
					go func() { _, e := child.Wait(ctx); observed <- e }()
					defer func() { cancel(); <-observed }()
					deadline := time.Now().Add(time.Second)
					for child.waitMu.TryLock() {
						child.waitMu.Unlock()
						if time.Now().After(deadline) {
							t.Fatal("waiter did not start")
						}
						time.Sleep(time.Millisecond)
					}
					if state, err := child.Wait(ctx); state != nil || err == nil {
						t.Fatal("second waiter admitted")
					}
					if !errors.Is(child.Close(), ErrAuthorityChildRunning) {
						t.Fatal("closed under concurrent wait")
					}
					if err := child.RequestStop(); err != nil {
						t.Fatal(err)
					}
					// Join here while leaving one value for deferred teardown on every path.
					e := <-observed
					observed <- e
					if e != nil {
						t.Fatal("concurrent stop failed", e)
					}
				} else {
					if err := child.RequestStop(); err != nil {
						t.Fatal(err)
					}
				}
				state, err := child.Wait(ctx)
				if err != nil || state == nil || !state.Success() {
					t.Fatal("clean stop failed", state, err)
				}
				if cached, e := child.Wait(ctx); e != nil || cached != state {
					t.Fatal("lost cached exit", e)
				}
				if !errors.Is(child.RequestStop(), os.ErrProcessDone) {
					t.Fatal("reaped process signaled")
				}
			}
			if err := child.Close(); err != nil {
				t.Fatal(err)
			}
			if err := child.Close(); err != nil {
				t.Fatal("close not idempotent", err)
			}
			requireAdversarialSnapshot(t, before, c.Paths)
			requireExecutableCleanup(t, c)
		})
	}
}

func cleanupAuthorityTestChild(t *testing.T, c *AuthorityChild) {
	t.Helper()
	t.Cleanup(func() {
		if c.state == nil && c.process != nil {
			// Test teardown only: never leave an unexpected child after a failed assertion.
			_ = c.process.Kill()
			state, _ := c.process.Wait()
			c.state = state
		}
		_ = c.Close()
	})
}

func authorityChildHandleInventory(t *testing.T) map[string]string {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	result := map[string]string{}
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		result[entry.Name()] = target
	}
	return result
}

func authorityChildParentSnapshot(t *testing.T, c AuthorityChildConfig) any {
	t.Helper()
	uid, euid, suid := unix.Getresuid()
	gid, egid, sgid := unix.Getresgid()
	groups, err := unix.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	var limits [2]unix.Rlimit
	if unix.Getrlimit(unix.RLIMIT_CORE, &limits[0]) != nil || unix.Getrlimit(unix.RLIMIT_NOFILE, &limits[1]) != nil {
		t.Fatal("parent limits")
	}
	var flags [6][2]int
	for i, f := range []*os.File{c.Bundle.Launch, c.Bundle.Image, c.Bundle.State, c.Bundle.Endpoint, c.Launcher, c.Null} {
		flags[i][0], err = unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
		if err != nil {
			t.Fatal(err)
		}
		flags[i][1], err = unix.FcntlInt(f.Fd(), unix.F_GETFD, 0)
		if err != nil {
			t.Fatal(err)
		}
	}
	return struct {
		Identity [6]int
		Groups   []int
		Limits   [2]unix.Rlimit
		Flags    [6][2]int
	}{[6]int{uid, euid, suid, gid, egid, sgid}, groups, limits, flags}
}
