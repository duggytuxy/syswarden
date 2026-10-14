package journal

import (
	"context"
	"errors"
	"math"
	"os"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var (
	ErrAuthorityChild        = errors.New("invalid authority child supervision")
	ErrAuthorityChildRunning = errors.New("authority child is running or not yet reaped")
	ErrAuthorityChildExit    = errors.New("authority child did not exit successfully")
)

const MaxAuthorityChildObservation = 30 * time.Second

// AuthorityChildConfig supplies independently approved, held resources. Null is
// a read/write Linux null-device descriptor for all three standard streams. The
// caller serializes handoff with modification/closure of these borrowed inputs.
// This configuration discovers no path, account, approval or dynamic dependency.
type AuthorityChildConfig struct {
	Bundle                                    *AuthorityLaunchBundle
	Launcher, Null                            *os.File
	LaunchSHA256, ImageSHA256, LauncherSHA256 string
}

// AuthorityChild owns one directly created process, its atomic pidfd and readiness
// channel. Always observe/reap it with Wait, then Close. Never copy this value.
// Context cancellation stops observation only; it does not stop or abandon a child.
type AuthorityChild struct {
	mu, waitMu, readyMu sync.Mutex
	process             *os.Process
	pidfd               *os.File
	readiness           *AuthorityReadinessChannel
	state               *os.ProcessState
	startErr, closeErr  error
	closed              bool
}

// StartAuthorityChild executes the pinned root launcher with a fixed descriptor,
// argument, environment and stdio layout. Success means creation, not readiness.
// A non-nil child MUST be retained even when an error also returns: post-start
// cleanup uncertainty must not lose a live process. There is no shell, retry,
// inherited environment, numeric-PID signal fallback or automatic forced kill.
func StartAuthorityChild(c AuthorityChildConfig) (child *AuthorityChild, result error) {
	return startAuthorityChild(c, os.StartProcess)
}

func startAuthorityChild(c AuthorityChildConfig, start func(string, []string, *os.ProcAttr) (*os.Process, error)) (child *AuthorityChild, result error) {
	if start == nil || c.Bundle == nil || !validRecoveryApproval(c.LaunchSHA256) || !validRecoveryApproval(c.ImageSHA256) || !validRecoveryApproval(c.LauncherSHA256) {
		return nil, ErrAuthorityChild
	}
	u, e, s := unix.Getresuid()
	g, eg, sg := unix.Getresgid()
	if u != 0 || e != 0 || s != 0 || g != 0 || eg != 0 || sg != 0 {
		return nil, ErrAuthorityChild
	}
	inputs := [6]*os.File{c.Bundle.Launch, c.Bundle.State, c.Bundle.Endpoint, c.Bundle.Image, c.Launcher, c.Null}
	var held [6]*os.File
	defer func() {
		for _, file := range held {
			if file != nil {
				result = errors.Join(result, file.Close())
			}
		}
		if child != nil {
			child.startErr = result
		}
	}()
	for i, input := range inputs {
		var err error
		held[i], err = duplicateAuthorityChildInput(input)
		if err != nil {
			return nil, errors.Join(ErrAuthorityChild, err)
		}
	}
	if err := attestAuthorityChildInputs(held, c); err != nil {
		return nil, errors.Join(ErrAuthorityChild, err)
	}
	ready, err := NewAuthorityReadinessChannel()
	if err != nil {
		return nil, errors.Join(ErrAuthorityChild, err)
	}
	pidfd := -1
	process, err := start("/proc/self/fd/8",
		[]string{"syswarden-authority-launch", "--launch-sha256", c.LaunchSHA256, "--image-sha256", c.ImageSHA256},
		&os.ProcAttr{Dir: "/", Env: []string{"GOMAXPROCS=2"},
			Files: []*os.File{held[5], held[5], held[5], held[0], held[1], held[2], ready.Writer(), held[3], held[4]},
			Sys:   &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 0, Gid: 0, Groups: []uint32{}}, PidFD: &pidfd, Setsid: true},
		})
	if err != nil {
		return nil, errors.Join(ErrAuthorityChild, err, ready.Close())
	}
	child = &AuthorityChild{process: process, readiness: ready}
	if pidfd < 0 {
		// CLONE_PIDFD must return the handle atomically. Preserve the created
		// child for explicit operator inspection if that kernel contract fails.
		return child, errors.Join(ErrAuthorityChild, ready.CloseWriter())
	}
	child.pidfd = os.NewFile(uintptr(pidfd), "authority-child-pidfd")
	return child, ready.CloseWriter()
}

func duplicateAuthorityChildInput(file *os.File) (*os.File, error) {
	if file == nil {
		return nil, ErrAuthorityChild
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return nil, err
	}
	fd := -1
	var operation error
	err = raw.Control(func(source uintptr) { fd, operation = unix.FcntlInt(source, unix.F_DUPFD_CLOEXEC, 0) })
	if err != nil || operation != nil {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		return nil, errors.Join(ErrAuthorityChild, err, operation)
	}
	return os.NewFile(uintptr(fd), "authority-child-input"), nil
}

func attestAuthorityChildInputs(f [6]*os.File, c AuthorityChildConfig) error {
	launch, err := LoadAuthorityLaunch(f[0], c.LaunchSHA256)
	if err != nil {
		return err
	}
	var st unix.Stat_t
	if unix.Fstat(int(f[0].Fd()), &st) != nil || st.Nlink != 0 {
		return ErrAuthorityChild
	}
	if _, err := InspectAuthorityExecutableImage(f[3], c.ImageSHA256); err != nil {
		return err
	}
	if _, err := InspectAuthorityExecutableImage(f[4], c.LauncherSHA256); err != nil {
		return err
	}
	state, err := attestAuthorityRuntimeDirectory(int(f[1].Fd()), launch.ServiceUID, launch.ServiceGID, 0700)
	if err != nil {
		return err
	}
	endpoint, err := attestAuthorityRuntimeDirectory(int(f[2].Fd()), launch.ServiceUID, launch.EndpointGID, 0750)
	if err != nil || sameAuthorityRuntimeObject(state, endpoint) {
		return ErrAuthorityChild
	}
	fd := int(f[5].Fd())
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDWR || flags&unix.O_PATH != 0 || unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFCHR || unix.Major(uint64(st.Rdev)) != 1 || unix.Minor(uint64(st.Rdev)) != 3 {
		return ErrAuthorityChild
	}
	return nil
}

// PID is diagnostic only. Signals use the retained pidfd, never this number.
func (c *AuthorityChild) PID() int {
	if c == nil || c.process == nil {
		return 0
	}
	return c.process.Pid
}

// AwaitReady is single-use. It may run alongside Wait or RequestStop, but a
// second concurrent receiver is refused. A ready result is not ongoing health.
func (c *AuthorityChild) AwaitReady(ctx context.Context) error {
	if c == nil || !c.readyMu.TryLock() {
		return ErrAuthorityChild
	}
	defer c.readyMu.Unlock()
	c.mu.Lock()
	invalid := c.closed || c.process == nil || c.readiness == nil || c.state != nil || c.startErr != nil
	c.mu.Unlock()
	if invalid {
		return ErrAuthorityChild
	}
	if err := c.readiness.Wait(ctx); err != nil {
		return errors.Join(ErrAuthorityChild, err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != nil {
		return ErrAuthorityChildExit
	}
	return nil
}

// RequestStop requests SIGTERM through the atomically obtained pidfd. It does
// not wait, prove a clean drain, send SIGKILL, or signal a reused numeric PID.
func (c *AuthorityChild) RequestStop() error {
	if c == nil {
		return ErrAuthorityChild
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.pidfd == nil {
		return ErrAuthorityChild
	}
	if c.state != nil {
		return os.ErrProcessDone
	}
	raw, err := c.pidfd.SyscallConn()
	if err != nil {
		return err
	}
	var operation error
	err = raw.Control(func(fd uintptr) { operation = unix.PidfdSendSignal(int(fd), unix.SIGTERM, nil, 0) })
	return errors.Join(err, operation)
}

// Wait polls for actual kernel exit and then reaps the directly owned child.
// Each observation is capped at 30 seconds and may be retried after cancellation
// or a failure. A failure never discards the process or pidfd. No goroutine or
// automatic signal is used. Only one waiter is admitted, but RequestStop remains
// concurrent. The supervisor must not install another reaper for this child.
func (c *AuthorityChild) Wait(ctx context.Context) (*os.ProcessState, error) {
	if c == nil || ctx == nil || !c.waitMu.TryLock() {
		return nil, ErrAuthorityChild
	}
	defer c.waitMu.Unlock()
	c.mu.Lock()
	invalid := c.closed || c.process == nil || c.pidfd == nil
	state := c.state
	c.mu.Unlock()
	if invalid {
		return nil, ErrAuthorityChild
	}
	if state != nil {
		return state, authorityChildExitError(state, c.startErr)
	}
	bounded, cancel := context.WithTimeout(ctx, MaxAuthorityChildObservation)
	defer cancel()
	tick := time.NewTicker(authorityReadinessInterval)
	defer tick.Stop()
	for {
		if err := bounded.Err(); err != nil {
			return nil, err
		}
		exited, err := authorityChildExited(c.pidfd)
		if err != nil {
			return nil, errors.Join(ErrAuthorityChild, err)
		}
		if err := bounded.Err(); err != nil {
			return nil, err
		}
		if exited {
			state, err = c.process.Wait()
			if err != nil || state == nil {
				return nil, errors.Join(ErrAuthorityChild, err)
			}
			c.mu.Lock()
			c.state = state
			c.mu.Unlock()
			return state, authorityChildExitError(state, c.startErr)
		}
		select {
		case <-bounded.Done():
			return nil, bounded.Err()
		case <-tick.C:
		}
	}
}

func authorityChildExitError(state *os.ProcessState, startErr error) error {
	if state == nil || !state.Success() {
		return errors.Join(ErrAuthorityChildExit, startErr)
	}
	return startErr
}

func authorityChildExited(file *os.File) (bool, error) {
	raw, err := file.SyscallConn()
	if err != nil {
		return false, err
	}
	var exited bool
	var operation error
	err = raw.Control(func(fd uintptr) { exited, operation = pollAuthorityChild(fd, unix.Poll) })
	return exited, errors.Join(err, operation)
}

func pollAuthorityChild(fd uintptr, poll func([]unix.PollFd, int) (int, error)) (bool, error) {
	if fd > math.MaxInt32 || poll == nil {
		return false, ErrAuthorityChild
	}
	fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	n, err := poll(fds, 0)
	if errors.Is(err, unix.EINTR) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	events := fds[0].Revents
	if n == 0 && events == 0 {
		return false, nil
	}
	if n != 1 || events == 0 || events & ^int16(unix.POLLIN|unix.POLLHUP) != 0 {
		return false, ErrAuthorityChild
	}
	return true, nil
}

// Close refuses live or unreaped children and concurrent wait/readiness calls.
// It releases only this supervisor's handles after a successful reap, even for
// a nonzero child exit. Exit status and evidence cleanup are separate verdicts.
func (c *AuthorityChild) Close() error {
	if c == nil {
		return nil
	}
	if !c.readyMu.TryLock() {
		return ErrAuthorityChildRunning
	}
	defer c.readyMu.Unlock()
	if !c.waitMu.TryLock() {
		return ErrAuthorityChildRunning
	}
	defer c.waitMu.Unlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return c.closeErr
	}
	if c.state == nil {
		return ErrAuthorityChildRunning
	}
	c.closed = true
	c.closeErr = errors.Join(c.startErr, c.readiness.Close(), c.pidfd.Close())
	return c.closeErr
}
