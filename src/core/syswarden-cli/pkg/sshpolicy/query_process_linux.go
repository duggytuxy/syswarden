//go:build linux

package sshpolicy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// runSSHQueryProcess captures only a prepared, bounded inspection command. The
// caller still owns executable attestation, fixed arguments and output limits.
// Keep the leader unreaped until group cleanup so no signal uses a recycled PID.
// Trusted tools must stay in this group; this is not a sandbox for arbitrary
// executables and cannot bound external daemons or uninterruptible kernel I/O.
func runSSHQueryProcess(ctx context.Context, command *exec.Cmd) error {
	if ctx == nil || command == nil || command.Process != nil || command.Stdin != nil ||
		command.Stdout == nil || command.Stderr == nil || command.SysProcAttr != nil {
		return ErrInventoryUnsafe
	}
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) > 10*time.Second {
		return ErrInventoryUnsafe
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	stdout, stdoutWrite, err := os.Pipe()
	if err != nil {
		return err
	}
	defer stdout.Close()
	defer stdoutWrite.Close()
	stderr, stderrWrite, err := os.Pipe()
	if err != nil {
		return err
	}
	defer stderr.Close()
	defer stderrWrite.Close()
	stdoutTarget, stderrTarget := command.Stdout, command.Stderr
	command.Stdout, command.Stderr = stdoutWrite, stderrWrite
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// This runner handles cancellation before reaping. Do not run os/exec's
	// concurrent context callback or delayed pipe cleanup against that lifecycle.
	command.Cancel = nil
	command.WaitDelay = 0
	if err := command.Start(); err != nil {
		return err
	}
	_ = stdoutWrite.Close()
	_ = stderrWrite.Close()
	var readers sync.WaitGroup
	readErrors := make(chan error, 2)
	readDone := make(chan struct{})
	readSignal := readDone
	for _, stream := range []struct {
		source *os.File
		target io.Writer
	}{
		{stdout, stdoutTarget}, {stderr, stderrTarget},
	} {
		readers.Add(1)
		go func(source *os.File, target io.Writer) {
			defer readers.Done()
			if _, copyErr := io.Copy(target, source); copyErr != nil && !errors.Is(copyErr, os.ErrClosed) {
				readErrors <- copyErr
			}
		}(stream.source, stream.target)
	}
	go func() { readers.Wait(); close(readDone) }()
	poll := time.NewTicker(10 * time.Millisecond)
	defer poll.Stop()
	streamsDone, owned := false, true
	var captureErr error
observe:
	for {
		if err := ctx.Err(); err != nil {
			captureErr = err
			break
		}
		exited, err := observeSSHQueryChild(command.Process.Pid)
		if err != nil {
			owned = false
			captureErr = err
			break
		}
		if streamsDone && exited {
			break
		}
		select {
		case <-ctx.Done():
			captureErr = ctx.Err()
			break observe
		case err := <-readErrors:
			captureErr = err
			break observe
		case <-readSignal:
			streamsDone = true
			readSignal = nil
		case <-poll.C:
		}
	}
	// Failure may precede the first observation. ECHILD or any other unexpected
	// ownership error forbids a process-group signal even if its numeric PID exists.
	if owned {
		if _, err := observeSSHQueryChild(command.Process.Pid); err != nil {
			owned = false
			captureErr = errors.Join(captureErr, err)
		}
	}
	if owned {
		if err := unix.Kill(-command.Process.Pid, unix.SIGKILL); err != nil && !errors.Is(err, unix.ESRCH) {
			captureErr = errors.Join(captureErr, err)
		}
	}
	_ = stdout.Close()
	_ = stderr.Close()
	readers.Wait()
	close(readErrors)
	for err := range readErrors {
		captureErr = errors.Join(captureErr, err)
	}
	waitErr := command.Wait()
	if captureErr != nil {
		return fmt.Errorf("SSH query capture failed: %w", captureErr)
	}
	return waitErr
}

func observeSSHQueryChild(pid int) (bool, error) {
	if pid <= 1 {
		return false, ErrInventoryUnsafe
	}
	for {
		var info unix.Siginfo
		err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return info.Signo != 0, err
	}
}
