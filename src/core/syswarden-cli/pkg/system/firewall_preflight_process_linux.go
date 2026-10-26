//go:build linux

package system

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

// captureFirewallPreflightProcess owns the child's process group until cleanup.
// Waitid observes exit without reaping: a later group signal must never target a
// recycled PID. Only Wait below reaps the original leader. Trusted manager tools
// must not escape their group; external daemons and kernel stalls are not bounded
// by this userspace runner.
func captureFirewallPreflightProcess(path string, arguments []string, timeout time.Duration, streams *boundedFirewallPreflightStreams) error {
	deadline := time.Now().Add(timeout)
	stdout, stdoutWrite, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("create firewall preflight stdout pipe: %w", err)
	}
	defer stdout.Close()
	defer stdoutWrite.Close()
	stderr, stderrWrite, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("create firewall preflight stderr pipe: %w", err)
	}
	defer stderr.Close()
	defer stderrWrite.Close()
	command := exec.Command(path, arguments...) // #nosec G204 -- caller validates the resolved trusted executable and selects fixed manager arguments
	command.Env = []string{"LC_ALL=C", "LANG=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Stdout, command.Stderr = stdoutWrite, stderrWrite
	// File-backed pipes avoid os/exec copy goroutines and implicit reaping while
	// inherited descendant descriptors are still open. Stdin defaults to null.
	if err := command.Start(); err != nil {
		return err
	}
	_ = stdoutWrite.Close()
	_ = stderrWrite.Close()
	var readers sync.WaitGroup
	readErrors := make(chan error, 2)
	readDone := make(chan struct{})
	readSignal := readDone
	for _, channel := range []struct {
		source *os.File
		target io.Writer
	}{
		{stdout, &boundedFirewallPreflightStreamWriter{streams: streams, target: &streams.stdout}},
		{stderr, &boundedFirewallPreflightStreamWriter{streams: streams, target: &streams.stderr}},
	} {
		readers.Add(1)
		go func(source *os.File, target io.Writer) {
			defer readers.Done()
			_, copyErr := io.Copy(target, source)
			if copyErr != nil && !errors.Is(copyErr, os.ErrClosed) {
				readErrors <- copyErr
			}
		}(channel.source, channel.target)
	}
	go func() { readers.Wait(); close(readDone) }()

	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	poll := time.NewTicker(10 * time.Millisecond)
	defer poll.Stop()
	completedStreams := false
	owned := true
	var captureErr error
observe:
	for {
		if !time.Now().Before(deadline) {
			captureErr = fmt.Errorf("firewall preflight command exceeded %s: %w", timeout, context.DeadlineExceeded)
			break
		}
		var info unix.Siginfo
		err := unix.Waitid(unix.P_PID, command.Process.Pid, &info, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT, nil)
		if err != nil && !errors.Is(err, syscall.EINTR) {
			owned = false
			captureErr = fmt.Errorf("firewall preflight leader ownership is unavailable: %w", err)
			break
		}
		if completedStreams && info.Signo != 0 {
			break
		}
		select {
		case <-timer.C:
			captureErr = fmt.Errorf("firewall preflight command exceeded %s: %w", timeout, context.DeadlineExceeded)
			break observe
		case <-streams.overflow:
			captureErr = errors.New("firewall preflight command output exceeds its capture bound")
			break observe
		case <-readSignal:
			completedStreams = true
			readSignal = nil
		case <-poll.C:
		}
	}
	// A second observation covers early overflow/deadline failure. Losing
	// parent ownership forbids group signaling, even when the PID still exists.
	if owned {
		var info unix.Siginfo
		if err := unix.Waitid(unix.P_PID, command.Process.Pid, &info, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT, nil); err != nil {
			owned = false
			captureErr = errors.Join(captureErr, fmt.Errorf("firewall preflight leader ownership was lost: %w", err))
		}
	}
	if owned {
		if err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			captureErr = errors.Join(captureErr, fmt.Errorf("stop original firewall preflight process group: %w", err))
		}
	}
	// Close inherited pipes independently of descendant behavior. No copy
	// goroutine or descriptor remains after the runner returns.
	_ = stdout.Close()
	_ = stderr.Close()
	readers.Wait()
	close(readErrors)
	for err := range readErrors {
		captureErr = errors.Join(captureErr, fmt.Errorf("read firewall preflight output: %w", err))
	}
	waitErr := command.Wait()
	if captureErr != nil {
		return captureErr
	}
	return waitErr
}
