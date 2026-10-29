//go:build linux

package sshpolicy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestSSHQueryProcessFixture(t *testing.T) {
	mode := os.Getenv("SYSWARDEN_SSH_QUERY_FIXTURE")
	if mode == "" {
		return
	}
	switch mode {
	case "sleep":
		time.Sleep(30 * time.Second)
	case "output":
		fmt.Fprint(os.Stdout, "query-output")
		fmt.Fprint(os.Stderr, "query-warning")
	case "exit":
		fmt.Fprint(os.Stderr, "PRIVATE-QUERY-DETAIL")
		os.Exit(7)
	case "stdout", "stderr":
		target := os.Stdout
		if mode == "stderr" {
			target = os.Stderr
		}
		for {
			if _, err := io.WriteString(target, strings.Repeat("x", 4096)); err != nil {
				time.Sleep(30 * time.Second)
			}
		}
	case "inherited", "detached-streams", "parent-live":
		child := exec.Command("/proc/self/exe", "-test.run=^TestSSHQueryProcessFixture$")
		child.Env = []string{"SYSWARDEN_SSH_QUERY_FIXTURE=sleep"}
		if mode != "detached-streams" {
			child.Stdout, child.Stderr = os.Stdout, os.Stderr
		}
		if err := child.Start(); err != nil {
			os.Exit(23)
		}
		fmt.Fprintln(os.Stdout, child.Process.Pid)
		if mode == "parent-live" {
			time.Sleep(30 * time.Second)
		}
		os.Exit(0)
	default:
		os.Exit(24)
	}
	os.Exit(0)
}

func sshQueryFixtureCommand(ctx context.Context, mode string) (*exec.Cmd, *parserOutput, *parserOutput) {
	command := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestSSHQueryProcessFixture$")
	command.Env = []string{"SYSWARDEN_SSH_QUERY_FIXTURE=" + mode}
	command.WaitDelay = 50 * time.Millisecond
	stdout, stderr := &parserOutput{}, &parserOutput{}
	command.Stdout, command.Stderr = stdout, stderr
	return command, stdout, stderr
}

func TestSSHQueryProcessKeepsSeparateBoundedOutput(t *testing.T) {
	for _, mode := range []string{"output", "exit", "stdout", "stderr"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			command, stdout, stderr := sshQueryFixtureCommand(ctx, mode)
			start := time.Now()
			err := runSSHQueryProcess(ctx, command)
			switch mode {
			case "output":
				if err != nil || string(stdout.Bytes()) != "query-output" || string(stderr.Bytes()) != "query-warning" {
					t.Fatal("output separation failed", err)
				}
			case "exit":
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 7 || strings.Contains(err.Error(), "PRIVATE-QUERY-DETAIL") {
					t.Fatal("lost private exit status", err)
				}
			default:
				if !errors.Is(err, ErrInventoryBounds) || stdout.Len() > MaxBytes || stderr.Len() > MaxBytes || time.Since(start) > 3*time.Second {
					t.Fatal("overflow did not stop promptly within bounds", err)
				}
			}
			if command.ProcessState == nil {
				t.Fatal("query leader was not reaped")
			}
		})
	}
}

func TestSSHQueryProcessStopsOriginalGroup(t *testing.T) {
	for _, mode := range []string{"inherited", "detached-streams", "parent-live"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 1500*time.Millisecond)
			defer cancel()
			command, stdout, _ := sshQueryFixtureCommand(ctx, mode)
			start := time.Now()
			err := runSSHQueryProcess(ctx, command)
			pid, parseErr := strconv.Atoi(strings.TrimSpace(string(stdout.Bytes())))
			if parseErr != nil || pid <= 1 {
				t.Fatal("fixture child identity missing", parseErr)
			}
			// Pin any surviving child before arranging test cleanup. Never signal a
			// numeric PID after the runner has reaped the original group leader.
			fd, openErr := unix.PidfdOpen(pid, 0)
			if openErr != nil && !errors.Is(openErr, unix.ESRCH) {
				t.Fatal(openErr)
			}
			if openErr == nil {
				defer unix.Close(fd)
				defer func() { _ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0) }()
				if fd < 0 || fd > 1<<31-1 {
					t.Fatal("fixture descriptor is out of range")
					return
				}
				descriptors := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
				n, pollErr := unix.Poll(descriptors, 2000)
				if pollErr != nil || n != 1 || descriptors[0].Revents&unix.POLLIN == 0 {
					t.Fatal("query descendant survived cleanup", pollErr)
				}
			}
			if mode == "detached-streams" {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("inherited process was not deadline bounded", err)
			}
			if time.Since(start) > 4*time.Second {
				t.Fatal("query cleanup exceeded bound")
			}
			if command.ProcessState == nil {
				t.Fatal("query leader was not reaped")
			}
		})
	}
}

func TestSSHQueryProcessRejectsInvalidLifecycle(t *testing.T) {
	for _, mode := range []string{"nil-context", "nil-command", "no-deadline", "long-deadline", "cancelled", "stdin", "missing-stdout", "missing-stderr", "attributes", "started"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			command, _, _ := sshQueryFixtureCommand(ctx, "output")
			switch mode {
			case "nil-context":
				ctx = nil
			case "nil-command":
				command = nil
			case "no-deadline":
				ctx = context.Background()
			case "long-deadline":
				var stop context.CancelFunc
				ctx, stop = context.WithTimeout(t.Context(), time.Minute)
				defer stop()
			case "cancelled":
				cancel()
			case "stdin":
				command.Stdin = strings.NewReader("unexpected")
			case "missing-stdout":
				command.Stdout = nil
			case "missing-stderr":
				command.Stderr = nil
			case "attributes":
				command.SysProcAttr = &syscall.SysProcAttr{}
			case "started":
				command.Process = &os.Process{Pid: os.Getpid()}
			}
			if err := runSSHQueryProcess(ctx, command); err == nil {
				t.Fatal("accepted invalid query lifecycle")
			}
			if mode != "started" && command != nil && command.Process != nil {
				t.Fatal("invalid command started")
			}
		})
	}
}

func TestSSHQueryProcessCancellationDoesNotUseExecCallback(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 1500*time.Millisecond)
	defer cancel()
	command, _, _ := sshQueryFixtureCommand(ctx, "sleep")
	command.Cancel = func() error { panic("unexpected asynchronous cancellation") }
	if err := runSSHQueryProcess(ctx, command); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if command.ProcessState == nil {
		t.Fatal("cancelled query was not reaped")
	}
}

func TestSSHQueryObservationDoesNotReapLeader(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	command, _, _ := sshQueryFixtureCommand(ctx, "output")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = command.Process.Kill(); _ = command.Wait() }()
	until := time.Now().Add(3 * time.Second)
	exited := false
	for time.Now().Before(until) {
		var err error
		exited, err = observeSSHQueryChild(command.Process.Pid)
		if err != nil {
			t.Fatal(err)
		}
		if exited {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !exited {
		t.Fatal("fixture leader did not exit")
	}
	if exited, err := observeSSHQueryChild(command.Process.Pid); err != nil || !exited {
		t.Fatal("leader identity was not retained", err)
	}
	if err := command.Wait(); err != nil {
		t.Fatal("observer reaped leader", err)
	}
	if _, err := observeSSHQueryChild(command.Process.Pid); !errors.Is(err, unix.ECHILD) {
		t.Fatal("lost child ownership was not detected", err)
	}
}

func TestSSHQueryProcessPreservesUnrelatedGroup(t *testing.T) {
	other := exec.Command("/proc/self/exe", "-test.run=^TestSSHQueryProcessFixture$")
	other.Env = []string{"SYSWARDEN_SSH_QUERY_FIXTURE=sleep"}
	other.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := other.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Process.Kill(); _ = other.Wait() }()
	fd, err := unix.PidfdOpen(other.Process.Pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if fd < 0 || fd > 1<<31-1 {
		t.Fatal("fixture descriptor is out of range")
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), 1500*time.Millisecond)
	defer cancel()
	command, _, _ := sshQueryFixtureCommand(ctx, "sleep")
	if err := runSSHQueryProcess(ctx, command); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	descriptors := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	if n, err := unix.Poll(descriptors, 0); err != nil || n != 0 {
		t.Fatal("unrelated process group was changed", err)
	}
}

func TestSSHQueryProcessClosesPipesWhenStartFails(t *testing.T) {
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for range 32 {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		command := exec.CommandContext(ctx, "/syswarden-missing-query-fixture")
		command.Stdout, command.Stderr = &parserOutput{}, &parserOutput{}
		err := runSSHQueryProcess(ctx, command)
		cancel()
		if err == nil || command.Process != nil {
			t.Fatal("missing executable started")
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) > len(before)+2 {
		t.Fatal("failed query starts leaked pipe descriptors")
	}
}
