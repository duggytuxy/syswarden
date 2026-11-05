//go:build linux

package network

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestWireGuardCaptureFixture(t *testing.T) {
	mode := ""
	for _, arg := range os.Args {
		if strings.HasPrefix(arg, "--wg-capture=") {
			mode = strings.TrimPrefix(arg, "--wg-capture=")
		}
	}
	if mode == "" {
		return
	}
	switch mode {
	case "echo":
		_, _ = io.Copy(os.Stdout, os.Stdin)
	case "fail":
		_, _ = io.Copy(os.Stdout, os.Stdin)
		fmt.Fprint(os.Stderr, "PRIVATE-TOOL-FIXTURE")
		os.Exit(7)
	case "sleep":
		time.Sleep(30 * time.Second)
	case "overflow":
		signal.Ignore(syscall.SIGPIPE)
		for {
			if _, err := io.WriteString(os.Stdout, strings.Repeat("x", 4096)); err != nil {
				time.Sleep(30 * time.Second)
			}
		}
	case "inherited", "service":
		child := exec.Command("/proc/self/exe", "-test.run=^TestWireGuardCaptureFixture$", "--", "--wg-capture=sleep")
		if mode == "inherited" {
			child.Stdout, child.Stderr = os.Stdout, os.Stderr
		}
		if err := child.Start(); err != nil {
			os.Exit(22)
		}
		fmt.Fprintf(os.Stdout, "%d %d\n", os.Getpid(), child.Process.Pid)
		os.Exit(0)
	default:
		os.Exit(23)
	}
	os.Exit(0)
}

func wireGuardCaptureCommand(ctx context.Context, mode string) *exec.Cmd {
	switch mode {
	case "echo", "fail", "overflow", "sleep", "inherited", "service":
	default:
		panic("invalid private fixture mode")
	}
	command := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestWireGuardCaptureFixture$", "--", "--wg-capture="+mode) // #nosec G204 -- fixed self-executable test fixture with a closed mode list and no shell
	command.Env = []string{"GORACE=atexit_sleep_ms=0"}
	return command
}

func TestWireGuardCaptureInputAndExit(t *testing.T) {
	for _, mode := range []string{"echo", "fail", "overflow", "sleep"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			input := "PRIVATE-KEY-FIXTURE"
			if mode == "sleep" {
				input = strings.Repeat("x", maximumWireGuardCommandOutput)
			}
			command := wireGuardCaptureCommand(ctx, mode)
			output := &boundedWireGuardCommandBuffer{limit: 128}
			start := time.Now()
			err := captureWireGuardProcess(ctx, command, input, output)
			switch mode {
			case "echo":
				if err != nil || output.buffer.String() != input {
					t.Fatal("input capture differs", err)
				}
			case "fail":
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 7 {
					t.Fatal("missing exit status", err)
				}
			case "overflow":
				if err == nil || !strings.Contains(err.Error(), "exceeds") || time.Since(start) > time.Second {
					t.Fatal("overflow was not stopped promptly", err)
				}
			case "sleep":
				if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 4*time.Second {
					t.Fatal("blocked stdin was not cancelled", err)
				}
			}
			if err != nil && (strings.Contains(err.Error(), "PRIVATE-KEY") || strings.Contains(err.Error(), "PRIVATE-TOOL")) {
				t.Fatal("private I/O leaked into error")
			}
			if output.buffer.Len() > 128 || command.ProcessState == nil {
				t.Fatal("capture bound or child cleanup lost")
			}
		})
	}
}

func wireGuardCaptureChild(t *testing.T, output *boundedWireGuardCommandBuffer) (int, int) {
	t.Helper()
	output.mu.Lock()
	wire := output.buffer.String()
	output.mu.Unlock()
	fields := strings.Fields(wire)
	if len(fields) != 2 {
		t.Fatal("fixture identities missing")
	}
	parent, err := strconv.Atoi(fields[0])
	if err != nil || parent <= 1 {
		t.Fatal("invalid fixture leader")
	}
	child, err := strconv.Atoi(fields[1])
	if err != nil || child <= 1 {
		t.Fatal("invalid fixture child")
	}
	return parent, child
}

func wireGuardCapturePIDFD(t *testing.T, pid int) int {
	t.Helper()
	fd, err := unix.PidfdOpen(pid, 0)
	if errors.Is(err, unix.ESRCH) {
		return -1
	}
	if err != nil || fd < 0 || fd > 1<<31-1 {
		t.Fatal("cannot pin fixture child", err)
	}
	t.Cleanup(func() { _ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); _ = unix.Close(fd) })
	return fd
}

func TestWireGuardCaptureRetainsLeaderUntilPipeCleanup(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	command := wireGuardCaptureCommand(ctx, "inherited")
	output := &boundedWireGuardCommandBuffer{limit: 1024}
	done := make(chan struct{})
	var runErr error
	go func() { runErr = captureWireGuardProcess(ctx, command, "", output); close(done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(6 * time.Second):
			t.Error("fixture runner did not stop")
		}
	})
	// Observe the kernel child rather than racing command.Process, which Start
	// sets in the runner goroutine. The fixture writes both numeric identities.
	until := time.Now().Add(time.Second)
	for time.Now().Before(until) {
		output.mu.Lock()
		ready := strings.Contains(output.buffer.String(), "\n")
		output.mu.Unlock()
		if ready {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	parent, child := wireGuardCaptureChild(t, output)
	childFD := wireGuardCapturePIDFD(t, child)
	// The original leader must remain waitable while its descendant holds the
	// capture descriptor. WNOWAIT observation itself never consumes that identity.
	sawExit := false
	until = time.Now().Add(time.Second)
	for time.Now().Before(until) {
		exited, err := observeWireGuardChild(parent)
		if err != nil {
			t.Fatal("leader reaped before capture cleanup", err)
		}
		if exited {
			sawExit = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !sawExit {
		t.Fatal("fixture leader did not exit")
	}
	<-done
	if !errors.Is(runErr, exec.ErrWaitDelay) {
		t.Fatal("missing inherited-pipe refusal", runErr)
	}
	if childFD >= 0 {
		if exited, err := wireGuardCaptureExited(childFD, 2000); err != nil || !exited {
			t.Fatal("original descendant survived cleanup", err)
		}
	}
	if command.ProcessState == nil {
		t.Fatal("leader not reaped after cleanup")
	}
}

func TestWireGuardCapturePreservesSuccessfulServiceChild(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	command := wireGuardCaptureCommand(ctx, "service")
	output := &boundedWireGuardCommandBuffer{limit: 1024}
	if err := captureWireGuardProcess(ctx, command, "", output); err != nil {
		t.Fatal(err)
	}
	_, child := wireGuardCaptureChild(t, output)
	fd := wireGuardCapturePIDFD(t, child)
	if fd < 0 {
		t.Fatal("successful service child was killed")
	}
	if exited, err := wireGuardCaptureExited(fd, 0); err != nil || exited {
		t.Fatal("successful service child was changed", err)
	}
}

func TestWireGuardCaptureRejectsInvalidInput(t *testing.T) {
	for _, mode := range []string{"nil-context", "cancelled", "nil-command", "nil-output", "overflow-input", "bad-limit", "stdin", "stdout", "stderr", "attributes", "started"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			command := wireGuardCaptureCommand(ctx, "echo")
			output := &boundedWireGuardCommandBuffer{limit: 1024}
			input := ""
			switch mode {
			case "nil-context":
				ctx = nil
			case "cancelled":
				cancel()
			case "nil-command":
				command = nil
			case "nil-output":
				output = nil
			case "overflow-input":
				input = strings.Repeat("x", maximumWireGuardCommandOutput+1)
			case "bad-limit":
				output.limit = 0
			case "stdin":
				command.Stdin = strings.NewReader("input")
			case "stdout":
				command.Stdout = io.Discard
			case "stderr":
				command.Stderr = io.Discard
			case "attributes":
				command.SysProcAttr = &syscall.SysProcAttr{}
			case "started":
				command.Process = &os.Process{Pid: os.Getpid()}
			}
			if err := captureWireGuardProcess(ctx, command, input, output); err == nil {
				t.Fatal("unsafe command accepted")
			}
			if mode != "started" && command != nil && command.Process != nil {
				t.Fatal("invalid command started")
			}
		})
	}
}

func wireGuardCaptureExited(fd, timeout int) (bool, error) {
	if fd < 0 || fd > 1<<31-1 {
		return false, errors.New("invalid fixture pidfd")
	}
	descriptors := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	n, err := unix.Poll(descriptors, timeout)
	return n == 1 && descriptors[0].Revents&unix.POLLIN != 0, err
}

func TestWireGuardCommandFailureDoesNotEchoPrivateOutput(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	previousResolver, previousCapture := wireGuardExecutableResolver, wireGuardExecutableIdentityCapture
	wireGuardExecutableResolver = func(name string) (string, error) {
		if name != "wg-fixture" {
			return "", errors.New("unexpected fixture tool")
		}
		return executable, nil
	}
	wireGuardExecutableIdentityCapture = func(path string) (wireGuardExecutableIdentity, error) {
		return captureWireGuardExecutableIdentityForOwner(path, networkTestUID(t), false)
	}
	t.Cleanup(func() {
		wireGuardExecutableResolver = previousResolver
		wireGuardExecutableIdentityCapture = previousCapture
	})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	wire, err := runBoundedWireGuardCommandContext(ctx, "wg-fixture", []string{"-test.run=^TestWireGuardCaptureFixture$", "--", "--wg-capture=fail"}, "PRIVATE-KEY-FIXTURE", 1024)
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 7 {
		t.Fatal("lost command exit status", err)
	}
	if !strings.Contains(string(wire), "PRIVATE-KEY-FIXTURE") || !strings.Contains(string(wire), "PRIVATE-TOOL-FIXTURE") {
		t.Fatal("bounded private classification output was lost")
	}
	if strings.Contains(err.Error(), "PRIVATE-KEY") || strings.Contains(err.Error(), "PRIVATE-TOOL") {
		t.Fatal("private output copied into command error")
	}
}
