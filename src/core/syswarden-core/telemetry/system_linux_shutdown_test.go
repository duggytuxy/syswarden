//go:build linux

package telemetry

import (
	"bufio"
	"context"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Exercise the actual platform commands with inert readers. The test follows
// the workers' order: consume stdout to EOF, then Wait. Killing only Bash
// leaves its readers holding that pipe open and blocks core shutdown.
func TestLinuxTelemetryCancellationClosesReaders(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatal(err)
	}
	sleep, err := exec.LookPath("sleep")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		command func(context.Context) *exec.Cmd
		tools   []string
		readers int
	}{
		{"allowed_openrc", allowedEventsCommand, []string{"tail", "rc-service"}, 1},
		{"allowed_journal", allowedEventsCommand, []string{"tail", "journalctl"}, 2},
		{"kernel_openrc", kernelDropsCommand, []string{"tail", "rc-service"}, 1},
		{"kernel_journal", kernelDropsCommand, []string{"journalctl"}, 1},
		{"kernel_dmesg", kernelDropsCommand, []string{"dmesg"}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Symlink(bash, filepath.Join(dir, "bash")); err != nil {
				t.Fatal(err)
			}
			for _, name := range tc.tools {
				body := fmt.Sprintf("#!%s\nprintf 'reader:%%s\\n' \"$$\"\nexec %s 60\n", bash, sleep)
				if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0700); err != nil { // #nosec G306 -- Inert executable fixture, owner-only in t.TempDir.
					t.Fatal(err)
				}
			}
			t.Setenv("PATH", dir)
			// A reader with the same executable, outside this command, must survive.
			neighbour := exec.Command(sleep, "60")
			if err := neighbour.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = neighbour.Process.Kill(); _ = neighbour.Wait() })

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cmd := tc.command(ctx)
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			var waitOnce sync.Once
			wait := func() { waitOnce.Do(func() { _ = cmd.Wait() }) }
			t.Cleanup(func() { cancel(); _ = cmd.Process.Kill(); _ = stdout.Close(); wait() })
			ready := make(chan string, 4)
			eof := make(chan error, 1)
			go func() {
				scanner := bufio.NewScanner(stdout)
				for scanner.Scan() {
					ready <- scanner.Text()
				}
				eof <- scanner.Err()
			}()
			var childFDs []int
			for range tc.readers {
				select {
				case line := <-ready:
					pid, err := strconv.Atoi(strings.TrimPrefix(line, "reader:"))
					if err != nil || pid <= 1 {
						t.Fatalf("invalid reader identity %q", line)
					}
					child, err := os.FindProcess(pid)
					if err != nil {
						t.Fatal(err)
					}
					fd, err := unix.PidfdOpen(pid, 0)
					if err != nil {
						_ = child.Kill()
						_ = child.Release()
						t.Fatal(err)
					}
					childFDs = append(childFDs, fd)
					t.Cleanup(func() { _ = unix.Close(fd) })
					t.Cleanup(func() { _ = child.Kill(); _ = child.Release() })
				case <-time.After(3 * time.Second):
					t.Fatal("reader did not produce its native stream readiness line")
				}
			}
			if err := neighbour.Process.Signal(syscall.Signal(0)); err != nil {
				t.Fatal(err)
			}
			cancel()
			select {
			case err := <-eof:
				if err != nil {
					t.Fatalf("reader pipe failed instead of reaching EOF: %v", err)
				}
				wait()
			case <-time.After(2 * time.Second):
				t.Fatal("context cancelled but a descendant still holds stdout open")
			}
			for _, fd := range childFDs {
				if fd < 0 || fd > math.MaxInt32 {
					t.Fatal("reader pidfd is outside poll descriptor range")
					return
				}
				// EOF can precede the final exit transition. Poll the captured
				// pidfd, not a reusable PID or a transient /proc state.
				deadline := time.Now().Add(2 * time.Second)
				for {
					remaining := time.Until(deadline)
					if remaining <= 0 {
						t.Fatal("owned reader did not exit after cancellation")
					}
					fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
					n, err := unix.Poll(fds, int((remaining+time.Millisecond-1)/time.Millisecond))
					if err == unix.EINTR {
						continue
					}
					if err != nil {
						t.Fatal(err)
					}
					if n > 0 {
						if fds[0].Revents&unix.POLLIN == 0 {
							t.Fatalf("invalid reader exit event: %v", fds[0].Revents)
						}
						break
					}
				}
			}
			if err := neighbour.Process.Signal(syscall.Signal(0)); err != nil {
				t.Fatalf("cancellation affected unrelated process: %v", err)
			}
		})
	}
}

func TestLinuxTelemetryAlreadyCancelledDoesNotStart(t *testing.T) {
	for _, command := range []func(context.Context) *exec.Cmd{allowedEventsCommand, kernelDropsCommand} {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		cmd := command(ctx)
		if err := cmd.Start(); err != context.Canceled {
			t.Fatalf("Start = %v, want cancelled", err)
		}
		if cmd.Process != nil {
			t.Fatal("cancelled command started a process")
		}
	}
}
