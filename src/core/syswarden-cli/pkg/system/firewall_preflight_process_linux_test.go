//go:build linux

package system

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func assertPreflightPIDStopped(t *testing.T, pid int) {
	t.Helper()
	until := time.Now().Add(2 * time.Second)
	for time.Now().Before(until) {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		end := strings.LastIndexByte(string(data), ')')
		if end < 0 {
			t.Fatal("invalid fixture process state")
		}
		fields := strings.Fields(string(data[end+1:]))
		if len(fields) > 0 && fields[0] == "Z" {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("preflight descendant remains running")
}

func TestFirewallPreflightStopsDescendantsAfterLeaderExit(t *testing.T) {
	directory := firewallPreflightTestDirectory(t)
	for _, inherited := range []bool{false, true} {
		t.Run(fmt.Sprintf("inherited_pipes_%t", inherited), func(t *testing.T) {
			redirect := " >/dev/null 2>&1"
			if inherited {
				redirect = ""
			}
			body := "sleep 60" + redirect + " &\nprintf '%s\n' \"$!\"\nexit 0\n"
			path := writeFirewallPreflightTestExecutable(t, directory, fmt.Sprintf("leader-%t", inherited), body, 0700)
			started := time.Now()
			output, err := runFirewallPreflightCommandWithTimeout(path, 200*time.Millisecond)
			if inherited {
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("inherited pipe deadline = %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if time.Since(started) > 2*time.Second {
				t.Fatal("preflight exceeded bounded observation")
			}
			pid, parseErr := strconv.Atoi(strings.TrimSpace(string(output)))
			if parseErr != nil || pid <= 1 {
				t.Fatalf("missing child fixture identity: %q, %v", output, parseErr)
			}
			assertPreflightPIDStopped(t, pid)
		})
	}
}

func TestFirewallPreflightOverflowStopsBeforeConfiguredDeadline(t *testing.T) {
	directory := firewallPreflightTestDirectory(t)
	for _, channel := range []string{"stdout", "stderr"} {
		t.Run(channel, func(t *testing.T) {
			redirect := ""
			if channel == "stderr" {
				redirect = " >&2"
			}
			path := writeFirewallPreflightTestExecutable(t, directory, "overflow-"+channel, "exec yes PRIVATE-TOOL-OUTPUT"+redirect, 0700)
			started := time.Now()
			output, err := runFirewallPreflightCommandWithTimeout(path, 5*time.Second)
			if err == nil || !strings.Contains(err.Error(), "output exceeds") {
				t.Fatalf("overflow = %v", err)
			}
			if len(output) != maximumFirewallPreflightOutput || time.Since(started) > 2*time.Second {
				t.Fatal("capture did not stop at its byte bound")
			}
			if strings.Contains(err.Error(), "PRIVATE-TOOL-OUTPUT") {
				t.Fatal("output leaked into diagnostic")
			}
		})
	}
}

func TestFirewallPreflightClosedPipesStillRequireLeaderCompletion(t *testing.T) {
	directory := firewallPreflightTestDirectory(t)
	path := writeFirewallPreflightTestExecutable(t, directory, "closed-pipes", "exec 1>&- 2>&-\nexec sleep 60", 0700)
	_, err := runFirewallPreflightCommandWithTimeout(path, 50*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("closed pipes accepted a live process: %v", err)
	}
}

func TestFirewallPreflightRetainsExactOutputAndExitStatus(t *testing.T) {
	directory := firewallPreflightTestDirectory(t)
	path := writeFirewallPreflightTestExecutable(t, directory, "raw-output", "test -z \"$(cat)\" || exit 9\nprintf 'record\r\n\377'\nprintf 'logger\r\n' >&2\nexit 17", 0700)
	output, err := runFirewallPreflightCommandWithTimeout(path, time.Second)
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 17 {
		t.Fatalf("lost native exit classification: %v", err)
	}
	if string(output) != "record\r\n\xfflogger\r\n" {
		t.Fatalf("evidence bytes changed: %q", output)
	}
}

func TestFirewallPreflightDoesNotRetainProcessDescriptors(t *testing.T) {
	directory := firewallPreflightTestDirectory(t)
	path := writeFirewallPreflightTestExecutable(t, directory, "no-leak", "printf exact", 0700)
	// Warm the runtime poller before comparing descriptors used by the loop.
	if _, err := runFirewallPreflightCommandWithTimeout(path, time.Second); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for range 24 {
		output, err := runFirewallPreflightCommandWithTimeout(path, time.Second)
		if err != nil || string(output) != "exact" {
			t.Fatalf("successful probe failed: %q, %v", output, err)
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) > len(before) {
		t.Fatalf("process descriptor growth: %d -> %d", len(before), len(after))
	}
}
