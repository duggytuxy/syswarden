//go:build linux

package system

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestAPKNativeOutputDrainCannotOutliveCancellationOrDescendantBound(t *testing.T) {
	for _, kind := range []string{"ordinary-exit", "inherited-descriptor", "cancel-after-leader-exit"} {
		t.Run(kind, func(t *testing.T) {
			childPath := filepath.Join(t.TempDir(), "child.pid")
			script := "printf complete; exit 0"
			if kind != "ordinary-exit" {
				script = "sleep 30 & printf '%s\\n' \"$!\" > \"$1\"; exit 0"
			}
			command := exec.Command("/bin/sh", "-c", script, "apk-output-fixture", childPath) // #nosec G204 -- script is one of two fixed test literals; the temporary child path is passed as quoted positional data
			command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			var output bytes.Buffer
			capture, err := prepareAPKNativeOutput(command, &output)
			if err != nil {
				t.Fatal(err)
			}
			defer capture.close()
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			if err := capture.write.Close(); err != nil {
				t.Fatal(err)
			}
			var identity unix.Siginfo
			if err := unix.Waitid(unix.P_PID, command.Process.Pid, &identity, unix.WEXITED|unix.WNOWAIT, nil); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if kind == "cancel-after-leader-exit" {
				cancel()
			}
			start := time.Now()
			err = finishAPKNativeProcess(ctx, command, capture, nil)
			if time.Since(start) > qualificationCommandTerminationGrace+2*time.Second {
				t.Fatal("native diagnostic cleanup exceeded its bounded drain")
			}
			if kind == "ordinary-exit" {
				if err != nil || output.String() != "complete" {
					t.Fatal("ordinary bounded completion failed", err, output.String())
				}
				return
			}
			if err == nil {
				t.Fatal("descendant or cancellation was hidden by leader exit0")
			}
			if kind == "cancel-after-leader-exit" && !errors.Is(err, context.Canceled) {
				t.Fatal("late cancellation lost", err)
			}
			raw, readErr := os.ReadFile(childPath) // #nosec G304 -- fixed child.pid basename inside this test private temporary directory
			if readErr != nil {
				t.Fatal(readErr)
			}
			pid, parseErr := strconv.Atoi(strings.TrimSpace(string(raw)))
			if parseErr != nil || pid <= 1 {
				t.Fatal("fixture child identity unavailable")
			}
			// A killed orphan can remain a zombie until container/init reaps it. It must
			// no longer execute or retain an open output pipe when this call returns.
			deadline := time.Now().Add(time.Second)
			for {
				process, openErr := os.OpenRoot("/proc/" + strconv.Itoa(pid))
				if errors.Is(openErr, os.ErrNotExist) {
					break
				}
				if openErr != nil {
					t.Fatal(openErr)
				}
				stat, statErr := readBoundedFirewallRemovalProcFile(process, "stat", 8192)
				_ = process.Close()
				if statErr != nil {
					break
				}
				end := strings.LastIndex(string(stat), ") ")
				if end >= 0 && strings.HasPrefix(string(stat)[end+2:], "Z ") {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("owned descendant survived native cleanup")
				}
				time.Sleep(10 * time.Millisecond)
			}
		})
	}
}
