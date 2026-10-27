//go:build linux

package system

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type apkNativeOutput struct {
	read, write *os.File
	done        chan error
}

func prepareAPKNativeOutput(command *exec.Cmd, output io.Writer) (*apkNativeOutput, error) {
	if command == nil || output == nil {
		return nil, errors.New("APK native diagnostics are unavailable")
	}
	read, write, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	capture := &apkNativeOutput{read: read, write: write, done: make(chan error, 1)}
	command.Stdout, command.Stderr = write, write
	go func() { _, err := io.Copy(output, read); capture.done <- err }()
	return capture, nil
}

func (output *apkNativeOutput) close() error {
	if output == nil {
		return nil
	}
	return errors.Join(output.read.Close(), output.write.Close())
}

// The leader remains our unreaped child until every group signal is finished.
// Explicit file pipes prevent exec.Wait from hiding an unbounded copy-goroutine
// wait. A descendant retaining diagnostics is a failure, never native success.
func finishAPKNativeProcess(ctx context.Context, command *exec.Cmd, output *apkNativeOutput, prior error) error {
	result := prior
	drained := false
	if result == nil {
		timer := time.NewTimer(qualificationCommandTerminationGrace)
		select {
		case err := <-output.done:
			result = errors.Join(result, err)
			drained = true
		case <-ctx.Done():
			result = errors.Join(result, ctx.Err())
		case <-timer.C:
			result = errors.Join(result, errors.New("APK descendant retained native diagnostic descriptors"))
		}
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
	result = errors.Join(result, stopAPKNativeChild(command.Process.Pid))
	closeErr := output.read.Close()
	if closeErr != nil && !errors.Is(closeErr, os.ErrClosed) {
		result = errors.Join(result, closeErr)
	}
	if !drained {
		err := <-output.done
		if err != nil && !errors.Is(err, os.ErrClosed) {
			result = errors.Join(result, err)
		}
	}
	// No os/exec output copying remains, and no signalling follows this reap.
	return errors.Join(result, command.Wait(), ctx.Err())
}

// The caller keeps its direct child unreaped until this operation completes.
// Waitid checks actual child ownership before signalling, without treating a
// reusable numeric PID or the custody lock as native transaction authority.
func stopAPKNativeChild(pid int) error {
	if pid <= 1 {
		return errors.New("APK original child identity is unavailable")
	}
	for {
		var identity unix.Siginfo
		err := unix.Waitid(unix.P_PID, pid, &identity, unix.WEXITED|unix.WNOHANG|unix.WNOWAIT, nil)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return errors.Join(errors.New("APK original child ownership was lost before group cleanup"), err)
		}
		return signalQualificationProcessGroup(pid, syscall.SIGKILL)
	}
}
