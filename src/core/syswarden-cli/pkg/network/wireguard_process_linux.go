//go:build linux

package network

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// captureWireGuardProcess keeps the original leader unreaped through failure
// cleanup. A successful service-manager command may intentionally leave a daemon
// running; only failed capture cancels its original process group. External
// daemons, escaped descendants and uninterruptible kernel operations are outside
// this trusted-tool boundary. No process-group signal occurs after Wait.
func captureWireGuardProcess(ctx context.Context, command *exec.Cmd, input string, output *boundedWireGuardCommandBuffer) error {
	if ctx == nil || command == nil || command.Process != nil || command.Stdin != nil || command.Stdout != nil || command.Stderr != nil ||
		command.SysProcAttr != nil || output == nil || output.limit < 1 || output.limit > maximumWireGuardCommandOutput || len(input) > maximumWireGuardCommandOutput {
		return errors.New("invalid WireGuard process capture")
	}
	ctx, cancel := context.WithTimeout(ctx, wireGuardCommandTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	readOutput, writeOutput, err := os.Pipe()
	if err != nil {
		return err
	}
	defer readOutput.Close()
	defer writeOutput.Close()
	var readInput, writeInput *os.File
	if input != "" {
		readInput, writeInput, err = os.Pipe()
		if err != nil {
			return err
		}
		defer readInput.Close()
		defer writeInput.Close()
		command.Stdin = readInput
	}
	command.Stdout, command.Stderr = writeOutput, writeOutput
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = nil
	command.WaitDelay = 0
	if err := command.Start(); err != nil {
		return err
	}
	_ = writeOutput.Close()
	if readInput != nil {
		_ = readInput.Close()
	}
	var copies sync.WaitGroup
	outputResult := make(chan error, 1)
	inputResult := make(chan error, 1)
	copies.Add(1)
	go func() { defer copies.Done(); _, err := io.Copy(output, readOutput); outputResult <- err }()
	if writeInput == nil {
		inputResult <- nil
	} else {
		copies.Add(1)
		go func() {
			defer copies.Done()
			_, err := io.Copy(writeInput, strings.NewReader(input))
			_ = writeInput.Close()
			inputResult <- err
		}()
	}
	outputSignal, inputSignal := outputResult, inputResult
	outputDone, inputDone := false, false
	var outputErr, inputErr, captureErr error
	var drainDeadline time.Time
	owned := true
	poll := time.NewTicker(10 * time.Millisecond)
	defer poll.Stop()
observe:
	for {
		if err := ctx.Err(); err != nil {
			captureErr = err
			break
		}
		exited, err := observeWireGuardChild(command.Process.Pid)
		if err != nil {
			owned = false
			captureErr = err
			break
		}
		if exited {
			if outputDone && inputDone {
				break
			}
			if drainDeadline.IsZero() {
				drainDeadline = time.Now().Add(wireGuardCommandWaitDelay)
			}
		}
		if !drainDeadline.IsZero() && !time.Now().Before(drainDeadline) {
			captureErr = exec.ErrWaitDelay
			break
		}
		select {
		case <-ctx.Done():
			captureErr = ctx.Err()
			break observe
		case outputErr = <-outputSignal:
			outputDone = true
			outputSignal = nil
			if outputErr != nil {
				captureErr = outputErr
				break observe
			}
		case inputErr = <-inputSignal:
			inputDone = true
			inputSignal = nil
		case <-poll.C:
		}
	}
	if captureErr != nil && owned {
		if _, err := observeWireGuardChild(command.Process.Pid); err != nil {
			owned = false
			captureErr = errors.Join(captureErr, err)
		}
		if owned {
			if err := unix.Kill(-command.Process.Pid, unix.SIGKILL); err != nil && !errors.Is(err, unix.ESRCH) {
				captureErr = errors.Join(captureErr, err)
			}
		}
	}
	_ = readOutput.Close()
	if writeInput != nil {
		_ = writeInput.Close()
	}
	copies.Wait()
	if !outputDone {
		outputErr = <-outputResult
	}
	if !inputDone {
		inputErr = <-inputResult
	}
	waitErr := command.Wait()
	if captureErr != nil {
		return captureErr
	}
	if waitErr != nil {
		return waitErr
	}
	if outputErr != nil && !errors.Is(outputErr, os.ErrClosed) {
		return outputErr
	}
	// A tool may deliberately stop reading after its complete input record.
	// Match os/exec's closed-stdin handling without hiding other I/O failures.
	if inputErr != nil && !errors.Is(inputErr, syscall.EPIPE) && !errors.Is(inputErr, os.ErrClosed) {
		return inputErr
	}
	return nil
}

func observeWireGuardChild(pid int) (bool, error) {
	if pid <= 1 {
		return false, errors.New("invalid WireGuard child identity")
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
