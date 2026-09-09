//go:build linux

package cmd

import (
	"context"
	"os/exec"
	"syswarden-cli/pkg/system"
)

const kernelAlertLogPath = "/var/log/kern.log"

// getKernelLogCommand returns a live-only kernel log follower.
func getKernelLogCommand(ctx context.Context) *exec.Cmd {
	if system.IsAlpine() {
		return exec.CommandContext(ctx, "tail", kernelLogCommandArgs(true)...) // #nosec G204 -- executable and arguments are fixed internally for the live kernel log follower
	}
	args := kernelLogCommandArgs(false)
	if _, err := exec.LookPath("stdbuf"); err == nil {
		return exec.CommandContext(ctx, "stdbuf", append([]string{"-oL", "/usr/bin/journalctl"}, args...)...) // #nosec G204 -- executable and arguments are fixed internally for the live journal follower
	}
	return exec.CommandContext(ctx, "/usr/bin/journalctl", args...) // #nosec G204 -- executable and arguments are fixed internally for the live journal follower
}

func kernelLogCommandArgs(alpine bool) []string {
	if alpine {
		return []string{"-F", "-n", "0", kernelAlertLogPath}
	}
	return []string{"-k", "-f", "-n", "0", "--no-pager"}
}
