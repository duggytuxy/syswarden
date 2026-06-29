//go:build linux

package cmd

import (
	"os/exec"
	"syswarden-cli/pkg/system"
)

// getKernelLogCommand returns the native linux command to stream kernel ring buffer logs
func getKernelLogCommand() *exec.Cmd {
	if system.IsAlpine() {
		return exec.Command("tail", "-F", "/var/log/messages")
	}
	// Native journalctl for Linux (captures kernel syswarden drops)
	return exec.Command("stdbuf", "-oL", "/usr/bin/journalctl", "-k", "-f", "-n", "10", "--no-pager")
}
