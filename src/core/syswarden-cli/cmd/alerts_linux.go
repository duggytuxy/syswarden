//go:build linux

package cmd

import (
	"os/exec"
)

// getKernelLogCommand returns the native linux command to stream kernel ring buffer logs
func getKernelLogCommand() *exec.Cmd {
	// Native journalctl for Linux (captures kernel syswarden drops)
	return exec.Command("stdbuf", "-oL", "/usr/bin/journalctl", "-k", "-f", "-n", "10", "--no-pager")
}
