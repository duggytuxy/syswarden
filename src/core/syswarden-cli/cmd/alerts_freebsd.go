//go:build freebsd

package cmd

import (
	"os/exec"
)

// getKernelLogCommand returns the native FreeBSD command to stream kernel / syslog buffer logs
func getKernelLogCommand() *exec.Cmd {
	// Native FreeBSD /var/log/messages contains kernel drops (log_arp_wrong_iface, etc.)
	return exec.Command("stdbuf", "-oL", "/usr/bin/tail", "-F", "-n", "10", "/var/log/messages")
}
