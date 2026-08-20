//go:build linux

package cmd

import (
	"os/exec"

	"syswarden-cli/pkg/system"
)

func restartCoreService() error {
	return coreServiceRestartCommand(system.IsAlpine()).Run()
}

func coreServiceRestartCommand(alpine bool) *exec.Cmd {
	if alpine {
		return exec.Command("rc-service", "syswarden-core", "restart")
	}
	return exec.Command("systemctl", "restart", "syswarden-core.service")
}
