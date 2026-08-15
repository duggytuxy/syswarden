//go:build !freebsd

package cmd

import (
	"os/exec"
)

func restartCoreService() error {
	return exec.Command("systemctl", "restart", "syswarden-core.service").Run()
}
