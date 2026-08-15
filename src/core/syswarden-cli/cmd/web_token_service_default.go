//go:build !freebsd

package cmd

import "os/exec"

const webTUIServiceDisplay = "syswarden-webtui.service"

func restartWebTUIService() error {
	if err := exec.Command("systemctl", "restart", "syswarden-webtui.service").Run(); err != nil {
		return err
	}
	return exec.Command("systemctl", "is-active", "--quiet", "syswarden-webtui.service").Run()
}
