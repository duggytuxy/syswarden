//go:build freebsd

package cmd

import "os/exec"

const webTUIServiceDisplay = "syswardenwebtui rc.d service"

func restartWebTUIService() error {
	if err := exec.Command("service", "syswardenwebtui", "restart").Run(); err != nil {
		return err
	}
	return exec.Command("service", "syswardenwebtui", "onestatus").Run()
}
