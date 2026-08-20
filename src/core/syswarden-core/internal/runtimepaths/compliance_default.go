//go:build linux

package runtimepaths

import (
	"os"
	"os/exec"
)

// RunInstalledComplianceAudit invokes the packaged Linux CLI.
func RunInstalledComplianceAudit() {
	if _, err := os.Stat("/opt/syswarden/bin/syswarden-cli"); err == nil {
		_ = exec.Command("/opt/syswarden/bin/syswarden-cli", "audit").Run()
	}
}
