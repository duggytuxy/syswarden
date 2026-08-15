//go:build freebsd

package runtimepaths

import (
	"os"
	"os/exec"
)

// RunInstalledComplianceAudit invokes the native packaged FreeBSD CLI.
func RunInstalledComplianceAudit() {
	if _, err := os.Stat("/usr/local/syswarden/bin/syswarden-cli"); err == nil {
		_ = exec.Command("/usr/local/syswarden/bin/syswarden-cli", "audit").Run()
	}
}
