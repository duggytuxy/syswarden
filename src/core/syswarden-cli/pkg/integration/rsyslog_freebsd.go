//go:build freebsd

package integration

import "syswarden-cli/pkg/system"

func ensureFreeBSDRsyslogRunning() error {
	return system.EnsureFreeBSDRsyslogRunning()
}
