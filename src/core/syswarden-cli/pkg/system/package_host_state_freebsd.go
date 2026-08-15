//go:build freebsd

package system

import "errors"

// RestoreFreeBSDPackageHostState recovers state owned outside the package
// payload. Callers must remove generated rsyslog fragments before invoking it
// and must restore PF afterwards because WireGuard teardown can touch its
// dedicated anchor.
func RestoreFreeBSDPackageHostState() error {
	var failures []error
	if err := RestoreFreeBSDWireGuard(); err != nil {
		failures = append(failures, err)
	}
	if err := RestoreFreeBSDCronAccess(); err != nil {
		failures = append(failures, err)
	}
	if err := RestoreFreeBSDLogging(); err != nil {
		failures = append(failures, err)
	}
	return errors.Join(failures...)
}
