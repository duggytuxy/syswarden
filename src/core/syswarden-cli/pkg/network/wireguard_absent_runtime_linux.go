//go:build linux

package network

import (
	"fmt"
	"net"
	"strings"
)

const absentWireGuardSystemdProperties = "Id,LoadState,ActiveState,SubState,UnitFileState,FragmentPath,DropInPaths,MainPID,ControlPID,Job"

// This fallback is restricted to orphan retirement after absent ownership and
// prepared services have been attested. A native package manager can remove
// wireguard-tools even when another package's erase scriptlet refuses removal.
// Prove the missing unit and kernel interface independently instead of treating
// a failed wg or systemctl command as absence.
func attestAbsentSystemdWireGuardRuntimeForOrphanRemoval(
	output wireGuardServiceOutputRunner,
	interfaces func() ([]net.Interface, error),
) error {
	if output == nil || interfaces == nil {
		return fmt.Errorf("absent WireGuard runtime requires independent systemd and kernel inspectors")
	}
	want := map[string]string{
		"Id": "wg-quick@wg-syswarden.service", "LoadState": "not-found",
		"ActiveState": "inactive", "SubState": "dead", "UnitFileState": "",
		"FragmentPath": "", "DropInPaths": "", "MainPID": "0", "ControlPID": "0", "Job": "",
	}
	for attempt := 0; attempt < 2; attempt++ {
		wire, err := output("systemctl", "show", "wg-quick@wg-syswarden.service", "--property="+absentWireGuardSystemdProperties)
		if err != nil {
			return fmt.Errorf("inspect missing WireGuard systemd unit: %w", err)
		}
		if len(wire) == 0 || len(wire) > 4096 || wire[len(wire)-1] != '\n' {
			return fmt.Errorf("missing WireGuard unit evidence is incomplete or oversized")
		}
		seen := make(map[string]bool, len(want))
		for _, line := range strings.Split(string(wire[:len(wire)-1]), "\n") {
			key, value, found := strings.Cut(line, "=")
			expected, known := want[key]
			if !found || !known || seen[key] || value != expected {
				return fmt.Errorf("WireGuard systemd unit is not exactly absent and quiescent")
			}
			seen[key] = true
		}
		if len(seen) != len(want) {
			return fmt.Errorf("missing WireGuard unit evidence lacks required properties")
		}
		current, err := interfaces()
		if err != nil {
			return fmt.Errorf("inspect kernel interfaces without WireGuard tools: %w", err)
		}
		for _, device := range current {
			if device.Name == "wg-syswarden" {
				return fmt.Errorf("interface wg-syswarden remains while its systemd unit is absent")
			}
		}
	}
	return nil
}
