//go:build linux

package system

import "fmt"

// FirewallWrapperStateVersion identifies the exact current compatibility
// receipt. Retirement accepts only its empty, fully reconciled form.
const FirewallWrapperStateVersion = "syswarden-firewall-wrappers-v3"

// RemoveEmptyFirewallWrapperStateForRemoval runs after firewall cleanup. It
// never removes a receipt that still declares owned or pending permissions.
func RemoveEmptyFirewallWrapperStateForRemoval() error {
	guard := func() error {
		if err := RequireRemovalTombstone(); err != nil {
			return err
		}
		if err := preflightHostRemovalMountBoundaries(); err != nil {
			return err
		}
		return ReattestFirewallStatePreparedForRemoval()
	}
	return removeEmptyFirewallWrapperState("/etc/syswarden/firewall-wrappers.state", guard)
}

func removeEmptyFirewallWrapperState(path string, guard func() error) error {
	if guard == nil {
		return fmt.Errorf("empty compatibility receipt retirement requires removal guards")
	}
	if err := guard(); err != nil {
		return err
	}
	if err := removePreparedExactServiceFile(path, FirewallWrapperStateVersion+"\n", 0600); err != nil {
		return fmt.Errorf("preserve unresolved compatibility ownership receipt: %w", err)
	}
	return guard()
}
