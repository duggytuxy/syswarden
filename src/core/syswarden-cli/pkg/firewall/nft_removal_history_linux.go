//go:build linux

package firewall

import (
	"context"
	"fmt"
	"syswarden-cli/pkg/system"
	"time"
)

// RetireRuntimeHistoryForRemoval independently verifies the absence of all
// product tables while holding the authoritative firewall lock. A previous
// cleanup result alone cannot authorize archiving live runtime claims.
func RetireRuntimeHistoryForRemoval() error {
	if firewallCleanupEffectiveUserID() != 0 {
		return fmt.Errorf("runtime history retirement requires root")
	}
	lock, err := acquireNFTReloadGuard()
	if err != nil {
		return fmt.Errorf("acquire runtime history retirement lock: %w", err)
	}
	defer releaseNFTReloadGuard(lock)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	runner, err := uninstallNFTRunnerFactory()
	if err != nil {
		return err
	}
	return system.RetireRuntimeHistoryForRemoval(func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := firewallRemovalServiceReattest(); err != nil {
			return err
		}
		// This fallback is strictly read-only and refuses every remaining product
		// table. It never deletes a table or derives ownership from its name.
		return cleanupReservedNFTablesForUninstall(ctx, runner)
	})
}
