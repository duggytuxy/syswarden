//go:build linux

package firewall

import (
	"context"
	"fmt"
	"syswarden-cli/pkg/system"
	"time"
)

// The removal barrier and repeated service/process reattestation quiesce all
// product writers. These read-only kernel probes create no replacement runtime
// lock after the original removal has retired it.
func retainHAState(apply bool, expected string) (system.LegacyLogRetentionPlan, string, error) {
	if firewallCleanupEffectiveUserID() != 0 {
		return system.LegacyLogRetentionPlan{}, "", fmt.Errorf("HA state retention requires root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	runner, err := uninstallNFTRunnerFactory()
	if err != nil {
		return system.LegacyLogRetentionPlan{}, "", err
	}
	guard := func() error {
		if err := ctx.Err(); err != nil {
			return err
		}
		return cleanupReservedNFTablesForUninstall(ctx, runner)
	}
	if apply {
		return system.ApplyHAStateRetention(expected, guard)
	}
	plan, err := system.InspectHAStateRetention(guard)
	return plan, "", err
}

func InspectHAStateRetention() (system.LegacyLogRetentionPlan, error) {
	plan, _, err := retainHAState(false, "")
	return plan, err
}

func ApplyHAStateRetention(expected string) (system.LegacyLogRetentionPlan, string, error) {
	return retainHAState(true, expected)
}
