package cmd

import (
	"fmt"
	"syswarden-cli/pkg/firewall"
	"syswarden-cli/pkg/integration"
	"syswarden-cli/pkg/network"
	"syswarden-cli/pkg/system"

	"github.com/spf13/cobra"
)

var beginRemoval = system.BeginRemoval
var removeOwnedCronStateForRemoval = system.RemoveOwnedCronStateForRemoval
var prepareFirewallStateForRemoval = system.PrepareFirewallStateForRemoval
var cleanupFirewallStateForRemoval = firewall.CleanupOwnedCompatibilityRulesForUninstall
var removeOwnedWireGuardStateForRemoval = func() error {
	return system.RemoveOwnedWireGuardArtifactsForRemoval(network.CleanupOwnedWireGuardNFTState)
}
var removePreparedServiceArtifacts = system.RemovePreparedServiceArtifactsForRemoval
var removePreparedFirewallRuntimeLock = system.RemovePreparedFirewallRuntimeLockForRemoval
var removeOwnedIntegrationArtifactsForRemoval = integration.RemoveOwnedGeneratedArtifactsForPackageRemoval

func prepareVerifiedFirewallRemoval() error {
	if err := beginRemoval(); err != nil {
		return fmt.Errorf("refusing removal before the durable removal barrier is published: %w", err)
	}
	if err := prepareFirewallStateForRemoval(); err != nil {
		return fmt.Errorf(
			"refusing removal before managed firewall services are stopped; the durable removal barrier is retained: %w",
			err,
		)
	}
	if err := removeOwnedCronStateForRemoval(); err != nil {
		return fmt.Errorf(
			"refusing removal before exact cron.d cleanup; the durable removal barrier, prepared exact services, and root crontab bytes are retained: %w",
			err,
		)
	}
	if err := removeOwnedWireGuardStateForRemoval(); err != nil {
		return fmt.Errorf(
			"refusing removal before exact WireGuard cleanup; the durable removal tombstone is retained: %w",
			err,
		)
	}
	if err := cleanupFirewallStateForRemoval(); err != nil {
		return fmt.Errorf(
			"refusing removal before verified firewall cleanup; the durable removal barrier and stopped exact firewall mutators are retained for recovery: %w",
			err,
		)
	}
	if err := removeOwnedIntegrationArtifactsForRemoval(); err != nil {
		return fmt.Errorf(
			"refusing removal before exact generated integration cleanup; every ambiguous artifact is preserved and the durable removal barrier is retained: %w",
			err,
		)
	}
	if err := removePreparedServiceArtifacts(); err != nil {
		return fmt.Errorf(
			"refusing removal after verified firewall cleanup because exact service artifacts could not be removed; the durable removal barrier is retained: %w",
			err,
		)
	}
	if err := removePreparedFirewallRuntimeLock(); err != nil {
		return fmt.Errorf(
			"refusing removal after verified firewall cleanup because the exact runtime lock could not be removed; the durable removal barrier is retained: %w",
			err,
		)
	}
	return nil
}

var preparePackageRemovalCmd = &cobra.Command{
	Use:    "prepare-package-removal",
	Short:  "Publish the removal barrier and verify owned firewall cleanup",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return prepareVerifiedFirewallRemoval()
	},
}

func init() {
	rootCmd.AddCommand(preparePackageRemovalCmd)
}
