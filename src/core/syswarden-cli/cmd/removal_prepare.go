package cmd

import (
	"fmt"
	"syswarden-cli/pkg/firewall"
	"syswarden-cli/pkg/integration"
	"syswarden-cli/pkg/network"
	"syswarden-cli/pkg/security"
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
var removeOwnedIntegrationArtifactsForRemoval = integration.RemoveOwnedRsyslogArtifactsForPackageRemoval
var removeExactRuntimeSocketForRemoval = system.RemoveExactRuntimeSocketForPackageRemoval
var removeOwnedRsyslogSELinuxPolicyForRemoval = integration.RemoveOwnedRsyslogSELinuxPolicyForPackageRemoval
var requireRemovalTombstoneForCISPolicyRemoval = system.RequireRemovalTombstone
var removeExactCISHardeningPoliciesForRemoval = security.RemoveExactCISHardeningPoliciesForRemoval

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
	rsyslogOutcome, err := removeOwnedIntegrationArtifactsForRemoval()
	if err != nil {
		return fmt.Errorf(
			"refusing removal before exact generated integration cleanup and an attested rsyslog restart; every ambiguous artifact, the runtime socket, and the SELinux policy are preserved; the durable removal barrier is retained: %w",
			err,
		)
	}
	switch rsyslogOutcome {
	case integration.RsyslogPackageRemovalActiveQuiesced:
		if err := removeExactRuntimeSocketForRemoval(); err != nil {
			return fmt.Errorf(
				"refusing removal before exact runtime socket cleanup; the rsyslog producer restart is complete, but the SELinux policy and durable removal barrier are retained: %w",
				err,
			)
		}
		if err := removeOwnedRsyslogSELinuxPolicyForRemoval(); err != nil {
			return fmt.Errorf(
				"refusing removal before exact rsyslog SELinux policy cleanup; the producer is quiesced, the runtime socket is absent, and the durable removal barrier is retained: %w",
				err,
			)
		}
	case integration.RsyslogPackageRemovalOfflineAlreadyComplete:
		// The integration phase already attested the exact socket, every
		// SELinux provenance/transaction target, and any installed module
		// absent. Preserve the OFFLINE read-only contract by never invoking
		// either related mutator. The independent package-manager cleanup of
		// prepared service artifacts and the runtime lock remains necessary.
	default:
		return fmt.Errorf(
			"refusing removal after an unrecognized rsyslog package-removal outcome %d; the runtime socket and SELinux policy are retained, and the durable removal barrier is retained",
			rsyslogOutcome,
		)
	}
	if err := requireRemovalTombstoneForCISPolicyRemoval(); err != nil {
		return fmt.Errorf(
			"refusing removal before exact CIS hardening policy cleanup because the durable removal barrier could not be reattested; CIS policies, prepared service artifacts, and runtime lock are retained: %w",
			err,
		)
	}
	if err := removeExactCISHardeningPoliciesForRemoval(); err != nil {
		return fmt.Errorf(
			"refusing removal before exact CIS hardening policy cleanup; the durable removal barrier, prepared service artifacts, and runtime lock are retained for retry: %w",
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
