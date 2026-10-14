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

var beginRemoval = func() error {
	if err := network.PreflightWireGuardRemoval(); err != nil {
		return err
	}
	return system.BeginRemoval()
}
var removeOwnedCronStateForRemoval = system.RemoveOwnedCronStateForRemoval
var prepareFirewallStateForRemoval = system.PrepareFirewallStateForRemoval
var preflightHistoricalHostForRemoval = system.PreflightHistoricalHostRemoval
var attestHistoricalHostRemovalComplete = system.AttestHistoricalHostRemovalComplete
var preflightHistoricalFail2banForRemoval = firewall.PreflightHistoricalFail2banRemoval
var preflightAdministratorPolicyForRemoval = firewall.PreflightAdministratorPolicyRemoval
var preflightKnownNFTPersistenceForRemoval = firewall.PreflightKnownNFTPersistenceRemoval
var cleanupFirewallStateForRemoval = firewall.CleanupOwnedCompatibilityRulesForUninstall
var removeOwnedWireGuardStateForRemoval = func() error {
	return system.RemoveOwnedWireGuardArtifactsForRemoval(
		network.RecoverPendingWireGuardForwardingState,
		network.CleanupOwnedWireGuardNFTState,
		network.CleanupAttestedStaleOrLegacyWireGuardNFTStateForRemoval,
		network.CleanupAttestedOrphanedWireGuardNFTStateForRemoval,
	)
}
var removePreparedServiceArtifacts = system.RemovePreparedServiceArtifactsForRemoval
var removePreparedFirewallRuntimeLock = system.RemovePreparedFirewallRuntimeLockForRemoval
var removeOwnedIntegrationArtifactsForRemoval = integration.RemoveOwnedRsyslogArtifactsForPackageRemoval
var removeExactRuntimeSocketForRemoval = system.RemoveExactRuntimeSocketForPackageRemoval
var removeOwnedRsyslogSELinuxPolicyForRemoval = integration.RemoveOwnedRsyslogSELinuxPolicyForPackageRemoval
var requireRemovalTombstoneForCISPolicyRemoval = system.RequireRemovalTombstone
var removeExactJournaldFragmentForRemoval = integration.RemoveExactJournaldFragmentForRemoval
var removeExactCISHardeningPoliciesForRemoval = security.RemoveExactCISHardeningPoliciesForRemoval
var attestRuntimeRetirementBeforeNativeErase = system.AttestRuntimeRetirementBeforeNativeErase
var removePristineDefaultConfigurationForRemoval = system.RemovePristineDefaultConfigurationForRemoval
var retireRuntimeHistoryForRemoval = firewall.RetireRuntimeHistoryForRemoval
var retireCreatedProductLogsForRemoval = system.RetireCreatedProductLogsForRemoval
var retireGeneratedListsForRemoval = system.RetireGeneratedListsForRemoval
var retireCreatedUISnapshotsForRemoval = system.RetireCreatedUISnapshotsForRemoval
var removeEmptyFirewallWrapperStateForRemoval = system.RemoveEmptyFirewallWrapperStateForRemoval

func prepareVerifiedFirewallRemoval() error {
	if err := preflightKnownNFTPersistenceForRemoval(); err != nil {
		return fmt.Errorf("persistent firewall recovery is required before removal starts; this read-only preflight has not stopped services or published a new removal barrier: %w", err)
	}
	if err := preflightHistoricalHostForRemoval(); err != nil {
		return fmt.Errorf("historical host recovery is required before removal starts; this read-only preflight has not stopped services or published a new removal barrier: %w", err)
	}
	if err := preflightHistoricalFail2banForRemoval(); err != nil {
		return fmt.Errorf("historical Fail2ban recovery is required before removal starts; this read-only preflight has not published a new removal barrier; preserve any existing evidence: %w", err)
	}
	if err := preflightAdministratorPolicyForRemoval(); err != nil {
		return fmt.Errorf("administrator policy preservation is required before removal starts; this read-only preflight has not stopped services or published a new removal barrier: %w", err)
	}
	if err := beginRemoval(); err != nil {
		return fmt.Errorf("refusing removal before the durable removal barrier is published: %w", err)
	}
	if err := preflightHistoricalFail2banForRemoval(); err != nil {
		return fmt.Errorf("refusing removal before historical Fail2ban recovery; this attempt has not stopped managed services or removed product files, and the durable removal barrier is retained: %w", err)
	}
	if err := preflightHistoricalHostForRemoval(); err != nil {
		return fmt.Errorf("historical host evidence changed before service preparation; the durable removal barrier and product files are retained: %w", err)
	}
	if err := preflightAdministratorPolicyForRemoval(); err != nil {
		return fmt.Errorf("administrator policy changed before service preparation; managed services have not been stopped and the durable removal barrier is retained: %w", err)
	}
	if err := preflightKnownNFTPersistenceForRemoval(); err != nil {
		return fmt.Errorf("persistent firewall evidence changed before service preparation; managed services have not been stopped and the durable removal barrier is retained: %w", err)
	}
	if err := prepareFirewallStateForRemoval(); err != nil {
		return fmt.Errorf(
			"refusing removal before managed firewall services are stopped; the durable removal barrier is retained; resolve the reported service or runtime cause without deleting ownership evidence, then retry the original removal command: %w",
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
			"refusing removal before exact WireGuard cleanup; the durable removal tombstone is retained; inspect exact historical state with 'sudo syswarden recover-wireguard' before explicit recovery, then retry the original removal command: %w",
			err,
		)
	}
	if err := preflightHistoricalFail2banForRemoval(); err != nil {
		return fmt.Errorf("refusing removal because historical Fail2ban evidence changed before firewall cleanup; the durable removal barrier and product files are retained: %w", err)
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
	if err := removeExactJournaldFragmentForRemoval(); err != nil {
		return fmt.Errorf("refusing removal before exact journald fragment retirement and verified logging activation; recovery resources and the durable removal barrier are retained: %w", err)
	}
	if err := attestHistoricalHostRemovalComplete(); err != nil {
		return fmt.Errorf("host recovery remains incomplete after exact cleanup; prepared services, the product executable and the durable removal barrier are retained: %w", err)
	}
	if err := preflightKnownNFTPersistenceForRemoval(); err != nil {
		return fmt.Errorf("persistent firewall recovery remains incomplete; prepared services, the product executable and the durable removal barrier are retained: %w", err)
	}
	if err := retireGeneratedListsForRemoval(); err != nil {
		return fmt.Errorf("generated list retirement remains incomplete; preserve administrator input, the CLI and the removal barrier; inspect unmarked legacy files with 'sudo syswarden recover-removal --retain-legacy-lists': %w", err)
	}
	if err := retireCreatedProductLogsForRemoval(); err != nil {
		return fmt.Errorf("product log retirement remains incomplete; preserve the CLI and removal barrier; inspect legacy log retention with 'sudo syswarden recover-removal --retain-legacy-logs': %w", err)
	}
	if err := retireCreatedUISnapshotsForRemoval(); err != nil {
		return fmt.Errorf("UI snapshot retirement remains incomplete; preserve the CLI and removal barrier for explicit recovery: %w", err)
	}
	if err := retireRuntimeHistoryForRemoval(); err != nil {
		return fmt.Errorf("runtime history retirement remains incomplete; preserve the CLI and removal barrier: %w", err)
	}
	if err := removeEmptyFirewallWrapperStateForRemoval(); err != nil {
		return fmt.Errorf("compatibility receipt retirement remains incomplete; preserve the CLI and removal barrier: %w", err)
	}
	if err := removePristineDefaultConfigurationForRemoval(); err != nil {
		return fmt.Errorf("default configuration retirement remains incomplete; preserve the CLI and removal barrier: %w", err)
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
		if err := prepareVerifiedFirewallRemoval(); err != nil {
			return err
		}
		if err := attestRuntimeRetirementBeforeNativeErase(); err != nil {
			return fmt.Errorf("refusing native package erase while generated file retirement is incomplete; the CLI and removal barrier must remain available: %w", err)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(preparePackageRemovalCmd)
}
