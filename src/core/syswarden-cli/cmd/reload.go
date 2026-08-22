package cmd

import (
	"errors"
	"fmt"
	"syswarden-cli/pkg/firewall"
	"syswarden-cli/pkg/integration"
	"syswarden-cli/pkg/network"

	"github.com/spf13/cobra"
)

var noRestart bool
var applyPoliciesForReload = firewall.ApplyPolicies
var setupWireGuardForReload = network.SetupWireguard

var reloadCmd = &cobra.Command{
	Use:   "reload",
	Short: "Reapply policy and normally restart syswarden-core",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := preflightConfiguredCronScheduling(); err != nil {
			return fmt.Errorf("cron scheduling preflight failed before reload mutation: %w", err)
		}
		if err := preflightConfiguredFirewallBackend(); err != nil {
			return fmt.Errorf("firewall backend preflight failed before reload mutation: %w", err)
		}
		fmt.Println("[*] Reloading SYSWARDEN configuration from memory...")
		var failures []error

		// Re-apply Firewall and Whitelists based on new config
		firewallReady := true
		if err := applyPoliciesForReload(); err != nil {
			fmt.Printf("[ERROR] Firewall reload failed: %v\n", err)
			failures = append(failures, fmt.Errorf("firewall reload: %w", err))
			firewallReady = false
		}

		// Re-apply Wireguard if changed
		if firewallReady {
			if err := setupWireGuardForReload(); err != nil {
				fmt.Printf("[ERROR] Wireguard reload failed: %v\n", err)
				failures = append(failures, fmt.Errorf("WireGuard reload: %w", err))
			}
		} else {
			fmt.Println("[WARN] WireGuard reload skipped because the authoritative firewall transaction failed.")
		}

		// Re-apply WAF Log Bridge (Rsyslog)
		if err := integration.SetupWAFLogForwarder(); err != nil {
			fmt.Printf("[ERROR] WAF Log Bridge reload failed: %v\n", err)
			failures = append(failures, fmt.Errorf("WAF log bridge reload: %w", err))
		}

		// Re-apply AbuseIPDB / Telemetry configuration
		if err := integration.SetupAbuseIPDB(); err != nil {
			fmt.Printf("[ERROR] AbuseIPDB reload failed: %v\n", err)
			failures = append(failures, fmt.Errorf("AbuseIPDB reload: %w", err))
		}

		// Re-apply Background Cron Orchestration (Repairs missing jobs)
		fmt.Println("[*] Verifying background orchestration...")
		if err := network.SetupFeedsCron(); err != nil {
			fmt.Printf("[WARN] Threat feeds cron repair failed: %v\n", err)
			failures = append(failures, fmt.Errorf("threat feeds cron repair: %w", err))
		}
		if err := network.SetupHACluster(); err != nil {
			fmt.Printf("[WARN] HA cluster cron repair failed: %v\n", err)
			failures = append(failures, fmt.Errorf("HA cluster cron repair: %w", err))
		}

		// Restart Daemons gracefully
		if !noRestart {
			fmt.Println("[*] Restarting background engines...")
			if err := restartCoreService(); err != nil {
				fmt.Printf("[WARN] syswarden-core restart failed: %v\n", err)
				failures = append(failures, fmt.Errorf("core service restart: %w", err))
			}
		}

		fmt.Println(reloadCompletionMessage(len(failures) > 0))
		if len(failures) > 0 {
			return fmt.Errorf("reload sequence did not reach a verified state: %w", errors.Join(failures...))
		}
		return nil
	},
}

func reloadCompletionMessage(hadReportedError bool) string {
	if hadReportedError {
		return "[WARNING] Reload sequence completed with reported errors; review the messages above and verify the resulting system state."
	}
	return "[INFO] Reload sequence completed; verify the resulting service and kernel state."
}

func init() {
	reloadCmd.Flags().BoolVar(&noRestart, "no-restart", false, "Do not restart syswarden-core.service (used by systemd)")
	rootCmd.AddCommand(reloadCmd)
}
