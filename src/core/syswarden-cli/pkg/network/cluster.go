package network

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"syswarden-cli/config"
	"syswarden-cli/pkg/cronstate"
	"syswarden-cli/pkg/platformpaths"
	"syswarden-cli/pkg/system"
)

type haClusterPeerPlan struct {
	Allowlist []string
	Dialable  []string
}

func planHAClusterPeers(value string) (haClusterPeerPlan, error) {
	configured := configuredHAPeers(value)
	plan := haClusterPeerPlan{
		Allowlist: make([]string, 0, len(configured)),
		Dialable:  make([]string, 0, len(configured)),
	}
	seenAllowlist := make(map[string]struct{}, len(configured))
	seenDialable := make(map[string]struct{}, len(configured))
	for _, candidate := range configured {
		canonical, err := config.CanonicalHAPeer(candidate)
		if err != nil {
			return haClusterPeerPlan{}, fmt.Errorf("invalid HA peer %q: %w", candidate, err)
		}
		if strings.Contains(canonical, "/") {
			if _, duplicate := seenAllowlist[canonical]; !duplicate {
				seenAllowlist[canonical] = struct{}{}
				plan.Allowlist = append(plan.Allowlist, canonical)
			}
			continue
		}
		if _, duplicate := seenAllowlist[canonical]; !duplicate {
			seenAllowlist[canonical] = struct{}{}
			plan.Allowlist = append(plan.Allowlist, canonical)
		}
		if _, duplicate := seenDialable[canonical]; !duplicate {
			seenDialable[canonical] = struct{}{}
			plan.Dialable = append(plan.Dialable, canonical)
		}
	}
	return plan, nil
}

func configureHASyncCron(enableOutbound bool) error {
	options := cronstate.DefaultOptions(system.ReadOnlyRootCrontabEvidence)
	options.AttestCronDProvider = system.AttestRuntimeCronDProvider
	err := cronstate.ReconcileHA(options, enableOutbound)
	if err != nil {
		return fmt.Errorf("failed to reconcile owned HA cron job: %w", err)
	}
	return nil
}

func SetupHACluster() error {
	return setupHACluster(platformpaths.WhitelistCommand, configureHASyncCron)
}

func failHASetupClosed(configureSyncCron func(bool) error, setupErr error) error {
	if err := configureSyncCron(false); err != nil {
		return errors.Join(setupErr, fmt.Errorf("disable HA synchronization after setup failure: %w", err))
	}
	return setupErr
}

func setupHACluster(
	whitelistCommand func(string) (*exec.Cmd, error),
	configureSyncCron func(bool) error,
) error {
	if !config.GlobalConfig.HAEnabled {
		if err := configureSyncCron(false); err != nil {
			return err
		}
		fmt.Println("[INFO] HA Cluster Sync is DISABLED.")
		return nil
	}

	peerPlan, err := planHAClusterPeers(config.GlobalConfig.HAPeerIP)
	if err != nil {
		return err
	}
	peerPort := config.GlobalConfig.HAPeerPort
	if len(peerPlan.Allowlist) == 0 {
		if err := configureSyncCron(false); err != nil {
			return err
		}
		fmt.Println("[WARN] HA Cluster enabled but no Peer IP configured.")
		return nil
	}

	fmt.Printf("[INFO] Configuring HA peer allowlist: %v on port %s\n", peerPlan.Allowlist, peerPort)

	// Auto-whitelist Peer IPs to allow HA traffic through the firewall
	for _, ip := range peerPlan.Allowlist {
		// Just call the binary to avoid cyclical imports or complex logic
		fmt.Printf("[INFO] Auto-whitelisting HA Peer IP: %s\n", ip)
		whitelistCmd, err := whitelistCommand(ip)
		if err != nil {
			return failHASetupClosed(
				configureSyncCron,
				fmt.Errorf("failed to prepare HA peer auto-whitelist for %s: %w", ip, err),
			)
		}
		if err := whitelistCmd.Run(); err != nil {
			return failHASetupClosed(
				configureSyncCron,
				fmt.Errorf("failed to auto-whitelist HA peer %s: %w", ip, err),
			)
		}
	}

	if len(peerPlan.Dialable) == 0 {
		if err := configureSyncCron(false); err != nil {
			return err
		}
		fmt.Println("[+] HA Cluster ENABLED in inbound-only mode (no dialable exact peer configured).")
		return nil
	}

	if err := configureSyncCron(true); err != nil {
		return err
	}
	fmt.Println("[+] HA Cluster Sync ENABLED.")
	return nil
}
