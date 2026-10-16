package network

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"syswarden-cli/config"
	"syswarden-cli/pkg/cronstate"
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

// SetupHACluster receives the automatic peer writer from the command layer to
// avoid a network/firewall import cycle and the manual whitelist CLI path.
func SetupHACluster(allowPeer func(string, string) error) error {
	return setupHACluster(allowPeer, configureHASyncCron)
}

func failHASetupClosed(configureSyncCron func(bool) error, setupErr error) error {
	if err := configureSyncCron(false); err != nil {
		return errors.Join(setupErr, fmt.Errorf("disable HA synchronization after setup failure: %w", err))
	}
	return setupErr
}

func setupHACluster(
	allowPeer func(string, string) error,
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
		return failHASetupClosed(configureSyncCron, err)
	}
	peerPort := config.GlobalConfig.HAPeerPort
	if len(peerPlan.Allowlist) == 0 {
		if err := configureSyncCron(false); err != nil {
			return err
		}
		fmt.Println("[WARN] HA Cluster enabled but no Peer IP configured.")
		return nil
	}
	port, err := strconv.ParseUint(peerPort, 10, 16)
	if err != nil || port == 0 || strconv.FormatUint(port, 10) != peerPort || allowPeer == nil {
		return failHASetupClosed(configureSyncCron, fmt.Errorf("HA peer access requires a writer and one canonical TCP port"))
	}

	fmt.Printf("[INFO] Configuring HA peer allowlist: %v on port %s\n", peerPlan.Allowlist, peerPort)

	// HA needs only its TCP listener port. A global whitelist would also unban
	// the peer and acquire the legacy writer fence before TLS bootstrap.
	for _, ip := range peerPlan.Allowlist {
		fmt.Printf("[INFO] Auto-whitelisting HA Peer IP: %s\n", ip)
		if err := allowPeer(ip, peerPort); err != nil {
			return failHASetupClosed(
				configureSyncCron,
				fmt.Errorf("failed to auto-whitelist HA peer %s: %w", ip, err),
			)
		}
	}

	if config.GlobalConfig.HAV2Enabled || len(peerPlan.Dialable) == 0 {
		if err := configureSyncCron(false); err != nil {
			return err
		}
		if config.GlobalConfig.HAV2Enabled {
			fmt.Println("[+] HA v2 peer access configured; legacy HA synchronization remains DISABLED.")
		} else {
			fmt.Println("[+] HA Cluster ENABLED in inbound-only mode (no dialable exact peer configured).")
		}
		return nil
	}

	if err := configureSyncCron(true); err != nil {
		return err
	}
	fmt.Println("[+] HA Cluster Sync ENABLED.")
	return nil
}
