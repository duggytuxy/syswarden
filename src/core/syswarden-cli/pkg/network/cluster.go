package network

import (
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"syswarden-cli/config"
	"syswarden-cli/pkg/platformpaths"
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
		if strings.Contains(candidate, "/") {
			prefix, err := netip.ParsePrefix(candidate)
			if err != nil || !prefix.IsValid() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" || prefix.Addr() != prefix.Masked().Addr() {
				return haClusterPeerPlan{}, fmt.Errorf("invalid HA peer CIDR")
			}
			canonical := prefix.Masked().String()
			if _, duplicate := seenAllowlist[canonical]; !duplicate {
				seenAllowlist[canonical] = struct{}{}
				plan.Allowlist = append(plan.Allowlist, canonical)
			}
			continue
		}
		address, err := netip.ParseAddr(strings.Trim(candidate, "[]"))
		if err != nil || address.Is4In6() || address.Zone() != "" {
			return haClusterPeerPlan{}, fmt.Errorf("invalid exact HA peer address")
		}
		canonical := address.String()
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

func readRootCrontab(command *exec.Cmd) (string, bool, error) {
	environment := command.Environ()
	filteredEnvironment := make([]string, 0, len(environment)+1)
	for _, variable := range environment {
		if !strings.HasPrefix(variable, "LC_ALL=") {
			filteredEnvironment = append(filteredEnvironment, variable)
		}
	}
	command.Env = append(filteredEnvironment, "LC_ALL=C")

	out, err := command.Output()
	if err == nil {
		return string(out), true, nil
	}
	var exitError *exec.ExitError
	if len(out) == 0 && errors.As(err, &exitError) && exitError.ExitCode() == 1 {
		message := strings.TrimSuffix(string(exitError.Stderr), "\n")
		if message == "no crontab for root" ||
			message == "crontab: no crontab for root" ||
			message == "crontab: can't open 'root': No such file or directory" {
			return "", false, nil
		}
	}
	return "", false, fmt.Errorf("failed to read root crontab: %w", err)
}

func writeRootCrontab(command *exec.Cmd, content string) error {
	command.Stdin = strings.NewReader(content)
	if err := command.Run(); err != nil {
		return fmt.Errorf("failed to write root crontab: %w", err)
	}
	return nil
}

func updateRootCrontab(readCommand, writeCommand *exec.Cmd, build func(string) (string, error)) error {
	existing, _, err := readRootCrontab(readCommand)
	if err != nil {
		return err
	}
	updated, err := build(existing)
	if err != nil {
		return err
	}
	if updated == existing {
		return nil
	}
	return writeRootCrontab(writeCommand, updated)
}

func configureHASyncCron(enableOutbound bool) error {
	err := updateRootCrontab(
		exec.Command("crontab", "-l"),
		exec.Command("crontab", "-"),
		func(existing string) (string, error) { return buildHACrontab(existing, enableOutbound) },
	)
	if err != nil {
		return fmt.Errorf("failed to update HA cron job: %w", err)
	}
	return nil
}

func buildHACrontab(existing string, enableOutbound bool) (string, error) {
	if !enableOutbound {
		return platformpaths.ReconcileCronRecords(existing, platformpaths.IsManagedHACronLine, "")
	}
	return platformpaths.ReconcileCronRecords(
		existing,
		platformpaths.IsManagedHACronLine,
		"*/30 * * * * "+platformpaths.CLI+" ha-sync >/dev/null 2>&1",
	)
}

func SetupHACluster() error {
	if !config.GlobalConfig.HAEnabled {
		if err := configureHASyncCron(false); err != nil {
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
		if err := configureHASyncCron(false); err != nil {
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
		whitelistCmd, err := platformpaths.WhitelistCommand(ip)
		if err != nil {
			return err
		}
		_ = whitelistCmd.Run()
	}

	if len(peerPlan.Dialable) == 0 {
		if err := configureHASyncCron(false); err != nil {
			return err
		}
		fmt.Println("[+] HA Cluster ENABLED in inbound-only mode (no dialable exact peer configured).")
		return nil
	}

	if err := configureHASyncCron(true); err != nil {
		return err
	}
	fmt.Println("[+] HA Cluster Sync ENABLED.")
	return nil
}
