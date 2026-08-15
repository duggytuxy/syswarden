package network

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"syswarden-cli/config"
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

func configureHASyncCron(enableOutbound bool) {
	out, _ := exec.Command("crontab", "-l").Output() // #nosec
	newCron := buildHACrontab(string(out), enableOutbound)
	cmd := exec.Command("crontab", "-") // #nosec
	cmd.Stdin = strings.NewReader(newCron)
	if err := cmd.Run(); err != nil {
		fmt.Printf("[WARN] Failed to update HA cron job: %v\n", err)
	}
}

func buildHACrontab(existing string, enableOutbound bool) string {
	lines := strings.Split(existing, "\n")
	newLines := make([]string, 0, len(lines)+1)
	for _, line := range lines {
		if strings.TrimSpace(line) != "" && !strings.Contains(line, "syswarden-cli ha-sync") {
			newLines = append(newLines, line)
		}
	}
	if enableOutbound {
		newLines = append(newLines, "*/30 * * * * /opt/syswarden/bin/syswarden-cli ha-sync >/dev/null 2>&1")
	}
	newCron := ""
	if len(newLines) > 0 {
		newCron = strings.Join(newLines, "\n") + "\n"
	}
	return newCron
}

func SetupHACluster() error {
	if !config.GlobalConfig.HAEnabled {
		fmt.Println("[INFO] HA Cluster Sync is DISABLED.")
		configureHASyncCron(false)
		return nil
	}

	peerPlan, err := planHAClusterPeers(config.GlobalConfig.HAPeerIP)
	if err != nil {
		return err
	}
	peerPort := config.GlobalConfig.HAPeerPort
	if len(peerPlan.Allowlist) == 0 {
		fmt.Println("[WARN] HA Cluster enabled but no Peer IP configured.")
		return nil
	}

	fmt.Printf("[INFO] Configuring HA peer allowlist: %v on port %s\n", peerPlan.Allowlist, peerPort)

	// Auto-whitelist Peer IPs to allow HA traffic through the firewall
	for _, ip := range peerPlan.Allowlist {
		// Just call the binary to avoid cyclical imports or complex logic
		fmt.Printf("[INFO] Auto-whitelisting HA Peer IP: %s\n", ip)
		_ = exec.Command("/opt/syswarden/bin/syswarden-cli", "whitelist", ip).Run() // #nosec
	}

	if len(peerPlan.Dialable) == 0 {
		configureHASyncCron(false)
		fmt.Println("[+] HA Cluster ENABLED in inbound-only mode (no dialable exact peer configured).")
		return nil
	}

	configureHASyncCron(true)
	fmt.Println("[+] HA Cluster Sync ENABLED.")
	return nil
}
