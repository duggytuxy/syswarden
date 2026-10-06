package firewall

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"syswarden-cli/config"
)

// AutoWhitelistAdminAndInfra detects and safely whitelists the admin IP and critical infra IPs
func AutoWhitelistAdminAndInfra() error {
	if _, err := preflightConfiguredFirewallBackendMutation(); err != nil {
		return fmt.Errorf("validate firewall backend before automatic whitelist mutation: %w", err)
	}
	if _, err := retireLegacyMetadataWhitelistEntry(); err != nil {
		return fmt.Errorf("retire legacy metadata whitelist entry: %w", err)
	}
	fmt.Println("[INFO] Scanning and auto-whitelisting critical infrastructure & Admin IP...")

	// 1. Admin IP Detection
	adminIP := ""
	sshConn := os.Getenv("SSH_CONNECTION")
	if sshConn != "" {
		adminIP = strings.Split(sshConn, " ")[0]
	} else {
		sshClient := os.Getenv("SSH_CLIENT")
		if sshClient != "" {
			adminIP = strings.Split(sshClient, " ")[0]
		}
	}

	if adminIP == "" || adminIP == "127.0.0.1" {
		fmt.Println("[WARN] Could not safely determine Admin IP from environment.")
	}

	// 2. Infra IPs (DNS, gateway, and local interface addresses)
	var discoveredInfraIPs []string
	if config.GlobalConfig.WhitelistInfra {
		infraIPs, err := infraIPv4Candidates()
		if err != nil {
			return err
		}
		discoveredInfraIPs = infraIPs
	}

	ipsToAdd, ipsToAddV6 := automaticWhitelistCandidates(
		adminIP,
		config.GlobalConfig.WhitelistInfra,
		discoveredInfraIPs,
		strings.Fields(config.GlobalConfig.WhitelistIPs),
	)
	canonicalAdminIP := ""
	if entry, err := parseCanonicalListEntry(adminIP, false); err == nil && entry.isIPv4 {
		canonicalAdminIP = entry.network
	}

	if err := EnsurePersistentWhitelistPair(); err != nil {
		return err
	}
	addedCount := 0
	for _, family := range []struct {
		name       string
		candidates []string
	}{
		{"syswarden_whitelist.ipv4", ipsToAdd},
		{"syswarden_whitelist.ipv6", ipsToAddV6},
	} {
		added, err := appendAutomaticWhitelist(approvedListFile{directory: "/etc/syswarden/lists", name: family.name}, family.candidates)
		if err != nil {
			return err
		}
		for _, ip := range added {
			if ip == canonicalAdminIP {
				fmt.Printf(" -> Auto-whitelisting Admin SSH IP: %s\n", ip)
			} else {
				fmt.Printf(" -> Auto-whitelisting infrastructure IP: %s\n", ip)
			}
		}
		addedCount += len(added)
	}
	if addedCount > 0 {
		fmt.Printf("[+] Safely added %d IPs to the absolute whitelist.\n", addedCount)
	}

	return nil
}

func automaticWhitelistCandidates(adminIP string, includeInfra bool, infraIPs, configuredIPs []string) ([]string, []string) {
	candidates := make([]string, 0, 1+len(infraIPs)+len(configuredIPs))
	if adminIP != "" && adminIP != "127.0.0.1" {
		candidates = append(candidates, adminIP)
	}
	if includeInfra {
		candidates = append(candidates, infraIPs...)
	}
	candidates = append(candidates, configuredIPs...)
	return canonicalWhitelistCandidates(candidates...)
}

// Automatic changes retain origin only when the exact previous list is still
// generated. Existing unmarked or manually edited lists are never adopted.
func appendAutomaticWhitelist(target approvedListFile, candidates []string) ([]string, error) {
	if target.name != "syswarden_whitelist.ipv4" && target.name != "syswarden_whitelist.ipv6" {
		return nil, fmt.Errorf("automatic whitelist target is unsupported")
	}
	directory, err := openListDirectory(target, false)
	if err != nil {
		return nil, err
	}
	defer func() { _ = directory.Close() }()
	lease, err := lockListDirectory(directory)
	if err != nil {
		return nil, err
	}
	defer unlockListDirectory(lease)
	snapshot, err := snapshotTransactionalListFileInDirectory(directory, target)
	if err != nil {
		return nil, err
	}
	if !snapshot.exists {
		return nil, fmt.Errorf("automatic whitelist pair has not been initialized")
	}
	content := bytes.Clone(snapshot.content)
	existing := make(map[string]bool)
	for _, line := range strings.Split(string(content), "\n") {
		existing[strings.TrimSpace(line)] = true
	}
	var added []string
	for _, candidate := range candidates {
		entry, err := parseCanonicalListEntry(candidate, false)
		if err != nil || entry.network != candidate || entry.isIPv4 != (target.name == "syswarden_whitelist.ipv4") {
			return nil, fmt.Errorf("automatic whitelist candidate is noncanonical or has the wrong family")
		}
		if existing[candidate] {
			continue
		}
		if len(content) != 0 && content[len(content)-1] != '\n' {
			content = append(content, '\n')
		}
		content = append(content, []byte(candidate+"\n")...)
		existing[candidate] = true
		added = append(added, candidate)
	}
	if len(added) == 0 {
		return added, nil
	}
	if len(content) > maximumTransactionalListSnapshotBytes {
		return nil, fmt.Errorf("automatic whitelist exceeds the bounded snapshot limit")
	}
	if err := writeListFileInDirectoryWithOrigin(directory, target, content, &snapshot.digest, nil, true); err != nil {
		return nil, err
	}
	return added, nil
}
