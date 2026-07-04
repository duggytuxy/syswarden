package network

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syswarden-cli/config"
)

func SetupHACluster() error {
	if !config.GlobalConfig.HAEnabled {
		fmt.Println("[INFO] HA Cluster Sync is DISABLED.")
		// Remove cron natively
		out, _ := exec.Command("crontab", "-l").Output()
		lines := strings.Split(string(out), "\n")
		var newLines []string
		for _, line := range lines {
			if strings.TrimSpace(line) != "" && !strings.Contains(line, "syswarden-cli ha-sync") {
				newLines = append(newLines, line)
			}
		}
		newCron := ""
		if len(newLines) > 0 {
			newCron = strings.Join(newLines, "\n") + "\n"
		}
		cmd := exec.Command("crontab", "-")
		cmd.Stdin = strings.NewReader(newCron)
		_ = cmd.Run()
		return nil
	}

	peerIPsStr := strings.ReplaceAll(config.GlobalConfig.HAPeerIP, ",", " ")
	peerIPs := strings.Fields(peerIPsStr)
	peerPort := config.GlobalConfig.HAPeerPort
	if len(peerIPs) == 0 {
		fmt.Println("[WARN] HA Cluster enabled but no Peer IP configured.")
		return nil
	}

	fmt.Printf("[INFO] Configuring HA Synchronization Engine to Peers: %v on port %s\n", peerIPs, peerPort)

	// Trust On First Use (TOFU): Automatically fetch and store the peer's host key
	if config.GlobalConfig.HAStrictHostKey {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			sshDir := filepath.Join(homeDir, ".ssh")
			_ = os.MkdirAll(sshDir, 0700)
			knownHosts := filepath.Join(sshDir, "known_hosts")

			for _, ip := range peerIPs {
				fmt.Printf("[INFO] Auto-discovering ED25519 host key for %s (TOFU)...\n", ip)
				scanCmd := exec.Command("ssh-keyscan", "-t", "ed25519", "-p", peerPort, ip)
				keyOut, err := scanCmd.Output()
				if err == nil && len(keyOut) > 0 {
					existingKeys, _ := os.ReadFile(knownHosts)
					if !strings.Contains(string(existingKeys), strings.TrimSpace(string(keyOut))) {
						f, err := os.OpenFile(knownHosts, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
						if err == nil {
							_, _ = f.Write(keyOut)
							_ = f.Close()
							fmt.Printf("[+] Peer %s host key securely added to known_hosts.\n", ip)
						}
					} else {
						fmt.Printf("[+] Peer %s host key already trusted.\n", ip)
					}
				} else {
					fmt.Printf("[WARN] Could not fetch host key from %s. Manual ssh-keyscan may be required.\n", ip)
				}
			}
		}
	}

	// In a full Go architecture, we register a cron job that calls the Go CLI to perform the sync natively
	// instead of relying on a bash script containing python sockets.
	cronJob := "*/30 * * * * /opt/syswarden/bin/syswarden-cli ha-sync >/dev/null 2>&1"

	out, _ := exec.Command("crontab", "-l").Output()
	lines := strings.Split(string(out), "\n")
	var newLines []string
	for _, line := range lines {
		if strings.TrimSpace(line) != "" && !strings.Contains(line, "syswarden-cli ha-sync") {
			newLines = append(newLines, line)
		}
	}
	newLines = append(newLines, cronJob)

	newCron := strings.Join(newLines, "\n") + "\n"
	cmd := exec.Command("crontab", "-")
	cmd.Stdin = strings.NewReader(newCron)
	if err := cmd.Run(); err != nil {
		fmt.Printf("[WARN] Failed to inject HA cron job: %v\n", err)
	}

	fmt.Println("[+] HA Cluster Sync ENABLED.")
	return nil
}
