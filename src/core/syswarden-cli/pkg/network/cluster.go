package network

import (
	"fmt"
	"os/exec"
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

	peerIP := config.GlobalConfig.HAPeerIP
	peerPort := config.GlobalConfig.HAPeerPort
	if peerIP == "" {
		fmt.Println("[WARN] HA Cluster enabled but no Peer IP configured.")
		return nil
	}

	fmt.Printf("[INFO] Configuring HA Synchronization Engine to Peer %s:%s\n", peerIP, peerPort)

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

