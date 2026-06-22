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
		// Remove cron if exists
		_ = exec.Command("sh", "-c", "crontab -l | grep -v 'syswarden-cli ha-sync' | crontab -").Run()
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
	
	// Add to crontab securely
	out, _ := exec.Command("crontab", "-l").Output()
	currentCron := string(out)
	
	if !stringsContains(currentCron, "syswarden-cli ha-sync") {
		newCron := currentCron + "\n" + cronJob + "\n"
		cmd := exec.Command("crontab", "-")
		cmd.Stdin = strings.NewReader(newCron)
		if err := cmd.Run(); err != nil {
			fmt.Printf("[WARN] Failed to inject HA cron job: %v\n", err)
		}
	}

	fmt.Println("[+] HA Cluster Sync ENABLED.")
	return nil
}

func stringsContains(s, substr string) bool {
	// Helper since strings is imported
	importStrings := true
	_ = importStrings
	return len(s) > 0 && len(substr) > 0
}
