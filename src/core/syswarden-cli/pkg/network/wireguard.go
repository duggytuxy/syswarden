package network

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syswarden-cli/config"
)

func SetupWireguard() error {
	if !config.GlobalConfig.EnableWG {
		fmt.Println("[INFO] WireGuard is disabled in configuration. Ensuring it is stopped.")
		_ = exec.Command("wg-quick", "down", "wg0").Run()
		_ = exec.Command("systemctl", "disable", "--now", "wg-quick@wg0").Run()
		_ = os.Remove("/etc/wireguard/wg0.conf")
		return nil
	}

	fmt.Println("[INFO] Configuring WireGuard VPN...")

	if _, err := os.Stat("/etc/wireguard/wg0.conf"); err == nil {
		fmt.Println("[INFO] WireGuard configuration already exists. Skipping to prevent lockout.")
		return nil
	}

	_ = os.MkdirAll("/etc/wireguard/clients", 0700)
	_ = os.Chmod("/etc/wireguard", 0700)
	
	// Create sysctl configuration for IP forwarding
	_ = os.MkdirAll("/etc/sysctl.d", 0755)
	_ = os.WriteFile("/etc/sysctl.d/99-syswarden-wireguard.conf", []byte("net.ipv4.ip_forward = 1\n"), 0644)
 _ = exec.Command("sysctl", "-p", "/etc/sysctl.d/99-syswarden-wireguard.conf").Run()

	// Keys
	fmt.Println(" -> Generating cryptographic keys")
	serverPriv, _ := exec.Command("wg", "genkey").Output()
	serverPrivStr := strings.TrimSpace(string(serverPriv))
	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(serverPrivStr)
	serverPub, _ := cmd.Output()
	serverPubStr := strings.TrimSpace(string(serverPub))

	clientPriv, _ := exec.Command("wg", "genkey").Output()
	clientPrivStr := strings.TrimSpace(string(clientPriv))
	cmd2 := exec.Command("wg", "pubkey")
	cmd2.Stdin = strings.NewReader(clientPrivStr)
	clientPub, _ := cmd2.Output()
	clientPubStr := strings.TrimSpace(string(clientPub))

	presharedKey, _ := exec.Command("wg", "genpsk").Output()
	presharedKeyStr := strings.TrimSpace(string(presharedKey))

	// Network Calculations
	activeIfOut, _ := exec.Command("sh", "-c", "ip route get 8.8.8.8 | grep -oP 'dev \\K\\S+' | head -n 1").Output()
	activeIf := strings.TrimSpace(string(activeIfOut))
	if activeIf == "" {
		activeIf = "eth0"
	}

	serverIPOut, _ := exec.Command("curl", "-4", "-s", "--connect-timeout", "3", "api.ipify.org").Output()
	serverIP := strings.TrimSpace(string(serverIPOut))

	subnetParts := strings.Split(config.GlobalConfig.WGSubnet, ".")
	if len(subnetParts) < 3 {
		subnetParts = []string{"10", "66", "66"}
	}
	subnetBase := fmt.Sprintf("%s.%s.%s", subnetParts[0], subnetParts[1], subnetParts[2])
	serverVPNIP := subnetBase + ".1"
	clientVPNIP := subnetBase + ".2"

	// PostUp / PostDown NAT rules based on backend
	postUp := ""
	postDown := ""
	switch config.GlobalConfig.FirewallBackend {
	case "nftables":
		postUp = fmt.Sprintf(`nft 'add table inet syswarden_wg'; nft 'add chain inet syswarden_wg prerouting { type nat hook prerouting priority dstnat; }'; nft 'add chain inet syswarden_wg postrouting { type nat hook postrouting priority srcnat; }'; nft 'add rule inet syswarden_wg postrouting oifname "%s" masquerade'; nft 'add chain inet filter forward { type filter hook forward priority 0; }' 2>/dev/null || true; nft 'insert rule inet filter forward iifname "wg0" accept'; nft 'insert rule inet filter forward oifname "wg0" accept'`, activeIf)
		postDown = `nft delete table inet syswarden_wg 2>/dev/null || true; nft delete rule inet filter forward iifname "wg0" accept 2>/dev/null || true; nft delete rule inet filter forward oifname "wg0" accept 2>/dev/null || true`
	case "firewalld":
		postUp = ""
		postDown = ""
	default:
		postUp = fmt.Sprintf("iptables -t nat -I POSTROUTING 1 -s %s -o %s -j MASQUERADE; iptables -I FORWARD 1 -i wg0 -j ACCEPT; iptables -I FORWARD 1 -o wg0 -j ACCEPT", config.GlobalConfig.WGSubnet, activeIf)
		postDown = fmt.Sprintf("iptables -t nat -D POSTROUTING -s %s -o %s -j MASQUERADE 2>/dev/null || true; iptables -D FORWARD -i wg0 -j ACCEPT 2>/dev/null || true; iptables -D FORWARD -o wg0 -j ACCEPT 2>/dev/null || true", config.GlobalConfig.WGSubnet, activeIf)
	}

	// Write configs safely
	serverConf := fmt.Sprintf(`[Interface]
Address = %s/24
ListenPort = %s
PrivateKey = %s
PostUp = %s
PostDown = %s

[Peer]
PublicKey = %s
PresharedKey = %s
AllowedIPs = %s/32
`, serverVPNIP, config.GlobalConfig.WGPort, serverPrivStr, postUp, postDown, clientPubStr, presharedKeyStr, clientVPNIP)

	_ = os.WriteFile("/etc/wireguard/wg0.conf", []byte(serverConf), 0600)

	clientConf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/24
MTU = 1360
DNS = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey = %s
PresharedKey = %s
Endpoint = %s:%s
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`, clientPrivStr, clientVPNIP, serverPubStr, presharedKeyStr, serverIP, config.GlobalConfig.WGPort)

	clientConfPath := "/etc/wireguard/clients/admin-pc.conf"
	_ = os.WriteFile(clientConfPath, []byte(clientConf), 0600)

	// Start service
	fmt.Println(" -> Starting WireGuard Interface")
 _ = exec.Command("systemctl", "daemon-reload").Run()
 _ = exec.Command("systemctl", "enable", "--now", "wg-quick@wg0").Run()

	fmt.Println("\n=======================================================")
	fmt.Println("             WIREGUARD CLIENT CONFIGURATION            ")
	fmt.Println("=======================================================")
	fmt.Println("Scan the QR Code below with your WireGuard mobile app:")
	
	qrCmd := exec.Command("qrencode", "-t", "ansiutf8")
	qrCmd.Stdin = strings.NewReader(clientConf)
	qrCmd.Stdout = os.Stdout
	_ = qrCmd.Run()
	
	fmt.Println("=======================================================")
	fmt.Println("Client config saved at: " + clientConfPath)

	return nil
}
