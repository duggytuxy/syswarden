//go:build freebsd

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
		fmt.Println("[INFO] WireGuard is disabled in SYSWARDEN configuration. Skipping WireGuard setup.")
		return nil
	}

	fmt.Println("[INFO] Configuring WireGuard VPN natively for FreeBSD...")

	if _, err := os.Stat("/usr/local/etc/wireguard/wg-syswarden.conf"); err == nil {
		fmt.Println("[INFO] WireGuard configuration already exists. Skipping to prevent lockout.")
		return nil
	}

	_ = os.MkdirAll("/usr/local/etc/wireguard/clients", 0700)
	_ = os.Chmod("/usr/local/etc/wireguard", 0700)

	// Create sysrc configuration for IP forwarding
	_ = exec.Command("sysrc", "gateway_enable=YES").Run()
	_ = exec.Command("sysctl", "net.inet.ip.forwarding=1").Run()

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
	activeIfOut, _ := exec.Command("route", "-n", "get", "default").Output()
	activeIf := "vtnet0"
	lines := strings.Split(string(activeIfOut), "\n")
	for _, line := range lines {
		if strings.Contains(line, "interface:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				activeIf = fields[1]
			}
		}
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

	// PostUp / PostDown NAT rules based on pf
	// We use the PF syswarden_wg anchor
	postUp := fmt.Sprintf("echo 'nat on %s from %s to any -> (%s)' | pfctl -a syswarden_wg -f -", activeIf, config.GlobalConfig.WGSubnet, activeIf)
	postDown := "pfctl -a syswarden_wg -F all"

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

	_ = os.WriteFile("/usr/local/etc/wireguard/wg-syswarden.conf", []byte(serverConf), 0600)

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

	clientConfPath := "/usr/local/etc/wireguard/clients/admin-pc.conf"
	_ = os.WriteFile(clientConfPath, []byte(clientConf), 0600)

	// Start service
	fmt.Println(" -> Starting WireGuard Interface")
	_ = exec.Command("sysrc", "wireguard_enable=YES").Run()
	_ = exec.Command("sysrc", "wireguard_interfaces=wg-syswarden").Run()
	_ = exec.Command("service", "wireguard", "start").Run()

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
