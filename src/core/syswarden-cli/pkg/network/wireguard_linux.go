//go:build linux

package network

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"syswarden-cli/config"
	"syswarden-cli/pkg/system"
)

var wireGuardInterfaceName = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)
var wireGuardManagerRuntimeState = system.ServiceManagerRuntimeState

type wireGuardRenderInput struct {
	Subnet       string
	Port         string
	Backend      string
	ActiveIf     string
	EndpointIP   string
	ServerPriv   string
	ServerPub    string
	ClientPriv   string
	ClientPub    string
	PresharedKey string
}

type wireGuardServiceRunner func(name string, args ...string) error

func runWireGuardServiceCommand(name string, args ...string) error {
	return exec.Command(name, args...).Run() // #nosec G204 -- executable, service names and actions are fixed product constants
}

func ensureExactSymlink(target, link string) error {
	info, err := os.Lstat(link)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("refusing to replace non-symlink %s", link)
		}
		currentTarget, err := os.Readlink(link)
		if err != nil {
			return fmt.Errorf("read existing symlink %s: %w", link, err)
		}
		if currentTarget != target {
			return fmt.Errorf("refusing to replace symlink %s targeting %s", link, currentTarget)
		}
		return nil
	case !os.IsNotExist(err):
		return fmt.Errorf("inspect symlink %s: %w", link, err)
	}

	if err := os.Symlink(target, link); err != nil {
		return fmt.Errorf("create symlink %s: %w", link, err)
	}
	return nil
}

func activateWireGuardService(alpine bool, ensureOpenRCLink func() error, run wireGuardServiceRunner) error {
	if alpine {
		if err := ensureOpenRCLink(); err != nil {
			return fmt.Errorf("prepare OpenRC WireGuard service: %w", err)
		}
		if err := run("rc-update", "add", "wg-quick.wg-syswarden", "default"); err != nil {
			return fmt.Errorf("enable OpenRC WireGuard service: %w", err)
		}
		if err := run("rc-service", "wg-quick.wg-syswarden", "start"); err != nil {
			return fmt.Errorf("start OpenRC WireGuard service: %w", err)
		}
		return nil
	}

	if err := run("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("reload systemd before activating WireGuard: %w", err)
	}
	if err := run("systemctl", "enable", "--now", "wg-quick@wg-syswarden"); err != nil {
		return fmt.Errorf("enable and start systemd WireGuard service: %w", err)
	}
	return nil
}

func activateConfiguredWireGuardService() error {
	state, err := system.ServiceManagerRuntimeState()
	if err != nil {
		return fmt.Errorf("classify service-manager runtime before WireGuard activation: %w", err)
	}
	if state == "OFFLINE" {
		return fmt.Errorf("WireGuard activation requires an active service manager; offline package installation cannot attest boot enablement")
	}
	if state != "ACTIVE" {
		return fmt.Errorf("refusing unrecognized service-manager runtime state %q", state)
	}
	ensureOpenRCLink := func() error {
		return ensureExactSymlink("/etc/init.d/wg-quick", "/etc/init.d/wg-quick.wg-syswarden")
	}
	return activateWireGuardService(system.IsAlpine(), ensureOpenRCLink, runWireGuardServiceCommand)
}

func inspectWireGuardConfigurationFile(path string) (os.FileInfo, bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("inspect %s: %w", path, err)
	}
	return info, true, nil
}

func validateExistingWireGuardConfigurationFile(path string, info os.FileInfo, expectedUID uint32) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("existing WireGuard configuration %s is not a real regular file", path)
	}
	if info.Mode().Perm() != 0600 {
		return fmt.Errorf("existing WireGuard configuration %s must have mode 0600", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("read ownership of existing WireGuard configuration %s", path)
	}
	if stat.Uid != expectedUID {
		return fmt.Errorf("existing WireGuard configuration %s has unexpected owner UID %d", path, stat.Uid)
	}
	if stat.Nlink != 1 {
		return fmt.Errorf("existing WireGuard configuration %s must have exactly one hard link", path)
	}
	return nil
}

func reuseExistingWireGuardConfiguration(serverPath, clientPath string, expectedUID uint32, activate func() error) (bool, error) {
	serverInfo, serverExists, err := inspectWireGuardConfigurationFile(serverPath)
	if err != nil {
		return false, err
	}
	clientInfo, clientExists, err := inspectWireGuardConfigurationFile(clientPath)
	if err != nil {
		return false, err
	}
	if !serverExists && !clientExists {
		return false, nil
	}
	if !serverExists {
		return false, fmt.Errorf("partial WireGuard configuration: %s exists without completion marker %s", clientPath, serverPath)
	}
	if err := validateExistingWireGuardConfigurationFile(serverPath, serverInfo, expectedUID); err != nil {
		return false, err
	}
	if clientExists {
		if err := validateExistingWireGuardConfigurationFile(clientPath, clientInfo, expectedUID); err != nil {
			return false, err
		}
	}
	if err := activate(); err != nil {
		return false, fmt.Errorf("activate existing WireGuard configuration: %w", err)
	}
	return true, nil
}

func canonicalWireGuardKey(value string) (string, error) {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n") {
		return "", fmt.Errorf("WireGuard key is empty or contains surrounding/control whitespace")
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 || base64.StdEncoding.EncodeToString(decoded) != value {
		return "", fmt.Errorf("WireGuard key is not canonical base64 for 32 bytes")
	}
	return value, nil
}

func wireGuardHostAddresses(rawSubnet string) (netip.Prefix, netip.Addr, netip.Addr, error) {
	prefix, err := netip.ParsePrefix(rawSubnet)
	if err != nil || !prefix.Addr().Is4() || prefix.Addr().Is4In6() || prefix != prefix.Masked() || prefix.Bits() > 30 {
		return netip.Prefix{}, netip.Addr{}, netip.Addr{}, fmt.Errorf("WireGuard subnet must be a canonical IPv4 prefix with at least two host addresses")
	}
	server := prefix.Addr().Next()
	client := server.Next()
	if !server.IsValid() || !client.IsValid() || !prefix.Contains(server) || !prefix.Contains(client) {
		return netip.Prefix{}, netip.Addr{}, netip.Addr{}, fmt.Errorf("WireGuard subnet has no usable server/client address pair")
	}
	return prefix, server, client, nil
}

func renderWireGuardConfigurations(input wireGuardRenderInput) (string, string, error) {
	prefix, serverVPNIP, clientVPNIP, err := wireGuardHostAddresses(input.Subnet)
	if err != nil {
		return "", "", err
	}
	portNumber, err := strconv.Atoi(input.Port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return "", "", fmt.Errorf("invalid WireGuard port %q", input.Port)
	}
	port := strconv.Itoa(portNumber)
	if !wireGuardInterfaceName.MatchString(input.ActiveIf) {
		return "", "", fmt.Errorf("invalid WireGuard egress interface %q", input.ActiveIf)
	}
	endpoint, err := netip.ParseAddr(input.EndpointIP)
	if err != nil || endpoint.Zone() != "" || endpoint.Is4In6() {
		return "", "", fmt.Errorf("invalid WireGuard endpoint IP %q", input.EndpointIP)
	}
	keys := []*string{&input.ServerPriv, &input.ServerPub, &input.ClientPriv, &input.ClientPub, &input.PresharedKey}
	for _, key := range keys {
		canonical, err := canonicalWireGuardKey(*key)
		if err != nil {
			return "", "", err
		}
		*key = canonical
	}

	var postUp, postDown string
	switch input.Backend {
	case "nftables":
		postUp = fmt.Sprintf(`nft 'add table inet syswarden_wg'; nft 'add chain inet syswarden_wg prerouting { type nat hook prerouting priority dstnat; }'; nft 'add chain inet syswarden_wg postrouting { type nat hook postrouting priority srcnat; }'; nft 'add rule inet syswarden_wg postrouting oifname "%s" masquerade'; nft 'add table inet filter' 2>/dev/null || true; nft 'add chain inet filter forward { type filter hook forward priority 0; }' 2>/dev/null || true; nft 'insert rule inet filter forward iifname "wg-syswarden" accept'; nft 'insert rule inet filter forward oifname "wg-syswarden" accept'`, input.ActiveIf)
		postDown = `nft delete table inet syswarden_wg 2>/dev/null || true; nft delete rule inet filter forward iifname "wg-syswarden" accept 2>/dev/null || true; nft delete rule inet filter forward oifname "wg-syswarden" accept 2>/dev/null || true`
	case "iptables", "keep":
		postUp = fmt.Sprintf("iptables -t nat -I POSTROUTING 1 -s %s -o %s -j MASQUERADE; iptables -I FORWARD 1 -i wg-syswarden -j ACCEPT; iptables -I FORWARD 1 -o wg-syswarden -j ACCEPT", prefix.String(), input.ActiveIf)
		postDown = fmt.Sprintf("iptables -t nat -D POSTROUTING -s %s -o %s -j MASQUERADE 2>/dev/null || true; iptables -D FORWARD -i wg-syswarden -j ACCEPT 2>/dev/null || true; iptables -D FORWARD -o wg-syswarden -j ACCEPT 2>/dev/null || true", prefix.String(), input.ActiveIf)
	default:
		return "", "", fmt.Errorf("unsupported WireGuard firewall backend %q", input.Backend)
	}

	serverConf := fmt.Sprintf(`[Interface]
Address = %s/%d
ListenPort = %s
PrivateKey = %s
PostUp = %s
PostDown = %s

[Peer]
PublicKey = %s
PresharedKey = %s
AllowedIPs = %s/32
`, serverVPNIP, prefix.Bits(), port, input.ServerPriv, postUp, postDown, input.ClientPub, input.PresharedKey, clientVPNIP)

	clientConf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/%d
MTU = 1360
DNS = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey = %s
PresharedKey = %s
Endpoint = %s
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`, input.ClientPriv, clientVPNIP, prefix.Bits(), input.ServerPub, input.PresharedKey, net.JoinHostPort(endpoint.String(), port))
	return serverConf, clientConf, nil
}

func SetupWireguard() error {
	if !config.GlobalConfig.EnableWG {
		fmt.Println("[INFO] WireGuard is disabled in SYSWARDEN configuration. Skipping WireGuard setup.")
		return nil
	}
	managerState, err := wireGuardManagerRuntimeState()
	if err != nil {
		return fmt.Errorf("classify service-manager runtime before WireGuard setup: %w", err)
	}
	if managerState != "ACTIVE" {
		return fmt.Errorf("WireGuard setup requires an attestable active service manager; state is %s", managerState)
	}

	fmt.Println("[INFO] Configuring WireGuard VPN...")

	reused, err := reuseExistingWireGuardConfiguration(
		"/etc/wireguard/wg-syswarden.conf",
		"/etc/wireguard/clients/admin-pc.conf",
		0,
		activateConfiguredWireGuardService,
	)
	if err != nil {
		return err
	}
	if reused {
		fmt.Println("[INFO] Existing WireGuard keys preserved and service activation verified.")
		return nil
	}

	if err := ensurePrivateDirectory("/etc", "wireguard"); err != nil {
		return fmt.Errorf("prepare WireGuard directory: %w", err)
	}
	if err := ensurePrivateDirectory("/etc", "wireguard/clients"); err != nil {
		return fmt.Errorf("prepare WireGuard clients directory: %w", err)
	}

	// Create sysctl configuration for IP forwarding
	_ = os.MkdirAll("/etc/sysctl.d", 0750)
	if err := os.WriteFile("/etc/sysctl.d/99-syswarden-wireguard.conf", []byte("net.ipv4.ip_forward = 1\n"), 0600); err != nil {
		return fmt.Errorf("write WireGuard sysctl configuration: %w", err)
	}
	if err := exec.Command("sysctl", "-p", "/etc/sysctl.d/99-syswarden-wireguard.conf").Run(); err != nil { // #nosec G204 -- executable and configuration path are fixed product constants
		return fmt.Errorf("apply WireGuard sysctl configuration: %w", err)
	}

	// Keys
	fmt.Println(" -> Generating cryptographic keys (incl. Post-Quantum PSK)")
	serverPriv, err := exec.Command("wg", "genkey").Output() // #nosec G204 -- executable and subcommand are fixed product constants
	if err != nil {
		return fmt.Errorf("generate WireGuard server key: %w", err)
	}
	serverPrivStr := strings.TrimSpace(string(serverPriv))
	cmd := exec.Command("wg", "pubkey") // #nosec G204 -- executable and subcommand are fixed product constants
	cmd.Stdin = strings.NewReader(serverPrivStr)
	serverPub, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("derive WireGuard server public key: %w", err)
	}
	serverPubStr := strings.TrimSpace(string(serverPub))

	clientPriv, err := exec.Command("wg", "genkey").Output() // #nosec G204 -- executable and subcommand are fixed product constants
	if err != nil {
		return fmt.Errorf("generate WireGuard client key: %w", err)
	}
	clientPrivStr := strings.TrimSpace(string(clientPriv))
	cmd2 := exec.Command("wg", "pubkey") // #nosec G204 -- executable and subcommand are fixed product constants
	cmd2.Stdin = strings.NewReader(clientPrivStr)
	clientPub, err := cmd2.Output()
	if err != nil {
		return fmt.Errorf("derive WireGuard client public key: %w", err)
	}
	clientPubStr := strings.TrimSpace(string(clientPub))

	presharedKey, err := exec.Command("wg", "genpsk").Output() // #nosec G204 -- executable and subcommand are fixed product constants
	if err != nil {
		return fmt.Errorf("generate WireGuard preshared key: %w", err)
	}
	presharedKeyStr := strings.TrimSpace(string(presharedKey))
	fmt.Println(" -> Injecting Quantum-Resistant PresharedKey (PSK)")

	// Network Calculations
	activeIfOut, err := exec.Command("ip", "route", "get", "8.8.8.8").Output() // #nosec G204 -- executable, route query and destination are fixed product constants
	if err != nil {
		return fmt.Errorf("discover WireGuard egress interface: %w", err)
	}
	activeIf := ""
	fields := strings.Fields(string(activeIfOut))
	for i, v := range fields {
		if v == "dev" && i+1 < len(fields) {
			activeIf = fields[i+1]
			break
		}
	}
	if activeIf == "" {
		return fmt.Errorf("WireGuard egress route has no interface")
	}

	serverIPOut, err := exec.Command(
		"curl",
		"--proto", "=https",
		"--tlsv1.3",
		"--fail",
		"--silent",
		"--show-error",
		"--connect-timeout", "3",
		"--max-time", "5",
		"-4",
		"https://api.ipify.org",
	).Output() // #nosec G204 -- executable, fail-closed TLS options and endpoint are fixed product constants
	if err != nil {
		return fmt.Errorf("discover WireGuard endpoint IP: %w", err)
	}
	serverIP := strings.TrimSpace(string(serverIPOut))

	serverConf, clientConf, err := renderWireGuardConfigurations(wireGuardRenderInput{
		Subnet:       config.GlobalConfig.WGSubnet,
		Port:         config.GlobalConfig.WGPort,
		Backend:      config.GlobalConfig.FirewallBackend,
		ActiveIf:     activeIf,
		EndpointIP:   serverIP,
		ServerPriv:   serverPrivStr,
		ServerPub:    serverPubStr,
		ClientPriv:   clientPrivStr,
		ClientPub:    clientPubStr,
		PresharedKey: presharedKeyStr,
	})
	if err != nil {
		return fmt.Errorf("render WireGuard configuration: %w", err)
	}
	// Publish the client export first so the server configuration remains the
	// durable completion marker. Historical deployments may remove the export.
	clientConfPath := "/etc/wireguard/clients/admin-pc.conf"
	if err := os.WriteFile(clientConfPath, []byte(clientConf), 0600); err != nil {
		return fmt.Errorf("write WireGuard client configuration: %w", err)
	}
	if err := os.WriteFile("/etc/wireguard/wg-syswarden.conf", []byte(serverConf), 0600); err != nil {
		return fmt.Errorf("write WireGuard server configuration: %w", err)
	}

	// Start service
	fmt.Println(" -> Starting WireGuard Interface")
	if err := activateConfiguredWireGuardService(); err != nil {
		return err
	}

	fmt.Println("\n=======================================================")
	fmt.Println("             WIREGUARD CLIENT CONFIGURATION            ")
	fmt.Println("=======================================================")
	fmt.Println("Scan the QR Code below with your WireGuard mobile app:")

	qrCmd := exec.Command("qrencode", "-t", "ansiutf8") // #nosec G204 -- executable and output mode are fixed product constants
	qrCmd.Stdin = strings.NewReader(clientConf)
	qrCmd.Stdout = os.Stdout
	_ = qrCmd.Run()

	fmt.Println("=======================================================")
	fmt.Println("Client config saved at: " + clientConfPath)

	return nil
}
