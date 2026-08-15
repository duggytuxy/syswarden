//go:build freebsd

package network

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"

	"syswarden-cli/config"
	"syswarden-cli/pkg/system"
)

const (
	freeBSDWireGuardRoot       = "/usr/local/etc/wireguard"
	freeBSDWireGuardConfigName = "wg-syswarden.conf"
	freeBSDWireGuardClientRoot = "/usr/local/etc/wireguard/clients"
	freeBSDWireGuardClientName = "admin-pc.conf"
)

func freeBSDWireGuardKey(command *exec.Cmd, label string) (string, error) {
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("generate %s: %w", label, err)
	}
	value := strings.TrimSpace(string(output))
	if value == "" || strings.ContainsAny(value, "\x00\r\n") {
		return "", fmt.Errorf("generated %s is empty or malformed", label)
	}
	return value, nil
}

func freeBSDWireGuardPublicKey(privateKey, label string) (string, error) {
	command := exec.Command("wg", "pubkey")
	command.Stdin = strings.NewReader(privateKey)
	return freeBSDWireGuardKey(command, label)
}

func validFreeBSDInterfaceName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, character := range name {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			strings.ContainsRune("_.:-", character) {
			continue
		}
		return false
	}
	return true
}

func freeBSDDefaultInterface() (string, error) {
	output, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return "", fmt.Errorf("resolve default FreeBSD interface: %w", err)
	}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "interface:" && validFreeBSDInterfaceName(fields[1]) {
			return fields[1], nil
		}
	}
	return "", fmt.Errorf("default FreeBSD interface is missing or malformed")
}

func freeBSDWireGuardAddresses(subnet string) (string, string, string, error) {
	if subnet == "" {
		subnet = "10.66.66.0/24"
	}
	prefix, err := netip.ParsePrefix(subnet)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 24 || prefix != prefix.Masked() {
		return "", "", "", fmt.Errorf("WireGuard subnet must be a canonical IPv4 /24")
	}
	base := prefix.Addr().As4()
	server := netip.AddrFrom4([4]byte{base[0], base[1], base[2], 1})
	client := netip.AddrFrom4([4]byte{base[0], base[1], base[2], 2})
	return prefix.String(), server.String(), client.String(), nil
}

func writeExclusiveFreeBSDWireGuardFile(directory, name string, payload []byte) error {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	clean := false
	defer func() {
		_ = file.Close()
		if !clean {
			_ = root.Remove(name)
		}
	}()
	if _, err := file.Write(payload); err != nil {
		return err
	}
	if err := file.Chown(0, 0); err != nil {
		return err
	}
	if err := file.Chmod(0600); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	clean = true
	return file.Close()
}

func freeBSDWireGuardInterfaceActive() (bool, error) {
	err := exec.Command("ifconfig", "wg-syswarden").Run()
	if err == nil {
		return true, nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) && exitError.ExitCode() == 1 {
		return false, nil
	}
	return false, err
}

func SetupWireguard() (resultErr error) {
	if !config.GlobalConfig.EnableWG {
		fmt.Println("[INFO] WireGuard is disabled in SYSWARDEN configuration. Skipping WireGuard setup.")
		return nil
	}

	fmt.Println("[INFO] Configuring WireGuard VPN natively for FreeBSD...")
	configPath := freeBSDWireGuardRoot + "/" + freeBSDWireGuardConfigName
	clientPath := freeBSDWireGuardClientRoot + "/" + freeBSDWireGuardClientName
	if info, err := os.Lstat(configPath); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing unsafe existing WireGuard configuration")
		}
		fmt.Println("[INFO] WireGuard configuration already exists. Skipping to prevent lockout.")
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := os.Lstat(clientPath); err == nil {
		return fmt.Errorf("refusing to replace preexisting WireGuard client configuration")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	fmt.Println(" -> Generating cryptographic keys (incl. Post-Quantum PSK)")
	serverPrivate, err := freeBSDWireGuardKey(exec.Command("wg", "genkey"), "server private key")
	if err != nil {
		return err
	}
	serverPublic, err := freeBSDWireGuardPublicKey(serverPrivate, "server public key")
	if err != nil {
		return err
	}
	clientPrivate, err := freeBSDWireGuardKey(exec.Command("wg", "genkey"), "client private key")
	if err != nil {
		return err
	}
	clientPublic, err := freeBSDWireGuardPublicKey(clientPrivate, "client public key")
	if err != nil {
		return err
	}
	presharedKey, err := freeBSDWireGuardKey(exec.Command("wg", "genpsk"), "preshared key")
	if err != nil {
		return err
	}

	activeInterface, err := freeBSDDefaultInterface()
	if err != nil {
		return err
	}
	publicOutput, err := exec.Command("curl", "-4", "-sS", "--connect-timeout", "3", "api.ipify.org").Output()
	if err != nil {
		return fmt.Errorf("resolve public IPv4 address: %w", err)
	}
	publicIP := strings.TrimSpace(string(publicOutput))
	if address, parseErr := netip.ParseAddr(publicIP); parseErr != nil || !address.Is4() {
		return fmt.Errorf("public IPv4 address is missing or malformed")
	}
	port, err := strconv.Atoi(config.GlobalConfig.WGPort)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("WireGuard port is outside 1..65535")
	}
	subnet, serverVPNIP, clientVPNIP, err := freeBSDWireGuardAddresses(config.GlobalConfig.WGSubnet)
	if err != nil {
		return err
	}

	postUp := fmt.Sprintf(
		"echo 'nat on %s from %s to any -> (%s)' | pfctl -a syswarden_wg -f -",
		activeInterface,
		subnet,
		activeInterface,
	)
	postDown := "pfctl -a syswarden_wg -F all"
	serverConfig := fmt.Sprintf(`[Interface]
Address = %s/24
ListenPort = %d
PrivateKey = %s
PostUp = %s
PostDown = %s

[Peer]
PublicKey = %s
PresharedKey = %s
AllowedIPs = %s/32
`, serverVPNIP, port, serverPrivate, postUp, postDown, clientPublic, presharedKey, clientVPNIP)
	clientConfig := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/24
MTU = 1360
DNS = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey = %s
PresharedKey = %s
Endpoint = %s:%d
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`, clientPrivate, clientVPNIP, serverPublic, presharedKey, publicIP, port)

	if err := system.PrepareFreeBSDWireGuardOwnership([]byte(serverConfig), []byte(clientConfig)); err != nil {
		return fmt.Errorf("capture WireGuard ownership state: %w", err)
	}
	rollbackRequired := true
	defer func() {
		if rollbackRequired && resultErr != nil {
			if rollbackErr := system.RestoreFreeBSDWireGuard(); rollbackErr != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("rollback WireGuard setup: %w", rollbackErr))
			}
		}
	}()
	if err := ensurePrivateDirectory("/usr/local/etc", "wireguard"); err != nil {
		return fmt.Errorf("prepare WireGuard directory: %w", err)
	}
	if err := ensurePrivateDirectory("/usr/local/etc", "wireguard/clients"); err != nil {
		return fmt.Errorf("prepare WireGuard clients directory: %w", err)
	}
	if err := writeExclusiveFreeBSDWireGuardFile(freeBSDWireGuardRoot, freeBSDWireGuardConfigName, []byte(serverConfig)); err != nil {
		return fmt.Errorf("write server WireGuard configuration: %w", err)
	}
	if err := writeExclusiveFreeBSDWireGuardFile(freeBSDWireGuardClientRoot, freeBSDWireGuardClientName, []byte(clientConfig)); err != nil {
		return fmt.Errorf("write client WireGuard configuration: %w", err)
	}
	if err := system.ActivateFreeBSDWireGuardHostState(); err != nil {
		return fmt.Errorf("activate WireGuard rc and forwarding state: %w", err)
	}
	if output, err := exec.Command("/usr/local/bin/wg-quick", "up", configPath).CombinedOutput(); err != nil {
		return fmt.Errorf("start wg-syswarden: %s: %w", strings.TrimSpace(string(output)), err)
	}
	if active, err := freeBSDWireGuardInterfaceActive(); err != nil || !active {
		return fmt.Errorf("verify wg-syswarden active: %w", err)
	}

	fmt.Println("\n=======================================================")
	fmt.Println("             WIREGUARD CLIENT CONFIGURATION            ")
	fmt.Println("=======================================================")
	fmt.Println("Scan the QR Code below with your WireGuard mobile app:")
	qrCommand := exec.Command("qrencode", "-t", "ansiutf8")
	qrCommand.Stdin = strings.NewReader(clientConfig)
	qrCommand.Stdout = os.Stdout
	if err := qrCommand.Run(); err != nil {
		return fmt.Errorf("render WireGuard client QR code: %w", err)
	}
	fmt.Println("=======================================================")
	fmt.Println("Client config saved at: " + clientPath)
	rollbackRequired = false
	return nil
}
