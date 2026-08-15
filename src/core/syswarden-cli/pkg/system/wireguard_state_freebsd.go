//go:build freebsd

package system

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

const (
	freeBSDWireGuardStateName  = "wireguard-state.json"
	freeBSDWireGuardConfig     = "/usr/local/etc/wireguard/wg-syswarden.conf"
	freeBSDWireGuardClient     = "/usr/local/etc/wireguard/clients/admin-pc.conf"
	freeBSDWireGuardClientRoot = "/usr/local/etc/wireguard/clients"
)

type freeBSDWireGuardState struct {
	SchemaVersion           int            `json:"schema_version"`
	GatewayEnable           freeBSDRCValue `json:"gateway_enable"`
	WireGuardEnable         freeBSDRCValue `json:"wireguard_enable"`
	WireGuardInterfaces     freeBSDRCValue `json:"wireguard_interfaces"`
	Forwarding              int            `json:"forwarding"`
	ConfigSHA256            string         `json:"config_sha256"`
	ClientSHA256            string         `json:"client_sha256"`
	ClientsDirectoryExisted bool           `json:"clients_directory_existed"`
}

func wireGuardPayloadSHA256(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func validSHA256Hex(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func readFreeBSDWireGuardState() (freeBSDWireGuardState, bool, error) {
	var state freeBSDWireGuardState
	found, err := readFreeBSDOwnedState(freeBSDWireGuardStateName, 16<<10, &state)
	if err != nil || !found {
		return state, found, err
	}
	if state.SchemaVersion != 1 || (state.Forwarding != 0 && state.Forwarding != 1) ||
		!validFreeBSDRCValue(state.GatewayEnable.Value) ||
		!validFreeBSDRCValue(state.WireGuardEnable.Value) ||
		!validFreeBSDRCValue(state.WireGuardInterfaces.Value) ||
		!validSHA256Hex(state.ConfigSHA256) || !validSHA256Hex(state.ClientSHA256) {
		return state, false, fmt.Errorf("invalid FreeBSD WireGuard ownership state")
	}
	return state, true, nil
}

func freeBSDForwardingState() (int, error) {
	output, err := exec.Command("sysctl", "-n", "net.inet.ip.forwarding").Output()
	if err != nil {
		return 0, err
	}
	switch strings.TrimSpace(string(output)) {
	case "0":
		return 0, nil
	case "1":
		return 1, nil
	default:
		return 0, fmt.Errorf("unexpected net.inet.ip.forwarding value")
	}
}

func setFreeBSDForwarding(value int) error {
	var command *exec.Cmd
	switch value {
	case 0:
		command = exec.Command("sysctl", "net.inet.ip.forwarding=0")
	case 1:
		command = exec.Command("sysctl", "net.inet.ip.forwarding=1")
	default:
		return fmt.Errorf("invalid forwarding value")
	}
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("restore net.inet.ip.forwarding: %s: %w", strings.TrimSpace(string(output)), err)
	}
	return nil
}

func freeBSDPathExistsWithoutSymlink(path string, directory bool) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("unsafe FreeBSD WireGuard path %s", path)
	}
	if directory != info.IsDir() {
		return false, fmt.Errorf("unexpected FreeBSD WireGuard path type %s", path)
	}
	return true, nil
}

// PrepareFreeBSDWireGuardOwnership captures all host state before SysWarden
// writes either generated configuration file or changes rc/sysctl state.
func PrepareFreeBSDWireGuardOwnership(configPayload, clientPayload []byte) error {
	configSHA := wireGuardPayloadSHA256(configPayload)
	clientSHA := wireGuardPayloadSHA256(clientPayload)
	if state, found, err := readFreeBSDWireGuardState(); err != nil {
		return err
	} else if found {
		if state.ConfigSHA256 != configSHA || state.ClientSHA256 != clientSHA {
			return fmt.Errorf("existing WireGuard ownership state belongs to different generated payloads")
		}
		return nil
	}
	for _, path := range []string{freeBSDWireGuardConfig, freeBSDWireGuardClient} {
		if exists, err := freeBSDPathExistsWithoutSymlink(path, false); err != nil {
			return err
		} else if exists {
			return fmt.Errorf("refusing to replace operator-owned WireGuard file %s", path)
		}
	}
	clientsExisted, err := freeBSDPathExistsWithoutSymlink(freeBSDWireGuardClientRoot, true)
	if err != nil {
		return err
	}
	values, err := freeBSDRCValues()
	if err != nil {
		return err
	}
	forwarding, err := freeBSDForwardingState()
	if err != nil {
		return err
	}
	state := freeBSDWireGuardState{
		SchemaVersion:           1,
		GatewayEnable:           capturedFreeBSDRCValue(values, "gateway_enable"),
		WireGuardEnable:         capturedFreeBSDRCValue(values, "wireguard_enable"),
		WireGuardInterfaces:     capturedFreeBSDRCValue(values, "wireguard_interfaces"),
		Forwarding:              forwarding,
		ConfigSHA256:            configSHA,
		ClientSHA256:            clientSHA,
		ClientsDirectoryExisted: clientsExisted,
	}
	return writeFreeBSDOwnedState(freeBSDWireGuardStateName, state)
}

// ActivateFreeBSDWireGuardHostState applies only the rc/sysctl values owned by
// SysWarden. The original values remain in the state file for exact recovery.
func ActivateFreeBSDWireGuardHostState() error {
	state, found, err := readFreeBSDWireGuardState()
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("FreeBSD WireGuard ownership state is absent")
	}
	interfaces := strings.Fields(state.WireGuardInterfaces.Value)
	managedPresent := false
	for _, name := range interfaces {
		if name == "wg-syswarden" {
			managedPresent = true
		}
	}
	if !managedPresent {
		interfaces = append(interfaces, "wg-syswarden")
	}
	if err := exactFreeBSDRCValue("gateway_enable", "YES"); err != nil {
		return err
	}
	if err := exactFreeBSDRCValue("wireguard_enable", "YES"); err != nil {
		return err
	}
	if err := exactFreeBSDRCValue("wireguard_interfaces", strings.Join(interfaces, " ")); err != nil {
		return err
	}
	return setFreeBSDForwarding(1)
}

func validateFreeBSDManagedFile(path, expectedSHA string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm() != 0600 || info.Size() > 1<<20 {
		return false, fmt.Errorf("unsafe managed FreeBSD file %s", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 {
		return false, fmt.Errorf("managed FreeBSD file is not root-owned: %s", path)
	}
	var directory, name string
	switch path {
	case freeBSDWireGuardConfig:
		directory = "/usr/local/etc/wireguard"
		name = "wg-syswarden.conf"
	case freeBSDWireGuardClient:
		directory = "/usr/local/etc/wireguard/clients"
		name = "admin-pc.conf"
	default:
		return false, fmt.Errorf("unsupported managed FreeBSD file path")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return false, err
	}
	defer func() { _ = root.Close() }()
	payload, err := root.ReadFile(name)
	if err != nil || wireGuardPayloadSHA256(payload) != expectedSHA {
		return false, fmt.Errorf("managed FreeBSD file changed after creation: %s", path)
	}
	return true, nil
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

// RestoreFreeBSDWireGuard removes only byte-identical SysWarden-owned files
// and restores rc/sysctl values captured before the first mutation.
func RestoreFreeBSDWireGuard() error {
	state, found, err := readFreeBSDWireGuardState()
	if err != nil || !found {
		return err
	}
	configExists, err := validateFreeBSDManagedFile(freeBSDWireGuardConfig, state.ConfigSHA256)
	if err != nil {
		return err
	}
	clientExists, err := validateFreeBSDManagedFile(freeBSDWireGuardClient, state.ClientSHA256)
	if err != nil {
		return err
	}
	active, err := freeBSDWireGuardInterfaceActive()
	if err != nil {
		return err
	}
	if active {
		if !configExists {
			return fmt.Errorf("wg-syswarden is active but its owned configuration is absent")
		}
		if output, err := exec.Command("/usr/local/bin/wg-quick", "down", freeBSDWireGuardConfig).CombinedOutput(); err != nil {
			return fmt.Errorf("stop owned WireGuard interface: %s: %w", strings.TrimSpace(string(output)), err)
		}
		if active, err := freeBSDWireGuardInterfaceActive(); err != nil || active {
			return fmt.Errorf("verify owned WireGuard interface stopped: %w", err)
		}
	}
	if configExists {
		if err := os.Remove(freeBSDWireGuardConfig); err != nil {
			return err
		}
	}
	if clientExists {
		if err := os.Remove(freeBSDWireGuardClient); err != nil {
			return err
		}
	}
	if !state.ClientsDirectoryExisted {
		if err := os.Remove(freeBSDWireGuardClientRoot); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove owned empty WireGuard client directory: %w", err)
		}
	}
	for name, value := range map[string]freeBSDRCValue{
		"gateway_enable":       state.GatewayEnable,
		"wireguard_enable":     state.WireGuardEnable,
		"wireguard_interfaces": state.WireGuardInterfaces,
	} {
		if err := setFreeBSDRCValue(name, value); err != nil {
			return err
		}
	}
	if err := setFreeBSDForwarding(state.Forwarding); err != nil {
		return err
	}
	return removeFreeBSDOwnedState(freeBSDWireGuardStateName)
}
