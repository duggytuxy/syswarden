//go:build linux

package system

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"syscall"

	"syswarden-cli/pkg/wireguardstate"
)

const maximumFirewallRemovalUnitSize = 64 << 10

const systemdWireGuardQuickService = `[Unit]
Description=WireGuard via wg-quick(8) for %I
After=network-online.target nss-lookup.target
Wants=network-online.target nss-lookup.target
PartOf=wg-quick.target
Documentation=man:wg-quick(8)
Documentation=man:wg(8)
Documentation=https://www.wireguard.com/
Documentation=https://www.wireguard.com/quickstart/
Documentation=https://git.zx2c4.com/wireguard-tools/about/src/man/wg-quick.8

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/wg-quick up %i
ExecStop=/usr/bin/wg-quick down %i
Environment=WG_ENDPOINT_RESOLUTION_RETRIES=infinity

[Install]
WantedBy=multi-user.target
`

type firewallRemovalWireGuardEvidence struct {
	present              bool
	transactionPending   bool
	transactionOperation wireguardstate.TransactionOperation
	inventory            wireguardstate.Inventory
	manifest             wireguardstate.Manifest
}

func attestFirewallRemovalWireGuardStateOperationAwareWith(
	inspectTransaction func() (wireguardstate.TransactionOperation, bool, error),
	inspect func() (wireguardstate.Inventory, error),
	verify func() (wireguardstate.Manifest, error),
) (firewallRemovalWireGuardEvidence, error) {
	if inspectTransaction == nil || inspect == nil || verify == nil {
		return firewallRemovalWireGuardEvidence{}, fmt.Errorf("WireGuard state attestation dependencies are incomplete")
	}
	operation, transactionPending, err := inspectTransaction()
	if err != nil {
		return firewallRemovalWireGuardEvidence{}, fmt.Errorf("inspect bounded WireGuard transaction: %w", err)
	}
	if !transactionPending {
		return attestFirewallRemovalWireGuardStateWith(inspect, verify)
	}
	switch operation {
	case wireguardstate.TransactionOperationRemovePendingReload:
	case wireguardstate.TransactionOperationRemove:
		return firewallRemovalWireGuardEvidence{}, fmt.Errorf(
			"refusing unproven WireGuard removal transaction without durable nftables-cleanup evidence",
		)
	case wireguardstate.TransactionOperationPublish:
		return firewallRemovalWireGuardEvidence{}, fmt.Errorf(
			"refusing WireGuard removal while a publication transaction is pending",
		)
	default:
		return firewallRemovalWireGuardEvidence{}, fmt.Errorf(
			"refusing unknown WireGuard transaction operation %q", operation,
		)
	}
	inventory, err := inspect()
	if err != nil {
		return firewallRemovalWireGuardEvidence{}, fmt.Errorf("inspect bounded WireGuard removal debt: %w", err)
	}
	if !inventory.Transaction {
		return firewallRemovalWireGuardEvidence{}, fmt.Errorf(
			"WireGuard removal journal disappeared during state attestation",
		)
	}
	confirmedOperation, confirmedPending, err := inspectTransaction()
	if err != nil {
		return firewallRemovalWireGuardEvidence{}, fmt.Errorf("reinspect bounded WireGuard transaction: %w", err)
	}
	confirmedInventory, err := inspect()
	if err != nil {
		return firewallRemovalWireGuardEvidence{}, fmt.Errorf("reinspect bounded WireGuard removal debt: %w", err)
	}
	if !confirmedPending || confirmedOperation != operation || !reflect.DeepEqual(inventory, confirmedInventory) {
		return firewallRemovalWireGuardEvidence{}, fmt.Errorf(
			"WireGuard removal transaction changed during state attestation",
		)
	}
	return firewallRemovalWireGuardEvidence{
		transactionPending:   true,
		transactionOperation: operation,
		inventory:            inventory,
	}, nil
}

func attestFirewallRemovalWireGuardStateWith(
	inspect func() (wireguardstate.Inventory, error),
	verify func() (wireguardstate.Manifest, error),
) (firewallRemovalWireGuardEvidence, error) {
	if inspect == nil || verify == nil {
		return firewallRemovalWireGuardEvidence{}, fmt.Errorf("WireGuard state attestation dependencies are incomplete")
	}
	inventory, err := inspect()
	if err != nil {
		return firewallRemovalWireGuardEvidence{}, fmt.Errorf("inspect bounded WireGuard state: %w", err)
	}
	if inventory.Transaction {
		return firewallRemovalWireGuardEvidence{}, fmt.Errorf(
			"refusing WireGuard removal while a recoverable transaction is pending",
		)
	}
	if inventory.Empty() {
		return firewallRemovalWireGuardEvidence{}, nil
	}
	manifest, err := verify()
	if err != nil {
		return firewallRemovalWireGuardEvidence{}, fmt.Errorf("verify bounded WireGuard state: %w", err)
	}
	confirmed, err := inspect()
	if err != nil {
		return firewallRemovalWireGuardEvidence{}, fmt.Errorf("reinspect bounded WireGuard state: %w", err)
	}
	if !reflect.DeepEqual(inventory, confirmed) {
		return firewallRemovalWireGuardEvidence{}, fmt.Errorf("WireGuard state inventory changed during attestation")
	}
	return firewallRemovalWireGuardEvidence{
		present: true, inventory: inventory, manifest: manifest,
	}, nil
}

func attestFirewallRemovalWireGuardState() (firewallRemovalWireGuardEvidence, error) {
	return attestFirewallRemovalWireGuardStateOperationAwareWith(
		func() (wireguardstate.TransactionOperation, bool, error) {
			return wireguardstate.InspectTransaction("/", 0, 0)
		},
		func() (wireguardstate.Inventory, error) { return wireguardstate.Inspect("/") },
		func() (wireguardstate.Manifest, error) { return wireguardstate.ReadAndVerify("/", 0, 0) },
	)
}

var readWireGuardServerBeforeRemovalStop = func() ([]byte, error) {
	manifest, err := wireguardstate.ReadAndVerify("/", 0, 0)
	if err != nil {
		return nil, fmt.Errorf("reattest WireGuard ownership manifest: %w", err)
	}
	server, err := wireguardstate.ReadVerifiedArtifact(
		"/", manifest, wireguardstate.ServerConfigurationPath, 0, 0,
	)
	if err != nil {
		return nil, fmt.Errorf("reattest WireGuard server artifact: %w", err)
	}
	return server, nil
}

var attestWireGuardStopHookExecutables = wireguardstate.AttestServerHookExecutables

func verifyWireGuardServerBeforeRemovalStop() error {
	server, err := readWireGuardServerBeforeRemovalStop()
	if err != nil {
		return err
	}
	identity, err := wireguardstate.ParseServerConfiguration(server)
	if err != nil {
		return fmt.Errorf("verify WireGuard server grammar: %w", err)
	}
	if err := attestWireGuardStopHookExecutables(identity); err != nil {
		return fmt.Errorf("reattest WireGuard server hook executables immediately before stop: %w", err)
	}
	return nil
}

func sameFirewallRemovalWireGuardEvidence(left, right firewallRemovalWireGuardEvidence) bool {
	return left.present == right.present && left.transactionPending == right.transactionPending &&
		left.transactionOperation == right.transactionOperation && reflect.DeepEqual(left.inventory, right.inventory) &&
		reflect.DeepEqual(left.manifest, right.manifest)
}

func inspectWireGuardRemovalInterface() (bool, error) {
	_, err := os.Lstat("/sys/class/net/wg-syswarden")
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect wg-syswarden interface: %w", err)
	}
	return true, nil
}

func resolveWireGuardRemovalExecutable() (string, error) {
	resolved, err := filepath.EvalSymlinks("/usr/bin/wg-quick")
	if err != nil {
		return "", fmt.Errorf("resolve /usr/bin/wg-quick: %w", err)
	}
	resolved = filepath.Clean(resolved)
	if !filepath.IsAbs(resolved) {
		return "", fmt.Errorf("resolved wg-quick executable is not absolute")
	}
	if err := validateResolvedFirewallExecutable(resolved); err != nil {
		return "", err
	}
	return resolved, nil
}

func attestRootOwnedFirewallRemovalFile(path string, executable bool) (os.FileInfo, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("firewall removal file path %q is not clean and absolute", path)
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Mode().Perm()&0022 != 0 ||
		stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 || before.Size() < 0 || before.Size() > maximumFirewallRemovalUnitSize {
		return nil, fmt.Errorf("refusing unsafe firewall removal file %s", path)
	}
	if executable && before.Mode().Perm()&0111 == 0 {
		return nil, fmt.Errorf("firewall removal service file %s is not executable", path)
	}
	return before, nil
}

func readExactFirewallRemovalFile(path string, expected string, mode os.FileMode) error {
	before, err := attestRootOwnedFirewallRemovalFile(path, mode&0111 != 0)
	if err != nil {
		return err
	}
	if before.Mode().Perm() != mode {
		return fmt.Errorf("firewall removal service file %s has mode %04o, want %04o", path, before.Mode().Perm(), mode)
	}
	file, err := os.Open(path) // #nosec G304 -- fixed product service paths are lstat/fstat identity attested
	if err != nil {
		return err
	}
	opened, statErr := file.Stat()
	content, readErr := io.ReadAll(io.LimitReader(file, maximumFirewallRemovalUnitSize+1))
	closeErr := file.Close()
	if statErr != nil || readErr != nil || closeErr != nil || !os.SameFile(before, opened) || len(content) > maximumFirewallRemovalUnitSize {
		return fmt.Errorf("firewall removal service file %s changed while reading", path)
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(opened, after) || opened.Mode() != after.Mode() {
		return fmt.Errorf("firewall removal service file %s changed during attestation", path)
	}
	if string(content) != expected {
		return fmt.Errorf("refusing modified firewall removal service file %s", path)
	}
	return nil
}

func removeExactFirewallRemovalFile(path string, expected string, mode os.FileMode) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect firewall removal service file %s: %w", path, err)
	}
	if err := readExactFirewallRemovalFile(path, expected, mode); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove exact firewall removal service file %s: %w", path, err)
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("verify firewall removal service file absence %s: %w", path, err)
	}
	return fmt.Errorf("firewall removal service file %s remains after removal", path)
}

func attestSystemdFirewallRemovalUnitFile(path string) error {
	switch path {
	case "/etc/systemd/system/syswarden-core.service":
		return readExactFirewallRemovalFile(path, systemdCoreService, 0600)
	case "/etc/systemd/system/syswarden-firewall.service":
		return readExactFirewallRemovalFile(path, systemdFirewallService, 0600)
	case "/usr/lib/systemd/system/wg-quick@.service", "/lib/systemd/system/wg-quick@.service":
		return readExactFirewallRemovalFile(path, systemdWireGuardQuickService, 0644)
	default:
		return fmt.Errorf("refusing unexpected systemd firewall removal unit file %s", path)
	}
}

func attestOpenRCFirewallRemovalUnit(service firewallRemovalService) error {
	switch service.name {
	case "syswarden-core":
		return readExactFirewallRemovalFile("/etc/init.d/syswarden-core", openRCCoreService, 0755)
	case "syswarden-firewall":
		return readExactFirewallRemovalFile("/etc/init.d/syswarden-firewall", openRCFirewallService, 0755)
	case "wg-quick@wg-syswarden":
		return attestOpenRCWireGuardDefinitionWith(productionOpenRCWireGuardDefinitionPaths())
	default:
		return fmt.Errorf("refusing ambiguous OpenRC firewall mutator %s", service.name)
	}
}

func inspectOpenRCFirewallRemovalUnitPresence(service firewallRemovalService) (bool, error) {
	path := ""
	switch service.name {
	case "syswarden-core", "syswarden-firewall", "syswarden", "syswarden-reporter":
		path = "/etc/init.d/" + service.name
	case "wg-quick@wg-syswarden":
		path = "/etc/init.d/wg-quick.wg-syswarden"
	default:
		return false, fmt.Errorf("refusing unknown OpenRC firewall removal unit %s", service.name)
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("inspect OpenRC firewall removal unit %s: %w", path, err)
	}
	return true, nil
}

func attestOpenRCRemovalRunlevelDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 ||
		stat.Uid != 0 || stat.Gid != 0 {
		return fmt.Errorf("refusing unsafe OpenRC runlevel directory %s", path)
	}
	return nil
}

func attestOpenRCFirewallRemovalRunlevelLink(service firewallRemovalService, runlevel string) error {
	if !validOpenRCRunlevelForRemoval(runlevel) {
		return fmt.Errorf("refusing invalid OpenRC runlevel %q", runlevel)
	}
	if err := attestOpenRCRemovalRunlevelDirectory("/etc/runlevels"); err != nil {
		return err
	}
	parent := filepath.Join("/etc/runlevels", runlevel)
	if err := attestOpenRCRemovalRunlevelDirectory(parent); err != nil {
		return err
	}
	name := openRCFirewallRemovalServiceName(service)
	path := filepath.Join(parent, name)
	before, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || before.Mode()&os.ModeSymlink == 0 || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 {
		return fmt.Errorf("refusing unsafe OpenRC runlevel link %s", path)
	}
	target, err := os.Readlink(path)
	expectedAbsolute := filepath.Join("/etc/init.d", name)
	expectedRelative := filepath.Join("..", "..", "init.d", name)
	if err != nil || target != expectedAbsolute && target != expectedRelative {
		return fmt.Errorf("refusing unexpected OpenRC runlevel target %q for %s", target, path)
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
		return fmt.Errorf("OpenRC runlevel link %s changed during attestation", path)
	}
	return nil
}

func verifyOpenRCFirewallRemovalRunlevelLinkAbsent(service firewallRemovalService, runlevel string) error {
	name := openRCFirewallRemovalServiceName(service)
	path := filepath.Join("/etc/runlevels", runlevel, name)
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("verify OpenRC runlevel link absence %s: %w", path, err)
	}
	return fmt.Errorf("OpenRC runlevel link %s remains after disable", path)
}
