//go:build linux

package sshpolicy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"time"
)

// PortSummary describes the protected configuration graph parsed with fixed
// options. Service arguments and socket activation may select other listeners.
// No field grants hardening consent, firewall authority or successful access.
type PortSummary struct {
	Schema           int      `json:"schema"`
	ConfiguredPorts  []uint16 `json:"configured_ports"`
	ListenPorts      []uint16 `json:"listen_ports"`
	ParserSHA256     string   `json:"parser_sha256"`
	ParserVerified   bool     `json:"parser_verified"`
	RuntimeVerified  bool     `json:"runtime_verified"`
	HardeningApplied bool     `json:"hardening_applied"`
}

// InspectPorts reads the standard SSH graph independently of migration intent
// and general SysWarden configuration. It never creates policy, state, locks or
// directories, changes GlobalConfig, contacts a service manager or opens SSH.
func InspectPorts() (PortSummary, error) {
	if os.Geteuid() != 0 {
		return PortSummary{}, fmt.Errorf("SSH port inspection requires root")
	}
	root, err := os.Open("/")
	if err != nil {
		return PortSummary{}, err
	}
	defer root.Close()
	inventory, err := openInventory(root, 0)
	if err != nil {
		return PortSummary{}, err
	}
	defer inventory.Close()
	daemon, err := openSSHD(root, 0)
	if err != nil {
		return PortSummary{}, err
	}
	defer daemon.file.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	return inspectPorts(ctx, inventory.snapshot, daemon.digest, daemon.run, func() error {
		return errors.Join(inventory.Recheck(), daemon.recheck(root, 0))
	})
}

func inspectPorts(ctx context.Context, snapshot inventorySnapshot, digest string, run sshParserRun, recheck func() error) (PortSummary, error) {
	values, err := inspectSSHEffective(ctx, snapshot, digest, run, recheck)
	if err != nil {
		return PortSummary{}, err
	}
	configured, listeners, err := effectivePorts(values)
	if err != nil {
		return PortSummary{}, err
	}
	return PortSummary{Schema: 1, ConfiguredPorts: configured, ListenPorts: listeners,
		ParserSHA256: digest, ParserVerified: true}, nil
}

func inspectSSHEffective(ctx context.Context, snapshot inventorySnapshot, digest string, run sshParserRun, recheck func() error) (values sshEffective, err error) {
	if ctx == nil || run == nil || recheck == nil || !lowerDigest.MatchString(digest) {
		return nil, ErrInventoryUnsafe
	}
	image, err := newParserImage(snapshot.files)
	if err != nil {
		return nil, err
	}
	defer func() {
		err = errors.Join(err, image.Close())
		if err != nil {
			values = nil
		}
	}()
	invoke := func(image *parserImage, mode string) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := recheck(); err != nil {
			return nil, err
		}
		output, runErr := run(ctx, image, mode, "")
		if err := errors.Join(ctx.Err(), recheck()); err != nil {
			return nil, errors.Join(ErrInventoryChanged, err)
		}
		return output, runErr
	}
	var effective []sshEffective
	for _, graph := range []*parserImage{nil, image} {
		if _, err := invoke(graph, "syntax"); err != nil {
			return nil, fmt.Errorf("SSH port inspection syntax verification failed: %w", err)
		}
		output, err := invoke(graph, "effective")
		if err != nil {
			return nil, fmt.Errorf("SSH port inspection parser failed: %w", err)
		}
		values, err := parseEffective(output)
		if err != nil {
			return nil, err
		}
		effective = append(effective, values)
	}
	if err := compareEffective(effective[0], effective[1], nil); err != nil {
		return nil, fmt.Errorf("SSH port inspection sealed baseline differs: %w", err)
	}
	if err := errors.Join(ctx.Err(), recheck()); err != nil {
		return nil, err
	}
	return effective[0], nil
}

// OpenSSH can expand one Port to IPv4 and IPv6 listeners, or use an explicit
// ListenAddress port instead. Never infer 22 or conflate these two sets.
func effectivePorts(values sshEffective) ([]uint16, []uint16, error) {
	declared, listeners := values["port"], values["listenaddress"]
	if len(declared) == 0 || len(declared) > 256 || len(listeners) == 0 || len(listeners) > 512 {
		return nil, nil, fmt.Errorf("SSH port observation is missing or exceeds bounds")
	}
	var ports, listenPorts []uint16
	for _, value := range declared {
		port, err := canonicalSSHPort(value)
		if err != nil {
			return nil, nil, err
		}
		ports = append(ports, port)
	}
	for _, value := range listeners {
		host, portText, err := net.SplitHostPort(value)
		if err != nil {
			return nil, nil, fmt.Errorf("unsupported SSH listenaddress observation")
		}
		if _, err := netip.ParseAddr(host); err != nil {
			return nil, nil, fmt.Errorf("SSH listenaddress is not a numeric address")
		}
		port, err := canonicalSSHPort(portText)
		if err != nil {
			return nil, nil, err
		}
		listenPorts = append(listenPorts, port)
	}
	slices.Sort(ports)
	slices.Sort(listenPorts)
	return slices.Compact(ports), slices.Compact(listenPorts), nil
}

func canonicalSSHPort(value string) (uint16, error) {
	port, err := strconv.ParseUint(value, 10, 16)
	if err != nil || port == 0 || strconv.FormatUint(port, 10) != value {
		return 0, fmt.Errorf("SSH parser returned a noncanonical port")
	}
	return uint16(port), nil
}
