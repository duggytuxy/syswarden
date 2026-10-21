//go:build linux

package sshpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"
)

// EndpointSummary compares the current protected standard graph with live
// sockets. Agreement does not prove that SSH consumed that graph or policy.
type EndpointSummary struct {
	Schema                     int             `json:"schema"`
	Listeners                  ListenerSummary `json:"listeners"`
	ParserSHA256               string          `json:"parser_sha256"`
	ConfigurationFilesSHA256   string          `json:"configuration_files_sha256"`
	ExpectedEndpointsSHA256    string          `json:"expected_endpoints_sha256"`
	ConfiguredEndpointsMatched bool            `json:"configured_endpoints_matched"`
	ConfigurationVerified      bool            `json:"configuration_verified"`
	RuntimeActivated           bool            `json:"runtime_activated"`
	AccessVerified             bool            `json:"access_verified"`
}

type sshEndpointObserver func(context.Context, []netip.AddrPort, func() error) (ListenerSummary, error)

func observeSSHEndpoints(ctx context.Context, snapshot inventorySnapshot, digest string, run sshParserRun,
	guard func() error, observe sshEndpointObserver) (EndpointSummary, error) {
	if ctx == nil || guard == nil || observe == nil {
		return EndpointSummary{}, ErrInventoryUnsafe
	}
	values, err := inspectSSHEffective(ctx, snapshot, digest, run, guard)
	if err != nil {
		return EndpointSummary{}, err
	}
	expected, err := sshExpectedEndpoints(values)
	if err != nil {
		return EndpointSummary{}, err
	}
	if err := errors.Join(ctx.Err(), guard()); err != nil {
		return EndpointSummary{}, err
	}
	listeners, observeErr := observe(ctx, expected, guard)
	if err := errors.Join(observeErr, ctx.Err(), guard()); err != nil {
		return EndpointSummary{}, err
	}
	if !listeners.TCPListenersObserved || listeners.ListenerCount != len(expected) || !lowerDigest.MatchString(listeners.SocketsSHA256) ||
		!listeners.Process.ProcessObserved || !listeners.Process.ExecutableVerified || listeners.Process.ExecutableSHA256 != digest {
		return EndpointSummary{}, ErrInventoryChanged
	}
	configuration, err := json.Marshal(snapshot.files)
	if err != nil {
		return EndpointSummary{}, err
	}
	endpointHash, err := sshEndpointDigest(expected)
	if err != nil {
		return EndpointSummary{}, err
	}
	return EndpointSummary{Schema: 1, Listeners: listeners, ParserSHA256: digest,
		ConfigurationFilesSHA256: digestBytes(configuration), ExpectedEndpointsSHA256: endpointHash, ConfiguredEndpointsMatched: true}, nil
}

func observeSSHConfiguredListeners(ctx context.Context, expected []netip.AddrPort, guard func() error) (ListenerSummary, error) {
	if ctx == nil || guard == nil {
		return ListenerSummary{}, ErrInventoryUnsafe
	}
	capture := &sshListenerCapture{}
	process, err := observeSystemdProcessStartupContext(ctx, func(ctx context.Context, process *sshProcessBinding) sshProcessLease {
		return configuredSSHListenerLease(ctx, process, expected, guard, capture)
	}, true, guard)
	if err != nil {
		return ListenerSummary{}, err
	}
	return summarizeSSHListeners(process, capture)
}

func configuredSSHListenerLease(ctx context.Context, process *sshProcessBinding, expected []netip.AddrPort, guard func() error, capture *sshListenerCapture) *sshListenerProcessLease {
	read := func(ctx context.Context) ([]sshListenerSocket, error) {
		if err := errors.Join(ctx.Err(), guard()); err != nil {
			return nil, err
		}
		namespace, err := sshNamespaceCookie(process.namespaces["net"])
		if err != nil {
			return nil, err
		}
		sockets, err := process.listeners(ctx)
		if err != nil {
			return nil, err
		}
		if err := errors.Join(matchSSHEndpoints(expected, sockets, namespace), ctx.Err(), guard()); err != nil {
			return nil, err
		}
		return sockets, nil
	}
	return &sshListenerProcessLease{sshProcessLease: process, ctx: ctx, read: read, capture: capture}
}

// ObserveSystemdEndpoints uses only fixed protected configuration and installed
// parser paths. It never publishes configuration, activates SSH or sends traffic.
// Static service arguments are checked against the observed invocation.
// Dynamic arguments and active socket-unit policy require separate qualification.
func ObserveSystemdEndpoints() (summary EndpointSummary, err error) {
	defer func() {
		if err != nil {
			summary = EndpointSummary{}
		}
	}()
	if os.Geteuid() != 0 {
		return summary, fmt.Errorf("SSH endpoint observation requires root")
	}
	root, err := os.Open("/")
	if err != nil {
		return summary, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	inventory, err := openInventory(root, 0)
	if err != nil {
		return summary, err
	}
	defer func() { err = errors.Join(err, inventory.Close()) }()
	daemon, err := openSSHD(root, 0)
	if err != nil {
		return summary, err
	}
	defer func() { err = errors.Join(err, daemon.file.Close()) }()
	guard := func() error { return errors.Join(inventory.Recheck(), daemon.recheck(root, 0)) }
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return observeSSHEndpoints(ctx, inventory.snapshot, daemon.digest, daemon.run, guard, observeSSHConfiguredListeners)
}
