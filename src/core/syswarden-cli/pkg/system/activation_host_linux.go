//go:build linux

package system

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sort"

	"syswarden-cli/pkg/cronstate"
)

// ActivationHostObservation binds the live service/scheduling and interface
// observations shown in a configuration activation plan. It is not kernel-rule,
// authenticated-access or migration acceptance evidence. Mutation owners must
// still enforce their independent ownership and transaction contracts.
type ActivationHostObservation struct {
	digest  string
	summary []string
	observe func(context.Context) (activationHostState, error)
}

type activationHostService struct {
	Name      string
	Load      string
	Active    string
	Enabled   string
	Runlevels string
}

type activationHostInterface struct {
	Index     int
	Name      string
	Flags     uint
	Hardware  string
	Addresses []string
}

type activationHostState struct {
	PlatformProofSHA256 string
	CronProofSHA256     string
	Schema              string
	Manager             string
	Backend             string
	Services            []activationHostService
	Scheduler           CronDProviderEvidence
	Cron                cronstate.Inspection
	Interfaces          []activationHostInterface
}

func (observation *ActivationHostObservation) Digest() string {
	if observation == nil {
		return ""
	}
	return observation.digest
}

func (observation *ActivationHostObservation) Summary() []string {
	if observation == nil {
		return nil
	}
	return append([]string(nil), observation.summary...)
}

func (observation *ActivationHostObservation) Revalidate(ctx context.Context) error {
	if ctx == nil || observation == nil || observation.observe == nil {
		return errors.New("activation host observation is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	state, err := observation.observe(ctx)
	if err != nil {
		return err
	}
	digest, err := activationHostDigest(state)
	if err != nil {
		return err
	}
	if digest != observation.digest {
		return errors.New("activation host state changed after review; inspect a new plan")
	}
	return ctx.Err()
}

// CaptureActivationHost uses only read-only production observers and fixed
// native manager queries. It performs no dependency install, configuration
// normalization, service change or pending transaction recovery.
func CaptureActivationHost(ctx context.Context, backend string, ha bool) (*ActivationHostObservation, error) {
	return captureActivationHostWith(ctx, func(ctx context.Context) (activationHostState, error) {
		return observeActivationHost(ctx, backend, ha)
	})
}

func captureActivationHostWith(ctx context.Context, observe func(context.Context) (activationHostState, error)) (*ActivationHostObservation, error) {
	if ctx == nil || observe == nil {
		return nil, errors.New("activation host observer is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	state, err := observe(ctx)
	if err != nil {
		return nil, err
	}
	digest, err := activationHostDigest(state)
	if err != nil {
		return nil, err
	}
	summary := []string{fmt.Sprintf("Live service manager: %s; configured firewall backend: %s.", state.Manager, state.Backend)}
	for _, service := range state.Services {
		summary = append(summary, fmt.Sprintf("%s: load=%s, active=%s, enablement=%s.", service.Name, service.Load, service.Active, service.Enabled))
	}
	summary = append(summary, fmt.Sprintf("Verified cron.d provider: %s; owned feed schedule=%t, owned HA schedule=%t, legacy feed entries=%d, legacy HA entries=%d.", state.Scheduler.Manager, state.Cron.OwnedFeed, state.Cron.OwnedHA, state.Cron.LegacyFeedCount, state.Cron.LegacyHACount))
	summary = append(summary, fmt.Sprintf("%d host interfaces captured privately; addresses are not printed.", len(state.Interfaces)))
	observation := &ActivationHostObservation{digest: digest, summary: summary, observe: observe}
	if err := observation.Revalidate(ctx); err != nil {
		return nil, err
	}
	return observation, nil
}

func activationHostDigest(state activationHostState) (string, error) {
	raw, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func observeActivationHost(ctx context.Context, backend string, ha bool) (activationHostState, error) {
	state := activationHostState{Schema: "syswarden-activation-host-observation-v1", Backend: backend}
	if ctx == nil {
		return state, errors.New("activation host context is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return state, err
	}
	var revalidateProvider func() error
	if IsAlpine() {
		if err := requireActivationServiceManager(true, classifyServiceManagerRuntime); err != nil {
			return state, err
		}
		observed, err := observeActivationOpenRC(ctx, backend)
		if err != nil {
			return state, err
		}
		state.Manager = "openrc"
		state.Services = observed.Services
		state.Scheduler = observed.Scheduler
		state.PlatformProofSHA256 = observed.ProofSHA256
		revalidateProvider = func() error {
			confirmed, err := observeActivationOpenRC(ctx, backend)
			if err != nil {
				return err
			}
			if !reflect.DeepEqual(confirmed, observed) {
				return errors.New("OpenRC activation evidence changed before approval")
			}
			return nil
		}
	} else {
		executor := activationSystemdExecutor()
		if err := preflightHostFirewallBackend(backend, executor, func() bool { return false }, classifyServiceManagerRuntime); err != nil {
			return state, err
		}
		if err := requireActivationServiceManager(false, classifyServiceManagerRuntime); err != nil {
			return state, err
		}
		state.Manager = "systemd"
		inspect, err := installationServiceInspector(executor, false)
		if err != nil {
			return state, err
		}
		services, err := inspect()
		if err != nil {
			return state, err
		}
		for _, service := range services {
			state.Services = append(state.Services, activationHostService{Name: service.name, Load: service.load, Active: service.active, Enabled: service.enabled, Runlevels: service.runlevels})
		}
		state.Scheduler, state.PlatformProofSHA256, err = activationSystemdCronProvider()
		if err != nil {
			return state, err
		}
		revalidateProvider = func() error {
			confirmed, proof, err := activationSystemdCronProvider()
			if err != nil {
				return err
			}
			if !reflect.DeepEqual(confirmed, state.Scheduler) || proof != state.PlatformProofSHA256 {
				return errors.New("systemd cron provider changed before approval")
			}
			return nil
		}
	}
	var err error
	state.Cron, state.CronProofSHA256, err = preflightActivationCron(ctx, state.Scheduler, ha, revalidateProvider)
	if err != nil {
		return state, err
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return state, err
	}
	if len(interfaces) > 4096 {
		return state, errors.New("activation interface inventory exceeds its bound")
	}
	for _, current := range interfaces {
		addresses, err := current.Addrs()
		if err != nil {
			return state, err
		}
		if len(addresses) > 4096 {
			return state, errors.New("activation interface address inventory exceeds its bound")
		}
		entry := activationHostInterface{Index: current.Index, Name: current.Name, Flags: uint(current.Flags), Hardware: current.HardwareAddr.String()}
		for _, address := range addresses {
			entry.Addresses = append(entry.Addresses, address.String())
		}
		sort.Strings(entry.Addresses)
		state.Interfaces = append(state.Interfaces, entry)
	}
	sort.Slice(state.Interfaces, func(i, j int) bool { return state.Interfaces[i].Index < state.Interfaces[j].Index })
	return state, ctx.Err()
}

// Read-only systemd queries use fixed distribution tools, never an inherited
// PATH wrapper. OpenRC observation never reaches this executor.
func activationSystemdExecutable(name string) (string, error) {
	switch name {
	case "systemctl":
		return "/usr/bin/systemctl", nil
	case "dpkg-query":
		return "/usr/bin/dpkg-query", nil
	case "rpm":
		return "/usr/bin/rpm", nil
	case "nft":
		return "/usr/sbin/nft", nil
	default:
		return "", errors.New("unsupported executable in read-only activation observation")
	}
}

func activationSystemdExecutor() firewallManagerExecutor {
	return firewallManagerExecutor{lookPath: activationSystemdExecutable, validate: validateResolvedFirewallExecutable, output: runFirewallPreflightCommand}
}

func activationSystemdCronProvider() (CronDProviderEvidence, string, error) {
	host := productionCronDProviderHost()
	host.alpine = false
	host.executor = activationSystemdExecutor()
	return activationSystemdCronProviderWith(host)
}

// Keep the complete verified snapshot in the plan binding. The public provider
// labels deliberately omit package versions, loaded arguments and drop-in
// contents, so labels alone cannot detect a changed activation prerequisite.
func activationSystemdCronProviderWith(host cronDProviderHost) (CronDProviderEvidence, string, error) {
	snapshot, err := host.attestSystemdRuntimeSnapshot()
	if err != nil {
		return CronDProviderEvidence{}, "", err
	}
	wire, err := json.Marshal(struct {
		Schema                                               string
		Mode, Manager, Unit, Daemon, Fragment                string
		PackageEvidence, Active, Enabled, DropIns, ExecStart string
	}{
		"syswarden-activation-systemd-cron-v1",
		snapshot.mode, snapshot.manager, snapshot.unit, snapshot.daemon, snapshot.fragment,
		snapshot.packageEvidence, snapshot.active, snapshot.enabled, snapshot.dropIns, snapshot.execStart,
	})
	if err != nil {
		return CronDProviderEvidence{}, "", err
	}
	digest := sha256.Sum256(wire)
	evidence := CronDProviderEvidence{
		Mode: snapshot.mode, Manager: snapshot.manager, Unit: snapshot.unit,
		Daemon: snapshot.daemon, Fragment: snapshot.fragment, Packages: packageNames(snapshot),
	}
	return evidence, hex.EncodeToString(digest[:]), nil
}

// The runtime classifier reads protected runtime and PID1 evidence only. An
// offline package context is never sufficient for a live activation review.
func requireActivationServiceManager(alpine bool, classify func(bool) (serviceManagerState, error)) error {
	manager, err := classify(alpine)
	if err != nil {
		return err
	}
	if manager != serviceManagerActive {
		return errors.New("activation review requires the live target service manager")
	}
	return nil
}
