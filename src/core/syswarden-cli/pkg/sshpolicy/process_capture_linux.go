//go:build linux

package sshpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"reflect"
	"time"
)

// ProcessSummary binds a stable manager observation to a live executable.
// It is neither durable authorization nor evidence that a daemon has consumed
// a particular configuration. Mutable process command-line strings are not trusted.
type ProcessSummary struct {
	Startup               *StartupSummary `json:"startup,omitempty"`
	Schema                int             `json:"schema"`
	Manager               SystemdSummary  `json:"manager"`
	IdentitySHA256        string          `json:"identity_sha256"`
	ExecutableSHA256      string          `json:"executable_sha256"`
	ProcessObserved       bool            `json:"process_observed"`
	ExecutableVerified    bool            `json:"executable_verified"`
	ConfigurationVerified bool            `json:"configuration_verified"`
	ListenersVerified     bool            `json:"listeners_verified"`
	RuntimeActivated      bool            `json:"runtime_activated"`
	AccessVerified        bool            `json:"access_verified"`
}

type sshProcessLease interface {
	observe() (sshProcessIdentity, error)
	Close() error
}

func observeSSHSystemdProcess(ctx context.Context, snapshot func(context.Context) (sshSystemdSnapshot, error),
	bind func(int, string) (sshProcessLease, error), guard func() error) (summary ProcessSummary, err error) {
	return observeSSHSystemdProcessStartup(ctx, snapshot, bind, guard, nil)
}

func observeSSHSystemdProcessStartup(ctx context.Context, snapshot func(context.Context) (sshSystemdSnapshot, error),
	bind func(int, string) (sshProcessLease, error), guard func() error,
	startup func(context.Context, sshSystemdSnapshot) (StartupSummary, error)) (ProcessSummary, error) {
	held, err := retainSSHSystemdProcess(ctx, snapshot, bind, guard, startup)
	if err != nil {
		return ProcessSummary{}, err
	}
	summary := held.summary
	if err := held.Close(); err != nil {
		return ProcessSummary{}, err
	}
	return summary, nil
}

// The private owner retains the original process lease. Public observations
// still close it before returning and never grant activation authority.
type sshRetainedProcess struct {
	lease   sshProcessLease
	summary ProcessSummary
	manager sshSystemdSnapshot
	process sshProcessIdentity
}

func (held *sshRetainedProcess) Close() error {
	if held == nil || held.lease == nil {
		return nil
	}
	lease := held.lease
	held.lease = nil
	return lease.Close()
}

func retainSSHSystemdProcess(ctx context.Context, snapshot func(context.Context) (sshSystemdSnapshot, error),
	bind func(int, string) (sshProcessLease, error), guard func() error,
	startup func(context.Context, sshSystemdSnapshot) (StartupSummary, error)) (_ *sshRetainedProcess, err error) {
	if ctx == nil || snapshot == nil || bind == nil || guard == nil {
		return nil, ErrInventoryUnsafe
	}
	if err = errors.Join(ctx.Err(), guard()); err != nil {
		return nil, err
	}
	before, err := snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if !before.summary.ManagerObserved || !before.summary.ServiceActive || before.summary.SocketInstanced {
		return nil, fmt.Errorf("SSH process observation requires an active supported service")
	}
	var command *StartupSummary
	if startup != nil {
		observed, startErr := startup(ctx, before)
		if startErr != nil || !observed.DeclarationVerified || !lowerDigest.MatchString(observed.CommandSHA256) {
			return nil, errors.Join(ErrInventoryUnsafe, startErr)
		}
		command = &observed
	}
	u := before.units[before.summary.Service]
	pid, err := sshSystemdUint(u["MainPID"], 32)
	if err != nil || pid <= 1 || pid > 1<<31-1 || !validSSHControlGroup(u["ControlGroup"]) {
		return nil, ErrInventoryUnsafe
	}
	lease, err := bind(int(pid), u["ControlGroup"])
	if err != nil || lease == nil {
		if lease != nil {
			err = errors.Join(err, lease.Close())
		}
		return nil, errors.Join(ErrInventoryUnsafe, err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, lease.Close())
		}
	}()
	first, err := lease.observe()
	if err != nil {
		return nil, err
	}
	if err = errors.Join(ctx.Err(), guard()); err != nil {
		return nil, err
	}
	after, snapshotErr := snapshot(ctx)
	var startupErr error
	if startup != nil && snapshotErr == nil {
		observed, readErr := startup(ctx, after)
		startupErr = readErr
		if command == nil || *command != observed {
			startupErr = errors.Join(startupErr, ErrInventoryChanged)
		}
	}
	second, processErr := lease.observe()
	if err = errors.Join(snapshotErr, startupErr, processErr, ctx.Err(), guard()); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(first, second) || first.PID != int(pid) ||
		first.StartTicks == 0 || !lowerDigest.MatchString(first.ExecutableSHA256) || len(first.Namespaces) != 4 ||
		first.Root.Inode == 0 || first.ControlGroupHash != digestBytes([]byte(u["ControlGroup"])) {
		return nil, ErrInventoryChanged
	}
	for _, name := range []string{"pid", "net", "user", "mnt"} {
		if first.Namespaces[name].Inode == 0 {
			return nil, ErrInventoryUnsafe
		}
	}
	wire, err := json.Marshal(first)
	if err != nil {
		return nil, err
	}
	summary := ProcessSummary{Startup: command, Schema: 1, Manager: before.summary, IdentitySHA256: digestBytes(wire),
		ExecutableSHA256: first.ExecutableSHA256, ProcessObserved: true, ExecutableVerified: true}
	// Retained expectations must not alias a provider's reusable maps.
	before.units = maps.Clone(before.units)
	for name, unit := range before.units {
		before.units[name] = maps.Clone(unit)
	}
	first.Namespaces = maps.Clone(first.Namespaces)
	return &sshRetainedProcess{lease: lease, summary: summary, manager: before, process: first}, nil
}

// ObserveSystemdProcess executes only fixed manager queries and bounded procfs
// reads. No signal, namespace transition, configuration write or login occurs.
// Inactive/socket-only services and unsupported process visibility are refused.
func ObserveSystemdProcess() (ProcessSummary, error) {
	return observeSystemdProcess(nil)
}

func observeSystemdProcess(wrap func(context.Context, *sshProcessBinding) sshProcessLease) (ProcessSummary, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return observeSystemdProcessContext(ctx, wrap)
}

func observeSystemdProcessContext(ctx context.Context, wrap func(context.Context, *sshProcessBinding) sshProcessLease) (summary ProcessSummary, err error) {
	return observeSystemdProcessStartupContext(ctx, wrap, false, nil)
}

func observeSystemdProcessStartupContext(ctx context.Context, wrap func(context.Context, *sshProcessBinding) sshProcessLease, requireStartup bool, configurationGuard func() error) (summary ProcessSummary, err error) {
	defer func() {
		if err != nil {
			summary = ProcessSummary{}
		}
	}()
	if ctx == nil {
		return summary, ErrInventoryUnsafe
	}
	if err := ctx.Err(); err != nil {
		return summary, err
	}
	if os.Geteuid() != 0 {
		return summary, fmt.Errorf("SSH process observation requires root")
	}
	resources, err := openSSHProcessResources(ctx, requireStartup)
	if err != nil {
		return summary, err
	}
	defer func() { err = errors.Join(err, resources.Close()) }()
	guard := func() error {
		if configurationGuard != nil {
			if err := configurationGuard(); err != nil {
				return err
			}
		}
		return resources.recheck()
	}
	snapshot := func(ctx context.Context) (sshSystemdSnapshot, error) {
		return observeSSHSystemdSnapshot(ctx, resources.tool.digest, resources.tool.run, guard)
	}
	bind := func(pid int, group string) (sshProcessLease, error) {
		lease, bindErr := bindSSHProcess(pid, 0, group, resources.daemon.state, resources.daemon.digest)
		if bindErr != nil {
			return nil, bindErr
		}
		if wrap != nil {
			wrapped := wrap(ctx, lease)
			if wrapped == nil {
				return nil, errors.Join(ErrInventoryUnsafe, lease.Close())
			}
			return wrapped, nil
		}
		return lease, nil
	}
	var startup func(context.Context, sshSystemdSnapshot) (StartupSummary, error)
	if requireStartup {
		startup = func(ctx context.Context, snapshot sshSystemdSnapshot) (StartupSummary, error) {
			return resources.startup(ctx, snapshot, guard)
		}
	}
	return observeSSHSystemdProcessStartup(ctx, snapshot, bind, guard, startup)
}
