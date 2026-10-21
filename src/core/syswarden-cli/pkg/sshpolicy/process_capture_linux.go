//go:build linux

package sshpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"time"
)

// ProcessSummary binds a stable manager observation to a live executable.
// It is neither durable authorization nor evidence that a daemon has consumed
// a particular configuration. Command-line strings are deliberately not trusted.
type ProcessSummary struct {
	Schema                int            `json:"schema"`
	Manager               SystemdSummary `json:"manager"`
	IdentitySHA256        string         `json:"identity_sha256"`
	ExecutableSHA256      string         `json:"executable_sha256"`
	ProcessObserved       bool           `json:"process_observed"`
	ExecutableVerified    bool           `json:"executable_verified"`
	ConfigurationVerified bool           `json:"configuration_verified"`
	ListenersVerified     bool           `json:"listeners_verified"`
	RuntimeActivated      bool           `json:"runtime_activated"`
	AccessVerified        bool           `json:"access_verified"`
}

type sshProcessLease interface {
	observe() (sshProcessIdentity, error)
	Close() error
}

func observeSSHSystemdProcess(ctx context.Context, snapshot func(context.Context) (sshSystemdSnapshot, error),
	bind func(int, string) (sshProcessLease, error), guard func() error) (summary ProcessSummary, err error) {
	defer func() {
		if err != nil {
			summary = ProcessSummary{}
		}
	}()
	if ctx == nil || snapshot == nil || bind == nil || guard == nil {
		return summary, ErrInventoryUnsafe
	}
	if err = errors.Join(ctx.Err(), guard()); err != nil {
		return summary, err
	}
	before, err := snapshot(ctx)
	if err != nil {
		return summary, err
	}
	if !before.summary.ManagerObserved || !before.summary.ServiceActive || before.summary.SocketInstanced {
		return summary, fmt.Errorf("SSH process observation requires an active supported service")
	}
	u := before.units[before.summary.Service]
	pid, err := sshSystemdUint(u["MainPID"], 32)
	if err != nil || pid <= 1 || pid > 1<<31-1 || !validSSHControlGroup(u["ControlGroup"]) {
		return summary, ErrInventoryUnsafe
	}
	lease, err := bind(int(pid), u["ControlGroup"])
	if err != nil || lease == nil {
		if lease != nil {
			err = errors.Join(err, lease.Close())
		}
		return summary, errors.Join(ErrInventoryUnsafe, err)
	}
	defer func() { err = errors.Join(err, lease.Close()) }()
	first, err := lease.observe()
	if err != nil {
		return summary, err
	}
	if err = errors.Join(ctx.Err(), guard()); err != nil {
		return summary, err
	}
	after, snapshotErr := snapshot(ctx)
	second, processErr := lease.observe()
	if err = errors.Join(snapshotErr, processErr, ctx.Err(), guard()); err != nil {
		return summary, err
	}
	if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(first, second) || first.PID != int(pid) ||
		first.StartTicks == 0 || !lowerDigest.MatchString(first.ExecutableSHA256) || len(first.Namespaces) != 4 ||
		first.Root.Inode == 0 || first.ControlGroupHash != digestBytes([]byte(u["ControlGroup"])) {
		return summary, ErrInventoryChanged
	}
	for _, name := range []string{"pid", "net", "user", "mnt"} {
		if first.Namespaces[name].Inode == 0 {
			return summary, ErrInventoryUnsafe
		}
	}
	wire, err := json.Marshal(first)
	if err != nil {
		return summary, err
	}
	return ProcessSummary{Schema: 1, Manager: before.summary, IdentitySHA256: digestBytes(wire),
		ExecutableSHA256: first.ExecutableSHA256, ProcessObserved: true, ExecutableVerified: true}, nil
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
	root, err := os.Open("/")
	if err != nil {
		return summary, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	tool, err := openSSHSystemctl(root, 0)
	if err != nil {
		return summary, err
	}
	defer func() { err = errors.Join(err, tool.file.Close()) }()
	daemon, err := openSSHD(root, 0)
	if err != nil {
		return summary, err
	}
	defer func() { err = errors.Join(err, daemon.file.Close()) }()
	endpoint, err := readSSHSystemdEndpoint(root, 0)
	if err != nil {
		return summary, err
	}
	guard := func() error {
		current, endpointErr := readSSHSystemdEndpoint(root, 0)
		if endpointErr != nil || !reflect.DeepEqual(endpoint, current) {
			return errors.Join(ErrInventoryChanged, endpointErr)
		}
		return errors.Join(tool.recheck(root, 0), daemon.recheck(root, 0))
	}
	snapshot := func(ctx context.Context) (sshSystemdSnapshot, error) {
		return observeSSHSystemdSnapshot(ctx, tool.digest, tool.run, guard)
	}
	bind := func(pid int, group string) (sshProcessLease, error) {
		lease, bindErr := bindSSHProcess(pid, 0, group, daemon.state, daemon.digest)
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
	return observeSSHSystemdProcess(ctx, snapshot, bind, guard)
}
