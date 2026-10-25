//go:build linux

package sshpolicy

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// This private adapter serves explicit original restoration, but no forward
// activation CLI or installer caller. Every dispatcher must durably record
// intent before request. A successful send never acknowledges
// consumed policy, independent access or a completed migration.
func bindSSHSystemdActivation(parent context.Context, policyGuard func() error) (_ sshActivationLease, err error) {
	if parent == nil || policyGuard == nil {
		return nil, ErrInventoryUnsafe
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	var resources *sshProcessResources
	var held *sshRetainedProcess
	var execution *sshExecReload
	cleanup := func() error {
		cancel()
		return errors.Join(execution.Close(), held.Close(), resources.Close())
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, cleanup())
		}
	}()
	if err := errors.Join(ctx.Err(), policyGuard()); err != nil {
		return nil, err
	}
	resources, err = openSSHProcessResources(ctx, true)
	if err != nil {
		return nil, err
	}
	// Do not retain the pre-intent policy guard in the target. After the
	// durable intent exists, request receives its distinct post-intent guard.
	guard := func() error { return errors.Join(ctx.Err(), resources.recheck(), policyGuard()) }
	snapshot := func(ctx context.Context) (sshSystemdSnapshot, error) {
		return observeSSHSystemdSnapshot(ctx, resources.tool.digest, resources.tool.run, resources.recheck)
	}
	startup := func(ctx context.Context, state sshSystemdSnapshot) (StartupSummary, error) {
		return resources.startup(ctx, state, resources.recheck)
	}
	held, err = retainSSHSystemdProcess(ctx, snapshot,
		func(pid int, group string) (sshProcessLease, error) {
			return bindSSHProcessForActivation(pid, 0, group, resources.daemon.state, resources.daemon.digest)
		}, guard, startup)
	if err != nil {
		return nil, err
	}
	process, ok := held.lease.(*sshProcessBinding)
	if !ok || process == nil || held.summary.Startup == nil || !held.summary.Startup.DeclarationVerified {
		return nil, ErrInventoryUnsafe
	}
	check := func(ctx context.Context) error {
		return held.recheck(ctx, snapshot, resources.recheck, startup)
	}
	// Expectations come from the protected current graph and pinned parser.
	// They are not supplied by the caller or inferred from current listeners.
	inventory, err := collectInventory(resources.root, 0)
	if err != nil {
		return nil, err
	}
	values, err := inspectSSHEffective(ctx, inventory, resources.daemon.digest, resources.daemon.run, guard)
	if err != nil {
		return nil, err
	}
	configuration, err := bindSSHConfigurationSelection(ctx, *held.summary.Startup, resources.daemon.digest,
		values, resources.daemon.runDefaultConfiguration, guard)
	if err != nil {
		return nil, err
	}
	expected, err := sshExpectedEndpoints(values)
	if err != nil {
		return nil, err
	}
	namespace, err := sshNamespaceCookie(process.namespaces["net"])
	if err != nil {
		return nil, err
	}
	read := func(ctx context.Context) ([]sshListenerSocket, error) {
		if err := check(ctx); err != nil {
			return nil, err
		}
		sockets, err := process.listenerState(ctx, true)
		if err := errors.Join(err, check(ctx)); err != nil {
			return nil, err
		}
		return sockets, nil
	}
	listeners, err := prepareSSHListenerReload(ctx, expected, namespace, read)
	if err != nil {
		return nil, err
	}
	memory, err := pinSSHExecMemory(process.proc, process.uid)
	if err != nil {
		return nil, err
	}
	execution = &sshExecReload{before: memory, open: func() (*sshExecMemory, error) {
		return pinSSHExecMemory(process.proc, process.uid)
	}}
	if err := errors.Join(check(ctx), guard(), execution.beforeRequest()); err != nil {
		return nil, err
	}
	target, err := sshActivationDigest([]any{"systemd-pidfd-sighup-exec-listeners-v4", held.summary, configuration, expected, namespace, listeners.before})
	if err != nil {
		return nil, err
	}
	// pidfd_send_signal cannot retarget a recycled numeric PID. Only SIGHUP
	// to the retained thread-group leader is allowed, with no shell, manager
	// mutation, child signal, numeric-PID fallback or automatic retry.
	send := func() error { return sendSSHProcessReload(process) }
	verify := func(ctx context.Context) error { return errors.Join(listeners.check(ctx), execution.beforeRequest()) }
	after := func(ctx context.Context, guard func() error) error {
		if err := listeners.wait(ctx, guard, pauseSSHListenerObservation); err != nil {
			return err
		}
		if err := execution.observe(ctx, func() error { return errors.Join(check(ctx), guard()) }); err != nil {
			return err
		}
		return errors.Join(listeners.wait(ctx, func() error {
			return errors.Join(guard(), execution.checkAfter())
		}, pauseSSHListenerObservation), execution.checkAfter())
	}
	return &sshActivationTarget{ctx: ctx, target: target, verify: verify, preSend: execution.beforeRequest, send: send, after: after, closeFn: cleanup}, nil
}

func sendSSHProcessReload(process *sshProcessBinding) error {
	if err := process.alive(); err != nil {
		return err
	}
	return unix.PidfdSendSignal(process.pidfd, unix.SIGHUP, nil, 0)
}

// Callbacks are private fixed production closures, or isolated test doubles.
// The mutex serializes request and Close so the pidfd cannot be closed and
// recycled in this process before the one allowed syscall completes.
type sshActivationTarget struct {
	mu                sync.Mutex
	ctx               context.Context
	target            string
	verify            func(context.Context) error
	preSend, send     func() error
	after             func(context.Context, func() error) error
	closeFn           func() error
	attempted, closed bool
}

func (l *sshActivationTarget) identity() string {
	if l == nil {
		return ""
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return ""
	}
	return l.target
}

func (l *sshActivationTarget) check() error {
	if l == nil {
		return ErrInventoryClosed
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.checkLocked(l.ctx)
}

func (l *sshActivationTarget) checkLocked(ctx context.Context) error {
	if l.closed || l.attempted || ctx == nil || l.ctx == nil || l.verify == nil || l.send == nil || l.after == nil || l.closeFn == nil || !lowerDigest.MatchString(l.target) {
		return ErrInventoryClosed
	}
	if err := errors.Join(ctx.Err(), l.ctx.Err()); err != nil {
		return err
	}
	return errors.Join(l.verify(ctx), ctx.Err(), l.ctx.Err())
}

func (l *sshActivationTarget) request(parent context.Context, policyGuard func() error) error {
	if l == nil {
		return ErrInventoryClosed
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || l.attempted {
		return ErrInventoryClosed
	}
	// Even a rejected dispatch consumes this lease. The durable transaction
	// must be recovered explicitly; no uncertain request is replayed.
	defer func() { l.attempted = true }()
	if parent == nil || policyGuard == nil || l.ctx == nil {
		return ErrInventoryUnsafe
	}
	ctx, cancel := context.WithCancel(l.ctx)
	stop := context.AfterFunc(parent, cancel)
	defer stop()
	defer cancel()
	if err := errors.Join(parent.Err(), ctx.Err(), policyGuard()); err != nil {
		return err
	}
	if err := l.checkLocked(ctx); err != nil {
		return err
	}
	if err := errors.Join(parent.Err(), ctx.Err(), policyGuard()); err != nil {
		return err
	}
	// The production pre-send probe may wait inside the kernel. Recheck both
	// request and binder cancellation directly after it returns, before signal.
	// Fixed test targets without a memory observer may omit this private hook.
	if l.preSend != nil {
		if err := l.preSend(); err != nil {
			return err
		}
	}
	if err := errors.Join(parent.Err(), ctx.Err(), l.ctx.Err()); err != nil {
		return err
	}
	if err := errors.Join(l.send(), parent.Err(), ctx.Err(), policyGuard()); err != nil {
		return err
	}
	// Wait for a replaced stable listener generation under the post-intent
	// guard. This is still neither consumed-policy nor authenticated-access
	// proof, and the dispatcher always retains its recovery fence.
	return errors.Join(l.after(ctx, policyGuard), parent.Err(), ctx.Err(), policyGuard())
}

func (l *sshActivationTarget) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	if l.closeFn == nil {
		return ErrInventoryUnsafe
	}
	err := l.closeFn()
	l.verify, l.preSend, l.send, l.after, l.closeFn = nil, nil, nil, nil, nil
	return err
}

func (held *sshRetainedProcess) recheck(ctx context.Context,
	snapshot func(context.Context) (sshSystemdSnapshot, error), guard func() error,
	startup func(context.Context, sshSystemdSnapshot) (StartupSummary, error)) error {
	if held == nil || held.lease == nil || ctx == nil || snapshot == nil || guard == nil || startup == nil || held.summary.Startup == nil {
		return ErrInventoryClosed
	}
	if err := errors.Join(ctx.Err(), guard()); err != nil {
		return err
	}
	current, err := snapshot(ctx)
	if err != nil {
		return err
	}
	command, err := startup(ctx, current)
	if err != nil {
		return err
	}
	process, err := held.lease.observe()
	if err := errors.Join(err, ctx.Err(), guard()); err != nil {
		return err
	}
	if !reflect.DeepEqual(current, held.manager) || command != *held.summary.Startup || !reflect.DeepEqual(process, held.process) {
		return ErrInventoryChanged
	}
	return nil
}
