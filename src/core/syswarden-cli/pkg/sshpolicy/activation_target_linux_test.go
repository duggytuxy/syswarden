//go:build linux

package sshpolicy

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSSHRetainedProcessSurvivesObservationAndRefusesDrift(t *testing.T) {
	for _, scenario := range []string{"stable", "manager", "startup", "process", "namespace", "guard", "cancel", "snapshot-error", "startup-error", "process-error"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			state := sshStartupSnapshot(t)
			command, err := verifySSHStartup(sshStartupFixture(), state, "/usr/sbin/sshd")
			if err != nil {
				t.Fatal(err)
			}
			process := &sshProcessFixtureLease{identity: sshProcessFixtureIdentity()}
			drift := false
			snapshot := func(context.Context) (sshSystemdSnapshot, error) {
				if drift && scenario == "snapshot-error" {
					return sshSystemdSnapshot{}, ErrInventoryChanged
				}
				return state, nil
			}
			startup := func(context.Context, sshSystemdSnapshot) (StartupSummary, error) {
				if drift && scenario == "startup-error" {
					return StartupSummary{}, ErrInventoryChanged
				}
				return command, nil
			}
			guard := func() error {
				if drift && scenario == "guard" {
					return ErrInventoryChanged
				}
				return nil
			}
			held, err := retainSSHSystemdProcess(ctx, snapshot, func(int, string) (sshProcessLease, error) { return process, nil }, guard, startup)
			if err != nil || held == nil || process.closes != 0 || process.reads != 2 {
				t.Fatal("ownership was not retained", err)
			}
			defer held.Close()
			drift = true
			switch scenario {
			case "manager":
				state.units[state.summary.Service]["InvocationID"] = strings.Repeat("e", 32)
			case "startup":
				command.CommandSHA256 = strings.Repeat("c", 64)
			case "process":
				process.identity.StartTicks++
			case "namespace":
				process.identity.Namespaces["mnt"] = sshKernelIdentity{55, 66}
			case "cancel":
				cancel()
			case "process-error":
				process.onRead = func(*sshProcessFixtureLease) error { return ErrInventoryChanged }
			}
			err = held.recheck(ctx, snapshot, guard, startup)
			if (err == nil) != (scenario == "stable") {
				t.Fatal("drift decision", err)
			}
			if held.summary.RuntimeActivated || held.summary.AccessVerified || held.summary.ConfigurationVerified {
				t.Fatal("invented activation proof")
			}
			if err := held.Close(); err != nil || process.closes != 1 {
				t.Fatal("lease not released exactly once", err)
			}
			if held.recheck(ctx, snapshot, guard, startup) == nil || held.Close() != nil || process.closes != 1 {
				t.Fatal("closed lease reused")
			}
		})
	}
}

func TestSSHActivationTargetOneShotGuardAndCancellation(t *testing.T) {
	for _, scenario := range []string{"success", "nil-context", "nil-guard", "bind-cancel", "request-cancel", "target-drift", "cancel-during-check", "cancel-during-pre-send", "target-drift-pre-send", "policy-drift", "send-error", "cancel-after-send", "post-send-drift", "close-error"} {
		t.Run(scenario, func(t *testing.T) {
			bound, cancelBound := context.WithCancel(context.Background())
			defer cancelBound()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls, checks, guards, closes := 0, 0, 0, 0
			l := &sshActivationTarget{ctx: bound, target: strings.Repeat("d", 64),
				verify: func(ctx context.Context) error {
					checks++
					if scenario == "target-drift" {
						return ErrInventoryChanged
					}
					if scenario == "cancel-during-check" {
						cancel()
						<-ctx.Done()
						return ctx.Err()
					}
					return nil
				}, preSend: func() error {
					if scenario == "cancel-during-pre-send" {
						cancel()
					}
					if scenario == "target-drift-pre-send" {
						return ErrInventoryChanged
					}
					return nil
				}, send: func() error {
					calls++
					if scenario == "send-error" {
						return ErrInventoryChanged
					}
					if scenario == "cancel-after-send" {
						cancel()
					}
					return nil
				}, after: func(context.Context, func() error) error { return nil }, closeFn: func() error {
					closes++
					if scenario == "close-error" {
						return ErrInventoryChanged
					}
					return nil
				}}
			defer l.Close()
			guard := func() error {
				guards++
				if (scenario == "policy-drift" && guards == 2) || (scenario == "post-send-drift" && guards == 3) {
					return ErrInventoryChanged
				}
				return nil
			}
			var requestContext context.Context = ctx
			switch scenario {
			case "nil-context":
				requestContext = nil
			case "nil-guard":
				guard = nil
			case "bind-cancel":
				cancelBound()
			case "request-cancel":
				cancel()
			}
			err := l.request(requestContext, guard)
			ok := scenario == "success" || scenario == "close-error"
			if (err == nil) != ok {
				t.Fatal("incorrect request result", err)
			}
			wantSend := ok || scenario == "send-error" || scenario == "cancel-after-send" || scenario == "post-send-drift"
			if (calls == 1) != wantSend || calls > 1 {
				t.Fatal("incorrect dispatch count", calls)
			}
			if l.request(context.Background(), func() error { return nil }) == nil || l.check() == nil {
				t.Fatal("reused consumed lease")
			}
			before := calls
			closeErr := l.Close()
			if (closeErr != nil) != (scenario == "close-error") || closes != 1 || l.identity() != "" || l.Close() != nil || closes != 1 || calls != before {
				t.Fatal("close lost ownership or replayed")
			}
			if ok && (checks != 1 || guards != 4) {
				t.Fatal("missing pre/post guards")
			}
		})
	}
}

func TestSSHActivationTargetSerializesConcurrentRequestsAndClose(t *testing.T) {
	entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	calls, closes := 0, 0
	l := &sshActivationTarget{ctx: context.Background(), target: strings.Repeat("e", 64), verify: func(context.Context) error { return nil },
		send: func() error { calls++; close(entered); <-release; return nil }, after: func(context.Context, func() error) error { return nil }, closeFn: func() error { closes++; return nil }}
	go func() { finished <- l.request(context.Background(), func() error { return nil }) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not reach sender")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = l.request(context.Background(), func() error { return nil })
			_ = l.Close()
		}()
	}
	close(release)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if calls != 1 || closes != 1 {
		t.Fatal("request replay or duplicate release", calls, closes)
	}
}

func TestSSHActivationTargetUsesPostIntentGuardAndRetainsFence(t *testing.T) {
	_, plan, deps, journal := ownedPublicationFixture(t)
	calls, closes := 0, 0
	result, err := attemptSSHActivation(context.Background(), journal, plan.summary.PlanSHA256, deps.parserDigest, deps.run, deps.checkParser,
		func(ctx context.Context, bindingGuard func() error) (sshActivationLease, error) {
			if err := bindingGuard(); err != nil {
				return nil, err
			}
			return &sshActivationTarget{ctx: ctx, target: strings.Repeat("f", 64), verify: func(context.Context) error { return nil },
				send: func() error {
					calls++
					if _, err := journal.readRecord(sshActivationIntentName); err != nil {
						t.Fatal("send before durable intent", err)
					}
					return nil
				}, after: func(context.Context, func() error) error { return nil }, closeFn: func() error { closes++; return nil }}, nil
		})
	if err != nil || calls != 1 || closes != 1 || !result.IntentDurable || !result.RequestReturned || !result.RecoveryRequired || !journal.poisoned {
		t.Fatal("lost activation boundary", result, err)
	}
}

func TestSSHActivationTargetInvalidInputsDoNotOpenRuntime(t *testing.T) {
	badGuard := func() error { return ErrInventoryChanged }
	for _, item := range []struct {
		ctx   context.Context
		guard func() error
	}{{nil, badGuard}, {context.Background(), nil}, {context.Background(), badGuard}} {
		lease, err := bindSSHSystemdActivation(item.ctx, item.guard)
		if err == nil || lease != nil {
			t.Fatal("invalid binder input accepted", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if lease, err := bindSSHSystemdActivation(ctx, func() error { return nil }); err == nil || lease != nil {
		t.Fatal("cancelled binder opened runtime")
	}
	if os.Geteuid() != 0 {
		if lease, err := bindSSHSystemdActivation(context.Background(), func() error { return nil }); err == nil || lease != nil {
			t.Fatal("unprivileged activation binding accepted")
		}
	}
	var nilTarget *sshActivationTarget
	if nilTarget.identity() != "" || nilTarget.check() == nil || nilTarget.request(context.Background(), func() error { return nil }) == nil || nilTarget.Close() != nil {
		t.Fatal("nil target accepted")
	}
	l := &sshActivationTarget{}
	if l.check() == nil || l.request(context.Background(), func() error { return nil }) == nil || l.Close() == nil {
		t.Fatal("incomplete target accepted")
	}
	var held *sshRetainedProcess
	if !errors.Is(held.recheck(context.Background(), nil, nil, nil), ErrInventoryClosed) || !reflect.DeepEqual(held, (*sshRetainedProcess)(nil)) {
		t.Fatal("nil retained process accepted")
	}
}
