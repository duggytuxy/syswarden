//go:build linux

package sshpolicy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func sshReloadListenerFixture(t *testing.T) (*sshListenerReload, []sshListenerSocket) {
	t.Helper()
	before := []sshListenerSocket{sshListenerFixture(3, 33)}
	expected := []netip.AddrPort{netip.AddrPortFrom(before[0].Address, before[0].Port)}
	l, err := prepareSSHListenerReload(context.Background(), expected, before[0].NetNSCookie,
		func(context.Context) ([]sshListenerSocket, error) { return before, nil })
	if err != nil {
		t.Fatal(err)
	}
	after := slices.Clone(before)
	after[0].Cookie++
	after[0].Inode++
	return l, after
}

func TestSSHListenerReloadRequiresStableCompleteReplacement(t *testing.T) {
	for _, scenario := range []string{"new", "old-then-new", "empty-then-new", "unstable-new", "gap-resets", "old-resets", "same-inode-new-cookie", "fd-only", "inode-only", "old", "empty", "wrong-port", "wrong-namespace", "reused-cookie", "read-error", "cancel-read", "guard-error", "late-guard-error", "pause-error"} {
		t.Run(scenario, func(t *testing.T) {
			l, after := sshReloadListenerFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reads, guards, pauses := 0, 0, 0
			l.read = func(context.Context) ([]sshListenerSocket, error) {
				reads++
				value := slices.Clone(after)
				switch scenario {
				case "old-then-new":
					if reads == 1 {
						return slices.Clone(l.before), nil
					}
				case "empty-then-new":
					if reads == 1 {
						return nil, nil
					}
				case "unstable-new":
					if reads == 1 {
						value[0].Cookie++
					}
				case "gap-resets":
					if reads == 2 {
						return nil, nil
					}
				case "old-resets":
					if reads == 2 {
						return slices.Clone(l.before), nil
					}
				case "same-inode-new-cookie":
					value[0].Inode = l.before[0].Inode
				case "fd-only":
					value = slices.Clone(l.before)
					value[0].FD++
				case "inode-only":
					value[0].Cookie = l.before[0].Cookie
				case "old":
					return slices.Clone(l.before), nil
				case "empty":
					return nil, nil
				case "wrong-port":
					value[0].Port++
				case "wrong-namespace":
					value[0].NetNSCookie++
				case "reused-cookie":
					value[0].Cookie = l.before[0].Cookie
				case "read-error":
					return nil, unix.EACCES
				case "cancel-read":
					cancel()
				}
				return value, nil
			}
			guard := func() error {
				guards++
				if scenario == "guard-error" || (scenario == "late-guard-error" && guards == 5) {
					return ErrInventoryChanged
				}
				return nil
			}
			pause := func(context.Context) error {
				pauses++
				if scenario == "pause-error" {
					return context.Canceled
				}
				return nil
			}
			err := l.wait(ctx, guard, pause)
			want := map[string]int{"new": 2, "old-then-new": 3, "empty-then-new": 3, "unstable-new": 3, "gap-resets": 4, "old-resets": 4, "same-inode-new-cookie": 2}[scenario]
			if (err == nil) != (want != 0) || (want != 0 && reads != want) {
				t.Fatal("incorrect generation decision", reads, err)
			}
			if reads > 150 || pauses > 150 {
				t.Fatal("unbounded observations")
			}
			if scenario == "old" && reads != 150 {
				t.Fatal("old generation was accepted")
			}
		})
	}
}

func TestSSHListenerReloadPreparationRejectsDriftAndAliases(t *testing.T) {
	for _, scenario := range []string{"stable", "drift", "empty", "read-error", "cancel", "wrong-expected"} {
		t.Run(scenario, func(t *testing.T) {
			value := []sshListenerSocket{sshListenerFixture(3, 33)}
			expected := []netip.AddrPort{netip.AddrPortFrom(value[0].Address, value[0].Port)}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := 0
			read := func(context.Context) ([]sshListenerSocket, error) {
				calls++
				if scenario == "drift" && calls == 2 {
					value[0].Cookie++
				}
				if scenario == "empty" {
					return nil, nil
				}
				if scenario == "read-error" {
					return nil, unix.EPERM
				}
				if scenario == "cancel" {
					cancel()
				}
				return value, nil
			}
			if scenario == "wrong-expected" {
				expected[0] = netip.MustParseAddrPort("192.0.2.44:4444")
			}
			l, err := prepareSSHListenerReload(ctx, expected, value[0].NetNSCookie, read)
			if (err == nil) != (scenario == "stable") {
				t.Fatal(err)
			}
			if err != nil {
				return
			}
			expected[0] = netip.MustParseAddrPort("192.0.2.44:4444")
			value[0].Cookie++
			if l.check(ctx) == nil {
				t.Fatal("mutable provider changed retained expectations")
			}
		})
	}
}

func TestSSHListenerReloadAllEndpointsMustChange(t *testing.T) {
	first := sshListenerFixture(3, 33)
	second := sshListenerFixture(4, 44)
	second.Port++
	before := []sshListenerSocket{first, second}
	expected := []netip.AddrPort{netip.AddrPortFrom(first.Address, first.Port), netip.AddrPortFrom(second.Address, second.Port)}
	l, err := prepareSSHListenerReload(context.Background(), expected, first.NetNSCookie, func(context.Context) ([]sshListenerSocket, error) { return before, nil })
	if err != nil {
		t.Fatal(err)
	}
	after := slices.Clone(before)
	after[0].Cookie++
	after[0].Inode++
	if ready, err := l.replaced(after); ready || err != nil {
		t.Fatal("partial replacement", err)
	}
	after[1].Cookie++
	after[1].Inode++
	if ready, err := l.replaced(after); !ready || err != nil {
		t.Fatal("complete replacement", err)
	}
	after[1].Cookie = after[0].Cookie
	if _, err := l.replaced(after); err == nil {
		t.Fatal("contradictory cookie accepted")
	}
}

func TestSSHListenerReloadRejectsInvalidInputsAndHonorsDeadline(t *testing.T) {
	l, _ := sshReloadListenerFixture(t)
	guard := func() error { return nil }
	pause := func(context.Context) error { return nil }
	for _, invalid := range []struct {
		ctx   context.Context
		guard func() error
		pause func(context.Context) error
	}{{nil, guard, pause}, {context.Background(), nil, pause}, {context.Background(), guard, nil}} {
		if l.wait(invalid.ctx, invalid.guard, invalid.pause) == nil {
			t.Fatal("invalid arguments accepted")
		}
	}
	var absent *sshListenerReload
	if absent.wait(context.Background(), guard, pause) == nil || absent.check(context.Background()) == nil {
		t.Fatal("nil observer accepted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	l.read = func(ctx context.Context) ([]sshListenerSocket, error) { <-ctx.Done(); return nil, ctx.Err() }
	if !errors.Is(l.wait(ctx, guard, pause), context.DeadlineExceeded) {
		t.Fatal("request deadline ignored")
	}
	if !errors.Is(pauseSSHListenerObservation(ctx), context.DeadlineExceeded) {
		t.Fatal("pause ignored deadline")
	}
}

func TestSSHListenerReloadFailureRetainsDurableFence(t *testing.T) {
	for _, fail := range []bool{false, true} {
		_, plan, deps, journal := ownedPublicationFixture(t)
		sends, closes, after := 0, 0, 0
		result, err := attemptSSHActivation(context.Background(), journal, plan.summary.PlanSHA256, deps.parserDigest, deps.run, deps.checkParser,
			func(ctx context.Context, _ func() error) (sshActivationLease, error) {
				return &sshActivationTarget{ctx: ctx, target: strings.Repeat("a", 64), verify: func(context.Context) error { return nil }, send: func() error { sends++; return nil },
					after: func(_ context.Context, guard func() error) error {
						after++
						if err := guard(); err != nil {
							return err
						}
						if fail {
							return context.DeadlineExceeded
						}
						return nil
					},
					closeFn: func() error { closes++; return nil }}, nil
			})
		if (err != nil) != fail || sends != 1 || after != 1 || closes != 1 || !result.RecoveryRequired || result.RequestReturned == fail || !journal.poisoned {
			t.Fatal("lost uncertainty boundary", result, err)
		}
	}
}

func TestSSHListenerReloadNativeSocketGeneration(t *testing.T) {
	open := func(address string) *net.TCPListener {
		t.Helper()
		var config net.ListenConfig
		config.SetMultipathTCP(false)
		listener, err := config.Listen(context.Background(), "tcp4", address)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		return listener.(*net.TCPListener)
	}
	observe := func(listener *net.TCPListener) sshListenerSocket {
		t.Helper()
		raw, err := listener.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var value sshListenerSocket
		var probeErr error
		err = raw.Control(func(fd uintptr) {
			var state unix.Stat_t
			probeErr = unix.Fstat(int(fd), &state)
			if probeErr != nil {
				return
			}
			var listening bool
			value, listening, probeErr = inspectSSHSocket(int(fd), state.Ino)
			value.FD = int(fd)
			if !listening && probeErr == nil {
				probeErr = ErrInventoryUnsafe
			}
		})
		if err != nil || probeErr != nil {
			t.Fatal(err, probeErr)
		}
		return value
	}
	old := open("127.0.0.1:0")
	address := old.Addr().String()
	before := observe(old)
	current := []sshListenerSocket{before}
	l, err := prepareSSHListenerReload(context.Background(), []netip.AddrPort{netip.MustParseAddrPort(address)}, before.NetNSCookie,
		func(context.Context) ([]sshListenerSocket, error) { return current, nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	current = []sshListenerSocket{observe(open(address))}
	if current[0].Cookie == before.Cookie {
		t.Fatal("kernel reused live socket generation")
	}
	if err := l.wait(context.Background(), func() error { return nil }, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestSSHReloadEmptySamplesDoNotRelaxPublicListenerObserver(t *testing.T) {
	list := func(context.Context) (map[int]uint64, error) { return map[int]uint64{}, nil }
	probe := func(int, uint64) (sshListenerSocket, bool, error) {
		t.Fatal("probe without descriptor")
		return sshListenerSocket{}, false, nil
	}
	if _, err := collectSSHListeners(context.Background(), list, probe); err == nil {
		t.Fatal("public observer accepted empty listeners")
	}
	if sockets, err := collectSSHListenerState(context.Background(), list, probe, true); err != nil || len(sockets) != 0 {
		t.Fatal("bounded observer lost empty interval", err)
	}
}
