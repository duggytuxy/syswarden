//go:build linux

package sshpolicy

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSSHListenerCoordinatorRejectsProcessAndSocketDrift(t *testing.T) {
	for _, scenario := range []string{"stable", "process-drift", "process-exit", "socket-drift", "socket-error", "empty", "close-error", "cancel"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			lease := &sshProcessFixtureLease{identity: sshProcessFixtureIdentity()}
			lease.onRead = func(l *sshProcessFixtureLease) error {
				if l.reads == 2 {
					switch scenario {
					case "process-drift":
						l.identity.StartTicks++
					case "process-exit":
						return ErrInventoryChanged
					}
				}
				return nil
			}
			if scenario == "close-error" {
				lease.closeErr = errors.New("fixture close failure")
			}
			capture := &sshListenerCapture{}
			reads := 0
			read := func(context.Context) ([]sshListenerSocket, error) {
				reads++
				value := sshListenerFixture(3, 33)
				switch scenario {
				case "socket-error":
					return nil, unix.EPERM
				case "empty":
					return nil, nil
				case "socket-drift":
					if reads == 2 {
						value.Cookie++
					}
				case "cancel":
					cancel()
				}
				return []sshListenerSocket{value}, nil
			}
			snapshot := func(ctx context.Context) (sshSystemdSnapshot, error) {
				return observeSSHSystemdSnapshot(ctx, strings.Repeat("a", 64),
					sshFixtureQuery(sshManagerFixture("ssh.service", "", true, false, false)), func() error { return nil })
			}
			bind := func(int, string) (sshProcessLease, error) {
				return &sshListenerProcessLease{sshProcessLease: lease, ctx: ctx, read: read, capture: capture}, nil
			}
			process, err := observeSSHSystemdProcess(ctx, snapshot, bind, func() error { return nil })
			if lease.closes != 1 {
				t.Fatal("process lease was not closed exactly once")
			}
			if scenario != "stable" {
				if err == nil || !reflect.DeepEqual(process, ProcessSummary{}) {
					t.Fatal("accepted changed or failed socket/process observations", err)
				}
				if _, err := summarizeSSHListeners(process, capture); err == nil {
					t.Fatal("failed observation produced a summary")
				}
				return
			}
			result, summaryErr := summarizeSSHListeners(process, capture)
			if err != nil || summaryErr != nil || !result.TCPListenersObserved || result.ListenerCount != 1 || reads != 2 || lease.reads != 4 ||
				result.ConfigurationVerified || result.RuntimeActivated || result.AccessVerified || result.Process.ListenersVerified || !lowerDigest.MatchString(result.SocketsSHA256) {
				t.Fatal("incorrect socket observation or stronger proof", err, summaryErr)
			}
			wire, _ := json.Marshal(result)
			if strings.Contains(string(wire), "192.0.2.1") || strings.Contains(string(wire), "2222") || strings.Contains(string(wire), "Cookie") {
				t.Fatal("public summary disclosed raw socket observations")
			}
		})
	}
}

func TestSSHListenerSummaryCountsSocketsAndRefusesAmbiguousEvidence(t *testing.T) {
	process := ProcessSummary{ProcessObserved: true, ExecutableVerified: true, IdentitySHA256: strings.Repeat("a", 64)}
	for _, scenario := range []string{"duplicate-fd-reference", "incomplete", "unsorted", "zero-cookie", "missing-address", "conflicting-object"} {
		t.Run(scenario, func(t *testing.T) {
			first := sshListenerFixture(3, 33)
			second := first
			second.FD = 4
			capture := &sshListenerCapture{samples: 2, sockets: []sshListenerSocket{first, second}}
			switch scenario {
			case "incomplete":
				capture.samples = 1
			case "unsorted":
				capture.sockets[1].FD = 3
			case "zero-cookie":
				capture.sockets[0].Cookie = 0
			case "missing-address":
				capture.sockets[0].Address = sshListenerSocket{}.Address
			case "conflicting-object":
				capture.sockets[1].Port++
			}
			got, err := summarizeSSHListeners(process, capture)
			if scenario == "duplicate-fd-reference" {
				if err != nil || got.ListenerCount != 1 {
					t.Fatal("counted duplicate descriptors as separate sockets", err)
				}
			} else if err == nil || !reflect.DeepEqual(got, ListenerSummary{}) {
				t.Fatal("accepted ambiguous evidence", err)
			}
		})
	}
	if _, err := summarizeSSHListeners(process, nil); err == nil {
		t.Fatal("accepted absent evidence")
	}
}

func TestSSHListenerNativeProcessBinding(t *testing.T) {
	fd, inode := sshTestTCPListener(t, unix.AF_INET)
	state, digest, group := sshProcessOracleExpectation(t)
	binding, err := bindSSHProcess(os.Getpid(), os.Geteuid(), group, state, digest)
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Close()
	capture := &sshListenerCapture{}
	lease := &sshListenerProcessLease{sshProcessLease: binding, ctx: context.Background(), read: binding.listeners, capture: capture}
	first, err := lease.observe()
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) || errors.Is(err, unix.ENOSYS) {
		t.Skip("kernel policy does not permit native descriptor observation; production refuses")
	}
	if err != nil {
		t.Fatal(err)
	}
	second, err := lease.observe()
	if err != nil || !reflect.DeepEqual(first, second) || capture.samples != 2 {
		t.Fatal("native process/listener binding was unstable", err)
	}
	found := false
	for _, socket := range capture.sockets {
		found = found || (socket.FD == fd && socket.Inode == inode && socket.Address.IsLoopback())
	}
	if !found {
		t.Fatal("native binding omitted its own listener")
	}
	if _, err := lease.observe(); err == nil {
		t.Fatal("capture accepted an unbounded extra sample")
	}
	if os.Geteuid() != 0 {
		if summary, err := ObserveSystemdListeners(); err == nil || !reflect.DeepEqual(summary, ListenerSummary{}) {
			t.Fatal("unprivileged caller obtained a root observer result", err)
		}
	}
}
