//go:build linux

package sshpolicy

import (
	"context"
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestSSHEndpointCoordinatorRequiresFreshParserAndRuntimeEvidence(t *testing.T) {
	for _, scenario := range []string{"exact", "parser-failure", "parser-drift", "no-family", "observe-error", "wrong-parser", "wrong-count", "no-process", "no-listeners", "bad-hash", "guard-drift", "cancel"} {
		t.Run(scenario, func(t *testing.T) {
			f := newInventoryFixture(t, includeDropIns+"AllowTcpForwarding local\n")
			inventory := f.open()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			parserCalls, observations, checks := 0, 0, 0
			digest := strings.Repeat("a", 64)
			run := func(_ context.Context, image *parserImage, mode, _ string) ([]byte, error) {
				parserCalls++
				if scenario == "parser-failure" {
					return nil, ErrInventoryUnsafe
				}
				if mode == "syntax" {
					return nil, nil
				}
				output := "port 22\naddressfamily inet\nlistenaddress 192.0.2.1:2222\nallowtcpforwarding local\n"
				if scenario == "no-family" {
					output = strings.ReplaceAll(output, "addressfamily inet\n", "")
				}
				if scenario == "parser-drift" && image != nil {
					output = strings.ReplaceAll(output, "local", "no")
				}
				return []byte(output), nil
			}
			guard := func() error {
				checks++
				if scenario == "guard-drift" && observations != 0 {
					return ErrInventoryChanged
				}
				return inventory.Recheck()
			}
			observe := func(_ context.Context, expected []netip.AddrPort, _ func() error) (ListenerSummary, error) {
				observations++
				socket := sshListenerFixture(3, 33)
				if err := matchSSHEndpoints(expected, []sshListenerSocket{socket}, 7); err != nil {
					t.Fatal(err)
				}
				result := ListenerSummary{TCPListenersObserved: true, ListenerCount: 1, SocketsSHA256: strings.Repeat("b", 64), Process: ProcessSummary{ProcessObserved: true, ExecutableVerified: true, ExecutableSHA256: digest}}
				switch scenario {
				case "observe-error":
					return result, ErrInventoryUnsafe
				case "wrong-parser":
					result.Process.ExecutableSHA256 = strings.Repeat("c", 64)
				case "wrong-count":
					result.ListenerCount++
				case "no-process":
					result.Process.ProcessObserved = false
				case "no-listeners":
					result.TCPListenersObserved = false
				case "bad-hash":
					result.SocketsSHA256 = "bad"
				case "cancel":
					cancel()
				}
				return result, nil
			}
			got, err := observeSSHEndpoints(ctx, inventory.snapshot, digest, run, guard, observe)
			if scenario != "exact" {
				if err == nil || !reflect.DeepEqual(got, EndpointSummary{}) {
					t.Fatal("accepted incomplete correspondence", err)
				}
				if strings.HasPrefix(scenario, "parser-") || scenario == "no-family" {
					if observations != 0 {
						t.Fatal("observed runtime after invalid parser result")
					}
				}
				return
			}
			if err != nil || !got.ConfiguredEndpointsMatched || !lowerDigest.MatchString(got.ExpectedEndpointsSHA256) || !lowerDigest.MatchString(got.ConfigurationFilesSHA256) ||
				got.ConfigurationVerified || got.RuntimeActivated || got.AccessVerified || got.Listeners.Process.ListenersVerified || parserCalls != 4 || observations != 1 || checks != 11 {
				t.Fatal("incorrect proof boundary", err)
			}
			wire, _ := json.Marshal(got)
			for _, private := range []string{"192.0.2.1", "2222", "allowtcpforwarding", "local"} {
				if strings.Contains(string(wire), private) {
					t.Fatal("disclosed configuration values")
				}
			}
			if err := inventory.Recheck(); err != nil {
				t.Fatal("configuration changed", err)
			}
		})
	}
}
