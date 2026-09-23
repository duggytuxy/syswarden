//go:build linux

package firewall

import (
	"context"
	"errors"
	"testing"

	"github.com/google/nftables"
)

func TestNativeRefreshRequiresOwnedTablesAndAllFamilies(t *testing.T) {
	for _, failure := range []string{"inet-table", "netdev-table", "wrong-family", "inet-ipv6", "netdev-ipv6", "query-error"} {
		t.Run(failure, func(t *testing.T) {
			connection := fullFakeNftablesConnection()
			manager, err := newNftablesManager(func() nftablesConnection { return connection })
			if err != nil {
				t.Fatal(err)
			}
			switch failure {
			case "inet-table":
				connection.tables = connection.tables[1:]
			case "netdev-table":
				connection.tables = connection.tables[:1]
			case "wrong-family":
				connection.tables[0] = &nftables.Table{Name: "syswarden", Family: nftables.TableFamilyIPv4}
			case "inet-ipv6", "netdev-ipv6":
				index := 0
				if failure == "netdev-ipv6" {
					index = 1
				}
				key := fakeNftTableKey(connection.tables[index])
				connection.sets[key] = connection.sets[key][:1]
			case "query-error":
				connection.getSetsErr = errors.New("kernel query refused")
			}
			called := false
			err = manager.WithNativeRuntimeSnapshot(context.Background(), []string{"192.0.2.44"}, func([]NativeRuntimeEntrySnapshot) error { called = true; return nil })
			if err == nil || called || manager.Health() == HealthHealthy {
				t.Fatalf("stale or partial inventory accepted: %v", err)
			}
			prepared := false
			noop := func() error { return nil }
			err = manager.RunRecoverableMutation(context.Background(), RecoverableMutation{Entry: "192.0.2.44", Present: true, Permanent: true}, RecoverableMutationHooks{
				ObserveBefore: func(NativeRuntimeEntrySnapshot) error { return nil },
				ObserveAfter:  func(NativeRuntimeEntrySnapshot) error { return nil },
				Prepare:       func() error { prepared = true; return nil }, Persist: noop, Commit: noop,
			})
			if err == nil || prepared || connection.flushCalls != 0 {
				t.Fatalf("unverified mutation reached persistence or kernel: %v", err)
			}
		})
	}
}
