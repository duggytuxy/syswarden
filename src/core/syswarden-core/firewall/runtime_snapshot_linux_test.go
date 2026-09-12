//go:build linux

package firewall

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/nftables"
)

func TestNativeRuntimeWitnessesBracketMutationUnderLock(t *testing.T) {
	connection := fullFakeNftablesConnection()
	manager, err := newNftablesManager(func() nftablesConnection { return connection })
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	hooks := RecoverableMutationHooks{
		ObserveBefore: func(snapshot NativeRuntimeEntrySnapshot) error {
			order = append(order, "before")
			if snapshot.Present || snapshot.Entry != "192.0.2.44" || snapshot.CapturedAt.IsZero() {
				t.Fatalf("incorrect initial witness: %+v", snapshot)
			}
			return nil
		},
		Prepare: func() error { order = append(order, "prepare"); return nil },
		ObserveAfter: func(snapshot NativeRuntimeEntrySnapshot) error {
			order = append(order, "after")
			if !snapshot.Present || snapshot.Permanent || !snapshot.ExpiresAt.After(snapshot.CapturedAt) {
				t.Fatalf("incorrect applied witness: %+v", snapshot)
			}
			return nil
		},
		Persist: func() error { order = append(order, "persist"); return nil },
		Commit:  func() error { order = append(order, "commit"); return nil },
	}
	if err := manager.RunRecoverableMutation(context.Background(), RecoverableMutation{Entry: "192.0.2.44", Present: true, TTL: time.Minute}, hooks); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(order, []string{"before", "prepare", "after", "persist", "commit"}) {
		t.Fatalf("native evidence escaped transaction ordering: %v", order)
	}
}

func TestNativeRuntimeSnapshotRefusesPartialOrContradictoryLayers(t *testing.T) {
	for _, test := range []string{"missing-layer", "read-error", "presence-disagreement", "lifetime-disagreement"} {
		t.Run(test, func(t *testing.T) {
			connection := fullFakeNftablesConnection()
			manager, err := newNftablesManager(func() nftablesConnection { return connection })
			if err != nil {
				t.Fatal(err)
			}
			if test != "missing-layer" {
				if err := manager.BanWithTTL("192.0.2.44", time.Minute); err != nil {
					t.Fatal(err)
				}
			}
			switch test {
			case "missing-layer":
				missing := newFakeNftablesConnection("inet", "inet6", "netdev")
				connection.tables, connection.sets = missing.tables, missing.sets
			case "read-error":
				connection.getElementsErr = errors.New("injected netlink read failure")
			case "presence-disagreement":
				connection.elements[fakeNftSetKey(manager.netdevSet)] = nil
			case "lifetime-disagreement":
				elements := connection.elements[fakeNftSetKey(manager.netdevSet)]
				for index := range elements {
					elements[index].Timeout = 0
					elements[index].Expires = 0
				}
			}
			called := false
			err = manager.WithNativeRuntimeSnapshot(context.Background(), []string{"192.0.2.44"}, func([]NativeRuntimeEntrySnapshot) error { called = true; return nil })
			if err == nil || called {
				t.Fatalf("partial native evidence was exposed: called=%t, err=%v", called, err)
			}
		})
	}
}

func TestNativeWitnessFailureKeepsAppliedMutationUncommitted(t *testing.T) {
	connection := fullFakeNftablesConnection()
	manager, err := newNftablesManager(func() nftablesConnection { return connection })
	if err != nil {
		t.Fatal(err)
	}
	prepared, persisted := false, false
	err = manager.RunRecoverableMutation(context.Background(), RecoverableMutation{Entry: "192.0.2.45", Present: true, Permanent: true}, RecoverableMutationHooks{
		ObserveBefore: func(NativeRuntimeEntrySnapshot) error { return nil },
		Prepare:       func() error { prepared = true; return nil },
		ObserveAfter:  func(NativeRuntimeEntrySnapshot) error { return errors.New("injected witness rejection") },
		Persist:       func() error { persisted = true; return nil },
		Commit:        func() error { t.Fatal("unwitnessed mutation committed"); return nil },
	})
	if err == nil || !prepared || persisted || connection.flushCalls == 0 {
		t.Fatalf("failed witness did not leave recoverable prepared state: %v", err)
	}
}

func TestNativeRuntimeSnapshotPreservesStrongerBan(t *testing.T) {
	connection := fullFakeNftablesConnection()
	manager, err := newNftablesManager(func() nftablesConnection { return connection })
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.BanPermanent("192.0.2.46"); err != nil {
		t.Fatal(err)
	}
	noop := func() error { return nil }
	err = manager.RunRecoverableMutation(context.Background(), RecoverableMutation{Entry: "192.0.2.46", Present: true, TTL: time.Minute, PreserveStronger: true}, RecoverableMutationHooks{
		Prepare: noop, Persist: noop, Commit: noop,
		ObserveBefore: func(NativeRuntimeEntrySnapshot) error { return nil },
		ObserveAfter: func(snapshot NativeRuntimeEntrySnapshot) error {
			if !snapshot.Permanent || !snapshot.ExpiresAt.IsZero() {
				t.Fatalf("shorter timed claim weakened permanent enforcement: %+v", snapshot)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestIndexedNativeSnapshotUsesMutationIntervalSemantics(t *testing.T) {
	connection := fullFakeNftablesConnection()
	manager, err := newNftablesManager(func() nftablesConnection { return connection })
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range []string{"192.0.2.0/25", "192.0.2.128/25", "2001:db8::/64"} {
		if err := manager.BanPermanent(entry); err != nil {
			t.Fatal(err)
		}
	}
	if err := manager.WithNativeRuntimeSnapshot(context.Background(), []string{"192.0.2.0/25", "192.0.2.128/25", "2001:db8::/64", "198.51.100.1"}, func(snapshots []NativeRuntimeEntrySnapshot) error {
		for index, snapshot := range snapshots {
			if snapshot.Present != (index < 3) {
				t.Fatalf("incorrect interval evidence: %+v", snapshots)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// A retained interval end without its expired start is absence, matching
	// the native mutation verifier's commit-driven garbage collection rule.
	entry, _ := parseFirewallEntry("192.0.2.0/25")
	elements := nftablesIntervalElements(entry, 0)
	_, present, open, err := indexedNativeElementState([]nftables.SetElement{elements[1]}, entry)
	if err != nil || present || open {
		t.Fatalf("expired boundary residue became presence: %t, %t, %v", present, open, err)
	}
}

func TestNativeRuntimeSnapshotRefusesUntrackedKernelClaim(t *testing.T) {
	connection := fullFakeNftablesConnection()
	manager, err := newNftablesManager(func() nftablesConnection { return connection })
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.BanPermanent("192.0.2.81"); err != nil {
		t.Fatal(err)
	}
	called := false
	if err := manager.WithNativeRuntimeSnapshot(context.Background(), nil, func([]NativeRuntimeEntrySnapshot) error { called = true; return nil }); err == nil || called {
		t.Fatal("untracked kernel enforcement became a complete empty inventory")
	}
}

func TestNativeMutationRefusesPointInsideUntrackedPrefixBeforePreparation(t *testing.T) {
	connection := fullFakeNftablesConnection()
	manager, err := newNftablesManager(func() nftablesConnection { return connection })
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.BanPermanent("192.0.2.0/24"); err != nil {
		t.Fatal(err)
	}
	prepared := false
	noop := func() error { return nil }
	err = manager.RunRecoverableMutation(context.Background(), RecoverableMutation{Entry: "192.0.2.81"}, RecoverableMutationHooks{
		ObserveBefore: func(NativeRuntimeEntrySnapshot) error { return nil },
		ObserveAfter:  func(NativeRuntimeEntrySnapshot) error { return nil },
		Prepare:       func() error { prepared = true; return nil }, Persist: noop, Commit: noop,
	})
	if err == nil || prepared {
		t.Fatal("covered native point received an absence witness or prepared a deletion")
	}
}

func TestNativeRuntimeExpiryUsesCaptureIntervals(t *testing.T) {
	base := time.Date(2026, 9, 12, 5, 22, 56, 0, time.UTC)
	for _, test := range []struct {
		name          string
		inetStart     time.Duration
		inetEnd       time.Duration
		netdevStart   time.Duration
		netdevEnd     time.Duration
		inetExpires   time.Duration
		netdevExpires time.Duration
		wantError     bool
	}{
		{
			name:      "native boundary with millisecond wire precision",
			inetStart: 920378592, inetEnd: 920461872,
			netdevStart: 920629481, netdevEnd: 920694681,
			inetExpires: 2565377506 * time.Millisecond, netdevExpires: 2565379506 * time.Millisecond,
		},
		{
			name:        "equal deadlines observed across a slow read",
			inetEnd:     900 * time.Millisecond,
			netdevStart: time.Second, netdevEnd: 1900 * time.Millisecond,
			inetExpires: time.Minute, netdevExpires: 59 * time.Second,
		},
		{
			name:        "boundary plus bounded read latency",
			inetEnd:     400 * time.Millisecond,
			netdevStart: 500 * time.Millisecond, netdevEnd: 900 * time.Millisecond,
			inetExpires: time.Minute, netdevExpires: 61900 * time.Millisecond,
		},
		{
			name:        "divergence beyond both capture intervals",
			inetEnd:     100 * time.Microsecond,
			netdevStart: 200 * time.Microsecond, netdevEnd: 300 * time.Microsecond,
			inetExpires: time.Minute, netdevExpires: 62002 * time.Millisecond,
			wantError: true,
		},
		{
			name:        "reverse divergence beyond both capture intervals",
			inetEnd:     100 * time.Microsecond,
			netdevStart: 200 * time.Microsecond, netdevEnd: 300 * time.Microsecond,
			inetExpires: 62002 * time.Millisecond, netdevExpires: time.Minute,
			wantError: true,
		},
		{
			name:        "first layer expires during second capture",
			inetEnd:     100 * time.Microsecond,
			netdevStart: 500 * time.Microsecond, netdevEnd: 2 * time.Millisecond,
			inetExpires: time.Millisecond, netdevExpires: time.Millisecond,
			wantError: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, value := range []string{"192.0.2.44", "2001:db8::44"} {
				entry, err := parseFirewallEntry(value)
				if err != nil {
					t.Fatal(err)
				}
				observations := make(map[string]nativeLayerObservation)
				for _, layer := range []struct {
					name       string
					start, end time.Duration
					expires    time.Duration
				}{
					{"inet", test.inetStart, test.inetEnd, test.inetExpires},
					{"netdev", test.netdevStart, test.netdevEnd, test.netdevExpires},
				} {
					elements := nftablesIntervalElements(entry, MaximumBanTTL)
					elements[0].Expires = layer.expires
					observations[layer.name] = nativeLayerObservation{
						elements: elements, startedAt: base.Add(layer.start), endedAt: base.Add(layer.end),
					}
				}
				got, err := nativeRuntimeEntrySnapshot(entry, []nftablesLayer{{name: "inet"}, {name: "netdev"}}, observations, true)
				if (err != nil) != test.wantError {
					t.Fatalf("%s: snapshot %+v, error %v, want error %t", value, got, err, test.wantError)
				}
				if test.wantError {
					continue
				}
				if got.Entry != value || !got.Present || got.Permanent || !got.CapturedAt.Equal(base.Add(test.netdevEnd)) {
					t.Fatalf("invalid native identity or observation: %+v", got)
				}
				// The exposed deadline must cover each layer's upper bound.
				// A shorter witness could expire a still-enforced claim early.
				for _, observation := range observations {
					upper := observation.endedAt.Add(observation.elements[0].Expires + time.Millisecond)
					if got.ExpiresAt.Before(upper) {
						t.Fatalf("native witness shortened enforcement: %+v, layer %+v", got, observation)
					}
				}
			}
		})
	}
}
