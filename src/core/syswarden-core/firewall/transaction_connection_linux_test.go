//go:build linux

package firewall

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/nftables"
)

type trackedTransactionConnection struct {
	*fakeNftablesConnection
	reads    map[string]int
	closed   int
	closeErr error
}

func (c *trackedTransactionConnection) CloseLasting() error {
	c.closed++
	return c.closeErr
}

func (c *trackedTransactionConnection) GetSetElements(set *nftables.Set) ([]nftables.SetElement, error) {
	c.reads[set.Name]++
	return c.fakeNftablesConnection.GetSetElements(set)
}

func trackedTransactionManager(t *testing.T) (*NftablesManager, *[]*trackedTransactionConnection) {
	t.Helper()
	kernel := fullFakeNftablesConnection()
	manager, err := newNftablesManager(func() nftablesConnection { return kernel })
	if err != nil {
		t.Fatal(err)
	}
	var opened []*trackedTransactionConnection
	manager.newTransactionConn = func() (nftablesTransactionConnection, error) {
		// Connections see the same kernel inventory, but never share a batch.
		connection := fullFakeNftablesConnection()
		connection.elements = kernel.elements
		tracked := &trackedTransactionConnection{fakeNftablesConnection: connection, reads: make(map[string]int)}
		opened = append(opened, tracked)
		return tracked, nil
	}
	return manager, &opened
}

func assertTransactionConnectionsClosed(t *testing.T, manager *NftablesManager, opened []*trackedTransactionConnection) {
	t.Helper()
	for index, connection := range opened {
		if connection.closed != 1 {
			t.Fatalf("connection %d closed %d times", index, connection.closed)
		}
	}
	if manager.transactionConnections != nil {
		t.Fatal("transaction retained owned connections")
	}
	if _, ok := manager.conn.(nftablesTransactionConnection); ok {
		t.Fatal("transaction retained a queued or closed lasting connection")
	}
}

func TestRecoverableMutationOwnsConnectionsAcrossFailures(t *testing.T) {
	for _, failure := range []string{"none", "before", "prepare", "after", "persist", "commit", "close", "open", "partial-open", "read", "cancel"} {
		t.Run(failure, func(t *testing.T) {
			manager, opened := trackedTransactionManager(t)
			injected := errors.New("injected transaction failure")
			factory := manager.newTransactionConn
			manager.newTransactionConn = func() (nftablesTransactionConnection, error) {
				if failure == "open" {
					return nil, injected
				}
				connection, err := factory()
				tracked := connection.(*trackedTransactionConnection)
				switch failure {
				case "close":
					tracked.closeErr = injected
				case "read":
					tracked.getElementsErr = injected
				case "partial-open":
					return connection, injected
				}
				return connection, err
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			prepared, persisted, committed := false, false, false
			failAt := func(stage string) error {
				if stage == failure {
					return injected
				}
				return nil
			}
			err := manager.RunRecoverableMutation(ctx, RecoverableMutation{Entry: "192.0.2.44", Present: true, TTL: time.Minute}, RecoverableMutationHooks{
				ObserveBefore: func(snapshot NativeRuntimeEntrySnapshot) error {
					if snapshot.Present {
						t.Fatal("unexpected prior claim")
					}
					return failAt("before")
				},
				Prepare: func() error {
					prepared = true
					if failure == "cancel" {
						cancel()
					}
					return failAt("prepare")
				},
				ObserveAfter: func(snapshot NativeRuntimeEntrySnapshot) error {
					if !snapshot.Present || snapshot.Permanent || !snapshot.ExpiresAt.After(snapshot.CapturedAt) {
						t.Fatal("missing verified timed claim")
					}
					return failAt("after")
				},
				Persist: func() error { persisted = true; return failAt("persist") },
				Commit:  func() error { committed = true; return failAt("commit") },
			})
			if (err == nil) != (failure == "none") {
				t.Fatalf("failure %s: %v", failure, err)
			}
			if (failure == "open" || failure == "partial-open" || failure == "read" || failure == "before") && prepared {
				t.Fatal("unwitnessed mutation prepared")
			}
			if (failure == "prepare" || failure == "after" || failure == "cancel") && (persisted || committed) {
				t.Fatal("failed mutation persisted or committed")
			}
			if failure == "persist" && committed {
				t.Fatal("failed persistence committed")
			}
			assertTransactionConnectionsClosed(t, manager, *opened)
		})
	}
}

func TestRecoverableMutationRetriesWithFreshConnection(t *testing.T) {
	manager, opened := trackedTransactionManager(t)
	factory := manager.newTransactionConn
	manager.newTransactionConn = func() (nftablesTransactionConnection, error) {
		connection, err := factory()
		if len(*opened) == 1 {
			connection.(*trackedTransactionConnection).flushErr = errors.New("injected failed batch")
		}
		return connection, err
	}
	noop := func() error { return nil }
	err := manager.RunRecoverableMutation(context.Background(), RecoverableMutation{Entry: "192.0.2.44", Present: true, Permanent: true}, RecoverableMutationHooks{
		ObserveBefore: func(snapshot NativeRuntimeEntrySnapshot) error {
			if snapshot.Present {
				t.Fatal("unexpected initial claim")
			}
			return nil
		},
		Prepare: noop, Persist: noop, Commit: noop,
		ObserveAfter: func(snapshot NativeRuntimeEntrySnapshot) error {
			if !snapshot.Present || !snapshot.Permanent {
				t.Fatal("retry was not witnessed")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(*opened) != 3 || (*opened)[0].flushCalls != 1 || (*opened)[1].flushCalls != 1 {
		t.Fatalf("retry did not replace the failed connection: %+v", *opened)
	}
	assertTransactionConnectionsClosed(t, manager, *opened)
}

func TestFailedRetryAndSnapshotCallbackCloseAllConnections(t *testing.T) {
	manager, opened := trackedTransactionManager(t)
	factory := manager.newTransactionConn
	manager.newTransactionConn = func() (nftablesTransactionConnection, error) {
		connection, err := factory()
		connection.(*trackedTransactionConnection).flushErr = errors.New("both batches fail")
		return connection, err
	}
	noop := func() error { return nil }
	witness := func(NativeRuntimeEntrySnapshot) error { return nil }
	err := manager.RunRecoverableMutation(context.Background(), RecoverableMutation{Entry: "192.0.2.44", Present: true, Permanent: true}, RecoverableMutationHooks{
		ObserveBefore: witness, Prepare: noop, ObserveAfter: witness,
		Persist: func() error { t.Fatal("failed retry persisted"); return nil }, Commit: noop,
	})
	if err == nil || len(*opened) != 3 {
		t.Fatalf("failed retry did not discard its final batch: %v", err)
	}
	assertTransactionConnectionsClosed(t, manager, *opened)
	callbackErr := errors.New("consumer failed")
	err = manager.WithNativeRuntimeSnapshot(context.Background(), nil, func([]NativeRuntimeEntrySnapshot) error { return callbackErr })
	if !errors.Is(err, callbackErr) {
		t.Fatalf("lost consumer error: %v", err)
	}
	assertTransactionConnectionsClosed(t, manager, *opened)
}

func TestMutationWitnessReadsTargetFamilyAndInventoryStillRejectsForeignClaims(t *testing.T) {
	for _, entry := range []string{"192.0.2.44", "2001:db8::44"} {
		t.Run(entry, func(t *testing.T) {
			manager, opened := trackedTransactionManager(t)
			noop := func() error { return nil }
			witness := func(NativeRuntimeEntrySnapshot) error { return nil }
			err := manager.RunRecoverableMutation(context.Background(), RecoverableMutation{Entry: entry, Present: true, Permanent: true}, RecoverableMutationHooks{ObserveBefore: witness, Prepare: noop, ObserveAfter: witness, Persist: noop, Commit: noop})
			if err != nil {
				t.Fatal(err)
			}
			wanted, foreign := "banned_ips", "banned_ips6"
			foreignEntry := "2001:db8::45"
			if entry == "2001:db8::44" {
				wanted, foreign = foreign, wanted
				foreignEntry = "192.0.2.45"
			}
			for _, connection := range *opened {
				if connection.reads[wanted] == 0 || connection.reads[foreign] != 0 {
					t.Fatalf("unexpected mutation inventory reads: %v", connection.reads)
				}
			}
			assertTransactionConnectionsClosed(t, manager, *opened)
			if err := manager.BanPermanent(foreignEntry); err != nil {
				t.Fatal(err)
			}
			consumed := false
			err = manager.WithNativeRuntimeSnapshot(context.Background(), []string{entry}, func([]NativeRuntimeEntrySnapshot) error { consumed = true; return nil })
			if err == nil || consumed {
				t.Fatal("authoritative inventory accepted an untracked other-family claim")
			}
			if (*opened)[len(*opened)-1].reads[foreign] == 0 {
				t.Fatal("authoritative inventory omitted the other family")
			}
			assertTransactionConnectionsClosed(t, manager, *opened)
		})
	}
}
