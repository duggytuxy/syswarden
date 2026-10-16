package network

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"syswarden-core/firewall"
)

func TestRuntimeLifecycleFencedStartupRestoresOnlyDurableClaims(t *testing.T) {
	for _, populated := range []bool{false, true} {
		name := "empty"
		if populated {
			name = "retained_claims"
		}
		t.Run(name, func(t *testing.T) {
			manager, native := lifecycleManagerFixture(t)
			if populated {
				for entry, ttl := range map[string]time.Duration{"192.0.2.1": time.Minute, "192.0.2.2": 2 * time.Minute} {
					if err := manager.BanWithTTL(entry, ttl); err != nil {
						t.Fatal(err)
					}
				}
				for _, entry := range []string{"192.0.2.3", "192.0.2.4"} {
					if err := manager.BanPermanent(entry); err != nil {
						t.Fatal(err)
					}
				}
				if err := manager.Unban("192.0.2.4"); err != nil {
					t.Fatal(err)
				}
			}
			fence := newHAFenceTombstoneTestController(t, filepath.Join(t.TempDir(), "fence"))
			if err := fence.prepareForServer(); err != nil {
				t.Fatal(err)
			}
			publishHAFenceTestTombstones(t, fence, []haFenceEpochEvent{testHAFenceEngagementEvent()})
			publishHAFenceTestState(t, fence, activeHAFenceTestState(3))
			if err := fence.prepareForServer(); err != nil {
				t.Fatal(err)
			}
			manager.operatorFence = fence
			retained := readHAFenceTestState(t, fence)
			root, err := fence.openDirectory(false)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			tombstones, err := root.ReadFile(haFenceTombstonesName)
			if err != nil {
				t.Fatal(err)
			}
			native.entries = make(map[string]firewall.NativeRuntimeEntrySnapshot)
			native.now = native.now.Add(65*time.Second + 100*time.Millisecond)
			native.afterApply = func() error {
				root, err := fence.openDirectory(false)
				if err != nil {
					return err
				}
				defer root.Close()
				if lease, err := openHAFenceLockMode(root, fence.expectedOwnerUID, true, true); err == nil {
					closeHAFenceLock(lease)
					return errors.New("exclusive fence transition crossed startup restoration")
				}
				return nil
			}
			if err := manager.restoreRetainedClaimsAtStartup(); err != nil {
				t.Fatal(err)
			}
			if populated {
				if len(native.entries) != 2 || !native.entries["192.0.2.3"].Permanent || native.entries["192.0.2.2"].ExpiresAt.Sub(native.now) != 55*time.Second {
					t.Fatalf("startup changed durable ownership or extended the original TTL: %+v", native.entries)
				}
			} else if len(native.entries) != 0 {
				t.Fatal("empty startup invented a claim")
			}
			if after := readHAFenceTestState(t, fence); !reflect.DeepEqual(after, retained) {
				t.Fatal("startup changed the active fence")
			}
			after, err := root.ReadFile(haFenceTombstonesName)
			if err != nil || !bytes.Equal(tombstones, after) {
				t.Fatal("startup changed epoch tombstones")
			}
			called := false
			if err := manager.withOperatorFence(func() error { called = true; return nil }); err == nil || called {
				t.Fatal("startup enabled new operator writes")
			}
			if err := fence.withLegacyMutation("POST", nil, func() { called = true }); err == nil || called {
				t.Fatal("startup enabled legacy writes")
			}
			if err := fence.withLock(true, false, func(*os.Root) error { return nil }); err != nil {
				t.Fatalf("startup leaked its read lease: %v", err)
			}
		})
	}
}

func TestRuntimeLifecycleStartupRefusesUnsafeFenceBeforeMutation(t *testing.T) {
	for _, stateName := range []string{haFenceStateEngaging, haFenceStateRecovering, haFenceStateError, "malformed", "busy"} {
		t.Run(stateName, func(t *testing.T) {
			manager, native := lifecycleManagerFixture(t)
			if err := manager.BanPermanent("192.0.2.1"); err != nil {
				t.Fatal(err)
			}
			native.entries = make(map[string]firewall.NativeRuntimeEntrySnapshot)
			fence := newHAFenceTombstoneTestController(t, filepath.Join(t.TempDir(), "fence"))
			if err := fence.prepareForServer(); err != nil {
				t.Fatal(err)
			}
			manager.operatorFence = fence
			switch stateName {
			case "malformed":
				if err := os.WriteFile(filepath.Join(fence.directory, haFenceStateName), []byte("{broken\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "busy":
				root, err := fence.openDirectory(false)
				if err != nil {
					t.Fatal(err)
				}
				defer root.Close()
				lease, err := openHAFenceLockMode(root, fence.expectedOwnerUID, true, true)
				if err != nil {
					t.Fatal(err)
				}
				defer closeHAFenceLock(lease)
			default:
				state := activeHAFenceTestState(3)
				state.State = stateName
				state.Condition = ""
				state.DrainedAt = nil
				publishHAFenceTestState(t, fence, state)
			}
			before, _, err := manager.store.load()
			if err != nil {
				t.Fatal(err)
			}
			if err := manager.restoreRetainedClaimsAtStartup(); err == nil {
				t.Fatal("unsafe fence admitted startup restoration")
			}
			after, pending, err := manager.store.load()
			if err != nil || pending != nil || after.Sequence != before.Sequence || len(native.entries) != 0 {
				t.Fatal("refused startup changed history or kernel state")
			}
		})
	}
}

func TestRuntimeLifecycleFencedStartupStillRefusesPendingHistory(t *testing.T) {
	manager, native := lifecycleManagerFixture(t)
	fence := newHAFenceTombstoneTestController(t, filepath.Join(t.TempDir(), "fence"))
	if err := fence.prepareForServer(); err != nil {
		t.Fatal(err)
	}
	publishHAFenceTestState(t, fence, activeHAFenceTestState(3))
	manager.operatorFence = fence
	intent := runtimeLifecycleIntent{Entry: "192.0.2.1", Present: true, Permanent: true, PreparedAt: native.now.Format(time.RFC3339Nano)}
	if err := manager.store.prepare(intent); err != nil {
		t.Fatal(err)
	}
	if err := manager.restoreRetainedClaimsAtStartup(); err == nil {
		t.Fatal("startup bypassed pending native recovery")
	}
	_, pending, err := manager.store.load()
	if err != nil || pending == nil || len(native.entries) != 0 {
		t.Fatal("startup changed pending recovery or native state")
	}
}
