package network

import (
	"net/http"
	"testing"
	"time"
)

func TestHANativeLedgerExpiryPreservesPhysicalExpiryCause(t *testing.T) {
	manager, native := lifecycleManagerFixture(t)
	native.now = native.now.Add(900 * time.Millisecond)
	base := native.now
	fixture := newHAAPITestFixture(t, manager, []string{"9.9.9.10"})
	fixture.api.now = func() time.Time { return native.now }
	response := requestDirectHAHandler(t, fixture.handler, http.MethodPost, "Bearer shared-secret",
		`{"ip":"8.8.4.90","ttl":60,"reason":"native expiry regression","source":"bunkerweb"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("temporary POST = %d, %q", response.Code, response.Body.String())
	}
	for second := 1; second < 60; second++ {
		native.now = base.Add(time.Duration(second) * time.Second)
		if err := fixture.api.reconcileHABans(native.now, maxHALedgerRecords); err != nil {
			t.Fatal(err)
		}
	}
	// The ledger uses whole seconds. The witnessed kernel deadline is later.
	native.now = base.Truncate(time.Second).Add(60*time.Second + 100*time.Millisecond)
	if err := fixture.api.reconcileHABans(native.now, maxHALedgerRecords); err != nil {
		t.Fatal(err)
	}
	snapshot, err := manager.RuntimeLifecycleStateSnapshot(10)
	if err != nil || len(snapshot.Claims) != 1 || snapshot.Claims[0].State != "active" {
		t.Fatalf("ledger expiry deleted a still-live native ban: %+v, %v", snapshot, err)
	}
	ledger, err := fixture.api.readHALedger()
	if err != nil || len(ledger.Bans) != 0 {
		t.Fatalf("expired ledger was not finalized: %+v, %v", ledger, err)
	}
	native.now = base.Add(61 * time.Second)
	snapshot, err = manager.RuntimeLifecycleStateSnapshot(10)
	if err != nil || snapshot.Expired != 1 || snapshot.Claims[0].Cause != "native-expiry" {
		t.Fatalf("physical expiry lost its cause: %+v, %v", snapshot, err)
	}
	native.now = native.now.Add(30 * time.Second)
	snapshot, err = manager.RuntimeLifecycleStateSnapshot(10)
	if err != nil || snapshot.Tombstoned != 1 || snapshot.Claims[0].Cause != "native-expiry" {
		t.Fatalf("confirmed native expiry lost its cause: %+v, %v", snapshot, err)
	}
}

func TestHANativeLedgerExpiryPreservesStrongerNativeBan(t *testing.T) {
	manager, native := lifecycleManagerFixture(t)
	base := native.now
	if err := manager.BanWithTTL("8.8.4.90", 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	fixture := newHAAPITestFixture(t, manager, []string{"9.9.9.10"})
	fixture.api.now = func() time.Time { return native.now }
	response := requestDirectHAHandler(t, fixture.handler, http.MethodPost, "Bearer shared-secret",
		`{"ip":"8.8.4.90","ttl":60,"reason":"shorter HA claim","source":"bunkerweb"}`)
	if response.Code != http.StatusOK {
		t.Fatalf("temporary POST = %d, %q", response.Code, response.Body.String())
	}
	native.now = base.Add(61 * time.Second)
	if err := fixture.api.reconcileHABans(native.now, maxHALedgerRecords); err != nil {
		t.Fatal(err)
	}
	snapshot, err := manager.RuntimeLifecycleStateSnapshot(10)
	if err != nil || snapshot.Active != 1 || snapshot.Claims[0].ExpiresAt != base.Add(10*time.Minute).Format(time.RFC3339Nano) {
		t.Fatalf("expired HA claim removed a stronger native ban: %+v, %v", snapshot, err)
	}
}

func TestHANativeExpiryRecoveryKeepsExplicitDeletionDistinct(t *testing.T) {
	for _, state := range []string{haBanActive, haBanPendingApply, haBanPendingDelete} {
		t.Run(state, func(t *testing.T) {
			manager, native := lifecycleManagerFixture(t)
			base := native.now
			if err := manager.BanWithTTL("8.8.4.90", 10*time.Minute); err != nil {
				t.Fatal(err)
			}
			fixture := newHAAPITestFixture(t, manager, []string{"9.9.9.10"})
			addHAActiveTemporaryRecord(t, fixture, "8.8.4.90", "bunkerweb", base, time.Minute)
			if err := fixture.api.mutateHALedger(func(ledger *haBanLedger) error {
				ledger.Bans[0].State = state
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			native.now = base.Add(61 * time.Second)
			if err := fixture.api.reconcileHABans(native.now, maxHALedgerRecords); err != nil {
				t.Fatal(err)
			}
			snapshot, err := manager.RuntimeLifecycleStateSnapshot(10)
			expected := "active"
			if state == haBanPendingDelete {
				expected = "deleted"
			}
			if err != nil || len(snapshot.Claims) != 1 || snapshot.Claims[0].State != expected {
				t.Fatalf("recovered %s ledger changed native intent: %+v, %v", state, snapshot, err)
			}
			ledger, err := fixture.api.readHALedger()
			if err != nil || len(ledger.Bans) != 0 {
				t.Fatalf("recovery did not finalize elapsed ledger: %+v, %v", ledger, err)
			}
		})
	}
}

func TestHANativeExpiryReleasesNewlyWhitelistedTarget(t *testing.T) {
	manager, native := lifecycleManagerFixture(t)
	base := native.now
	if err := manager.BanWithTTL("8.8.4.90", 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	fixture := newHAAPITestFixture(t, manager, []string{"9.9.9.10"})
	addHAActiveTemporaryRecord(t, fixture, "8.8.4.90", "bunkerweb", base, time.Minute)
	fixture.api.isWhitelisted = func(string) (bool, error) { return true, nil }
	native.now = base.Add(61 * time.Second)
	if err := fixture.api.reconcileHABans(native.now, maxHALedgerRecords); err != nil {
		t.Fatal(err)
	}
	snapshot, err := manager.RuntimeLifecycleStateSnapshot(10)
	if err != nil || snapshot.Deleted != 1 {
		t.Fatalf("expiry retained a newly whitelisted ban: %+v, %v", snapshot, err)
	}
}
