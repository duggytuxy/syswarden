package network

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"syswarden-core/firewall"
)

type lifecycleNativeFixture struct {
	now        time.Time
	entries    map[string]firewall.NativeRuntimeEntrySnapshot
	afterApply func() error
	readErr    error
}

func (native *lifecycleNativeFixture) Name() string     { return "native fixture" }
func (native *lifecycleNativeFixture) Ban(string) error { return errors.New("unguarded ban reached") }
func (native *lifecycleNativeFixture) Unban(string) error {
	return errors.New("unguarded unban reached")
}
func (native *lifecycleNativeFixture) Health() firewall.HealthState { return firewall.HealthHealthy }

func (native *lifecycleNativeFixture) witness(entry string) firewall.NativeRuntimeEntrySnapshot {
	witness := native.entries[entry]
	if !witness.ExpiresAt.IsZero() && !native.now.Before(witness.ExpiresAt) {
		delete(native.entries, entry)
		witness = firewall.NativeRuntimeEntrySnapshot{}
	}
	witness.Entry, witness.CapturedAt = entry, native.now
	return witness
}

func (native *lifecycleNativeFixture) RunRecoverableMutation(ctx context.Context, mutation firewall.RecoverableMutation, hooks firewall.RecoverableMutationHooks) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	before := native.witness(mutation.Entry)
	if err := hooks.ObserveBefore(before); err != nil {
		return err
	}
	if err := hooks.Prepare(); err != nil {
		return err
	}
	if mutation.Present {
		next := firewall.NativeRuntimeEntrySnapshot{Present: true, Permanent: mutation.Permanent}
		if !mutation.Permanent {
			next.ExpiresAt = native.now.Add(mutation.TTL)
		}
		if mutation.PreserveStronger && before.Present && (before.Permanent || before.ExpiresAt.After(next.ExpiresAt)) {
			next = before
		}
		native.entries[mutation.Entry] = next
	} else {
		delete(native.entries, mutation.Entry)
	}
	if native.afterApply != nil {
		if err := native.afterApply(); err != nil {
			return err
		}
	}
	if err := hooks.ObserveAfter(native.witness(mutation.Entry)); err != nil {
		return err
	}
	if err := hooks.Persist(); err != nil {
		return err
	}
	return hooks.Commit()
}

func (native *lifecycleNativeFixture) WithNativeRuntimeSnapshot(ctx context.Context, entries []string, consume func([]firewall.NativeRuntimeEntrySnapshot) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if native.readErr != nil {
		return native.readErr
	}
	witnesses := make([]firewall.NativeRuntimeEntrySnapshot, 0, len(entries))
	for _, entry := range entries {
		witnesses = append(witnesses, native.witness(entry))
	}
	return consume(witnesses)
}

func lifecycleManagerFixture(t *testing.T) (*runtimeLifecycleManager, *lifecycleNativeFixture) {
	t.Helper()
	store := openLifecycleTestStore(t, lifecyclePrivateTestDirectory(t))
	_, now := lifecycleModelFixture()
	if _, err := store.initialize(now); err != nil {
		t.Fatal(err)
	}
	native := &lifecycleNativeFixture{now: now, entries: make(map[string]firewall.NativeRuntimeEntrySnapshot)}
	manager, err := newRuntimeLifecycleManager(context.Background(), native, store)
	if err != nil {
		t.Fatal(err)
	}
	manager.now = func() time.Time { return native.now }
	return manager, native
}

func TestRuntimeLifecycleManagerPublishesRealDeletionAndExpiryHistories(t *testing.T) {
	manager, native := lifecycleManagerFixture(t)
	if err := manager.Ban("192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if err := manager.BanWithTTL("192.0.2.2", time.Minute); err != nil {
		t.Fatal(err)
	}
	active, err := manager.RuntimeLifecycleStateSnapshot(1024)
	if err != nil || active.Active != 2 || len(active.Claims) != 2 {
		t.Fatalf("active projection: %+v, %v", active, err)
	}
	native.now = native.now.Add(time.Second)
	if err := manager.Unban("192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	deleted, err := manager.RuntimeLifecycleStateSnapshot(1024)
	if err != nil || deleted.Active != 1 || deleted.Deleted != 1 || deleted.Claims[0].Cause != "verified-deletion" {
		t.Fatalf("deletion projection: %+v, %v", deleted, err)
	}
	native.now = native.now.Add(30 * time.Second)
	tombstone, err := manager.RuntimeLifecycleStateSnapshot(1024)
	if err != nil || tombstone.Tombstoned != 1 || tombstone.Active != 1 {
		t.Fatalf("deletion confirmation: %+v, %v", tombstone, err)
	}
	native.now = native.now.Add(29 * time.Second)
	expired, err := manager.RuntimeLifecycleStateSnapshot(1024)
	if err != nil || expired.Expired != 1 || expired.Active != 0 || expired.Claims[1].Cause != "native-expiry" {
		t.Fatalf("native expiry projection: %+v, %v", expired, err)
	}
	native.now = native.now.Add(30 * time.Second)
	final, err := manager.RuntimeLifecycleStateSnapshot(1024)
	if err != nil || final.Tombstoned != 2 || final.Expired != 0 {
		t.Fatalf("expiry confirmation: %+v, %v", final, err)
	}
	if active.ModelSHA256 == final.ModelSHA256 || final.Sequence <= active.Sequence || active.Claims[0].State != "active" {
		t.Fatal("durable projection identity or immutable snapshot did not advance")
	}
}

func TestRuntimeLifecycleManagerFencesUnwitnessedMutationAcrossRestart(t *testing.T) {
	manager, native := lifecycleManagerFixture(t)
	native.afterApply = func() error { return errors.New("injected failure after kernel mutation") }
	if err := manager.Ban("192.0.2.3"); err == nil {
		t.Fatal("injected native ambiguity was ignored")
	}
	if !native.entries["192.0.2.3"].Present {
		t.Fatal("fixture did not exercise the post-kernel failure boundary")
	}
	if manager.Health() != firewall.HealthDegraded {
		t.Fatal("ambiguous mutation remained healthy")
	}
	if _, err := manager.RuntimeLifecycleStateSnapshot(1024); err == nil {
		t.Fatal("prepared intent was exposed as complete evidence")
	}
	if err := manager.Unban("192.0.2.3"); err == nil {
		t.Fatal("new operation bypassed unresolved recovery")
	}
	path := manager.store.path
	manager.store.close()
	reopened := openLifecycleTestStore(t, path)
	if _, err := newRuntimeLifecycleManager(context.Background(), native, reopened); err == nil {
		t.Fatal("restart bypassed ambiguous native recovery")
	}
}

func TestRuntimeLifecycleManagerRefusesDriftAndUnverifiedAbsence(t *testing.T) {
	for _, fault := range []string{"missing", "expiry-changed", "read-failure"} {
		t.Run(fault, func(t *testing.T) {
			manager, native := lifecycleManagerFixture(t)
			if err := manager.BanWithTTL("192.0.2.4", time.Minute); err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "missing":
				delete(native.entries, "192.0.2.4")
			case "expiry-changed":
				entry := native.entries["192.0.2.4"]
				entry.ExpiresAt = entry.ExpiresAt.Add(time.Minute)
				native.entries["192.0.2.4"] = entry
			case "read-failure":
				native.readErr = errors.New("incomplete netlink read")
			}
			if _, err := manager.RuntimeLifecycleStateSnapshot(1024); err == nil {
				t.Fatal("drift or missing kernel evidence became a complete snapshot")
			}
			model, pending, err := manager.store.load()
			if err != nil || pending != nil || model.Records[0].State != "active" {
				t.Fatal("unverified drift rewrote authoritative history")
			}
		})
	}
}

func TestRuntimeLifecycleManagerPreservesStrongerAndBoundsProjection(t *testing.T) {
	manager, native := lifecycleManagerFixture(t)
	for index := 1; index <= 3; index++ {
		if err := manager.BanPermanent(fmt.Sprintf("192.0.2.%d", index)); err != nil {
			t.Fatal(err)
		}
	}
	native.now = native.now.Add(time.Second)
	if err := manager.BanWithTTL("192.0.2.1", time.Minute); err != nil {
		t.Fatal(err)
	}
	snapshot, err := manager.RuntimeLifecycleStateSnapshot(2)
	if err != nil || !snapshot.Truncated || snapshot.Active != 3 || len(snapshot.Claims) != 2 || snapshot.Claims[0].ExpiresAt != "" {
		t.Fatalf("bounded stronger-preserving projection: %+v, %v", snapshot, err)
	}
	for _, limit := range []int{0, 1025} {
		if _, err := manager.RuntimeLifecycleStateSnapshot(limit); err == nil {
			t.Fatal("invalid projection bound accepted")
		}
	}
	if err := manager.Unban("198.51.100.9"); err != nil {
		t.Fatalf("verified absent no-op failed: %v", err)
	}
}

func TestRuntimeLifecycleRefusesOverlappingClaimsBeforeNativeMutation(t *testing.T) {
	manager, native := lifecycleManagerFixture(t)
	if err := manager.BanPermanent("192.0.2.0/24"); err != nil {
		t.Fatal(err)
	}
	for _, entry := range []string{"192.0.2.10", "192.0.2.0", "192.0.2.0/25", "192.0.0.0/16"} {
		if err := manager.Unban(entry); err == nil {
			t.Fatalf("partial or wider deletion falsely succeeded for %s", entry)
		}
		if err := manager.Ban(entry); err == nil {
			t.Fatalf("overlapping claim bypassed durable interval identity: %s", entry)
		}
	}
	if len(native.entries) != 1 || !native.entries["192.0.2.0/24"].Present {
		t.Fatal("rejected overlap changed native state")
	}
	if err := manager.Unban("192.0.2.0/24"); err != nil {
		t.Fatal(err)
	}
	if err := manager.BanPermanent("192.0.2.10"); err != nil {
		t.Fatalf("removed prefix still blocked a new point claim: %v", err)
	}
}
