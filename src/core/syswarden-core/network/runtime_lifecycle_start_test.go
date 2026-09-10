package network

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"syswarden-core/firewall"
)

func TestRuntimeLifecycleStartupRestoresOnlyRetainedLiveClaims(t *testing.T) {
	directory := filepath.Join(lifecyclePrivateTestDirectory(t), "history")
	native := &lifecycleNativeFixture{entries: make(map[string]firewall.NativeRuntimeEntrySnapshot)}
	manager, closeStore, err := prepareRuntimeLifecycleAt(context.Background(), native, directory, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeStore)
	initial, _, err := manager.store.load()
	if err != nil {
		t.Fatal(err)
	}
	native.now, _ = runtimeLifecycleTime(initial.UpdatedAt)
	native.now = native.now.Add(time.Second)
	manager.now = func() time.Time { return native.now }
	for entry, ttl := range map[string]time.Duration{"192.0.2.2": time.Minute, "192.0.2.3": 2 * time.Minute} {
		if err := manager.BanWithTTL(entry, ttl); err != nil {
			t.Fatal(err)
		}
	}
	for _, entry := range []string{"192.0.2.1", "192.0.2.4"} {
		if err := manager.BanPermanent(entry); err != nil {
			t.Fatal(err)
		}
	}
	if err := manager.Unban("192.0.2.4"); err != nil {
		t.Fatal(err)
	}
	closeStore()
	// Simulate loss of volatile kernel sets during a real host restart.
	native.entries = make(map[string]firewall.NativeRuntimeEntrySnapshot)
	native.now = native.now.Add(65*time.Second + 100*time.Millisecond)
	restarted, closeRestart, err := prepareRuntimeLifecycleAt(context.Background(), native, directory, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(closeRestart)
	restarted.now = func() time.Time { return native.now }
	if err := restarted.restoreRetainedClaims(); err != nil {
		t.Fatal(err)
	}
	if len(native.entries) != 2 || !native.entries["192.0.2.1"].Permanent || native.entries["192.0.2.3"].ExpiresAt.Sub(native.now) != 55*time.Second {
		t.Fatalf("restart resurrected a terminal claim or reset the full TTL: %+v", native.entries)
	}
	snapshot, err := restarted.RuntimeLifecycleStateSnapshot(1024)
	if err != nil || snapshot.Identity != initial.Identity || snapshot.Active != 2 || snapshot.Expired != 1 || snapshot.Tombstoned != 1 {
		t.Fatalf("restart lost anchored history or native absence: %+v, %v", snapshot, err)
	}
}

func TestRuntimeLifecycleStartupRefusesExistingEmptyDirectory(t *testing.T) {
	native := &lifecycleNativeFixture{entries: make(map[string]firewall.NativeRuntimeEntrySnapshot)}
	directory := filepath.Join(lifecyclePrivateTestDirectory(t), "history")
	root, err := os.OpenRoot(filepath.Dir(directory))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := root.Mkdir("history", 0700); err != nil {
		t.Fatal(err)
	}
	if _, closeStore, err := prepareRuntimeLifecycleAt(context.Background(), native, directory, os.Geteuid()); err == nil {
		closeStore()
		t.Fatal("existing empty history was silently initialized")
	}
	if _, err := root.Lstat("history/anchor.json"); !os.IsNotExist(err) {
		t.Fatal("failed startup fabricated an anchor")
	}
}
