package network

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"syswarden-core/firewall"
)

const runtimeLifecycleStateDirectory = "/var/lib/syswarden/runtime-lifecycle"

// PrepareRuntimeLifecycle installs durable native history before any legacy
// HA reconciliation or daemon worker can mutate the firewall. HA v2 keeps its
// own authoritative replicated transaction manager and journal.
func PrepareRuntimeLifecycle(ctx context.Context, underlying firewall.Manager) (firewall.Manager, func(), error) {
	cfg := loadHAConfig()
	if cfg.V2Enabled {
		return underlying, func() {}, nil
	}
	manager, closeStore, err := prepareRuntimeLifecycleAt(ctx, underlying, runtimeLifecycleStateDirectory, 0)
	if err != nil {
		return nil, nil, err
	}
	if cfg.Enabled == "y" || cfg.Enabled == "true" || cfg.Enabled == "1" {
		fence, err := prepareRuntimeLifecycleHAFence(haTLSDir, haRuntimeBanLedgerFile, 0)
		if err != nil {
			closeStore()
			return nil, nil, err
		}
		manager.operatorFence = fence
	}
	if err := manager.withOperatorFence(manager.restoreRetainedClaims); err != nil {
		closeStore()
		return nil, nil, fmt.Errorf("restore retained native runtime claims: %w", err)
	}
	return manager, closeStore, nil
}

func prepareRuntimeLifecycleHAFence(tlsDirectory, ledgerFile string, ownerUID int) (*haFenceController, error) {
	// Runtime restoration precedes HA server startup. Its fence shares the HA
	// directory, so initialize TLS first without rotating any retained identity.
	if _, err := loadOrCreateHATLSCertificate(tlsDirectory); err != nil {
		return nil, fmt.Errorf("prepare native runtime HA TLS identity: %w", err)
	}
	fence, err := newHAFenceController(filepath.Join(filepath.Dir(ledgerFile), "fence"), ownerUID)
	if err != nil {
		return nil, err
	}
	if err := fence.prepareForServer(); err != nil {
		return nil, err
	}
	return fence, nil
}

func prepareRuntimeLifecycleAt(ctx context.Context, underlying firewall.Manager, directory string, ownerUID int) (*runtimeLifecycleManager, func(), error) {
	if ctx == nil || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || ownerUID < 0 {
		return nil, nil, fmt.Errorf("invalid native runtime lifecycle startup")
	}
	parent := filepath.Dir(directory)
	info, err := os.Lstat(parent)
	if err != nil {
		return nil, nil, err
	}
	owner, ownerErr := haFenceOwnerUID(info)
	if ownerErr != nil || owner != ownerUID || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		return nil, nil, fmt.Errorf("native runtime state parent must be a real owner-controlled directory")
	}
	root, err := os.OpenRoot(parent)
	if err != nil {
		return nil, nil, err
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(info, opened) {
		return nil, nil, fmt.Errorf("native runtime state parent changed while opening")
	}
	err = root.Mkdir(filepath.Base(directory), 0700)
	created := err == nil
	if err != nil && !errors.Is(err, os.ErrExist) {
		return nil, nil, err
	}
	if created {
		parentFile, err := root.Open(".")
		if err != nil {
			return nil, nil, err
		}
		syncErr := parentFile.Sync()
		closeErr := parentFile.Close()
		if err := errors.Join(syncErr, closeErr); err != nil {
			return nil, nil, fmt.Errorf("persist native runtime directory creation: %w", err)
		}
	}
	store, err := openRuntimeLifecycleStore(directory, ownerUID)
	if err != nil {
		return nil, nil, err
	}
	if created {
		if _, err := store.initialize(time.Now().UTC()); err != nil {
			store.close()
			return nil, nil, err
		}
	}
	manager, err := newRuntimeLifecycleManager(ctx, underlying, store)
	if err != nil {
		store.close()
		return nil, nil, err
	}
	closeStore := func() {
		manager.mu.Lock()
		defer manager.mu.Unlock()
		store.close()
	}
	return manager, closeStore, nil
}

// Reapply only verified, still-live desired claims. Kernel lifetime is rounded
// upward to whole seconds, matching the native backend's precision. Expired
// records wait for an independent absence snapshot before changing state.
func (manager *runtimeLifecycleManager) restoreRetainedClaims() error {
	model, pending, err := manager.store.load()
	if err != nil {
		return err
	}
	if pending != nil {
		return fmt.Errorf("unwitnessed native mutation requires explicit recovery")
	}
	for _, record := range model.Records {
		if record.State != "active" {
			continue
		}
		if record.ExpiresAt == "" {
			if err := manager.BanPermanent(record.Entry); err != nil {
				return err
			}
			continue
		}
		expiry, err := runtimeLifecycleTime(record.ExpiresAt)
		if err != nil {
			return err
		}
		remaining := expiry.Sub(manager.now().UTC())
		if remaining <= 0 {
			continue
		}
		ttl := remaining.Truncate(time.Second)
		if ttl < remaining {
			ttl += time.Second
		}
		if ttl > firewall.MaximumBanTTL {
			ttl = firewall.MaximumBanTTL
		}
		if err := manager.BanWithTTL(record.Entry, ttl); err != nil {
			return err
		}
	}
	return nil
}
