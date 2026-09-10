package network

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"syswarden-core/firewall"
)

type runtimeLifecycleManager struct {
	mu            sync.Mutex
	underlying    firewall.Manager
	mutator       firewall.RecoverableMutationManager
	reader        firewall.NativeRuntimeStateReader
	store         *runtimeLifecycleStore
	ctx           context.Context
	now           func() time.Time
	lastErr       error
	operatorFence *haFenceController
	operatorUnban func(string) error
}

func newRuntimeLifecycleManager(ctx context.Context, underlying firewall.Manager, store *runtimeLifecycleStore) (*runtimeLifecycleManager, error) {
	mutator, canMutate := underlying.(firewall.RecoverableMutationManager)
	reader, canRead := underlying.(firewall.NativeRuntimeStateReader)
	if ctx == nil || underlying == nil || store == nil || !canMutate || !canRead {
		return nil, fmt.Errorf("runtime lifecycle requires a durable store and an authoritative native manager")
	}
	if _, pending, err := store.load(); err != nil {
		return nil, err
	} else if pending != nil {
		return nil, fmt.Errorf("runtime lifecycle has an unwitnessed pending mutation; native recovery is required")
	}
	return &runtimeLifecycleManager{underlying: underlying, mutator: mutator, reader: reader, store: store, ctx: ctx, now: time.Now}, nil
}

func (manager *runtimeLifecycleManager) Name() string {
	return manager.underlying.Name() + " + durable lifecycle"
}

func (manager *runtimeLifecycleManager) Health() firewall.HealthState {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.lastErr != nil {
		return firewall.HealthDegraded
	}
	if reporter, available := manager.underlying.(firewall.HealthReporter); available {
		return reporter.Health()
	}
	return firewall.HealthUnavailable
}

func (manager *runtimeLifecycleManager) BanExpiryMode() firewall.BanExpiryMode {
	return firewall.BanExpiryNative
}

func (manager *runtimeLifecycleManager) Ban(entry string) error {
	return manager.BanWithTTL(entry, firewall.MaximumBanTTL)
}

func (manager *runtimeLifecycleManager) BanWithTTL(entry string, ttl time.Duration) error {
	return manager.mutate(firewall.RecoverableMutation{Entry: entry, Present: true, TTL: ttl, PreserveStronger: true})
}

func (manager *runtimeLifecycleManager) ReconcileBanTTL(entry string, ttl time.Duration) error {
	return manager.mutate(firewall.RecoverableMutation{Entry: entry, Present: true, TTL: ttl})
}

func (manager *runtimeLifecycleManager) BanPermanent(entry string) error {
	return manager.mutate(firewall.RecoverableMutation{Entry: entry, Present: true, Permanent: true})
}

func (manager *runtimeLifecycleManager) Unban(entry string) error {
	return manager.mutate(firewall.RecoverableMutation{Entry: entry})
}

func runtimeWitness(snapshot firewall.NativeRuntimeEntrySnapshot) runtimeLifecycleWitness {
	return runtimeLifecycleWitness{Complete: true, Present: snapshot.Present, Permanent: snapshot.Permanent, ExpiresAt: snapshot.ExpiresAt}
}

func (manager *runtimeLifecycleManager) mutate(mutation firewall.RecoverableMutation) (resultErr error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	defer func() { manager.lastErr = resultErr }()
	if !canonicalRuntimeLifecycleEntry(mutation.Entry) {
		return fmt.Errorf("runtime lifecycle mutation entry must be canonical")
	}
	model, pending, err := manager.store.load()
	if err != nil {
		return err
	}
	if pending != nil {
		return fmt.Errorf("runtime lifecycle mutation is fenced by pending recovery")
	}
	if err := validateRuntimeLifecycleOverlap(model, mutation.Entry); err != nil {
		return err
	}
	var before firewall.NativeRuntimeEntrySnapshot
	var candidate runtimeLifecycleModel
	return manager.mutator.RunRecoverableMutation(manager.ctx, mutation, firewall.RecoverableMutationHooks{
		ObserveBefore: func(snapshot firewall.NativeRuntimeEntrySnapshot) error {
			before = snapshot
			if snapshot.Entry != mutation.Entry {
				return fmt.Errorf("native pre-mutation witness belongs to another entry")
			}
			if !mutation.Present {
				if record, exists := model.lookup(mutation.Entry); exists {
					if snapshot.Present && record.State != "active" {
						return fmt.Errorf("terminal runtime claim reappeared before operator deletion")
					}
					if !snapshot.Present && record.State == "active" {
						if _, err := model.observeAbsence(mutation.Entry, snapshot.CapturedAt, runtimeWitness(snapshot)); err != nil {
							return err
						}
					}
				}
			}
			return model.validateObservation(mutation.Entry, snapshot.CapturedAt)
		},
		Prepare: func() error {
			now := manager.now().UTC()
			intent := runtimeLifecycleIntent{Entry: mutation.Entry, Present: mutation.Present, Permanent: mutation.Permanent,
				PreserveStronger: mutation.PreserveStronger, PreparedAt: now.Format(time.RFC3339Nano)}
			if mutation.Present && !mutation.Permanent {
				intent.ExpiresAt = now.Add(mutation.TTL).Format(time.RFC3339Nano)
			}
			return manager.store.prepare(intent)
		},
		ObserveAfter: func(after firewall.NativeRuntimeEntrySnapshot) error {
			if after.Entry != mutation.Entry || after.CapturedAt.Before(before.CapturedAt) {
				return fmt.Errorf("native post-mutation witness has the wrong identity or chronology")
			}
			var err error
			if mutation.Present {
				candidate, err = model.verifiedBan(mutation.Entry, after.CapturedAt, runtimeWitness(after))
			} else {
				candidate, err = model.verifiedDeletion(mutation.Entry, after.CapturedAt, runtimeWitness(before), runtimeWitness(after))
			}
			return err
		},
		Persist: func() error { return manager.store.commit(candidate) },
		Commit:  func() error { return nil },
	})
}

func (manager *runtimeLifecycleManager) RuntimeLifecycleStateSnapshot(limit int) (snapshot firewall.RuntimeLifecycleSnapshot, resultErr error) {
	if limit < 1 || limit > 1024 {
		return snapshot, fmt.Errorf("runtime lifecycle snapshot limit must be between 1 and 1024")
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	defer func() { manager.lastErr = resultErr }()
	model, pending, err := manager.store.load()
	if err != nil {
		return snapshot, err
	}
	if pending != nil {
		return snapshot, fmt.Errorf("runtime lifecycle snapshot is fenced by pending recovery")
	}
	entries := make([]string, 0, len(model.Records))
	for _, record := range model.Records {
		entries = append(entries, record.Entry)
	}
	err = manager.reader.WithNativeRuntimeSnapshot(manager.ctx, entries, func(witnesses []firewall.NativeRuntimeEntrySnapshot) error {
		if len(witnesses) != len(model.Records) {
			return fmt.Errorf("native runtime inventory has the wrong size")
		}
		candidate := model
		now := manager.now().UTC()
		updated, _ := runtimeLifecycleTime(model.UpdatedAt)
		if now.Before(updated) {
			return fmt.Errorf("native runtime capture clock moved behind its durable history")
		}
		for index, witness := range witnesses {
			record := model.Records[index]
			if witness.Entry != record.Entry || witness.CapturedAt.After(now) || witness.CapturedAt.Before(now.Add(-5*time.Second)) {
				return fmt.Errorf("native runtime inventory identity or capture time is invalid")
			}
			if witness.Present {
				if record.State != "active" || witness.Permanent != (record.ExpiresAt == "") {
					return fmt.Errorf("native runtime presence contradicts durable claim %s", record.Entry)
				}
				if !witness.Permanent {
					expiry, _ := runtimeLifecycleTime(record.ExpiresAt)
					if !expiry.After(now) || !witness.ExpiresAt.After(now) {
						return fmt.Errorf("native runtime claim expired during capture for %s", record.Entry)
					}
					delta := witness.ExpiresAt.Sub(expiry)
					if delta < -2*time.Second || delta > 2*time.Second {
						return fmt.Errorf("native runtime expiry changed outside the durable claim %s", record.Entry)
					}
				}
				continue
			}
			var err error
			candidate, err = candidate.observeAbsence(record.Entry, now, runtimeWitness(witness))
			if err != nil {
				return err
			}
		}
		if candidate.Sequence != model.Sequence {
			if err := manager.store.commit(candidate); err != nil {
				return err
			}
		}
		digest, err := candidate.digest()
		if err != nil {
			return err
		}
		snapshot = firewall.RuntimeLifecycleSnapshot{SchemaVersion: 1, Identity: candidate.Identity, Sequence: candidate.Sequence,
			ModelSHA256: digest, UpdatedAt: candidate.UpdatedAt, CapturedAt: now.Format(time.RFC3339Nano),
			Truncated: len(candidate.Records) > limit, Claims: []firewall.RuntimeLifecycleClaimSnapshot{}}
		for _, record := range candidate.Records {
			switch record.State {
			case "active":
				snapshot.Active++
			case "deleted":
				snapshot.Deleted++
			case "expired":
				snapshot.Expired++
			case "tombstoned":
				snapshot.Tombstoned++
			}
			if len(snapshot.Claims) < limit {
				snapshot.Claims = append(snapshot.Claims, firewall.RuntimeLifecycleClaimSnapshot(record))
			}
		}
		return nil
	})
	return snapshot, err
}

// One native interval must have one durable identity. Refuse overlapping
// targets rather than reporting a point unblocked inside a retained prefix,
// or letting a wider deletion silently remove another active claim.
func validateRuntimeLifecycleOverlap(model runtimeLifecycleModel, entry string) error {
	toPrefix := func(value string) netip.Prefix {
		if prefix, err := netip.ParsePrefix(value); err == nil {
			return prefix
		}
		address, _ := netip.ParseAddr(value)
		return netip.PrefixFrom(address, address.BitLen())
	}
	target := toPrefix(entry)
	if !target.IsValid() {
		return fmt.Errorf("runtime lifecycle target is invalid")
	}
	for _, record := range model.Records {
		if record.State == "active" && record.Entry != entry && target.Overlaps(toPrefix(record.Entry)) {
			return fmt.Errorf("runtime target overlaps active claim %s; operate on that exact claim first", record.Entry)
		}
	}
	return nil
}
