package network

import (
	"fmt"
	"os"
	"reflect"
	"slices"
	"sync"
)

// HAStartupLease reserves the HA v2 process lease before stateful daemon
// initialization. The reservation may be consumed by startup only once.
type HAStartupLease struct {
	mu       sync.Mutex
	cfg      HAConfig
	store    *haV2TransactionStore
	consumed bool
}

// ReserveHAStartupLease must precede telemetry initialization and any shared
// HA state preparation. Legacy HA does not require a reservation.
func ReserveHAStartupLease() (*HAStartupLease, error) {
	cfg := loadHAConfig()
	if !cfg.V2Enabled {
		return nil, nil
	}
	return reserveHARuntimeV2Lease(cfg)
}

func reserveHARuntimeV2Lease(cfg HAConfig) (*HAStartupLease, error) {
	if err := validateHARuntimeV2Config(cfg); err != nil {
		return nil, err
	}
	store, err := newHAV2TransactionStore(cfg.StateFile, cfg.TransactionFile, os.Geteuid())
	if err != nil {
		return nil, err
	}
	if err := store.acquireInstanceLock(); err != nil {
		return nil, err
	}
	cfg.PeerIPs = slices.Clone(cfg.PeerIPs)
	cfg.PeerCertSHA256 = slices.Clone(cfg.PeerCertSHA256)
	cfg.BunkerWebSchedulerIPs = slices.Clone(cfg.BunkerWebSchedulerIPs)
	return &HAStartupLease{cfg: cfg, store: store}, nil
}

// Close releases an unconsumed reservation. After startup takes ownership,
// its failure cleanup or process-lifetime retention owns the same lease.
func (lease *HAStartupLease) Close() {
	if lease == nil {
		return
	}
	lease.mu.Lock()
	store := lease.store
	lease.store = nil
	lease.mu.Unlock()
	if store != nil {
		store.releaseInstanceLock()
	}
}

func (lease *HAStartupLease) take(cfg HAConfig) (*haV2TransactionStore, error) {
	if lease == nil {
		return nil, fmt.Errorf("HA v2 startup requires a reserved instance lease")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.consumed {
		return nil, fmt.Errorf("HA v2 startup lease was already consumed")
	}
	if lease.store == nil {
		return nil, fmt.Errorf("HA v2 startup lease is closed")
	}
	if !reflect.DeepEqual(lease.cfg, cfg) {
		return nil, fmt.Errorf("HA v2 startup lease configuration changed")
	}
	store := lease.store
	lease.store = nil
	lease.consumed = true
	return store, nil
}
