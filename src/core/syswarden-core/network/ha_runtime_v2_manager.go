package network

import (
	"fmt"
	"sort"
	"time"

	"syswarden-core/firewall"
)

const haV2LocalRuntimeSource = "core-runtime"

// haV2ReplicatedManager is installed in front of every daemon-originated
// firewall writer only when HA v2 has passed its complete startup attestation.
// A static standby never originates mutations. A writer never mutates while
// degraded, recovering, or fenced.
type haV2ReplicatedManager struct {
	underlying firewall.Manager
	adapter    *haRuntimeV2Adapter
}

func (manager *haV2ReplicatedManager) HAReplicationStateSnapshot(limit int) (firewall.HAReplicationSnapshot, error) {
	if limit < 1 || limit > 1024 {
		return firewall.HAReplicationSnapshot{}, fmt.Errorf("HA v2 snapshot limit must be between 1 and 1024")
	}
	manager.adapter.mu.Lock()
	defer manager.adapter.mu.Unlock()
	evaluationNow := manager.adapter.now()
	now := evaluationNow.UTC().Truncate(time.Second)
	digest, err := manager.adapter.coordinator.stateDigest()
	if err != nil {
		return firewall.HAReplicationSnapshot{}, err
	}
	checkpointAt := now
	if !manager.adapter.peerCheckpointAt.IsZero() {
		checkpointAt = manager.adapter.peerCheckpointAt.UTC()
	}
	checkpoint, err := manager.adapter.coordinator.model.replicationCheckpointDigest(checkpointAt)
	if err != nil {
		return firewall.HAReplicationSnapshot{}, err
	}
	coordination := manager.adapter.coordinator.state
	if coordination == haCoordinationHealthy && !manager.adapter.peerReadyLocked(evaluationNow) {
		coordination = haCoordinationDegraded
	}
	result := firewall.HAReplicationSnapshot{
		SchemaVersion: 1, ClusterID: manager.adapter.coordinator.clusterID, Epoch: manager.adapter.coordinator.epoch,
		NodeID: manager.adapter.coordinator.localID, Role: string(manager.adapter.role),
		Coordination: string(coordination), ModelSHA256: digest,
		CheckpointSHA256: checkpoint, PeerCheckpointSHA256: manager.adapter.peerCheckpointSHA256,
		CheckpointAt: checkpointAt.Format(time.RFC3339Nano), CapturedAt: now.Format(time.RFC3339),
	}
	claims := manager.adapter.coordinator.model.snapshot()
	for _, claim := range claims {
		state := ""
		switch claim.Action {
		case "delete":
			state = "deleted"
			result.Deleted++
		case "expiry":
			state = "tombstoned"
			result.Tombstoned++
		case "upsert":
			state = "active"
			if claim.ExpiresAt != "" {
				expiresAt, parseErr := parseCanonicalHATime(claim.ExpiresAt)
				if parseErr != nil {
					return firewall.HAReplicationSnapshot{}, parseErr
				}
				if !expiresAt.After(now) {
					state = "expired"
					result.Expired++
				} else {
					result.Active++
				}
			} else {
				result.Active++
			}
		default:
			return firewall.HAReplicationSnapshot{}, fmt.Errorf("invalid HA v2 claim action")
		}
		if len(result.Claims) < limit {
			result.Claims = append(result.Claims, firewall.HAReplicationClaimSnapshot{
				Owner: claim.Owner, Source: claim.Source, IP: claim.IP, State: state,
				ExpiresAt: claim.ExpiresAt, TombstoneUntil: claim.TombstoneUntil,
			})
		} else {
			result.Truncated = true
		}
	}
	sort.Slice(result.Claims, func(i, j int) bool {
		if result.Claims[i].IP != result.Claims[j].IP {
			return result.Claims[i].IP < result.Claims[j].IP
		}
		if result.Claims[i].Owner != result.Claims[j].Owner {
			return result.Claims[i].Owner < result.Claims[j].Owner
		}
		return result.Claims[i].Source < result.Claims[j].Source
	})
	return result, nil
}

func newHAV2ReplicatedManager(underlying firewall.Manager, adapter *haRuntimeV2Adapter) (*haV2ReplicatedManager, error) {
	if underlying == nil || adapter == nil || adapter.transactionManager == nil || adapter.transactionStore == nil {
		return nil, fmt.Errorf("HA v2 replicated firewall manager requires a recoverable authoritative backend")
	}
	return &haV2ReplicatedManager{underlying: underlying, adapter: adapter}, nil
}

func (manager *haV2ReplicatedManager) Name() string {
	return manager.underlying.Name() + " + HA v2"
}

func (manager *haV2ReplicatedManager) Ban(ip string) error {
	return manager.adapter.applyLocalTarget(ip, haV2LocalRuntimeSource, "upsert", firewall.MaximumBanTTL, false)
}

func (manager *haV2ReplicatedManager) BanWithTTL(ip string, ttl time.Duration) error {
	return manager.adapter.applyLocalTarget(ip, haV2LocalRuntimeSource, "upsert", ttl, false)
}

func (manager *haV2ReplicatedManager) banSourceWithTTL(ip, source string, ttl time.Duration) error {
	return manager.adapter.applyLocalTarget(ip, source, "upsert", ttl, false)
}

func (manager *haV2ReplicatedManager) ReconcileBanTTL(ip string, ttl time.Duration) error {
	return manager.BanWithTTL(ip, ttl)
}

func (manager *haV2ReplicatedManager) BanPermanent(ip string) error {
	return manager.adapter.applyLocalTarget(ip, haV2LocalRuntimeSource, "upsert", 0, true)
}

func (manager *haV2ReplicatedManager) Unban(ip string) error {
	return manager.adapter.applyLocalTarget(ip, haV2LocalRuntimeSource, "delete", 0, false)
}

func (manager *haV2ReplicatedManager) unbanSource(ip, source string) error {
	return manager.adapter.applyLocalTarget(ip, source, "delete", 0, false)
}

// sourceClaimState inspects only the static writer's exact source namespace.
// The caller can therefore reconcile an integration-owned claim without
// shortening or tombstoning a local or independently sourced claim for the
// same address.
func (manager *haV2ReplicatedManager) sourceClaimState(ip, source string, requiredUntil, now time.Time) (bool, bool, error) {
	canonical, err := canonicalHAAddress(ip)
	if err != nil || !validHASource(source) {
		return false, false, fmt.Errorf("invalid HA v2 source claim identity")
	}
	manager.adapter.mu.Lock()
	defer manager.adapter.mu.Unlock()
	key := manager.adapter.coordinator.localID + "\x00" + source + "\x00" + canonical
	operation, exists := manager.adapter.coordinator.model.claims[key]
	if !exists || operation.Action != "upsert" {
		return false, false, nil
	}
	if operation.ExpiresAt == "" {
		return true, true, nil
	}
	expiresAt, err := parseCanonicalHATime(operation.ExpiresAt)
	if err != nil {
		return false, false, err
	}
	active := expiresAt.After(now.UTC())
	return true, active && !expiresAt.Before(requiredUntil.UTC()), nil
}

func (manager *haV2ReplicatedManager) BanExpiryMode() firewall.BanExpiryMode {
	return firewall.BanExpiryNative
}

func (manager *haV2ReplicatedManager) Health() firewall.HealthState {
	manager.adapter.mu.Lock()
	state := manager.adapter.coordinator.state
	peerReady := manager.adapter.peerReadyLocked(manager.adapter.now())
	manager.adapter.mu.Unlock()
	if state == haCoordinationFenced {
		return firewall.HealthUnavailable
	}
	if state != haCoordinationHealthy || !peerReady {
		return firewall.HealthDegraded
	}
	if reporter, ok := manager.underlying.(firewall.HealthReporter); ok {
		return reporter.Health()
	}
	return firewall.HealthHealthy
}
