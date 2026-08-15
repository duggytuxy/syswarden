package telemetry

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/viper"
)

const (
	defaultHASyncStatusFile      = "/var/lib/syswarden/ha/sync-status.json"
	maxHASyncStatusBytes         = 256 * 1024
	defaultHASyncTelemetryMaxAge = 35 * time.Minute
)

type HAPeerTelemetry struct {
	Peer           string `json:"peer"`
	State          string `json:"state"`
	InSync         bool   `json:"in_sync"`
	Desynced       bool   `json:"desynced"`
	LocalIPs       int    `json:"local_ips"`
	RemoteIPs      int    `json:"remote_ips"`
	MissingOnPeer  int    `json:"missing_on_peer"`
	MissingLocally int    `json:"missing_locally"`
	Pushed         int    `json:"pushed"`
	Attempts       int    `json:"attempts"`
	LastAttempt    string `json:"last_attempt"`
	LastError      string `json:"last_error,omitempty"`
}

type HATelemetry struct {
	Status    string            `json:"status"`
	UpdatedAt string            `json:"updated_at,omitempty"`
	Stale     bool              `json:"stale"`
	Peers     []HAPeerTelemetry `json:"peers"`
}

type haSyncStatusSnapshot struct {
	UpdatedAt string            `json:"updated_at"`
	Peers     []HAPeerTelemetry `json:"peers"`
}

func getHATelemetry() *HATelemetry {
	if !viper.GetBool("integrations.ha.enabled") {
		return nil
	}
	return loadHATelemetry(defaultHASyncStatusFile, viper.GetStringSlice("integrations.ha.peer_ips"), time.Now())
}

func loadHATelemetry(path string, configuredPeers []string, now time.Time) *HATelemetry {
	hasConfiguredScope := hasConfiguredHAPeerScope(configuredPeers)
	configuredPeers = normalizedHAPeerNames(configuredPeers)
	result := &HATelemetry{Status: "unknown", Peers: make([]HAPeerTelemetry, 0, len(configuredPeers))}
	if len(configuredPeers) == 0 {
		if hasConfiguredScope {
			result.Status = "inbound-only"
		} else {
			result.Status = "unconfigured"
		}
		return result
	}

	snapshot, err := readHASyncStatus(path)
	if err != nil {
		for _, peer := range configuredPeers {
			result.Peers = append(result.Peers, HAPeerTelemetry{Peer: peer, State: "unknown", LastError: "sync status unavailable"})
		}
		return result
	}
	result.UpdatedAt = snapshot.UpdatedAt
	updatedAt, timestampErr := time.Parse(time.RFC3339, snapshot.UpdatedAt)
	result.Stale = timestampErr != nil || now.Sub(updatedAt) > defaultHASyncTelemetryMaxAge || updatedAt.Sub(now) > 5*time.Minute

	byPeer := make(map[string]HAPeerTelemetry, len(snapshot.Peers))
	for _, peerStatus := range snapshot.Peers {
		name := strings.TrimSpace(peerStatus.Peer)
		if name == "" || !validHAPeerTelemetry(peerStatus) {
			continue
		}
		peerStatus.Peer = name
		byPeer[name] = peerStatus
	}
	for _, peer := range configuredPeers {
		status, ok := byPeer[peer]
		if !ok {
			status = HAPeerTelemetry{Peer: peer, State: "unknown", LastError: "peer missing from last sync status"}
		}
		result.Peers = append(result.Peers, status)
	}
	result.Status = aggregateHATelemetryStatus(result.Peers, result.Stale)
	return result
}

func readHASyncStatus(path string) (haSyncStatusSnapshot, error) {
	path = filepath.Clean(path)
	before, err := os.Lstat(path)
	if err != nil {
		return haSyncStatusSnapshot{}, err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm() != 0600 {
		return haSyncStatusSnapshot{}, fmt.Errorf("HA sync status must be a regular 0600 file")
	}
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return haSyncStatusSnapshot{}, err
	}
	defer root.Close()
	file, err := root.Open(filepath.Base(path))
	if err != nil {
		return haSyncStatusSnapshot{}, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return haSyncStatusSnapshot{}, err
	}
	current, err := root.Lstat(filepath.Base(path))
	if err != nil || !opened.Mode().IsRegular() || !current.Mode().IsRegular() || opened.Mode().Perm() != 0600 ||
		!os.SameFile(before, opened) || !os.SameFile(opened, current) {
		return haSyncStatusSnapshot{}, fmt.Errorf("HA sync status changed while opening")
	}
	wire, err := io.ReadAll(io.LimitReader(file, maxHASyncStatusBytes+1))
	if err != nil {
		return haSyncStatusSnapshot{}, err
	}
	if len(wire) > maxHASyncStatusBytes {
		return haSyncStatusSnapshot{}, fmt.Errorf("HA sync status exceeds %d bytes", maxHASyncStatusBytes)
	}
	var snapshot haSyncStatusSnapshot
	// The producer and consumer can be upgraded independently. Unknown fields
	// are intentionally tolerated in this local mixed-version artifact.
	if err := json.Unmarshal(wire, &snapshot); err != nil {
		return haSyncStatusSnapshot{}, err
	}
	if snapshot.UpdatedAt == "" {
		return haSyncStatusSnapshot{}, errors.New("HA sync status timestamp is missing")
	}
	return snapshot, nil
}

func normalizedHAPeerNames(peers []string) []string {
	seen := make(map[string]struct{}, len(peers))
	result := make([]string, 0, len(peers))
	for _, peer := range peers {
		peer = strings.TrimSpace(peer)
		address, err := netip.ParseAddr(strings.Trim(peer, "[]"))
		if err != nil || address.Is4In6() || address.Zone() != "" {
			continue
		}
		peer = address.String()
		if _, ok := seen[peer]; ok {
			continue
		}
		seen[peer] = struct{}{}
		result = append(result, peer)
	}
	sort.Strings(result)
	return result
}

func hasConfiguredHAPeerScope(peers []string) bool {
	for _, peer := range peers {
		peer = strings.TrimSpace(peer)
		if address, err := netip.ParseAddr(strings.Trim(peer, "[]")); err == nil && !address.Is4In6() && address.Zone() == "" {
			return true
		}
		prefix, err := netip.ParsePrefix(peer)
		if err == nil && prefix.IsValid() && !prefix.Addr().Is4In6() && prefix.Addr().Zone() == "" && prefix == prefix.Masked() {
			return true
		}
	}
	return false
}

func validHAPeerTelemetry(status HAPeerTelemetry) bool {
	if status.LocalIPs < 0 || status.RemoteIPs < 0 || status.MissingOnPeer < 0 || status.MissingLocally < 0 || status.Pushed < 0 || status.Attempts < 0 {
		return false
	}
	switch status.State {
	case "synced", "desynced", "offline", "rejected", "invalid", "error", "unknown":
		return true
	default:
		return false
	}
}

func aggregateHATelemetryStatus(peers []HAPeerTelemetry, stale bool) string {
	if stale {
		return "stale"
	}
	if len(peers) == 0 {
		return "unconfigured"
	}
	hasUnknown := false
	for _, peer := range peers {
		switch peer.State {
		case "offline", "rejected", "invalid", "error":
			return "degraded"
		case "unknown":
			hasUnknown = true
		}
		if peer.Desynced || !peer.InSync || peer.MissingOnPeer > 0 || peer.MissingLocally > 0 {
			if peer.State != "unknown" {
				return "desynced"
			}
		}
	}
	if hasUnknown {
		return "unknown"
	}
	return "synced"
}
