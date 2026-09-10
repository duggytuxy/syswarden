package telemetry

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"syswarden-core/firewall"
)

const (
	maximumRuntimeEnforcementClaims = 1024
	maximumHAReplicationClaims      = 16384
	// Five minutes exceeds the HA v2 heartbeat timeout ceiling of two minutes
	// while leaving bounded room for serialization latency and host clock skew.
	runtimeCheckpointTimeTolerance = 5 * time.Minute
)

var runtimeEnforcementIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
var runtimeEnforcementNow = time.Now

type runtimeEnforcementView struct {
	scope                string
	linked               bool
	complete             bool
	truncated            bool
	clusterID            string
	epoch                uint64
	nodeID               string
	role                 string
	coordination         string
	modelSHA256          string
	checkpointSHA256     string
	peerCheckpointSHA256 string
	checkpointAt         string
	capturedAt           string
	active               int
	expired              int
	deleted              int
	tombstoned           int
	byIP                 map[string]string
	localSnapshot        *firewall.RuntimeLifecycleSnapshot
}

type runtimeLifecycleObservation struct {
	state      string
	observedAt time.Time
}

func unavailableRuntimeEnforcementView() runtimeEnforcementView {
	return runtimeEnforcementView{
		scope: "not-reported",
		byIP:  make(map[string]string),
	}
}

func collectRuntimeEnforcementView(manager FirewallManager) (runtimeEnforcementView, error) {
	view := unavailableRuntimeEnforcementView()
	reporter, available := manager.(firewall.HAReplicationStateReporter)
	if !available {
		return collectLocalRuntimeEnforcementView(manager)
	}
	view.scope = "ha-v2-runtime-snapshot"
	snapshot, err := reporter.HAReplicationStateSnapshot(maximumRuntimeEnforcementClaims)
	if err != nil {
		return view, fmt.Errorf("read HA v2 runtime state: %w", err)
	}
	if err := validateRuntimeEnforcementSnapshot(snapshot); err != nil {
		return view, err
	}
	view.linked = true
	view.complete = !snapshot.Truncated
	view.truncated = snapshot.Truncated
	view.clusterID = snapshot.ClusterID
	view.epoch = snapshot.Epoch
	view.nodeID = snapshot.NodeID
	view.role = snapshot.Role
	view.coordination = snapshot.Coordination
	view.modelSHA256 = snapshot.ModelSHA256
	view.checkpointSHA256 = snapshot.CheckpointSHA256
	view.peerCheckpointSHA256 = snapshot.PeerCheckpointSHA256
	view.checkpointAt = snapshot.CheckpointAt
	view.capturedAt = snapshot.CapturedAt
	view.active = snapshot.Active
	view.expired = snapshot.Expired
	view.deleted = snapshot.Deleted
	view.tombstoned = snapshot.Tombstoned
	for _, claim := range snapshot.Claims {
		view.byIP[claim.IP] = strongerRuntimeEnforcementState(view.byIP[claim.IP], claim.State)
	}
	return view, nil
}

func validateRuntimeEnforcementSnapshot(snapshot firewall.HAReplicationSnapshot) error {
	if snapshot.SchemaVersion != 1 || snapshot.Epoch == 0 ||
		!runtimeEnforcementIDPattern.MatchString(snapshot.ClusterID) ||
		!runtimeEnforcementIDPattern.MatchString(snapshot.NodeID) {
		return fmt.Errorf("HA v2 runtime snapshot identity is invalid")
	}
	if len(snapshot.ModelSHA256) != 64 || strings.ToLower(snapshot.ModelSHA256) != snapshot.ModelSHA256 {
		return fmt.Errorf("HA v2 runtime snapshot digest is invalid")
	}
	if _, err := hex.DecodeString(snapshot.ModelSHA256); err != nil {
		return fmt.Errorf("HA v2 runtime snapshot digest is invalid")
	}
	if len(snapshot.CheckpointSHA256) != 64 || strings.ToLower(snapshot.CheckpointSHA256) != snapshot.CheckpointSHA256 {
		return fmt.Errorf("HA v2 runtime snapshot checkpoint is invalid")
	}
	if _, err := hex.DecodeString(snapshot.CheckpointSHA256); err != nil {
		return fmt.Errorf("HA v2 runtime snapshot checkpoint is invalid")
	}
	if snapshot.PeerCheckpointSHA256 != "" {
		if len(snapshot.PeerCheckpointSHA256) != 64 || strings.ToLower(snapshot.PeerCheckpointSHA256) != snapshot.PeerCheckpointSHA256 {
			return fmt.Errorf("HA v2 peer runtime checkpoint is invalid")
		}
		if _, err := hex.DecodeString(snapshot.PeerCheckpointSHA256); err != nil {
			return fmt.Errorf("HA v2 peer runtime checkpoint is invalid")
		}
	}
	if snapshot.Coordination == "healthy" && snapshot.PeerCheckpointSHA256 != snapshot.CheckpointSHA256 {
		return fmt.Errorf("healthy HA v2 runtime snapshot checkpoints diverge")
	}
	checkpointAt, err := time.Parse(time.RFC3339Nano, snapshot.CheckpointAt)
	if err != nil || checkpointAt.UTC().Format(time.RFC3339Nano) != snapshot.CheckpointAt {
		return fmt.Errorf("HA v2 runtime snapshot checkpoint time is invalid")
	}
	capturedAt, err := time.Parse(time.RFC3339, snapshot.CapturedAt)
	if err != nil || capturedAt.UTC().Format(time.RFC3339) != snapshot.CapturedAt ||
		capturedAt.After(runtimeEnforcementNow().UTC().Add(5*time.Minute)) {
		return fmt.Errorf("HA v2 runtime snapshot capture time is invalid")
	}
	if err := validateRuntimeCheckpointTiming(checkpointAt, capturedAt, snapshot.Coordination); err != nil {
		return fmt.Errorf("HA v2 runtime snapshot checkpoint timing is invalid: %w", err)
	}
	if snapshot.Role != "writer" && snapshot.Role != "standby" {
		return fmt.Errorf("HA v2 runtime snapshot role is invalid")
	}
	switch snapshot.Coordination {
	case "healthy", "degraded", "fenced", "recovering":
	default:
		return fmt.Errorf("HA v2 runtime snapshot coordination state is invalid")
	}
	counts := []int{snapshot.Active, snapshot.Expired, snapshot.Deleted, snapshot.Tombstoned}
	total := 0
	for _, count := range counts {
		if count < 0 || count > maximumHAReplicationClaims || total > maximumHAReplicationClaims-count {
			return fmt.Errorf("HA v2 runtime snapshot counters are outside bounds")
		}
		total += count
	}
	if len(snapshot.Claims) > maximumRuntimeEnforcementClaims ||
		(!snapshot.Truncated && len(snapshot.Claims) != total) ||
		(snapshot.Truncated && (len(snapshot.Claims) != maximumRuntimeEnforcementClaims || total <= len(snapshot.Claims))) {
		return fmt.Errorf("HA v2 runtime snapshot inventory is inconsistent")
	}
	observed := map[string]int{"active": 0, "expired": 0, "deleted": 0, "tombstoned": 0}
	seen := make(map[string]struct{}, len(snapshot.Claims))
	for _, claim := range snapshot.Claims {
		if err := validateRuntimeEnforcementClaim(claim); err != nil {
			return err
		}
		key := claim.Owner + "\x00" + claim.Source + "\x00" + claim.IP
		if _, duplicate := seen[key]; duplicate {
			return fmt.Errorf("HA v2 runtime snapshot contains a duplicate claim")
		}
		seen[key] = struct{}{}
		observed[claim.State]++
	}
	expected := map[string]int{
		"active": snapshot.Active, "expired": snapshot.Expired,
		"deleted": snapshot.Deleted, "tombstoned": snapshot.Tombstoned,
	}
	for state, count := range observed {
		if count > expected[state] || !snapshot.Truncated && count != expected[state] {
			return fmt.Errorf("HA v2 runtime snapshot state counters are inconsistent")
		}
	}
	return nil
}

func validateRuntimeCheckpointTiming(checkpointAt, capturedAt time.Time, coordination string) error {
	if checkpointAt.After(capturedAt.Add(runtimeCheckpointTimeTolerance)) {
		return fmt.Errorf("checkpoint is too far ahead of capture")
	}
	if coordination == "healthy" && checkpointAt.Before(capturedAt.Add(-runtimeCheckpointTimeTolerance)) {
		return fmt.Errorf("healthy checkpoint is stale")
	}
	return nil
}

func validateRuntimeEnforcementClaim(claim firewall.HAReplicationClaimSnapshot) error {
	if !runtimeEnforcementIDPattern.MatchString(claim.Owner) || len(claim.Source) < 1 || len(claim.Source) > 128 ||
		strings.TrimSpace(claim.Source) != claim.Source {
		return fmt.Errorf("HA v2 runtime claim identity is invalid")
	}
	for _, character := range claim.Source {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && !strings.ContainsRune("._:/-", character) {
			return fmt.Errorf("HA v2 runtime claim source is invalid")
		}
	}
	address, err := netip.ParseAddr(claim.IP)
	if err != nil || address.Is4In6() || address.Zone() != "" || address.String() != claim.IP {
		return fmt.Errorf("HA v2 runtime claim address is invalid")
	}
	parseTime := func(value string) error {
		parsed, parseErr := time.Parse(time.RFC3339, value)
		if parseErr != nil || parsed.UTC().Format(time.RFC3339) != value {
			return fmt.Errorf("HA v2 runtime claim timestamp is invalid")
		}
		return nil
	}
	switch claim.State {
	case "active":
		if claim.TombstoneUntil != "" || claim.ExpiresAt != "" && parseTime(claim.ExpiresAt) != nil {
			return fmt.Errorf("HA v2 active runtime claim is invalid")
		}
	case "expired":
		if claim.ExpiresAt == "" || claim.TombstoneUntil != "" || parseTime(claim.ExpiresAt) != nil {
			return fmt.Errorf("HA v2 expired runtime claim is invalid")
		}
	case "deleted", "tombstoned":
		if claim.ExpiresAt != "" || claim.TombstoneUntil == "" || parseTime(claim.TombstoneUntil) != nil {
			return fmt.Errorf("HA v2 tombstone runtime claim is invalid")
		}
	default:
		return fmt.Errorf("HA v2 runtime claim state is invalid")
	}
	return nil
}

func strongerRuntimeEnforcementState(current, candidate string) string {
	priority := map[string]int{"": 0, "unknown": 1, "absent": 2, "expired": 3, "deleted": 4, "tombstoned": 5, "active": 6}
	if priority[candidate] > priority[current] {
		return candidate
	}
	return current
}

func observeRuntimeLifecycleEvent(event TelemetryEvent, observed map[string]runtimeLifecycleObservation) {
	if observed == nil {
		return
	}
	state := ""
	switch event.Action {
	case "UNBANNED", "DELETED":
		state = "deleted"
	case "EXPIRED":
		state = "expired"
	case "TOMBSTONE":
		state = "tombstoned"
	default:
		return
	}
	address, err := netip.ParseAddr(event.IP)
	if err != nil || address.Is4In6() || address.Zone() != "" {
		return
	}
	canonical := address.String()
	if canonical != event.IP {
		return
	}
	observedAt, err := time.Parse(time.RFC3339Nano, event.Timestamp)
	if err != nil {
		return
	}
	previous, exists := observed[canonical]
	if exists && (observedAt.Before(previous.observedAt) || observedAt.Equal(previous.observedAt) &&
		strongerRuntimeEnforcementState(previous.state, state) == previous.state) {
		return
	}
	observed[canonical] = runtimeLifecycleObservation{state: state, observedAt: observedAt}
}

func resolveRuntimeEnforcementState(
	ip string,
	view runtimeEnforcementView,
	persistent persistentEnforcementView,
	lifecycle map[string]runtimeLifecycleObservation,
) string {
	if persistent.contains(ip) {
		return "active"
	}
	state := view.byIP[ip]
	if view.localSnapshot != nil {
		address, err := netip.ParseAddr(ip)
		if err == nil {
			for _, claim := range view.localSnapshot.Claims {
				if prefix, err := netip.ParsePrefix(claim.Entry); err == nil && prefix.Contains(address) {
					state = strongerRuntimeEnforcementState(state, claim.State)
				}
			}
		}
	}
	if state != "" {
		return state
	}
	if observation, exists := lifecycle[ip]; exists {
		return observation.state
	}
	if view.linked && view.complete && persistent.attested {
		return "absent"
	}
	return "unknown"
}
