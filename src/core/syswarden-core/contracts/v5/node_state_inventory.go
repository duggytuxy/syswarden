package v5

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

const (
	NodeStateInventorySchema     = "syswarden.node-state-inventory.v1"
	MaxNodeStateInventoryMembers = 4096
	MaxNodeStateInventoryInputs  = 8192
	MaxNodeStateInventoryBytes   = 8 * 1024 * 1024
)

var ErrInvalidNodeStateInventory = errors.New("invalid node state inventory")

// NodeStateInventoryContext pins a complete independently authorized
// population, policy and measurement instant. The caller must verify the actual
// membership contents and field permissions; references alone grant no authority.
type NodeStateInventoryContext struct {
	Scope        RateReference
	Membership   RateReference
	Policy       RateReference
	Now          time.Time
	MaxReportAge time.Duration
}

func (c NodeStateInventoryContext) validate() bool {
	return c.Scope.validate() && c.Membership.validate() && c.Policy.validate() &&
		timestamp(c.Now.UTC().Format(time.RFC3339Nano)) &&
		c.MaxReportAge > 0 && c.MaxReportAge <= MaxSnapshotLifetime
}

// NodeStateSelection comes from trusted admission, never from a submitted
// report. An empty selection means no report was selected; partial is invalid.
type NodeStateSelection struct {
	SnapshotID  string `json:"snapshot_id"`
	SHA256      string `json:"sha256"`
	CollectorID string `json:"collector_id"`
}

func (s NodeStateSelection) validate() bool {
	return s == (NodeStateSelection{}) ||
		(identifier(s.SnapshotID) && digest(s.SHA256) && identifier(s.CollectorID))
}

// NodeStateInventoryMember includes authorized nodes without reports. One
// node cannot have concurrent epochs or contradictory independent selections.
type NodeStateInventoryMember struct {
	Identity  NodeIdentity
	Selection NodeStateSelection
}

// NodeStateInventoryReport carries independently authenticated routing
// identity. Neither its payload nor this struct enrolls or authorizes a node.
// Input slices must not be changed concurrently with resolution.
type NodeStateInventoryReport struct {
	Identity NodeIdentity
	Document []byte
}

// NodeStateInventoryEntry retains every authorized identity and distinguishes
// transport from source quality. Rejected or missing input exposes no source
// metadata or values. Trusted selection alone is not a successful observation.
type NodeStateInventoryEntry struct {
	Identity              NodeIdentity          `json:"identity"`
	Selection             NodeStateSelection    `json:"selection"`
	ReportState           string                `json:"report_state"`
	Reason                string                `json:"reason"`
	CollectedAt           string                `json:"collected_at"`
	ValidUntil            string                `json:"valid_until"`
	CurrentReachability   string                `json:"current_reachability"`
	Reachability          Field                 `json:"reachability"`
	LastSuccessfulContact NodeSnapshotFieldView `json:"last_successful_contact"`
	ObservedAt            NodeSnapshotFieldView `json:"observed_at"`
	ClockQuality          NodeSnapshotFieldView `json:"clock_quality"`
	AgentVersion          NodeSnapshotFieldView `json:"agent_version"`
	PolicyRef             NodeSnapshotFieldView `json:"policy_ref"`
	ControlRef            NodeSnapshotFieldView `json:"control_ref"`
	IntegrationRef        NodeSnapshotFieldView `json:"integration_ref"`
}

type nodeStateInventoryManifest struct {
	Schema         string                    `json:"schema"`
	Scope          RateReference             `json:"scope"`
	Membership     RateReference             `json:"membership"`
	Policy         RateReference             `json:"policy"`
	AssessedAt     string                    `json:"assessed_at"`
	MaxReportAgeNS int64                     `json:"max_report_age_ns"`
	Entries        []NodeStateInventoryEntry `json:"entries"`
}

// NodeStateInventory is immutable through this API. It is not a registry,
// authenticated export, map permission, health verdict or KPI population.
type NodeStateInventory struct {
	context  NodeStateInventoryContext
	entries  []NodeStateInventoryEntry
	manifest []byte
}

func (i NodeStateInventory) Entries() []NodeStateInventoryEntry { return slices.Clone(i.entries) }
func (i NodeStateInventory) Manifest() []byte                   { return slices.Clone(i.manifest) }

func (i NodeStateInventory) Reference(ref string) (RateReference, error) {
	if len(i.manifest) == 0 || !identifier(ref) {
		return RateReference{}, invalidNodeStateInventory("reference")
	}
	return RateReference{Ref: ref, SHA256: nodeRateDigest(i.manifest)}, nil
}

func invalidNodeStateInventory(field string) error {
	return fmt.Errorf("%w: %s", ErrInvalidNodeStateInventory, field)
}

type nodeStateDocumentKey struct {
	identity NodeIdentity
	digest   [sha256.Size]byte
}

type nodeStateObservation struct {
	entry    NodeStateInventoryEntry
	seen     bool
	conflict bool
}

// ResolveNodeStateInventory begins with complete authorized membership, not
// responders. Foreign routing, incompatible membership and bounds reject the
// entire result. A malformed or substituted report leaves only its member
// rejected, with unknown current reachability and no payload fields.
func ResolveNodeStateInventory(c NodeStateInventoryContext, members []NodeStateInventoryMember, reports []NodeStateInventoryReport) (NodeStateInventory, error) {
	if !c.validate() || len(members) > MaxNodeStateInventoryInputs || len(reports) > MaxNodeStateInventoryInputs {
		return NodeStateInventory{}, invalidNodeStateInventory("context or input count")
	}
	indexed := make(map[NodeIdentity]NodeStateInventoryMember)
	epochs := make(map[[2]string]string)
	for _, m := range members {
		if m.Identity.Validate() != nil || !m.Selection.validate() {
			return NodeStateInventory{}, invalidNodeStateInventory("member")
		}
		key := [2]string{m.Identity.ClusterID, m.Identity.NodeID}
		if epoch, exists := epochs[key]; exists && epoch != m.Identity.Epoch {
			return NodeStateInventory{}, invalidNodeStateInventory("membership epoch conflict")
		}
		if old, exists := indexed[m.Identity]; exists && old != m {
			return NodeStateInventory{}, invalidNodeStateInventory("membership conflict")
		}
		indexed[m.Identity], epochs[key] = m, m.Identity.Epoch
		if len(indexed) > MaxNodeStateInventoryMembers {
			return NodeStateInventory{}, invalidNodeStateInventory("member count")
		}
	}
	total := 0
	for _, r := range reports {
		if r.Identity.Validate() != nil {
			return NodeStateInventory{}, invalidNodeStateInventory("report identity")
		}
		m, exists := indexed[r.Identity]
		if !exists || m.Selection == (NodeStateSelection{}) {
			return NodeStateInventory{}, invalidNodeStateInventory("foreign or unselected report")
		}
		if len(r.Document) > MaxDocumentBytes || len(r.Document) > MaxNodeStateInventoryBytes-total {
			return NodeStateInventory{}, invalidNodeStateInventory("document bounds")
		}
		total += len(r.Document)
	}
	observations := make(map[NodeIdentity]nodeStateObservation)
	processed := make(map[nodeStateDocumentKey]struct{})
	for _, r := range reports {
		old := observations[r.Identity]
		if old.conflict {
			continue
		}
		// Validate every identity and byte budget before hashing or decoding.
		key := nodeStateDocumentKey{identity: r.Identity, digest: sha256.Sum256(r.Document)}
		if _, seen := processed[key]; seen {
			continue
		}
		processed[key] = struct{}{}
		candidate := projectNodeStateInventoryReport(c, indexed[r.Identity], r.Document)
		if old.seen && old.entry != candidate {
			observations[r.Identity] = nodeStateObservation{seen: true, conflict: true,
				entry: unavailableNodeStateEntry(indexed[r.Identity], Rejected, "conflicting_reports")}
		} else {
			observations[r.Identity] = nodeStateObservation{seen: true, entry: candidate}
		}
	}
	entries := make([]NodeStateInventoryEntry, 0, len(indexed))
	for identity, m := range indexed {
		entry := unavailableNodeStateEntry(m, Missing, "missing_report")
		if observation := observations[identity]; observation.seen {
			entry = observation.entry
		}
		entries = append(entries, entry)
	}
	slices.SortFunc(entries, func(a, b NodeStateInventoryEntry) int {
		return compareNodeRateFields([3]string{a.Identity.ClusterID, a.Identity.NodeID, a.Identity.Epoch},
			[3]string{b.Identity.ClusterID, b.Identity.NodeID, b.Identity.Epoch})
	})
	data, err := json.Marshal(nodeStateInventoryManifest{Schema: NodeStateInventorySchema,
		Scope: c.Scope, Membership: c.Membership, Policy: c.Policy, AssessedAt: c.Now.UTC().Format(time.RFC3339Nano),
		MaxReportAgeNS: int64(c.MaxReportAge), Entries: entries})
	if err != nil || len(data) > MaxNodeStateInventoryBytes {
		return NodeStateInventory{}, invalidNodeStateInventory("manifest bounds")
	}
	c.Now = c.Now.UTC()
	return NodeStateInventory{context: c, entries: entries, manifest: data}, nil
}

func unavailableNodeStateEntry(m NodeStateInventoryMember, state, reason string) NodeStateInventoryEntry {
	field := NodeSnapshotFieldView{Reported: Field{State: state}, State: state}
	return NodeStateInventoryEntry{Identity: m.Identity, Selection: m.Selection,
		ReportState: state, Reason: reason, CurrentReachability: "unknown",
		Reachability: Field{State: state}, LastSuccessfulContact: field, ObservedAt: field,
		ClockQuality: field, AgentVersion: field, PolicyRef: field, ControlRef: field, IntegrationRef: field}
}

func projectNodeStateInventoryReport(c NodeStateInventoryContext, m NodeStateInventoryMember, data []byte) NodeStateInventoryEntry {
	s, err := DecodeNodeSnapshot(data)
	if err != nil {
		return unavailableNodeStateEntry(m, Rejected, "report_rejected")
	}
	view, err := ProjectNodeSnapshot(s, NodeSnapshotViewContext{SnapshotID: m.Selection.SnapshotID,
		SnapshotSHA256: m.Selection.SHA256, CollectorID: m.Selection.CollectorID,
		ReadContext: NodeReadContext{ExpectedIdentity: m.Identity, Now: c.Now, MaxAge: c.MaxReportAge}})
	if err != nil {
		return unavailableNodeStateEntry(m, Rejected, "report_rejected")
	}
	return NodeStateInventoryEntry{Identity: m.Identity, Selection: m.Selection,
		ReportState: view.ReportState, Reason: view.Reason, CollectedAt: view.CollectedAt,
		ValidUntil: view.ValidUntil, CurrentReachability: view.CurrentReachability,
		Reachability: view.Reachability, LastSuccessfulContact: view.LastSuccessfulContact,
		ObservedAt: view.ObservedAt, ClockQuality: view.ClockQuality, AgentVersion: view.AgentVersion,
		PolicyRef: view.PolicyRef, ControlRef: view.ControlRef, IntegrationRef: view.IntegrationRef}
}
