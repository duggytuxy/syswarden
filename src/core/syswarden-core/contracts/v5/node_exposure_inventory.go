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
	NodeExposureInventorySchema     = "syswarden.node-exposure-inventory.v1"
	MaxNodeExposureInventoryMembers = 4096
	MaxNodeExposureInventoryInputs  = 8192
	MaxNodeExposureInventoryBytes   = 8 * 1024 * 1024
)

var ErrInvalidNodeExposureInventory = errors.New("invalid node exposure inventory")

// NodeExposureInventoryContext pins a complete independently authorized
// population, policy and measurement instant. The caller must verify the actual
// membership contents and field permissions; references alone grant no authority.
type NodeExposureInventoryContext struct {
	Scope                RateReference
	Membership           RateReference
	Policy               RateReference
	Now                  time.Time
	MaxReportAge         time.Duration
	MaxClassificationAge time.Duration
}

func (c NodeExposureInventoryContext) validate() bool {
	return c.Scope.validate() && c.Membership.validate() && c.Policy.validate() &&
		timestamp(c.Now.UTC().Format(time.RFC3339Nano)) &&
		c.MaxReportAge > 0 && c.MaxReportAge <= MaxSnapshotLifetime &&
		c.MaxClassificationAge > 0 && c.MaxClassificationAge <= MaxSnapshotLifetime
}

// NodeExposureSelection comes from trusted admission, never from a submitted
// report. An empty selection means no report was selected; partial is invalid.
type NodeExposureSelection struct {
	SnapshotID  string `json:"snapshot_id"`
	SHA256      string `json:"sha256"`
	CollectorID string `json:"collector_id"`
}

func (s NodeExposureSelection) validate() bool {
	return s == (NodeExposureSelection{}) ||
		(identifier(s.SnapshotID) && digest(s.SHA256) && identifier(s.CollectorID))
}

// NodeExposureInventoryMember includes authorized nodes without reports. One
// node cannot have concurrent epochs or contradictory independent selections.
type NodeExposureInventoryMember struct {
	Identity  NodeIdentity
	Selection NodeExposureSelection
}

// NodeExposureInventoryReport carries independently authenticated routing
// identity. Neither its payload nor this struct enrolls or authorizes a node.
// Input slices must not be changed concurrently with resolution.
type NodeExposureInventoryReport struct {
	Identity NodeIdentity
	Document []byte
}

// NodeExposureInventoryEntry preserves uncertainty instead of guessing an
// Internal/External group from hosting or a missing report. Rejected payloads
// contribute no fields; identity and selection come from trusted membership.
type NodeExposureInventoryEntry struct {
	Identity     NodeIdentity            `json:"identity"`
	Selection    NodeExposureSelection   `json:"selection"`
	Group        string                  `json:"group"`
	ReportState  string                  `json:"report_state"`
	Reason       string                  `json:"reason"`
	Exposure     InventoryClassification `json:"exposure"`
	HostingModel InventoryClassification `json:"hosting_model"`
}

type nodeExposureInventoryManifest struct {
	Schema                 string                       `json:"schema"`
	Scope                  RateReference                `json:"scope"`
	Membership             RateReference                `json:"membership"`
	Policy                 RateReference                `json:"policy"`
	AssessedAt             string                       `json:"assessed_at"`
	MaxReportAgeNS         int64                        `json:"max_report_age_ns"`
	MaxClassificationAgeNS int64                        `json:"max_classification_age_ns"`
	Entries                []NodeExposureInventoryEntry `json:"entries"`
}

// NodeExposureInventory is immutable through this API. It is not a registry,
// authenticated export, map permission, health verdict or KPI population.
type NodeExposureInventory struct {
	context  NodeExposureInventoryContext
	entries  []NodeExposureInventoryEntry
	manifest []byte
}

func (i NodeExposureInventory) Entries() []NodeExposureInventoryEntry { return slices.Clone(i.entries) }
func (i NodeExposureInventory) Manifest() []byte                      { return slices.Clone(i.manifest) }

func (i NodeExposureInventory) Reference(ref string) (RateReference, error) {
	if len(i.manifest) == 0 || !identifier(ref) {
		return RateReference{}, invalidNodeExposureInventory("reference")
	}
	return RateReference{Ref: ref, SHA256: nodeRateDigest(i.manifest)}, nil
}

// SelectGroup returns an independent sorted subset of the same authorized
// snapshot. A valid empty group returns an empty slice, while an invalid group
// or uninitialized inventory returns nil and an error. This is not fresh RBAC:
// callers must reauthorize or rebuild after scope, policy or time changes.
func (i NodeExposureInventory) SelectGroup(group string) ([]NodeExposureInventoryEntry, error) {
	if len(i.manifest) == 0 || !member("external", "internal", "needs_classification")(group) {
		return nil, invalidNodeExposureInventory("group selection")
	}
	entries := make([]NodeExposureInventoryEntry, 0)
	for _, entry := range i.entries {
		if entry.Group == group {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

func invalidNodeExposureInventory(field string) error {
	return fmt.Errorf("%w: %s", ErrInvalidNodeExposureInventory, field)
}

type nodeExposureDocumentKey struct {
	identity NodeIdentity
	digest   [sha256.Size]byte
}

type nodeExposureObservation struct {
	entry    NodeExposureInventoryEntry
	seen     bool
	conflict bool
}

// ResolveNodeExposureInventory begins with complete authorized membership, not
// responders. Foreign routing, incompatible membership and bounds reject the
// entire result. A malformed or substituted selected report leaves its member
// visible with rejected fields in needs_classification, never Internal by default.
func ResolveNodeExposureInventory(c NodeExposureInventoryContext, members []NodeExposureInventoryMember, reports []NodeExposureInventoryReport) (NodeExposureInventory, error) {
	if !c.validate() || len(members) > MaxNodeExposureInventoryInputs || len(reports) > MaxNodeExposureInventoryInputs {
		return NodeExposureInventory{}, invalidNodeExposureInventory("context or input count")
	}
	indexed := make(map[NodeIdentity]NodeExposureInventoryMember)
	epochs := make(map[[2]string]string)
	for _, m := range members {
		if m.Identity.Validate() != nil || !m.Selection.validate() {
			return NodeExposureInventory{}, invalidNodeExposureInventory("member")
		}
		key := [2]string{m.Identity.ClusterID, m.Identity.NodeID}
		if epoch, exists := epochs[key]; exists && epoch != m.Identity.Epoch {
			return NodeExposureInventory{}, invalidNodeExposureInventory("membership epoch conflict")
		}
		if old, exists := indexed[m.Identity]; exists && old != m {
			return NodeExposureInventory{}, invalidNodeExposureInventory("membership conflict")
		}
		indexed[m.Identity], epochs[key] = m, m.Identity.Epoch
		if len(indexed) > MaxNodeExposureInventoryMembers {
			return NodeExposureInventory{}, invalidNodeExposureInventory("member count")
		}
	}
	total := 0
	for _, r := range reports {
		if r.Identity.Validate() != nil {
			return NodeExposureInventory{}, invalidNodeExposureInventory("report identity")
		}
		m, exists := indexed[r.Identity]
		if !exists || m.Selection == (NodeExposureSelection{}) {
			return NodeExposureInventory{}, invalidNodeExposureInventory("foreign or unselected report")
		}
		if len(r.Document) > MaxDocumentBytes || len(r.Document) > MaxNodeExposureInventoryBytes-total {
			return NodeExposureInventory{}, invalidNodeExposureInventory("document bounds")
		}
		total += len(r.Document)
	}
	observations := make(map[NodeIdentity]nodeExposureObservation)
	processed := make(map[nodeExposureDocumentKey]struct{})
	for _, r := range reports {
		old := observations[r.Identity]
		if old.conflict {
			continue
		}
		// Validate every identity and byte budget before hashing or decoding.
		key := nodeExposureDocumentKey{identity: r.Identity, digest: sha256.Sum256(r.Document)}
		if _, seen := processed[key]; seen {
			continue
		}
		processed[key] = struct{}{}
		candidate := projectNodeExposureInventoryReport(c, indexed[r.Identity], r.Document)
		if old.seen && old.entry != candidate {
			observations[r.Identity] = nodeExposureObservation{seen: true, conflict: true,
				entry: unavailableNodeExposureEntry(indexed[r.Identity], Rejected, "conflicting_reports")}
		} else {
			observations[r.Identity] = nodeExposureObservation{seen: true, entry: candidate}
		}
	}
	entries := make([]NodeExposureInventoryEntry, 0, len(indexed))
	for identity, m := range indexed {
		entry := unavailableNodeExposureEntry(m, Missing, "missing_report")
		if observation := observations[identity]; observation.seen {
			entry = observation.entry
		}
		entries = append(entries, entry)
	}
	slices.SortFunc(entries, func(a, b NodeExposureInventoryEntry) int {
		return compareNodeRateFields([3]string{a.Identity.ClusterID, a.Identity.NodeID, a.Identity.Epoch},
			[3]string{b.Identity.ClusterID, b.Identity.NodeID, b.Identity.Epoch})
	})
	data, err := json.Marshal(nodeExposureInventoryManifest{Schema: NodeExposureInventorySchema,
		Scope: c.Scope, Membership: c.Membership, Policy: c.Policy, AssessedAt: c.Now.UTC().Format(time.RFC3339Nano),
		MaxReportAgeNS: int64(c.MaxReportAge), MaxClassificationAgeNS: int64(c.MaxClassificationAge), Entries: entries})
	if err != nil || len(data) > MaxNodeExposureInventoryBytes {
		return NodeExposureInventory{}, invalidNodeExposureInventory("manifest bounds")
	}
	c.Now = c.Now.UTC()
	return NodeExposureInventory{context: c, entries: entries, manifest: data}, nil
}

func unavailableNodeExposureEntry(m NodeExposureInventoryMember, state, reason string) NodeExposureInventoryEntry {
	return NodeExposureInventoryEntry{Identity: m.Identity, Selection: m.Selection,
		Group: "needs_classification", ReportState: state, Reason: reason,
		Exposure: InventoryClassification{State: state}, HostingModel: InventoryClassification{State: state}}
}

func projectNodeExposureInventoryReport(c NodeExposureInventoryContext, m NodeExposureInventoryMember, data []byte) NodeExposureInventoryEntry {
	s, err := DecodeNodeExposureSnapshot(data)
	if err != nil {
		return unavailableNodeExposureEntry(m, Rejected, "report_rejected")
	}
	view, err := ProjectNodeExposureSnapshot(s, NodeExposureReadContext{SnapshotID: m.Selection.SnapshotID,
		SnapshotSHA256: m.Selection.SHA256, CollectorID: m.Selection.CollectorID, ExpectedIdentity: m.Identity,
		Scope: c.Scope, Policy: c.Policy, Now: c.Now, MaxReportAge: c.MaxReportAge, MaxClassificationAge: c.MaxClassificationAge})
	if err != nil {
		return unavailableNodeExposureEntry(m, Rejected, "report_rejected")
	}
	return NodeExposureInventoryEntry{Identity: m.Identity, Selection: m.Selection, Group: view.Group,
		ReportState: view.ReportState, Reason: view.Reason, Exposure: view.Exposure, HostingModel: view.HostingModel}
}
